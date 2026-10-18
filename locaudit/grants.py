"""Who may read location, and who was seen doing it.

Offline. Reads three captured files and writes facts:

    data/device/dumpsys_package/<pkg>.txt   granted permission - the reliable signal
    data/device/dumpsys_appops.txt          app-op mode per package, and access times per uid
    data/device/dumpsys_location.txt        active listeners and delivered-location counters

Only ACCESS_BACKGROUND_LOCATION means Always. A granted fine location permission without it is
while-in-use. App-op modes are per uid, so they are a cross-check, never the answer
(docs/reference/pitfalls.md#app-ops-modes-are-per-uid).
"""
import os
import re

from . import paths, sdks, store

LOCATION_PERMS = ("ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
                  "ACCESS_BACKGROUND_LOCATION")
EXTRA_PERMS = ("AD_ID", "ACCESS_ADSERVICES_AD_ID", "FOREGROUND_SERVICE_LOCATION",
               "RECEIVE_BOOT_COMPLETED", "BLUETOOTH_SCAN", "NEARBY_WIFI_DEVICES")
FINE_OP = "FINE_LOCATION"
LOCATION_OPS = ("FINE_LOCATION", "COARSE_LOCATION", "MONITOR_LOCATION", "MONITOR_HIGH_POWER_LOCATION")
OWNED = (tuple(f"perm:{p}" for p in LOCATION_PERMS + EXTRA_PERMS)
         + (f"appop:{FINE_OP}", "access:location", "reject:location", "listener:location", "delivered:location"))

_PKG_HEAD = re.compile(r"^  Package \[([^\]]+)\]")
_APP_ID = re.compile(r"^\s+appId=(\d+)$")
_VERSION_NAME = re.compile(r"^\s+versionName=(\S+)$")
_VERSION_CODE = re.compile(r"^\s+versionCode=(\d+)")
_GRANT = re.compile(r"^(\s+)([A-Za-z][\w.]*): granted=(true|false)")
_SECTION = re.compile(r"^(\s+)([\w ]+):$")
_USER = re.compile(r"^\s+User (\d+):")
_RAW_ALWAYS = re.compile(r"ACCESS_BACKGROUND_LOCATION: granted=true")
_UID_HEAD = re.compile(r"^  Uid (\S+):$")
_OP_PKG = re.compile(r"^    Package (\S+):$")
_OP_MODE_UID = re.compile(r"^      ([A-Z_]+): mode=(\w+)$")
_OP_MODE_PKG = re.compile(r"^      ([A-Z_]+) \(([^)]*)\):\s*$")
_ACCESS = re.compile(r"^\s+(Access|Reject):\s*\[([^\]]*)\]\s*(.*)$")
_LISTENER = re.compile(r"^\s+(\d+)/(\S+?)(?:\[([^\]]*)\])?/([0-9A-Fa-f]+)\s+"
                       r"(?:\(COARSE\)\s+)?Request\[(.*)\]$")
_PROVIDER = re.compile(r"^    (\w+) provider:$")
_COUNTER = re.compile(r"^\s+(\d+)/(\S+?)(?:\[[^\]]*\])?: .*locations = (\d+)\s*$")
_COUNTER_HEAD = re.compile(r"^  Historical Aggregate Location Provider Data:$")
_COUNTER_PROVIDER = re.compile(r"^    (\w+):$")
_UID_TEXT = re.compile(r"^u(\d+)a(\d+)$")


# --- dumpsys package ----------------------------------------------------------------

def parse_package(text, pkg):
    """One app's own account: its uid, its version, its permissions and their grants."""
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines)
                  if _PKG_HEAD.match(line) and _PKG_HEAD.match(line).group(1) == pkg), None)
    if start is None:
        return {}
    block = []
    for line in lines[start + 1:]:
        if _PKG_HEAD.match(line):
            break
        block.append(line)

    out = {"app_id": None, "version_name": None, "version_code": None,
           "requested": set(), "install": {}, "runtime": {}, "users": []}
    section, section_indent = None, 0
    for line in block:
        for pattern, key in ((_APP_ID, "app_id"), (_VERSION_NAME, "version_name"),
                             (_VERSION_CODE, "version_code")):
            m = pattern.match(line)
            if m and out[key] is None:
                out[key] = m.group(1)
        m = _USER.match(line)
        if m:
            out["users"].append(m.group(1))
            continue
        m = _SECTION.match(line)
        if m:
            section, section_indent = m.group(2).strip(), len(m.group(1))
            continue
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        if section == "requested permissions" and indent > section_indent:
            name = line.strip()
            if name and " " not in name:
                out["requested"].add(name.rsplit(".", 1)[-1])
            continue
        m = _GRANT.match(line)
        if m:
            perm, granted = m.group(2).rsplit(".", 1)[-1], m.group(3) == "true"
            bucket = out["runtime"] if section == "runtime permissions" else out["install"]
            # Several users can share a package: one user granting it is enough.
            bucket[perm] = bucket.get(perm, False) or granted
    # A runtime answer is the current one; an install-time entry is only a fallback.
    out["grants"] = dict(out["install"])
    out["grants"].update(out["runtime"])
    if out["app_id"] is not None:
        out["app_id"] = int(out["app_id"])
    if out["version_code"] is not None:
        out["version_code"] = int(out["version_code"])
    return out


# --- dumpsys appops -----------------------------------------------------------------

def parse_appops(text):
    """uid block -> {state, modes, packages{pkg: {modes, access{op: [...]}, rejected{op: [...]}}}}

    Access entries sit under the op they belong to, so the op is carried along. Attributing every
    entry to the package alone would credit one op's use to another.
    """
    uids = {}
    section = None
    current_op = None
    for line in text.splitlines():
        m = _UID_HEAD.match(line)
        if m:
            head = m.group(1)
            number = head
            t = _UID_TEXT.match(head)
            if t:
                number = int(t.group(1)) * 100000 + 10000 + int(t.group(2))
            elif head.isdigit():
                number = int(head)
            section = {"header": head, "uid": number, "state": None, "modes": {},
                       "packages": {}}
            uids[head] = section
            continue
        if section is None:
            continue
        if line.startswith("  Uid ") or (line and not line.startswith(" ")):
            section = None
            continue
        stripped = line.strip()
        if stripped.startswith("state="):
            section["state"] = stripped.split("=", 1)[1]
            continue
        m = _OP_PKG.match(line)
        if m:
            section["packages"].setdefault(m.group(1), {"modes": {}, "access": {},
                                                        "rejected": {}})
            current_op = None
            continue
        m = _OP_MODE_PKG.match(line)
        if m:
            current_op = None
            if section["packages"]:
                current_op = m.group(1)
                current = list(section["packages"].values())[-1]
                current["modes"][current_op] = m.group(2).split("/")[0].strip()
            continue
        m = _OP_MODE_UID.match(line)
        if m:
            section["modes"][m.group(1)] = m.group(2)
            current_op = None
            continue
        m = _ACCESS.match(line)
        if m and current_op and section["packages"]:
            kind = "access" if m.group(1) == "Access" else "rejected"
            flags, rest = m.group(2), m.group(3).strip()
            when = " ".join(rest.split()[:2]) if rest else ""
            current = list(section["packages"].values())[-1]
            current[kind].setdefault(current_op, []).append(
                {"flags": flags, "at": when, "background": flags.split("-")[0] in ("bg", "cch")})
    return uids


# --- dumpsys location ---------------------------------------------------------------

def parse_listeners(text):
    """[(uid, pkg, provider, request)] for registrations that are live right now."""
    out, provider = [], None
    for line in text.splitlines():
        m = _PROVIDER.match(line)
        if m:
            provider = m.group(1)
            continue
        m = _LISTENER.match(line)
        if m:
            out.append({"uid": int(m.group(1)), "pkg": m.group(2), "provider": provider,
                        "request": m.group(5).strip()})
    return out


def parse_counters(text):
    """{(uid, pkg): {provider: locations}} - deliveries, not requests."""
    out, inside, provider = {}, False, None
    for line in text.splitlines():
        if _COUNTER_HEAD.match(line):
            inside = True
            continue
        if not inside:
            continue
        if line.startswith("  ") and not line.startswith("    ") and line.strip():
            break  # the next section at the same level: the table has ended
        m = _COUNTER_PROVIDER.match(line)
        if m:
            provider = m.group(1)
            continue
        m = _COUNTER.match(line)
        if m and provider:
            key = (int(m.group(1)), m.group(2))
            out.setdefault(key, {})[provider] = int(m.group(3))
    return out


# --- the phase ----------------------------------------------------------------------

def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def run(rid=None):
    rid = store.resolve(rid)
    packages = _read(paths.device("third_party_pkgs.txt")).split()
    appops = parse_appops(_read(paths.device("dumpsys_appops.txt")))
    listeners = parse_listeners(_read(paths.device("dumpsys_location.txt")))
    counters = parse_counters(_read(paths.device("dumpsys_location.txt")))
    by_header = {entry["header"]: entry for entry in appops.values()}
    unreadable = []

    counts = {"always": 0, "while_in_use": 0, "denied": 0, "not_requested": 0,
              "seen": 0, "listening": 0}
    named = {"always": [], "while_in_use": [], "denied": [], "not_requested": []}
    for pkg in packages:
        path = paths.dumpsys(pkg + ".txt")
        if not os.path.exists(path):
            unreadable.append(pkg)
            continue
        raw_text = _read(path)
        info = parse_package(raw_text, pkg)
        found_sdks = sdks.detect_in_dumpsys(raw_text, pkg)
        uid = info.get("app_id")
        block = None
        if uid is not None:
            block = by_header.get(f"u0a{uid - 10000}") if uid >= 10000 else None
            block = block or next((entry for entry in appops.values()
                                   if entry["uid"] == uid), None)

        def mutate(doc, pkg=pkg, info=info, uid=uid, block=block, found_sdks=found_sdks):
            written = set()

            def add(subject, value, **kw):
                written.add(subject)
                return store.add_fact(doc, subject, value, **kw)
            doc["app"].update({k: v for k, v in
                               (("uid", uid), ("version_name", info.get("version_name")),
                                ("version_code", info.get("version_code"))) if v is not None})
            requested, granted = info.get("requested") or set(), info.get("grants") or {}
            for perm in LOCATION_PERMS:
                if perm in granted:
                    value = "granted" if granted[perm] else "denied"
                elif perm in requested:
                    value = "not_granted"
                else:
                    value = "not_requested"
                add(f"perm:{perm}", value, tier="T0", source="dumpsys package")

            for perm in EXTRA_PERMS:
                if perm in granted:
                    add(f"perm:{perm}", "granted" if granted[perm] else "denied",
                        tier="T0", source="dumpsys package")
                elif perm in requested:
                    add(f"perm:{perm}", "not_granted", tier="T0", source="dumpsys package")

            for prefix, summary in found_sdks:
                slug = re.sub(r"[^a-z0-9.-]", "-", prefix.lower())
                add(f"sdk:{slug}", summary, tier="T0", source="dumpsys package")

            entry = (block or {}).get("packages", {}).get(pkg) or {}
            mode = (entry.get("modes") or {}).get(FINE_OP)
            source = "dumpsys appops"
            confidence = "certain"
            if mode is None:
                mode = (block or {}).get("modes", {}).get(FINE_OP)
                confidence = "weak" if mode is not None else "certain"
                source = "dumpsys appops (per uid only)"
            if mode is not None:
                add(f"appop:{FINE_OP}", mode, tier="T0", source=source, confidence=confidence)

            access, ops = [], []
            for op in LOCATION_OPS:
                found = (entry.get("access") or {}).get(op) or []
                if found:
                    access.extend(found)
                    ops.append(op)
            if access:
                add("access:location", len(access), tier="T1", source="dumpsys appops",
                    background=any(a["background"] for a in access),
                    last=max(a["at"] for a in access), ops=sorted(set(ops)))

            rejected, rej_ops = [], []
            for op in LOCATION_OPS:
                found = (entry.get("rejected") or {}).get(op) or []
                if found:
                    rejected.extend(found)
                    rej_ops.append(op)
            if rejected:
                add("reject:location", len(rejected), tier="T1", source="dumpsys appops",
                    background=any(r["background"] for r in rejected),
                    last=max(r["at"] for r in rejected), ops=sorted(set(rej_ops)))

            mine = [l for l in listeners if uid is not None and l["uid"] == uid]
            if mine:
                add("listener:location", len(mine), tier="T1", source="dumpsys location",
                    providers=sorted({l["provider"] for l in mine if l["provider"]}))
            delivered = counters.get((uid, pkg)) if uid is not None else None
            if delivered:
                add("delivered:location", sum(delivered.values()), tier="T1",
                    source="dumpsys location counters", providers=delivered)

            # A re-run must not leave a fact this phase no longer finds: a stale "access:location"
            # reads as a real observation.
            for subject in list(doc["facts"]):
                if (subject in OWNED or subject.startswith("sdk:")) and subject not in written:
                    doc["facts"].pop(subject, None)

        sheet = store.update_app(pkg, mutate, rid)
        facts = sheet["facts"]
        value = lambda perm: (facts.get(f"perm:{perm}") or {}).get("value")
        background = value("ACCESS_BACKGROUND_LOCATION")
        foreground = [value("ACCESS_FINE_LOCATION"), value("ACCESS_COARSE_LOCATION")]
        if background == "granted":
            counts["always"] += 1
            named["always"].append(pkg)
        elif "granted" in foreground:
            counts["while_in_use"] += 1
            named["while_in_use"].append(pkg)
        elif "denied" in foreground or background == "denied":
            counts["denied"] += 1
            named["denied"].append(pkg)
        else:
            counts["not_requested"] += 1
            named["not_requested"].append(pkg)
        counts["seen"] += 1 if "access:location" in facts else 0
        counts["listening"] += 1 if "listener:location" in facts else 0

    # The check must be able to disagree with the parser, so the Always list is also read straight
    # from the raw text with a regex of its own.
    raw_always = [pkg for pkg in packages
                  if os.path.exists(paths.dumpsys(pkg + ".txt"))
                  and _RAW_ALWAYS.search(_read(paths.dumpsys(pkg + ".txt")))]
    sheets = store.apps(rid)
    fact_always = [sheet["pkg"] for sheet in sheets
                   if (sheet["facts"].get("perm:ACCESS_BACKGROUND_LOCATION") or {})
                   .get("value") == "granted"]
    wrong = sorted(set(raw_always) ^ set(fact_always))
    ok = (len(sheets) == len(packages) and not unreadable and not wrong)
    summary = (f"{len(packages)} apps: {counts['always']} can read location while closed, "
               f"{counts['while_in_use']} only while open, {counts['denied']} asked and were "
               f"refused, {counts['not_requested']} never asked; "
               f"{counts['seen']} were allowed to use location at some time, "
               f"{counts['listening']} were reading it at the capture")
    if unreadable:
        summary += f"; no capture for {', '.join(unreadable)}"
    if wrong:
        summary += (f"; the phone's own text and the findings disagree about reading "
                    f"location while closed for {', '.join(wrong)}")
    store.require(rid, "grants", ok, summary)
    return {"run": rid, "summary": summary, "counts": counts, "apps_in": named,
            "unreadable": unreadable, "wrong": wrong}
