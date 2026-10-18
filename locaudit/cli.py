"""CLI commands for android-loc-audit.

One way to do each task, with zero flags:
    uv run locaudit status                 show cached state in data/, progress, and priority targets
    uv run locaudit capture                snapshot phone via adb into data/ and parse dumpsys facts
    uv run locaudit location               list apps with location permissions, recorded use, Ad-ID & SDKs
    uv run locaudit apps                   list all discovered packages and installer origins
    uv run locaudit show <package>         display all recorded facts and evidence for one app
    uv run locaudit page <package> ...     fetch Google Play Data Safety disclosures (cached)
    uv run locaudit pull <package> ...     pull APKs for specific apps and verify signatures (cached)
    uv run locaudit inspect <package> ...  parse manifest, decompile with jadx, scan for location/Ad-ID/SDKs
    uv run locaudit pcap <file.pcap>       parse network traffic capture (.pcap file) for TLS SNIs, DNS & broadcasts
    uv run locaudit report                 write data/reports/digest.json and FINDINGS.md
"""
import argparse
import os
import shutil
import sys

from . import (__version__, capture, datasafety, device, findings, grants,
               meta, paths, pcap, pull, refdata, sdks, signing, store)

LABEL = 14
WIDTH = 100

TIER_SENTENCE = {
    "T0": "Android OS package/permission setting",
    "T1": "Android AppOps runtime usage log",
    "T2": "Google Play Data Safety declaration",
    "T3": "Decompiled APK bytecode (jadx)",
    "T4": "Network traffic capture",
}

SOURCE_SENTENCE = {
    "adb pull": "copied and verified APK file",
}

SOURCE_WORDS = {
    "dumpsys package": "dumpsys package",
    "dumpsys appops": "dumpsys appops",
    "dumpsys appops (per uid only)": "dumpsys appops (UID level)",
    "dumpsys location": "dumpsys location",
    "dumpsys location counters": "dumpsys location counters",
    "apksigner": "apksigner",
    "aapt2": "aapt2 manifest",
    "jadx": "jadx bytecode scan",
}

KIND_TITLES = {
    "perm": "Permissions & capabilities (Android package manager)",
    "appop": "AppOps permission mode",
    "access": "Recorded location accesses (Android AppOps)",
    "listener": "Active location listeners at capture time",
    "delivered": "Historical location fixes delivered (Location Manager)",
    "sdk": "Embedded tracker, location & analytics SDKs (from component table)",
    "code": "Deep-dive bytecode inspection (jadx)",
    "network": "Network traffic & telemetry analysis (PCAP)",
    "install": "Installer origin and build timestamps",
    "sig": "APK cryptographic signature verification",
    "datasafety": "Google Play Data Safety declarations",
    "declares": "Permissions declared in AndroidManifest.xml",
    "fgs": "Foreground services declared in AndroidManifest.xml",
    "receiver": "Broadcast receivers declared in AndroidManifest.xml",
    "provider": "Content providers declared in AndroidManifest.xml",
    "posture": "Application security posture",
    "apk": "Cached APK files and SHA-256 digests",
    "unknown": "Unresolved / unread items",
}


# --- output helpers ------------------------------------------------------------------

def _format_components(components, width=98):
    prefix = "   ↳ Components: "
    indent = "                 "
    lines, cur = [], prefix
    for comp in components:
        sep = ", " if cur != prefix and cur != indent else ""
        if len(cur) + len(sep) + len(comp) > width and cur != prefix and cur != indent:
            lines.append(cur + ",")
            cur = indent + comp
        else:
            cur += sep + comp
    if cur.strip():
        lines.append(cur)
    return "\n".join(lines)


def _names(values):
    return ", ".join(values)


def _run():
    return store.load_run(store.latest())


def _value(sheet, subject, default=None):
    return (sheet["facts"].get(subject) or {}).get("value", default)


def _reads(sheet):
    background = _value(sheet, "perm:ACCESS_BACKGROUND_LOCATION")
    fine = _value(sheet, "perm:ACCESS_FINE_LOCATION")
    coarse = _value(sheet, "perm:ACCESS_COARSE_LOCATION")
    if background == "granted":
        return "while closed"
    if "granted" in (fine, coarse):
        return "only while open"
    if "denied" in (fine, coarse, background):
        return "refused"
    return "never asked"


def _meaning_capture(run):
    sheets = store.apps(run["id"])
    closed = sum(1 for sheet in sheets if _reads(sheet) == "while closed")
    return (f"Cached in data/. {closed} of {len(sheets)} apps can read your location while closed.")


def _meaning_location(sheets):
    used = [sheet for sheet in sheets if "access:location" in sheet["facts"]]
    background = [sheet for sheet in used if (sheet["facts"]["access:location"]).get("background")]
    was = "was" if len(used) == 1 else "were"
    latest = max(((sheet["facts"]["access:location"].get("last") or "")[:19] for sheet in used),
                 default="")
    return (f"{len(used)} apps were allowed location at runtime ({len(background)} logged in background). "
            f"Most recent access: {latest or 'none'}.")


# --- commands ------------------------------------------------------------------------

def cmd_status(args):
    rid = store.latest()
    if not rid:
        print("No audit run in data/ yet. Run: uv run locaudit capture")
        return 0

    doc = findings.build(rid)
    counts = doc["counts"]
    dev = doc["device"]

    dumpsys_count = (len([n for n in os.listdir(paths.dumpsys()) if n.endswith(".txt")])
                     if os.path.isdir(paths.dumpsys()) else 0)
    apk_pkgs = (sorted(n for n in os.listdir(paths.apks())
                       if os.path.isdir(paths.apks(n)) and pull.cached_bundle(n))
                if os.path.isdir(paths.apks()) else [])
    page_pkgs = (sorted(n for n in os.listdir(paths.cache())
                        if os.path.exists(os.path.join(paths.cache(n), "datasafety.txt")))
                 if os.path.isdir(paths.cache()) else [])
    decompiled_pkgs = (sorted(n for n in os.listdir(paths.data("decompiled"))
                              if sdks.is_decompiled(n))
                       if os.path.isdir(paths.data("decompiled")) else [])

    closed_pkgs = [a["pkg"] for a in doc["by_reads"]["while closed"]]
    anomaly_pkgs = [a["pkg"] for a in doc["background_anomalies"]]
    undisclosed_pkgs = [a["pkg"] for a in doc.get("undisclosed_location", [])]
    inspected_pkgs = [a["pkg"] for a in doc["code_inspected"]]
    priority_targets = sorted(set(closed_pkgs + anomaly_pkgs + undisclosed_pkgs))
    uninspected_targets = [p for p in priority_targets if p not in inspected_pkgs]

    app_map = {a["pkg"]: a for a in doc["apps"]}
    ref_count = len(refdata.cached_feeds())

    print("Device & Snapshot")
    print(f"  Run:          {rid}")
    print(f"  Device:       {dev['brand']} {dev['model']} (Android {dev['android']}, build {dev['build']})")
    print(f"  Cached:       {dumpsys_count} app dumps | {ref_count}/{len(refdata.FEEDS)} reference feeds | "
          f"{len(apk_pkgs)} APK bundles | {len(page_pkgs)} Play pages | {len(decompiled_pkgs)} decompiled")

    print(f"\nPermission Posture ({counts['apps']} apps)")
    print(f"  Background:   {counts['while_closed']} apps (while closed)")
    print(f"  Foreground:   {counts['only_while_open']} apps (only while open)")
    print(f"  Refused:      {counts['refused']} apps")
    print(f"  Never asked:  {counts['never_asked']} apps")

    print(f"\nRisk Signals")
    print(f"  Background anomalies:      {counts['background_anomalies']} apps (logged/attempted bg access with only fg grant)")
    if counts.get('undisclosed_location'):
        print(f"  Undisclosed location:      {counts['undisclosed_location']} apps (reads location, declares none on Play)")
    print(f"  Survive reboot with FGS:   {counts['after_reboot']} apps")
    print(f"  Location + Advertising ID: {counts['location_with_ad_id']} apps (cross-app profiling risk)")
    print(f"  Location + 3rd-party SDKs: {counts['location_with_sdks']} apps")

    inspected_count = len(priority_targets) - len(uninspected_targets)
    print(f"\nAudit Targets ({len(priority_targets)} priority apps: {inspected_count} inspected, {len(uninspected_targets)} pending)")
    if not priority_targets:
        print("  none")
    else:
        for p in priority_targets:
            a = app_map.get(p, {})
            state = "inspected" if p in inspected_pkgs else "pending"
            tag = "[*]" if state == "inspected" else "[!]"
            reasons = []
            if a.get("reads") == "while closed":
                reasons.append("while closed")
            if a.get("used_in_background") and a.get("reads") != "while closed":
                reasons.append("bg access")
            if a.get("rejected_in_background") and a.get("reads") != "while closed":
                reasons.append("bg blocked")
            if a.get("undisclosed_location"):
                reasons.append("undisclosed loc")
            if a.get("ad_id"):
                reasons.append("ad-id")
            if a.get("fgs_location") and a.get("boot"):
                reasons.append("fgs+boot")
            reason_str = f" ({', '.join(reasons)})" if reasons else ""
            print(f"  {tag} {p:<44} {state:<9}{reason_str}")
    return 0


def cmd_capture(args):
    try:
        result = capture.run(None)
    except device.DeviceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    refdata.ensure()
    rid = result["run"]
    permissions = grants.run(rid)
    installs = meta.run(rid)
    info = result["device"]

    print("Device Snapshot Captured")
    print(f"  Run:          {rid}")
    print(f"  Phone:        {info['brand'].title()} {info['model']}, Android {info['android']} "
          f"(SDK {info['sdk']}), serial {info['serial']}")
    print(f"  Read:         {result['summary']}")
    print(f"  Permissions:  {permissions['summary']}")
    print(f"  Installs:     {installs['summary']}")
    print(f"  Assessment:   {_meaning_capture(store.load_run(rid))}")
    return 0


def cmd_location(args):
    run = _run()
    sheets = store.apps(run["id"])
    rows = []
    for sheet in sheets:
        reads = _reads(sheet)
        if reads == "never asked":
            continue
        used = sheet["facts"].get("access:location") or {}
        rejected = sheet["facts"].get("reject:location") or {}
        app_sdk_list = findings.app_sdks(sheet, compact=True)
        bg_used = bool(used.get("background"))
        bg_rej = bool(rejected.get("background"))
        bg_score = 2 if bg_used else (1 if bg_rej else 0)
        rows.append({
            "app": sheet["pkg"],
            "permission": reads,
            "uses": used.get("value") or 0,
            "last use": (used.get("last") or rejected.get("last") or "")[:19],
            "in background": bg_used,
            "rejected background": bg_rej,
            "bg_score": bg_score,
            "ad_id": findings.has_ad_id(sheet),
            "restart": findings.has_boot(sheet) and findings.has_fgs_location(sheet),
            "says it shares": _value(sheet, "datasafety:shared:location") or "-",
            "sdks": app_sdk_list,
        })
    order = {"while closed": 0, "only while open": 1, "refused": 2}
    rows.sort(key=lambda row: (order[row["permission"]], -row["bg_score"], -row["uses"], row["app"]))
    if not rows:
        print("No apps requested location permission in this run.")
        return 0

    head = f"{'App':<38}  {'Permission':<16}  {'Uses':>5}  {'Last Use':<19}  {'Bg':<4}  {'Ad-ID':<6}  {'Boot':<5}  Shares"
    print(head)
    print("-" * 102)
    for row in rows:
        last = row['last use'] or "-"
        if row['in background']:
            bg_val = "yes"
        elif row['rejected background']:
            bg_val = "blck"
        else:
            bg_val = "-"
        adid_val = "yes" if row['ad_id'] else "-"
        boot_val = "yes" if row['restart'] else "-"
        shares_val = row['says it shares']
        print(f"{row['app']:<38}  {row['permission']:<16}  {row['uses']:>5}  {last:<19}  "
              f"{bg_val:<4}  {adid_val:<6}  {boot_val:<5}  {shares_val}")
        if row["sdks"]:
            print(_format_components(row["sdks"], width=98))

    counts = {name: sum(1 for row in rows if row["permission"] == name) for name in order}
    print()
    print(f"Summary: {len(rows)} location-requesting apps ({counts['while closed']} while closed, "
          f"{counts['only while open']} only while open, {counts['refused']} refused)")
    print(_meaning_location(sheets))
    print("\nColumns:")
    print("  Permission  while closed (ACCESS_BACKGROUND_LOCATION), only while open, or refused")
    print("  Uses/Last   Count and latest timestamp in Android AppOps log (dumpsys appops)")
    print("  Bg          yes = allowed in background, blck = attempted in background and blocked by OS")
    print("  Ad-ID       yes = holds AD_ID permission (can link GPS to Google Advertising ID)")
    print("  Boot        yes = FOREGROUND_SERVICE_LOCATION + RECEIVE_BOOT_COMPLETED (tracks across reboots)")
    print("  Shares      yes/no declaration on Google Play Data Safety (- if unread)")
    print("  Components  Non-framework 3rd-party component namespaces from dumpsys package")
    return 0


def cmd_apps(args):
    run = _run()
    sheets = store.apps(run["id"])
    if not sheets:
        print("no apps in this run; read the phone with uv run locaudit capture")
        return 0
    print(f"{'App':<44}  {'Permission':<16}  {'Signed By':<24}  Installed By")
    print("-" * 102)
    for sheet in sorted(sheets, key=lambda sheet: sheet["pkg"]):
        reads = _reads(sheet)
        signer = _value(sheet, 'sig:signed-by') or 'not read'
        installer = _value(sheet, 'install:from') or 'not read'
        print(f"{sheet['pkg']:<44}  {reads:<16}  {signer:<24}  {installer}")
    return 0


def cmd_show(args):
    run = _run()
    sheet = store.load_app(args.pkg, run["id"])
    if not sheet:
        print(f"error: {args.pkg} is not in run {run['id']}", file=sys.stderr)
        return 1
    print(f"Package: {sheet['pkg']}")
    print(f"Run:     {sheet['run']}")
    app = sheet.get("app") or {}
    if app:
        print("\nApp Metadata:")
        for k in ("uid", "version_name", "version_code", "installer", "first_install", "last_update", "apks", "apk_bytes"):
            if k in app:
                print(f"  {k:<16} {app[k]}")

    grouped = {}
    for subject, record in sorted(sheet["facts"].items()):
        grouped.setdefault(subject.split(":", 1)[0], {})[subject] = record

    for kind, facts in grouped.items():
        title = KIND_TITLES.get(kind, kind)
        print(f"\n{title}:")
        for subject, record in facts.items():
            name = subject.split(":", 1)[1]
            val = str(record.get("value"))
            source = SOURCE_WORDS.get(record.get("source"), record.get("source"))
            sentence = SOURCE_SENTENCE.get(record.get("source"))
            provenance = sentence if sentence else f"{source}"
            if record.get("tier") and not sentence:
                tier_desc = TIER_SENTENCE.get(record.get("tier"), record.get("tier"))
                provenance = f"{tier_desc} ({source})"
            if record.get("confidence") and record["confidence"] != "certain":
                provenance += f" [{record['confidence']}]"

            if len(val) > 28:
                print(f"  {name}:")
                print(f"    value:      {val}")
                print(f"    source:     {provenance}")
            else:
                print(f"  {name:<32} {val:<16} [{provenance}]")
    return 0


def cmd_pull(args):
    rid = store.resolve(store.latest())
    try:
        result = pull.run(rid, apps=list(args.apps))
        signatures = signing.run(rid, apps=list(args.apps))
    except (device.DeviceError, ValueError, signing.SigningError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    free = shutil.disk_usage(paths.apks()).free
    print("APK Pull & Signature Verification")
    print(f"  Size:         {result['bytes'] / 1e9:.2f} GB ({free / 1e9:.1f} GB free on disk)")
    print(f"  Copied:       {result['summary']}")
    print(f"  Signatures:   {signatures['summary']}")
    return 0 if result["apps"] and not result["failures"] and signatures["ok"] else 1


def cmd_inspect(args):
    try:
        out = sdks.run(apps=list(args.apps))
    except (ValueError, RuntimeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for res in out["results"]:
        status = "cached" if res.get("cached") else "freshly decompiled"
        print(f"\n=== {res['pkg']} ({res['java_files']} Java classes, {status}) ===")

        arc = res.get("archive") or {}
        if arc:
            dex_mb = arc.get("dex_bytes", 0) / 1e6
            archs = ", ".join(arc.get("native_archs", [])) or "none"
            print(f"Binary Structure: {arc.get('dex_count', 0)} DEX ({dex_mb:.2f} MB), {arc.get('native_count', 0)} .so libs ({archs})")
            print(f"Primary Engine:   {res.get('engine', 'Standard Dalvik')}")
            print(f"Decompilation:    {res.get('confidence', 'full')}")
            confidence = res.get("confidence", "")
            engine = res.get("engine", "")
            if "partial" in confidence or "obstructed" in confidence:
                if "React Native" in engine:
                    print("  Note: App logic lives primarily in React Native bundle (assets/index.android.bundle).")
                elif "Flutter" in engine:
                    print("  Note: App logic lives primarily in compiled Flutter Dart AOT library (libapp.so).")
                elif "Unity" in engine:
                    print("  Note: App logic lives primarily in Unity game engine assets and native assemblies.")
                elif "Minimal DEX stub" in engine:
                    print("  Note: Minimal DEX stub detected; actual application code resides in native libraries or encrypted assets.")

        apis = res.get("location_apis") or []
        print("Location APIs:")
        if apis:
            for api in apis:
                print(f"  - {api}")
        else:
            print("  none found")

        loc_callers = res.get("location_classes") or []
        print("Location Callers:")
        if loc_callers:
            for c in loc_callers[:12]:
                print(f"  - {c['class']} [{', '.join(c['apis'])}]")
            if len(loc_callers) > 12:
                print(f"  ... and {len(loc_callers) - 12} more")
        else:
            print("  none found")

        adid_callers = res.get("ad_id_classes") or []
        print("Advertising ID Callers:")
        if adid_callers:
            for c in adid_callers[:12]:
                print(f"  - {c}")
            if len(adid_callers) > 12:
                print(f"  ... and {len(adid_callers) - 12} more")
        else:
            print("  none found")

        cooccur = "YES (code contains both location and Ad-ID callers)" if res.get("can_join_ad_id") else "no"
        print(f"Risk Co-occurrence (Loc + Ad-ID): {cooccur}")

        pkgs = res.get("packages") or []
        print("Compiled 3rd-Party Packages:")
        if pkgs:
            for p in pkgs[:15]:
                print(f"  - {p['package']} ({p['classes']} classes)")
            if len(pkgs) > 15:
                print(f"  ... and {len(pkgs) - 15} more")
        else:
            print("  none detected")

        endpoints = res.get("endpoints") or []
        print("Hardcoded Endpoints:")
        if endpoints:
            for ep in endpoints[:12]:
                print(f"  - {ep}")
            if len(endpoints) > 12:
                print(f"  ... and {len(endpoints) - 12} more")
        else:
            print("  none found")

    for pkg, err in out["failures"].items():
        print(f"error ({pkg}): {err}", file=sys.stderr)
    return 1 if out["failures"] else 0


def cmd_page(args):
    try:
        result = datasafety.run(apps=list(args.apps))
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    shared = (result.get("apps_in") or {}).get("shared") or []
    print("Google Play Data Safety Disclosures")
    print(f"  Read:         {result['summary']}")
    if shared:
        print(f"  Shares:       {len(shared)} apps declare sharing location with 3rd parties:")
        for pkg in shared:
            print(f"                - {pkg}")
    if result.get("unknown"):
        print("  Unavailable:")
        for pkg, reason in sorted(result["unknown"].items())[:8]:
            print(f"                - {pkg}: {reason}")
    return 0


def cmd_report(args):
    result = findings.write(store.latest())
    counts = result["doc"]["counts"]
    print("Audit Report Generated")
    print(f"  Summary:      {counts['apps']} apps: {counts['while_closed']} background location, "
          f"{counts['background_anomalies']} background anomalies, {counts['location_with_ad_id']} Location+Ad-ID, "
          f"{counts['code_inspected']} deep-dive inspected")
    print(f"  Digest:       {result['digest']}")
    print(f"  Markdown:     {result['markdown']}")
    return 0


def cmd_pcap(args):
    target = args.file
    if os.path.isfile(target):
        pcap_path = os.path.abspath(target)
    elif os.path.isfile(os.path.join(paths.cache(target), "traffic.pcap")):
        pcap_path = os.path.join(paths.cache(target), "traffic.pcap")
    else:
        print(f"error: PCAP file not found: '{target}'", file=sys.stderr)
        return 1

    size_kb = os.path.getsize(pcap_path) / 1024
    results = pcap.parse_pcap(pcap_path)

    # Infer package if the file is inside data/cache/<pkg>/
    pkg = None
    try:
        rel = os.path.relpath(pcap_path, paths.cache())
        parts = rel.split(os.sep)
        if len(parts) >= 2 and not rel.startswith(".."):
            pkg = parts[0]
    except Exception:
        pass

    print("Network Traffic & Telemetry Analysis (PCAP)")
    print(f"  File:         {pcap_path} ({size_kb:.1f} KB)")
    print(f"  Protocols:    {', '.join(results['protocols']) or 'none detected'}")

    print("\nTLS SNIs (Server Name Indications):")
    if results["snis"]:
        for sni in results["snis"]:
            print(f"  - {sni}")
    else:
        print("  none found")

    print("\nDNS Resolutions & Infrastructure Unmasking:")
    if results["dns_resolutions"]:
        for domain, res in sorted(results["dns_resolutions"].items()):
            if res["cnames"]:
                chain = " -> ".join(res["cnames"])
                print(f"  - {domain}")
                print(f"      ↳ CNAME: {chain}")
                if res["ips"]:
                    print(f"      ↳ IPs:   {', '.join(res['ips'])}")
            elif res["ips"]:
                print(f"  - {domain} -> {', '.join(res['ips'])}")
    else:
        print("  none found")

    if results["broadcasts"]:
        print("\nUnencrypted Local Discovery & Broadcasts:")
        for b in results["broadcasts"]:
            print(f"  - [{b['proto']} :{b['port']} -> {b['dst']}] {b['payload']}")

    if results["icmp_targets"]:
        print("\nICMP Connectivity Checks:")
        for target_ip in results["icmp_targets"]:
            print(f"  - Ping target: {target_ip}")

    print("\nTop Remote Endpoints:")
    if results["endpoints"]:
        for ep in results["endpoints"][:10]:
            domain_str = f" [{', '.join(ep['domains'])}]" if ep["domains"] else ""
            kb = ep["bytes"] / 1024
            print(f"  - {ep['ip']}:{ep['port']:<5} ({ep['proto']})  {ep['packets']:>4} pkts, {kb:>6.1f} KB{domain_str}")
    else:
        print("  none recorded")

    # If pkg is known and a run exists, store facts into the app sheet
    rid = store.latest()
    if pkg and rid and store.load_app(pkg, rid):
        def mutate(doc):
            if results["protocols"]:
                store.add_fact(doc, "network:protocols", ", ".join(results["protocols"]), tier="T4", source="traffic capture")
            if results["snis"]:
                store.add_fact(doc, "network:tls-snis", ", ".join(results["snis"]), tier="T4", source="traffic capture")
            if results["dns"]:
                store.add_fact(doc, "network:dns-queries", ", ".join(results["dns"][:20]), tier="T4", source="traffic capture")
            if results["broadcasts"]:
                store.add_fact(doc, "network:broadcasts", "; ".join(b["payload"] for b in results["broadcasts"][:5]), tier="T4", source="traffic capture")
            if results["icmp_targets"]:
                store.add_fact(doc, "network:icmp-pings", ", ".join(results["icmp_targets"]), tier="T4", source="traffic capture")
            if results["endpoints"]:
                summary_eps = []
                for ep in results["endpoints"][:5]:
                    d = f" ({ep['domains'][0]})" if ep["domains"] else ""
                    summary_eps.append(f"{ep['ip']}:{ep['port']}{d}")
                store.add_fact(doc, "network:endpoints", ", ".join(summary_eps), tier="T4", source="traffic capture")

        store.update_app(pkg, mutate, rid)
        print(f"\nRecorded: Tier 4 network facts updated in app dossier (data/runs/{rid}/apps/{pkg}.json)")

    return 0


# --- parser --------------------------------------------------------------------------

COMMANDS = {}


def build_parser():
    parser = argparse.ArgumentParser(
        prog="audit", description="Android location privacy audit tool.")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    def add(name, fn, help_text):
        sub_parser = sub.add_parser(name, help=help_text)
        sub_parser.set_defaults(fn=fn)
        COMMANDS[name] = fn
        return sub_parser

    add("status", cmd_status, "show cached state in data/, progress, and priority targets")
    add("capture", cmd_capture, "snapshot phone via adb into data/ and parse dumpsys facts")
    add("location", cmd_location, "list apps with location permissions, recorded use, Ad-ID & SDKs")
    add("apps", cmd_apps, "one line per app")

    p = add("show", cmd_show, "everything recorded about one app")
    p.add_argument("pkg", metavar="package")

    p = add("page", cmd_page, "fetch Google Play Data Safety disclosures for named apps")
    p.add_argument("apps", nargs="+", metavar="package")

    p = add("pull", cmd_pull, "copy the named apps' APKs (if not cached) and verify signatures")
    p.add_argument("apps", nargs="+", metavar="package")

    p = add("inspect", cmd_inspect, "parse manifest, decompile APKs with jadx, and scan bytecode")
    p.add_argument("apps", nargs="+", metavar="package")

    p = add("pcap", cmd_pcap, "parse network traffic capture (.pcap file) for TLS SNIs, DNS, and broadcasts")
    p.add_argument("file", metavar="filename.pcap", help="Path to .pcap capture file")

    add("report", cmd_report, "write data/reports/digest.json and FINDINGS.md")

    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except (store.GateFailed, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
