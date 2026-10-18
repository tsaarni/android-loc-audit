"""Where each app came from, and when this phone got its build.

Offline. Reads the capture taken earlier, which uv run locaudit capture wrote:

    data/device/dumpsys_package/<pkg>.txt   installerPackageName, versionCode, versionName,
                                           firstInstallTime, lastUpdateTime

The installer can be the string "null": Android writes that when no app recorded installing it.
That is a missing answer, not the answer "installed by hand", so it is recorded as missing
(docs/reference/pitfalls.md#an-empty-installer-is-not-installed-by-hand).
"""
import datetime
import os
import re

from . import paths, store

_APP_ID = re.compile(r"^\s+appId=(\d+)$")
_VERSION_CODE = re.compile(r"^\s+versionCode=(\d+)")
_VERSION_NAME = re.compile(r"^\s+versionName=(\S+)$")
_INSTALLER = re.compile(r"^\s+installerPackageName=(.*)$")
# The same line, searched in the whole text rather than one line at a time, for the check.
_INSTALLER_ANYWHERE = re.compile(r"^\s+installerPackageName=", re.M)
_FIRST = re.compile(r"^\s+firstInstallTime=(.*)$")
_LAST = re.compile(r"^\s+lastUpdateTime=(.*)$")
_STAMP = "%Y-%m-%d %H:%M:%S"

# What the phone writes when it has no answer, and what the tool says instead of copying it.
NO_INSTALLER = "none recorded"

# The two application stores here whose package names say nothing to a person.
STORE_WORDS = {
    "com.android.vending": "Google Play",
    "com.sec.android.app.samsungapps": "the Samsung Galaxy Store",
}

FIELDS = ((_INSTALLER, "installer"), (_VERSION_NAME, "version_name"),
          (_VERSION_CODE, "version_code"), (_FIRST, "first_install"), (_LAST, "last_update"))

OWNED = ("install:from", "install:got_build", "install:first_seen")


def _text(match):
    if not match:
        return None
    value = match.group(1).strip()
    return None if value in ("", "null") else value


def parse_package(text):
    """One app's own account: who installed it, and when its build and its first copy arrived."""
    out = {key: None for _, key in FIELDS}
    for line in text.splitlines():
        for pattern, key in FIELDS:
            if out[key] is not None:
                continue
            match = pattern.match(line)
            if match:
                out[key] = _text(match)
    if out["version_code"] is not None:
        out["version_code"] = int(out["version_code"])
    return out


def age_days(stamp, today=None):
    """How many days ago a stamp the phone wrote was. None when it cannot be read."""
    if not stamp:
        return None
    try:
        when = datetime.datetime.strptime(stamp, _STAMP)
    except ValueError:
        return None
    today = today or datetime.datetime.now()
    return (today - when).days


def _stores(counts):
    """The installers in words, biggest group first: '114 came from Google Play, ...'."""
    parts = []
    for name, count in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
        if name == NO_INSTALLER:
            parts.append(f"{count} have no installer recorded")
        elif name in STORE_WORDS:
            parts.append(f"{count} came from {STORE_WORDS[name]}")
        else:
            parts.append(f"{count} came from an app on the phone ({name})")
    return ", ".join(parts)


# --- the phase ----------------------------------------------------------------------

def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def run(rid=None):
    rid = store.resolve(rid)
    packages = _read(paths.device("third_party_pkgs.txt")).split()
    unreadable, no_installer = [], []
    counts, ages = {}, []
    for pkg in packages:
        path = paths.dumpsys(pkg + ".txt")
        if not os.path.exists(path):
            unreadable.append(pkg)
            continue
        info = parse_package(_read(path))

        def mutate(doc, info=info):
            written = set()

            def add(subject, value, **kw):
                written.add(subject)
                return store.add_fact(doc, subject, value, **kw)
            # The key is written even when the phone has no answer: "the phone did not say"
            # and "this phase never ran" must not look the same.
            doc["app"]["installer"] = info["installer"]
            doc["app"].update({k: v for k, v in
                               (("version_name", info["version_name"]),
                                ("version_code", info["version_code"]),
                                ("first_install", info["first_install"]),
                                ("last_update", info["last_update"])) if v is not None})
            add("install:from", info["installer"] or NO_INSTALLER,
                tier="T0", source="dumpsys package")
            if info["first_install"]:
                add("install:first_seen", info["first_install"],
                    tier="T0", source="dumpsys package")
            if info["last_update"]:
                add("install:got_build", info["last_update"],
                    tier="T0", source="dumpsys package")

            # A re-run must not leave a fact this phase no longer finds.
            for subject in OWNED:
                if subject not in written:
                    doc["facts"].pop(subject, None)

        sheet = store.update_app(pkg, mutate, rid)
        store_name = (sheet["facts"].get("install:from") or {}).get("value") or NO_INSTALLER
        counts[store_name] = counts.get(store_name, 0) + 1
        if store_name == NO_INSTALLER:
            no_installer.append(pkg)
        age = age_days((sheet["facts"].get("install:got_build") or {}).get("value"))
        if age is not None:
            ages.append(age)

    sheets = store.apps(rid)
    # The check has to be able to disagree with the parser: the raw text is searched with its own
    # pattern, and any app whose two answers differ is named rather than passed.
    raw_answered = {pkg for pkg in packages
                    if os.path.exists(paths.dumpsys(pkg + ".txt"))
                    and _INSTALLER_ANYWHERE.search(_read(paths.dumpsys(pkg + ".txt")))}
    with_answer = {sheet["pkg"] for sheet in sheets if "installer" in (sheet.get("app") or {})}
    wrong = sorted(raw_answered ^ with_answer)
    ok = bool(packages) and not unreadable and len(with_answer) == len(packages) and not wrong

    summary = f"{len(with_answer)} apps: {_stores(counts)}"
    if ages:
        recent = sum(1 for age in ages if age < 30)
        summary += (f"; {recent} got their build in the last 30 days, and the oldest arrived "
                    f"{max(ages)} days ago")
    if unreadable:
        summary += f"; no capture for {', '.join(unreadable)}"
    if wrong:
        summary += (f"; the phone's own text and the findings disagree about the installer for "
                    f"{', '.join(wrong)}")
    store.require(rid, "meta", ok, summary)
    return {"run": rid, "ok": ok, "summary": summary, "counts": counts,
            "ages_days": sorted(ages),
            "no_installer": no_installer, "unreadable": unreadable, "wrong": wrong,
            "apps": len(with_answer)}
