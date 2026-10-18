"""What each app declares it will do while you are not looking.

Offline, after the app files are copied (docs/commands/manifest.md). Reads AndroidManifest.xml out
of each app's files with aapt2 from the Android build-tools, because the file is binary and decoding
it by hand would be a second implementation with its own bugs.

    data/apks/<pkg>/*.apk   the manifest inside, read with "aapt2 dump xmltree"

The facts are named by what they are, not by what the phone did with them: this phase writes
"declares:" for what an app asks for, and the location permissions step writes "perm:" for what the
phone granted. Declaring a permission is not holding it.
"""
import os
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor

from . import paths, store

WORKERS = 8

# What kind of background work a foreground service declares. The number in the manifest is a
# bitmask, so 0x18 is location and connected device at once
# (docs/reference/pitfalls.md#foreground-service-type-is-a-bitmask).
FGS_TYPES = (
    (0x1, "data sync"),
    (0x2, "media playback"),
    (0x4, "phone call"),
    (0x8, "location"),
    (0x10, "connected device"),
    (0x20, "screen capture"),
    (0x40, "camera"),
    (0x80, "microphone"),
    (0x100, "health"),
    (0x200, "remote messaging"),
    (0x400, "system exemption"),
    (0x800, "short service"),
)

BOOT = ("android.intent.action.BOOT_COMPLETED", "android.intent.action.LOCKED_BOOT_COMPLETED",
        "android.intent.action.QUICKBOOT_POWERON")
REPLACED = ("android.intent.action.MY_PACKAGE_REPLACED", "android.intent.action.PACKAGE_REPLACED")

# Facts this phase owns. A re-run clears them first, so a manifest that stopped declaring something
# does not leave a stale declaration behind.
KINDS = ("declares", "fgs", "receiver", "provider", "posture")

_ELEMENT = re.compile(r"^( *)E: (\S+)")
_ATTRIBUTE = re.compile(r"^ *A: (\S+?)\(0x[0-9a-f]+\)=(.*)$")
_RAW = re.compile(r"\s*\(Raw: .*\)$")


class ManifestError(Exception):
    """The manifest could not be read at all, which is never the same as one that declares little."""


def find_aapt2():
    """The aapt2 to use: the newest build-tools one, or the one on the path."""
    roots = [os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT"),
             os.path.expanduser("~/Library/Android/sdk"), os.path.expanduser("~/Android/Sdk")]
    for root in filter(None, roots):
        build_tools = os.path.join(root, "build-tools")
        if not os.path.isdir(build_tools):
            continue
        for version in sorted(os.listdir(build_tools), reverse=True):
            candidate = os.path.join(build_tools, version, "aapt2")
            if os.path.exists(candidate):
                return candidate
    return shutil.which("aapt2")


def _value(text):
    text = _RAW.sub("", text.strip())
    if text.startswith('"') and text.endswith('"'):
        text = text[1:-1]
    return text.strip()


def _short(name):
    """The last part of a class name, with no space in it: a subject cannot hold one."""
    return re.sub(r"\s+", "-", name.strip().rsplit(".", 1)[-1])


def parse_tree(text):
    """The manifest as nested elements: name, attributes and children, by indentation."""
    root = {"name": "root", "attrs": {}, "children": []}
    stack = [(0, root)]
    for line in text.splitlines():
        match = _ELEMENT.match(line)
        if match:
            depth, name = len(match.group(1)), match.group(2)
            node = {"name": name, "attrs": {}, "children": []}
            while stack and stack[-1][0] >= depth:
                stack.pop()
            (stack[-1][1] if stack else root)["children"].append(node)
            stack.append((depth, node))
            continue
        match = _ATTRIBUTE.match(line)
        if match and stack:
            attribute = match.group(1).rsplit(":", 1)[-1]
            stack[-1][1]["attrs"][attribute] = _value(match.group(2))
    return root


def _walk(node):
    for child in node["children"]:
        yield child
        yield from _walk(child)


def _fgs_words(number):
    try:
        mask = int(number, 0)
    except (TypeError, ValueError):
        return ""
    words = [name for bit, name in FGS_TYPES if mask & bit]
    leftover = mask & ~sum(bit for bit, _ in FGS_TYPES)
    if leftover:
        words.append(f"unknown type {leftover:#x}")
    return ", ".join(words)


def read_manifest(text, pkg):
    """What one manifest declares: permissions, background services, receivers, posture."""
    root = parse_tree(text)
    permissions, services, providers = {}, {}, []
    boot, replaced, location_receivers, exported = False, False, [], 0
    debuggable = allow_backup = None
    for node in _walk(root):
        name = node["name"]
        attrs = node["attrs"]
        if node["name"] == "application":
            if "debuggable" in attrs:
                debuggable = attrs["debuggable"] == "true"
            if "allowBackup" in attrs:
                allow_backup = attrs["allowBackup"] == "true"
        if attrs.get("exported") == "true":
            exported += 1
        if name == "uses-permission" or name == "uses-permission-sdk-23":
            permission = attrs.get("name") or ""
            if permission.strip():
                # A permission with a maximum Android version is not asked for on a newer phone,
                # which is why the phone's own answer for it is "never asked".
                limit = attrs.get("maxSdkVersion")
                permissions[_short(permission)] = int(limit) if limit and limit.isdigit() else None
        elif name == "service":
            kind = attrs.get("foregroundServiceType")
            if kind and (attrs.get("name") or "").strip():
                services[_short(attrs["name"])] = _fgs_words(kind)
        elif name == "provider":
            if (attrs.get("name") or "").strip():
                providers.append(_short(attrs["name"]))
        elif name == "action":
            action = attrs.get("name") or ""
            if action in BOOT:
                boot = True
            if action in REPLACED:
                replaced = True
        if name == "receiver" and (attrs.get("name") or "").strip():
            if "location" in attrs["name"].lower():
                location_receivers.append(_short(attrs["name"]))
    return {
        "pkg": pkg,
        "permissions": permissions,
        "services": services,
        "providers": providers,
        "boot": boot,
        "package_replaced": replaced,
        "location_receivers": location_receivers,
        "debuggable": debuggable,
        "allow_backup": allow_backup,
        "exported": exported,
    }


def read_apk(path, aapt2=None, pkg=""):
    aapt2 = aapt2 or find_aapt2()
    if not aapt2:
        raise ManifestError("aapt2 was not found; it ships with the Android build-tools")
    try:
        done = subprocess.run([aapt2, "dump", "xmltree", "--file", "AndroidManifest.xml", path],
                              capture_output=True, text=True)
    except OSError as exc:
        raise ManifestError(f"aapt2 could not be run: {exc}") from exc
    if done.returncode != 0 or "E: manifest" not in (done.stdout or ""):
        first = ((done.stderr or done.stdout or "").strip().splitlines() or ["no output"])[0]
        raise ManifestError(f"{os.path.basename(path)}: {first}")
    return read_manifest(done.stdout, pkg)


# --- the phase ----------------------------------------------------------------------

def _apk_files(pkg):
    folder = paths.apks(pkg)
    if not os.path.isdir(folder):
        return []
    names = sorted(name for name in os.listdir(folder) if name.endswith(".apk"))
    base = [name for name in names if name == "base.apk"]
    return [os.path.join(folder, name) for name in (base or names)[:1]]


def run(rid=None, apps=None, progress=None, workers=WORKERS):
    """Read the manifests of the apps named in apps, and of no other app."""
    rid = store.resolve(rid or store.latest())
    copied = sorted(name for name in os.listdir(paths.apks())
                    if os.path.isdir(paths.apks(name)))
    packages = [pkg for pkg in (apps or []) if pkg in copied]
    absent = [pkg for pkg in (apps or []) if pkg not in copied]
    if absent:
        raise ManifestError(f"no app files for {', '.join(absent)}: copy them first with "
                            f"uv run locaudit pull <package> ...")
    aapt2 = find_aapt2()
    if not aapt2:
        raise ManifestError("aapt2 was not found; it ships with the Android build-tools")

    jobs = [(pkg, _apk_files(pkg)) for pkg in packages]
    found, unreadable = {}, {}
    jobs = [(pkg, files[0]) for pkg, files in jobs if files]
    no_files = [pkg for pkg, files in ((pkg, _apk_files(pkg)) for pkg in packages) if not files]

    def one(job):
        pkg, path = job
        try:
            return pkg, read_apk(path, aapt2, pkg), None
        except ManifestError as exc:
            return pkg, None, str(exc)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for index, (pkg, manifest, error) in enumerate(pool.map(one, jobs), 1):
            if error:
                unreadable[pkg] = error
            else:
                found[pkg] = manifest
            if progress:
                progress(index, len(jobs), pkg)

    for pkg, manifest in found.items():
        def mutate(doc, manifest=manifest):
            for subject in list(doc["facts"]):
                if subject.split(":", 1)[0] in KINDS:
                    doc["facts"].pop(subject)
            for permission, limit in sorted(manifest["permissions"].items()):
                value = True if limit is None else f"only up to Android API {limit}"
                store.add_fact(doc, f"declares:{permission}", value, tier="T0", source="aapt2",
                               max_sdk=limit)
            for service, kinds in sorted(manifest["services"].items()):
                store.add_fact(doc, f"fgs:{service}", kinds, tier="T0", source="aapt2")
            if manifest["boot"]:
                store.add_fact(doc, "receiver:boot-completed", True, tier="T0", source="aapt2")
            if manifest["package_replaced"]:
                store.add_fact(doc, "receiver:package-replaced", True, tier="T0", source="aapt2")
            for service in manifest["location_receivers"]:
                store.add_fact(doc, f"receiver:location-{service}", True, tier="T0",
                               source="aapt2")
            for provider in manifest["providers"]:
                store.add_fact(doc, f"provider:{provider}", True, tier="T0", source="aapt2")
            for posture, value in (("debuggable", manifest["debuggable"]),
                                   ("allow-backup", manifest["allow_backup"])):
                if value is not None:
                    store.add_fact(doc, f"posture:{posture}", value, tier="T0", source="aapt2")
            store.add_fact(doc, "posture:exported-components", manifest["exported"] or 0,
                           tier="T0", source="aapt2")

        store.update_app(pkg, mutate, rid)

    for pkg, error in unreadable.items():
        def mutate(doc, error=error):
            for subject in list(doc["facts"]):
                if subject.split(":", 1)[0] in KINDS:
                    doc["facts"].pop(subject)
            store.add_fact(doc, "unknown:manifest", True, tier="T3", source="aapt2",
                           confidence="weak", reason=error)

        store.update_app(pkg, mutate, rid)

    # The check can disagree with the reading: an app that declares the background location
    # permission in its manifest must be an app the phone did not answer "never asked" for.
    sheets = {sheet["pkg"]: sheet for sheet in store.apps(rid)}
    sdk = int((store.load_run(rid).get("device") or {}).get("sdk") or 0)
    wrong = []
    for pkg, sheet in sheets.items():
        record = sheet["facts"].get("declares:ACCESS_BACKGROUND_LOCATION")
        limit = (record or {}).get("max_sdk")
        # Asked for on this phone only when the manifest does not cap it below the phone's version.
        asked = bool(record) and (limit is None or not sdk or sdk <= limit)
        phone = (sheet["facts"].get("perm:ACCESS_BACKGROUND_LOCATION") or {}).get("value")
        if phone and (phone != "not_requested") != asked:
            wrong.append(pkg)
    wrong = sorted(set(wrong))
    read = [pkg for pkg in packages if "posture:exported-components" in sheets[pkg]["facts"]]
    boot = sum(1 for pkg in read if "receiver:boot-completed" in sheets[pkg]["facts"])
    location_fgs = sum(1 for pkg in read
                       if any("location" in (record.get("value") or "")
                              for subject, record in sheets[pkg]["facts"].items()
                              if subject.startswith("fgs:")))
    debuggable = sum(1 for pkg in read if (sheets[pkg]["facts"].get("posture:debuggable") or {})
                     .get("value") is True)
    restart = sorted(pkg for pkg in read
                     if (sheets[pkg]["facts"].get("perm:ACCESS_BACKGROUND_LOCATION") or {})
                     .get("value") == "granted"
                     and "receiver:boot-completed" in sheets[pkg]["facts"]
                     and any(subject.startswith("fgs:")
                             and "location" in (record.get("value") or "")
                             for subject, record in sheets[pkg]["facts"].items()))
    ok = bool(packages) and not unreadable and not no_files and not wrong \
        and len(read) == len(packages)
    summary = (f"{len(read)} apps: {location_fgs} declare a location foreground service, {boot} "
               f"declare they want to be told when the phone restarts, {debuggable} are marked "
               f"debuggable")
    if no_files:
        summary += f"; no app files for {', '.join(sorted(no_files)[:5])}"
    if unreadable:
        summary += (f"; {len(unreadable)} manifests could not be read, first "
                    f"{sorted(unreadable)[0]}")
    if wrong:
        summary += (f"; the manifest and the phone disagree about the background location "
                    f"permission for {', '.join(wrong[:5])}")

    return {"run": rid, "ok": ok, "summary": summary, "apps": len(read),
            "location_service": location_fgs, "boot": boot, "debuggable": debuggable,
            "restart": restart, "unreadable": sorted(unreadable), "no_files": sorted(no_files),
            "wrong": wrong}
