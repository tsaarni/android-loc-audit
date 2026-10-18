"""Read the phone once, change nothing.

The phone is a source that can be read again, but the state it is in now cannot be recovered later,
so this phase copies everything the later offline phases need and nothing interprets it yet.

Writes (see docs/commands/capture.md):
    data/device/device.json                brand, model, Android version, build id, capture time
    data/device/third_party_pkgs.txt       pm list packages -3, sorted
    data/device/dumpsys_location.txt       listeners, counters, event log
    data/device/dumpsys_package/<pkg>.txt  dumpsys package, one file per app
    data/device/dumpsys_appops.txt         the full app-ops dump
"""
import json
import os

from . import device, paths, store

PROPS = (
    ("brand", "ro.product.brand"),
    ("model", "ro.product.model"),
    ("device", "ro.product.device"),
    ("android", "ro.build.version.release"),
    ("sdk", "ro.build.version.sdk"),
    ("build_id", "ro.build.id"),
    ("fingerprint", "ro.build.fingerprint"),
)


def parse_props(text):
    """`getprop` lines look like '[ro.product.brand]: [samsung]'."""
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("[") or "]: [" not in line:
            continue
        key, value = line[1:].split("]: [", 1)
        out[key] = value[:-1] if value.endswith("]") else value
    return out


def parse_packages(text):
    """`pm list packages -3` lines look like 'package:com.example.app'."""
    names = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        names.add(line[len("package:"):] if line.startswith("package:") else line)
    return sorted(names)


def _write(name, text):
    path = paths.device(name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text if text.endswith("\n") else text + "\n")
    return path


def _prune(packages):
    """Delete per-app captures that are not in this list: an old file is not this phone's answer."""
    root = paths.dumpsys()
    keep = {pkg + ".txt" for pkg in packages}
    removed = []
    if os.path.isdir(root):
        for name in sorted(os.listdir(root)):
            if name.endswith(".txt") and name not in keep:
                os.unlink(os.path.join(root, name))
                removed.append(name[:-4])
    return removed


def read_phone(serial=None, progress=None):
    """Copy the raw state of the phone to data/device/. Returns what was read."""
    serial = serial or device.one_device()
    props = parse_props(device.shell("getprop", serial=serial))
    packages = parse_packages(device.shell("pm list packages -3", serial=serial))
    if not packages:
        raise device.DeviceError("pm list packages -3 returned nothing")

    info = {name: props.get(key, "") for name, key in PROPS}
    info.update({
        "serial": serial,
        "captured_at": store.now(),
        "packages": len(packages),
        "targets_sha256": store.targets_sha256(packages),
    })
    _write("device.json", json.dumps(info, indent=1, sort_keys=True))
    _write("third_party_pkgs.txt", "\n".join(packages))
    _write("dumpsys_location.txt", device.shell("dumpsys location", serial=serial))
    _write("dumpsys_appops.txt", device.shell("dumpsys appops", serial=serial))
    _prune(packages)

    empty = []
    for index, pkg in enumerate(packages, 1):
        text = device.shell(f"dumpsys package {pkg}", serial=serial)
        _write(os.path.join("dumpsys_package", pkg + ".txt"), text)
        if not text.strip():
            empty.append(pkg)
        if progress:
            progress(index, len(packages), pkg)
    return {"device": info, "packages": packages, "empty": empty}


def run(rid=None, serial=None, progress=None):
    """Capture the phone into data/device/ and record it in the run."""
    paths.ensure()
    if rid is None and store.latest() is None:
        from . import __version__
        rid = store.start_run(__version__)
    else:
        rid = store.resolve(rid)
    read = read_phone(serial=serial, progress=progress)
    info, packages = read["device"], read["packages"]

    def mutate(doc):
        doc["device"] = info
        doc["targets_sha256"] = info["targets_sha256"]
        doc["apps"] = list(packages)
        doc["datasets"] = doc.get("datasets") or {}

    store.update_run(rid, mutate)

    missing = [pkg for pkg in packages
               if not os.path.getsize(paths.dumpsys(pkg + ".txt"))]
    ok = len(packages) == info["packages"] and not missing
    summary = (f"{len(packages)} apps read from the phone, "
               f"{len(packages) - len(missing)} with a full capture, build "
               f"{info['build_id']} ({info['model']}, Android {info['android']})")
    store.require(rid, "capture", ok,
                  summary if ok else f"{summary}; no capture for {', '.join(missing)}")
    return {"run": rid, "summary": summary, "missing": missing, "device": info}
