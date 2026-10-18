"""How many bytes a copy would cost, and whether there is room.

Reads only. `pm path` lists every split APK of every app; `stat` gives its size. Nothing is copied
here, so a phone can be measured before anyone agrees to move gigabytes over USB.

Writes:
    data/device/apk_paths.txt   pkg, size in bytes and path of every APK, for the pull
    run.json -> bundles         APK count and bytes per app, the total, the free space it needs
"""
import os
import shutil

from . import device, paths, store

MARGIN = 1.1  # zip verification and the cache need room too


def parse_pm_path(text):
    """`pm path` prints one 'package:/data/app/.../base.apk' line per APK."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("package:"):
            line = line[len("package:"):]
        if line.startswith("/"):
            out.append(line)
    return out


def parse_sizes(text):
    """`stat -c '%s %n'` prints '<bytes> <path>'."""
    out = {}
    for line in text.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and parts[0].isdigit():
            out[parts[1]] = int(parts[0])
    return out


def _script(pkg):
    return ("pm path {pkg} | sed 's/^package://' | "
            "while read -r f; do stat -c '%s %n' \"$f\"; done").format(pkg=pkg)


def read_bundles(serial=None, packages=None, progress=None):
    """{pkg: {apks, bytes, files: [{path, bytes}]}} for every app on the phone."""
    serial = serial or device.one_device()
    if packages is None:
        packages = device.shell("pm list packages -3", serial=serial)
        from .capture import parse_packages
        packages = parse_packages(packages)
    bundles, unreadable = {}, []
    for index, pkg in enumerate(packages, 1):
        sizes = parse_sizes(device.shell(_script(pkg), serial=serial))
        files = [{"path": p, "bytes": n} for p, n in sorted(sizes.items())]
        if not files:
            unreadable.append(pkg)
        bundles[pkg] = {"apks": len(files), "bytes": sum(f["bytes"] for f in files),
                        "files": files}
        if progress:
            progress(index, len(packages), pkg)
    return bundles, unreadable, packages


def write_paths(bundles):
    lines = []
    for pkg, bundle in sorted(bundles.items()):
        for f in bundle["files"]:
            lines.append(f"{pkg}\t{f['bytes']}\t{f['path']}")
    path = paths.device("apk_paths.txt")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + ("\n" if lines else ""))
    return path


def run(rid=None, serial=None, progress=None):
    rid = store.resolve(rid)
    run_doc = store.load_run(rid)
    bundles, unreadable, packages = read_bundles(serial=serial, progress=progress)
    write_paths(bundles)

    total = sum(b["bytes"] for b in bundles.values())
    apks = sum(b["apks"] for b in bundles.values())
    free = shutil.disk_usage(paths.apks()).free
    need = int(total * MARGIN)
    changed = store.targets_sha256(packages) != run_doc.get("targets_sha256")

    summary_doc = {
        "measured_at": store.now(),
        "apps": {pkg: {"apks": b["apks"], "bytes": b["bytes"]} for pkg, b in bundles.items()},
        "apks": apks,
        "bytes": total,
        "need_bytes": need,
        "free_bytes": free,
        "enough_room": free >= need,
        "packages": len(packages),
        "changed_since_capture": changed,
    }

    def mutate(doc):
        doc["bundles"] = summary_doc

    store.update_run(rid, mutate)

    ok = bool(bundles) and not unreadable and not changed and summary_doc["enough_room"]
    summary = (f"{len(packages)} apps in {apks} app files, {total / 1e9:.1f} GB "
               f"({total / 2**30:.1f} GiB); the copy needs {need / 1e9:.1f} GB with room to "
               f"spare, and {free / 1e9:.1f} GB is free")
    if changed:
        summary += "; the phone's app list changed since the capture, so capture again"
    if unreadable:
        summary += f"; no APK path for {', '.join(unreadable)}"
    if not summary_doc["enough_room"]:
        summary += "; not enough free space for the copy"
    store.require(rid, "measure", ok, summary)
    return {"run": rid, "summary": summary, "bytes": total, "apks": apks,
            "free_bytes": free, "need_bytes": need, "apps": len(packages),
            "unreadable": unreadable, "changed": changed}
