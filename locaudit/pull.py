"""Copy the app files of the apps named, then prove the copy.

The phone is asked again for `pm path` before copying, so the copy is of the phone as it is now and
not of the phone as it was when it was measured. A file is skipped only if it exists, has the size
the phone reported, and opens as a zip: a file that exists is not a file that is complete.

Writes:
    data/apks/<pkg>/*.apk            base.apk and every split APK
    data/apks/<pkg>/artifacts.json   name, size and sha256 per file
    facts `apk:<name>` = sha256      so a diff between runs shows a changed app
"""
import hashlib
import json
import os
import zipfile

from . import device, measure, paths, store


def destination(pkg, source):
    """The local path for one APK: the package folder plus the file name the phone used."""
    return os.path.join(paths.apks(pkg), os.path.basename(source))


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def is_zip(path):
    try:
        with zipfile.ZipFile(path) as archive:
            archive.namelist()
        return True
    except (zipfile.BadZipFile, OSError):
        return False


def needs_copy(dest, expected):
    """Skip only a file that is present, the right size, and a readable zip."""
    if not os.path.exists(dest):
        return True
    if os.path.getsize(dest) != expected:
        return True
    return not is_zip(dest)


def _copy(serial, pkg, source, expected, progress=None):
    dest = destination(pkg, source)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    if not needs_copy(dest, expected):
        return {"name": os.path.basename(dest), "bytes": expected,
                "sha256": sha256(dest), "source": source, "skipped": True}
    part = dest + ".part"
    device.adb("pull", source, part, serial=serial, timeout=1800)
    if os.path.getsize(part) != expected:
        size = os.path.getsize(part)
        os.unlink(part)
        raise device.DeviceError(f"{pkg}: {os.path.basename(source)} arrived as {size} bytes, "
                                 f"the phone reported {expected}")
    if not is_zip(part):
        os.unlink(part)
        raise device.DeviceError(f"{pkg}: {os.path.basename(source)} is not a readable zip")
    os.replace(part, dest)
    return {"name": os.path.basename(dest), "bytes": expected, "sha256": sha256(dest),
            "source": source, "skipped": False}


def cached_bundle(pkg):
    """Return bundle metadata from data/apks/<pkg>/artifacts.json if all files are present and valid."""
    art_path = os.path.join(paths.apks(pkg), "artifacts.json")
    if not os.path.exists(art_path):
        return None
    try:
        with open(art_path, encoding="utf-8") as f:
            art = json.load(f)
        files = []
        for item in art.get("files") or []:
            dest = os.path.join(paths.apks(pkg), item["name"])
            if needs_copy(dest, item["bytes"]):
                return None
            files.append({"path": item.get("source") or dest, "bytes": item["bytes"]})
        return {"apks": len(files), "bytes": sum(f["bytes"] for f in files), "files": files} if files else None
    except (OSError, ValueError, KeyError):
        return None


def run(rid=None, serial=None, apps=None, progress=None):
    """Copy the app files of the apps named in apps, then verify them."""
    rid = store.resolve(rid)
    if not apps:
        raise ValueError("name the apps whose files to copy: uv run locaudit pull <package> ...")
    wanted = list(apps)
    bundles = {}
    need_phone = []
    for pkg in wanted:
        cached = cached_bundle(pkg)
        if cached:
            bundles[pkg] = cached
        else:
            need_phone.append(pkg)

    unreadable = []
    if need_phone:
        serial = serial or device.one_device()
        live_bundles, unreadable, _ = measure.read_bundles(serial=serial, packages=need_phone)
        for pkg in need_phone:
            if pkg in live_bundles and live_bundles[pkg]["files"]:
                bundles[pkg] = live_bundles[pkg]
    unknown = [pkg for pkg in wanted if pkg not in bundles or not bundles[pkg]["files"]]
    if unknown:
        raise ValueError(f"not installed on the phone (or unreadable): {', '.join(unknown)}")
    packages = wanted

    copied, skipped, failures = 0, 0, []
    total_bytes = 0
    for index, pkg in enumerate(wanted, 1):
        files = []
        for item in bundles[pkg]["files"]:
            try:
                record = _copy(serial, pkg, item["path"], item["bytes"])
            except (device.DeviceError, OSError) as exc:
                failures.append(str(exc))
                continue
            files.append(record)
            total_bytes += record["bytes"]
            copied += 0 if record["skipped"] else 1
            skipped += 1 if record["skipped"] else 0
        if files:
            artifacts = {"pkg": pkg, "run": rid, "at": store.now(),
                         "bytes": sum(f["bytes"] for f in files),
                         "apks": len(files), "files": files}
            with open(os.path.join(paths.apks(pkg), "artifacts.json"), "w",
                      encoding="utf-8") as fh:
                json.dump(artifacts, fh, indent=1)
                fh.write(chr(10))

            def mutate(doc, files=files, artifacts=artifacts):
                doc["app"].update({"apks": artifacts["apks"], "apk_bytes": artifacts["bytes"]})
                for f in files:
                    store.add_fact(doc, f"apk:{f['name']}", f["sha256"], tier="T0",
                                   source="adb pull", bytes=f["bytes"])

            store.update_app(pkg, mutate, rid)
        if progress:
            progress(index, len(wanted), pkg)

    missing = []
    for pkg in wanted:
        for item in bundles[pkg]["files"]:
            dest = destination(pkg, item["path"])
            if not os.path.exists(dest) or os.path.getsize(dest) != item["bytes"]:
                missing.append(f"{pkg}/{os.path.basename(item['path'])}")

    ok = not failures and not missing and not unreadable
    summary = (f"{len(wanted)} of {len(packages)} apps copied: {total_bytes / 1e9:.1f} GB "
               f"in {copied} files, {skipped} files were already complete")
    if failures:
        summary += f"; {len(failures)} failed: {failures[0]}"
    if missing:
        summary += f"; {len(missing)} files missing, first {missing[0]}"
    if len(wanted) < len(packages):
        summary += f"; partial: {len(packages) - len(wanted)} apps not pulled"
    store.require(rid, "pull", ok, summary)
    return {"run": rid, "summary": summary, "apps": len(wanted), "of": len(packages),
            "bytes": total_bytes, "copied": copied, "skipped": skipped,
            "failures": failures, "missing": missing, "partial": len(wanted) < len(packages)}
