"""Which key signed each app, and whether every file still verifies.

Offline, after the app files are copied (docs/commands/pull.md). Reads the files with `apksigner`
from the Android build-tools: re-implementing the signature schemes would be a second
implementation with its own bugs, and the point of a signature check is that somebody else checks.

    data/apks/<pkg>/*.apk   every file, verified, and the name inside its certificate read

apksigner's exit code is not trusted on its own: its text is parsed, and a file counts as verified
only when the text says "Verifies".
"""
import os
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor

from . import paths, store

WORKERS = 8

# apksigner checks a file against the Android version its manifest asks for, and a split APK often
# does not say, so it falls back to version 1 and then demands a signature scheme that a modern
# file does not carry: a v3-only split then reads as "DOES NOT VERIFY". The floor below is used
# only when the phone's own text has no answer (docs/reference/pitfalls.md#a-split-needs-its-min-sdk-version).
FLOOR_SDK = 24
_MIN_SDK = re.compile(r"^\s+versionCode=\d+ minSdk=(\d+)", re.M)

_VERIFIES = re.compile(r"^Verifies$", re.M)
_SCHEME = re.compile(r"^Verified using (v[\d.]+) scheme [^:]*: (true|false)$", re.M)
_DN = re.compile(r"^(.*)certificate DN: (.*)$", re.M)
_SHA = re.compile(r"^(.*)certificate SHA-256 digest: (.*)$", re.M)

# A key whose certificate carries no owner name says nothing about who holds it.
UNNAMED = "a key with no owner name in it"
GOOGLE = "Google"

OWNED = ("sig:cert-sha256", "sig:signed-by", "sig:scheme", "sig:source-stamp")


class SigningError(Exception):
    """The signature could not be read at all, which is never the same as one that failed."""


def find_apksigner():
    """The apksigner to use: the newest build-tools one, or the one on the path."""
    roots = [os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT"),
             os.path.expanduser("~/Library/Android/sdk"), os.path.expanduser("~/Android/Sdk")]
    found = []
    for root in filter(None, roots):
        build_tools = os.path.join(root, "build-tools")
        if not os.path.isdir(build_tools):
            continue
        for version in sorted(os.listdir(build_tools), reverse=True):
            candidate = os.path.join(build_tools, version, "apksigner")
            if os.path.exists(candidate):
                found.append(candidate)
                break
    return found[0] if found else shutil.which("apksigner")


def _fields(dn):
    """The parts of a certificate name: C, ST, L, O, OU, CN. Values may hold commas."""
    out = {}
    for part in re.split(r",\s*(?=[A-Z]+=)", dn):
        key, _, value = part.partition("=")
        if value:
            # A name holding a comma is quoted in the certificate: O="Google, Inc".
            out.setdefault(key.strip(), value.strip().strip('"'))
    return out


def owner(dn):
    """The name written in the certificate, in words a person can use."""
    if not dn:
        return UNNAMED
    fields = _fields(dn)
    name = fields.get("O") or fields.get("CN") or ""
    if not name or name.lower() in ("unknown", "android"):
        return UNNAMED
    if name.lower().startswith("google"):
        return GOOGLE
    return name


def parse(text):
    """apksigner's text for one file: whether it verifies, its schemes, its signers, its stamp."""
    out = {"verifies": bool(_VERIFIES.search(text)), "schemes": [], "signers": [], "stamp": None}
    for version, value in _SCHEME.findall(text):
        if value == "true":
            out["schemes"].append(version)
    names = {prefix.strip(): dn for prefix, dn in _DN.findall(text)}
    digests = {prefix.strip(): digest for prefix, digest in _SHA.findall(text)}
    for prefix, dn in names.items():
        if "source stamp" in prefix.lower():
            out["stamp"] = dn
            continue
        out["signers"].append({"dn": dn, "sha256": digests.get(prefix)})
    return out


def min_sdk(pkg, default=FLOOR_SDK):
    """The oldest Android the app says it runs on, from the text the phone gave about it."""
    path = paths.dumpsys(pkg + ".txt")
    if not os.path.exists(path):
        return default
    with open(path, encoding="utf-8") as f:
        match = _MIN_SDK.search(f.read())
    return int(match.group(1)) if match else default


def read_file(path, apksigner=None, sdk=FLOOR_SDK):
    """One app file, read by apksigner. Raises SigningError when it cannot be read at all."""
    apksigner = apksigner or find_apksigner()
    if not apksigner:
        raise SigningError("apksigner was not found; it ships with the Android build-tools, "
                           "and java must be installed to run it")
    try:
        done = subprocess.run([apksigner, "verify", "--min-sdk-version", str(sdk),
                               "--print-certs", "-v", path],
                              capture_output=True, text=True)
    except OSError as exc:
        raise SigningError(f"apksigner could not be run: {exc}") from exc
    text = (done.stdout or "") + (done.stderr or "")
    if not text.strip():
        raise SigningError(f"{os.path.basename(path)}: apksigner said nothing")
    found = parse(text)
    if not found["verifies"] and "Exception" in text:
        raise SigningError(f"{os.path.basename(path)}: {text.strip().splitlines()[0]}")
    return found


def _apk_files(pkg):
    folder = paths.apks(pkg)
    if not os.path.isdir(folder):
        return []
    return [os.path.join(folder, name) for name in sorted(os.listdir(folder))
            if name.endswith(".apk")]


# --- the phase ----------------------------------------------------------------------

def _bucket(name):
    if name == GOOGLE:
        return "google"
    if name == UNNAMED:
        return "unnamed"
    return "company"


def run(rid=None, apps=None, progress=None, workers=WORKERS):
    rid = store.resolve(rid)
    packages = apps or sorted(name for name in os.listdir(paths.apks())
                              if os.path.isdir(paths.apks(name)))
    apksigner = find_apksigner()
    if not apksigner:
        raise SigningError("apksigner was not found; it ships with the Android build-tools, "
                           "and java must be installed to run it")

    # Every file of every app, in parallel: one apksigner run each, and the file is read only.
    jobs = [(pkg, path) for pkg in packages for path in _apk_files(pkg)]
    results = {}

    floors = {pkg: min_sdk(pkg) for pkg in packages}

    def one(job):
        pkg, path = job
        return pkg, path, read_file(path, apksigner, floors[pkg])

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for index, (pkg, path, found) in enumerate(pool.map(one, jobs), 1):
            results.setdefault(pkg, []).append((os.path.basename(path), found))
            if progress:
                progress(index, len(jobs), os.path.basename(path))

    counts = {"google": 0, "company": 0, "unnamed": 0}
    unverified, not_copied, disagreeing, stamped = [], [], [], 0
    for pkg in packages:
        files = results.get(pkg) or []
        if not files:
            not_copied.append(pkg)
            continue
        bad = [name for name, found in files if not found["verifies"]]
        unverified.extend(f"{pkg}/{name}" for name in bad)
        # The certificate every file of this app shares. A rotated key keeps the old and the new
        # one in the same file, so the shared set may hold more than one.
        common = None
        for _, found in files:
            digests = {s.get("sha256") for s in found["signers"] if s.get("sha256")}
            common = digests if common is None else (common & digests)
        common = common or set()
        if not common:
            disagreeing.append(pkg)
        fingerprint = sorted(common)[0] if common else None
        dn = next((s["dn"] for _, found in files for s in found["signers"]
                   if s.get("sha256") == fingerprint), None)
        name = owner(dn)
        counts[_bucket(name)] += 1
        first = files[0][1]
        stamp = next((found["stamp"] for _, found in files if found.get("stamp")), None)
        if stamp and owner(stamp) == GOOGLE:
            stamped += 1
        schemes = ", ".join(sorted({s for _, found in files for s in found["schemes"]},
                                   key=lambda s: float(s[1:])))
        rotating = len(common) > 1

        def mutate(doc, fingerprint=fingerprint, name=name, schemes=schemes, stamp=stamp,
                   rotating=rotating):
            written = set()

            def add(subject, value, **kw):
                written.add(subject)
                return store.add_fact(doc, subject, value, **kw)
            if fingerprint:
                add("sig:cert-sha256", fingerprint, tier="T0", source="apksigner",
                    certificates=2 if rotating else None)
            add("sig:signed-by", name, tier="T0", source="apksigner")
            if schemes:
                add("sig:scheme", schemes, tier="T0", source="apksigner")
            if stamp:
                add("sig:source-stamp", owner(stamp), tier="T0", source="apksigner")
            for subject in OWNED:
                if subject not in written:
                    doc["facts"].pop(subject, None)

        store.update_app(pkg, mutate, rid)

    sheets = store.apps(rid)
    # The check has to be able to disagree with the reading: the number of files apksigner verified
    # is compared with the number of files the copy recorded, per app.
    from_copy = {}
    for sheet in sheets:
        from_copy[sheet["pkg"]] = sum(1 for subject in sheet["facts"] if subject.startswith("apk:"))
    wrong = sorted(pkg for pkg in packages
                   if len(results.get(pkg) or []) != from_copy.get(pkg))
    fingerprinted = [sheet for sheet in sheets
                     if (sheet["facts"].get("sig:cert-sha256") or {}).get("value")]
    ok = bool(packages) and not unverified and not not_copied and not disagreeing \
        and not wrong and len(fingerprinted) >= len(packages)

    files = sum(len(found) for found in results.values())
    summary = (f"{len(packages)} apps in {files} files verified: "
               f"{counts['google']} signed by {GOOGLE}, {counts['company']} signed by another "
               f"company, {counts['unnamed']} signed by {UNNAMED}")
    if stamped:
        summary += (f"; {stamped} carry a stamp from Google Play, which shows Play handled that "
                    f"copy")
    for label, items in (("no app files copied", not_copied), ("did not verify", unverified),
                         ("signed by more than one key", disagreeing),
                         ("the count disagrees with the copy", wrong)):
        if items:
            summary += f"; {len(items)} {label}: {', '.join(items[:5])}"
    store.require(rid, "signing", ok, summary)
    return {"run": rid, "ok": ok, "summary": summary, "counts": counts, "files": files,
            "stamped": stamped, "unverified": unverified, "not_copied": not_copied,
            "disagreeing": disagreeing, "wrong": wrong, "apps": len(packages)}
