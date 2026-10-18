"""Structural extraction of embedded components, package namespaces, and bytecode callers.

This module is a sharp, deterministic extractor — never a black-box classifier:
1. Tier 0 (Zero-pull, from dumpsys_package): extracts all non-framework component namespaces
   and class names registered in Android's Activity, Receiver, Service, and ContentProvider
   tables.
2. Tier 3 (Deep-dive, from jadx decompiled Java sources): decompiles APKs into
   data/decompiled/<pkg>/ (cached) and extracts:
   - All non-framework Java package namespaces compiled into the APK (with class counts)
   - Exact Java classes calling Android / Play Services Location APIs
   - Exact Java classes reading the Google Advertising ID (GAID)
   - Hardcoded HTTPS endpoints inside classes that touch location or Advertising ID
"""
from concurrent.futures import ThreadPoolExecutor
import json
import os
import re
import shutil
import subprocess
import zipfile

from . import manifests, paths, store

# Standard Android, Kotlin, Java, and cross-platform UI runtime plumbing that is not
# app-specific or third-party vendor logic.
FRAMEWORK_PREFIXES = (
    "android.",
    "androidx.",
    "kotlin.",
    "kotlinx.",
    "java.",
    "javax.",
    "dalvik.",
    "org.chromium.",
    "org.jetbrains.",
    "org.intellij.",
    "org.json.",
    "org.w3c.",
    "org.xml.",
    "org.slf4j.",
    "org.apache.",
    "com.google.common.",
    "com.google.gson.",
    "com.google.protobuf.",
    "com.google.crypto.",
    "com.google.errorprone.",
    "com.google.j2objc.",
    "com.google.android.material.",
    "com.google.android.datatransport.",
    "com.google.android.play.core.",
    "com.google.android.gms.common.",
    "com.google.android.gms.Dynamic",
    "com.google.android.gms.internal.",
    "com.google.android.gms.tasks.",
    "com.google.android.gms.signin.",
    "com.google.android.gms.auth.",
    "com.google.android.gms.base.",
    "com.google.android.gms.dynamite.",
    "com.google.android.gms.security.",
    "com.google.android.gms.metadata.",
    "com.google.android.gms.location.internal.",
    "com.google.android.gms.ads.identifier.",
    "com.google.firebase.provider.",
    "com.google.firebase.components.",
    "com.google.firebase.iid.",
    "com.google.firebase.messaging.",
    "com.google.firebase.sessions.",
    "com.google.firebase.installations.",
    "com.google.firebase.concurrent.",
    "com.google.firebase.datatransport.",
    "com.google.firebase.ktx.",
    "com.google.firebase.auth.",
    "com.google.firebase.crashlytics.",
    "com.google.mlkit.",
    "io.flutter.",
    "io.reactivex.",
    "expo.modules.",
    "com.facebook.react.",
    "com.facebook.soloader.",
    "com.facebook.fbreact.",
    "com.facebook.hermes.",
    "com.facebook.jni.",
    "com.facebook.yoga.",
    "com.facebook.drawee.",
    "com.facebook.imagepipeline.",
    "com.facebook.common.",
    "com.reactnative",
    "com.swmansion.",
    "com.th3rdwave.",
    "com.oblador.",
    "com.horcrux.",
    "okhttp3.",
    "okio.",
    "retrofit2.",
    "coil.",
    "dagger.",
    "hilt_aggregated_deps.",
    "butterknife.",
    "com.bumptech.glide.",
    "com.squareup.picasso.",
    "com.squareup.okhttp",
    "com.squareup.moshi.",
    "com.squareup.wire.",
    "com.airbnb.lottie.",
    "com.jakewharton.",
    " kotlinx.",
)

COMPONENT_RE = re.compile(
    r"(?:^|\s)([a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)+)/([a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_$]+){2,})"
)
ACTION_REFERRER_RE = re.compile(r"\b(com\.appsflyer\.referrer|com\.adjust\.sdk|io\.branch)\b")

# Location API patterns in decompiled Java code
LOCATION_API_PATTERNS = (
    ("FusedLocationProvider", re.compile(
        r"\b(FusedLocationProviderClient|getFusedLocationProviderClient|"
        r"LocationServices\.FusedLocationApi)\b")),
    ("LocationRequest", re.compile(
        r"\b(requestLocationUpdates|getCurrentLocation|getLastLocation|"
        r"getLastKnownLocation)\b")),
    ("Geofencing", re.compile(r"\b(GeofencingClient|Geofence\.Builder|addGeofences)\b")),
    ("Beacon/BLE Scan", re.compile(r"\b(BluetoothLeScanner|startLeScan)\b")),
    ("Wi-Fi Scan", re.compile(r"\b(getScanResults|startScan)\b")),
)

AD_ID_PATTERNS = re.compile(
    r"\b(AdvertisingIdClient|getAdvertisingIdInfo|AdIdManager)\b"
    r"|\"advertising_id\"|\"gaid\"|\"gps_adid\""
)

URL_PATTERN = re.compile(r"https://[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=-]{8,120}")
NOISE_URLS = (
    "schemas.android.com",
    "www.w3.org",
    "xml.org",
    "apache.org",
    "google.com/policies",
    "developers.google.com",
    "plus.google.com",
    "play.google.com/store",
    "example.com",
    "github.com",
    "creativecommons.org",
    "ns.adobe.com",
)

OWNED_CODE_FACTS = (
    "code:location-apis",
    "code:location-classes",
    "code:ad-id-classes",
    "code:packages",
    "code:endpoints",
    "code:ad-id-join",
    "code:decompilation-confidence",
    "code:primary-engine",
    "code:binary-structure",
)


def _namespace_prefix(cls_name):
    """Extract a clean package prefix (2–4 segments) from a full Java class name."""
    parts = cls_name.split(".")
    if len(parts) <= 2:
        return parts[0]
    pkg_parts = parts[:-1]
    if pkg_parts[:4] == ["com", "google", "android", "gms"] and len(pkg_parts) >= 5:
        return ".".join(pkg_parts[:5])
    if pkg_parts[:3] == ["com", "google", "firebase"] and len(pkg_parts) >= 4:
        return ".".join(pkg_parts[:4])
    if pkg_parts[:3] == ["com", "mapbox", "common"] and len(pkg_parts) >= 4:
        return ".".join(pkg_parts[:4])
    return ".".join(pkg_parts[:3])


def detect_in_dumpsys(text, pkg=""):
    """Extract non-framework component namespaces registered in dumpsys_package.

    Returns sorted list of (namespace_prefix, summary_string) where summary_string
    shows the namespace and its registered component classes, e.g.:
      ("com.mapbox.common.location", "com.mapbox.common.location (LocationUpdatesReceiver)")

    Strips queriesPackages lines and stops before the Packages: permission block so
    external app queries are never mistaken for embedded components.
    """
    resolver_block = text.split("\nPackages:\n", 1)[0]
    cleaned_lines = [
        line for line in resolver_block.splitlines()
        if not line.strip().startswith("queriesPackages=")
    ]
    haystack = "\n".join(cleaned_lines)

    pkg_root = ".".join(pkg.split(".")[:2]) if pkg else ""
    groups = {}

    for match in COMPONENT_RE.finditer(haystack):
        owner, cls = match.group(1), match.group(2)
        if pkg and owner != pkg:
            continue
        if cls.startswith("."):
            continue
        if pkg and (cls.startswith(pkg + ".") or (pkg_root and cls.startswith(pkg_root + "."))):
            continue
        if cls.startswith(FRAMEWORK_PREFIXES):
            continue
        prefix = _namespace_prefix(cls)
        short_cls = cls.rsplit(".", 1)[-1].split("$")[0]
        groups.setdefault(prefix, set()).add(short_cls)

    for match in ACTION_REFERRER_RE.finditer(haystack):
        prefix = match.group(1)
        groups.setdefault(prefix, set()).add("InstallReferrer")

    out = []
    for prefix, classes in sorted(groups.items()):
        cls_list = ", ".join(sorted(classes)[:3])
        if len(classes) > 3:
            cls_list += f" (+{len(classes) - 3})"
        out.append((prefix, f"{prefix} ({cls_list})"))
    return out


def find_jadx():
    return shutil.which("jadx")


def decompile_dir(pkg):
    return paths.data("decompiled", pkg)


def inspect_cache_path(pkg):
    return os.path.join(paths.cache(pkg), "inspect.json")


def inspect_archive(pkg):
    """Examine in-memory central directory of all pulled APKs for pkg without unzipping to disk."""
    apk_dir = paths.apks(pkg)
    if not os.path.isdir(apk_dir):
        return {}
    apk_files = sorted(
        os.path.join(apk_dir, name)
        for name in os.listdir(apk_dir)
        if name.endswith(".apk")
    )
    if not apk_files:
        return {}

    dex_files = []
    total_dex_bytes = 0
    native_libs = []
    archs = set()
    has_rn = False
    has_flutter = False
    has_unity = False
    rn_bundle_size = 0
    rn_is_hermes = False

    for path in apk_files:
        try:
            with zipfile.ZipFile(path, "r") as zf:
                for info in zf.infolist():
                    name = info.filename
                    if name.endswith(".dex") and ("/" not in name or name.startswith("classes")):
                        dex_files.append(name)
                        total_dex_bytes += info.file_size
                    elif name.startswith("lib/") and name.endswith(".so"):
                        native_libs.append(name)
                        parts = name.split("/")
                        if len(parts) >= 2:
                            archs.add(parts[1])
                    if name == "assets/index.android.bundle":
                        has_rn = True
                        rn_bundle_size += info.file_size
                        try:
                            head = zf.read(name)[:4]
                            rn_is_hermes = head in (b"\xc6\x1f\xbc\x03", b"\x1f\x55\x0c\x03")
                        except Exception:
                            pass
                    elif name.endswith("/libhermes.so"):
                        has_rn = True
                    if name.endswith("/libflutter.so") or name.endswith("/libapp.so"):
                        has_flutter = True
                    if name.endswith("/libunity.so") or name.startswith("assets/bin/Data/"):
                        has_unity = True
        except (zipfile.BadZipFile, OSError):
            continue

    if has_rn and rn_bundle_size:
        rn_type = "Hermes bytecode" if rn_is_hermes else "JavaScript bundle"
        engine = f"React Native ({rn_type}, {rn_bundle_size / 1e6:.1f} MB)"
        confidence = "partial (React Native bundle)"
    elif has_rn and total_dex_bytes < 5000000:
        engine = "React Native"
        confidence = "partial (React Native bundle)"
    elif has_flutter:
        engine = "Flutter"
        confidence = "partial (Flutter Dart AOT)"
    elif has_unity:
        engine = "Unity"
        confidence = "partial (Unity game engine)"
    elif total_dex_bytes < 50000 and native_libs:
        engine = "Minimal DEX stub"
        confidence = "obstructed (Minimal DEX stub; code in native libs/assets)"
    else:
        engine = "Standard Dalvik"
        confidence = "full"

    return {
        "apks": len(apk_files),
        "dex_count": len(dex_files),
        "dex_bytes": total_dex_bytes,
        "native_count": len(native_libs),
        "native_archs": sorted(archs),
        "engine": engine,
        "confidence": confidence,
    }


def is_decompiled(pkg):
    src = os.path.join(decompile_dir(pkg), "sources")
    return os.path.isdir(src) and bool(os.listdir(src))


def decompile(pkg, refresh=False, jobs=8):
    """Decompile all APKs of pkg into data/decompiled/<pkg>/ using jadx (cached)."""
    out_dir = decompile_dir(pkg)
    if not refresh and is_decompiled(pkg):
        return {"pkg": pkg, "dir": out_dir, "cached": True}

    apk_dir = paths.apks(pkg)
    if not os.path.isdir(apk_dir):
        raise ValueError(f"no pulled APKs for {pkg}; run: uv run locaudit pull {pkg}")
    apk_files = sorted(
        os.path.join(apk_dir, name)
        for name in os.listdir(apk_dir)
        if name.endswith(".apk")
    )
    if not apk_files:
        raise ValueError(f"no .apk files in {apk_dir}; run: uv run locaudit pull {pkg}")

    jadx_bin = find_jadx()
    if not jadx_bin:
        raise RuntimeError("jadx not found in PATH; install jadx to decompile APKs")

    if refresh and os.path.isdir(out_dir):
        shutil.rmtree(out_dir)
    os.makedirs(out_dir, exist_ok=True)

    cmd = [jadx_bin, "-d", out_dir, "--no-res", "-j", str(jobs)] + apk_files
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if not is_decompiled(pkg):
        stderr = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError(f"jadx produced no sources for {pkg}: {stderr[:200]}")
    return {"pkg": pkg, "dir": out_dir, "cached": False}


def _class_name(src_root, filepath):
    rel = os.path.relpath(filepath, src_root)
    if rel.endswith(".java"):
        rel = rel[:-5]
    return rel.replace(os.sep, ".")


def _is_non_framework(cls_name):
    return not cls_name.startswith(FRAMEWORK_PREFIXES)


def _scan_file(args):
    src_root, filepath = args
    cls_name = _class_name(src_root, filepath)
    if not _is_non_framework(cls_name):
        return None
    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return None

    loc_apis = []
    for api_name, pattern in LOCATION_API_PATTERNS:
        if pattern.search(text):
            loc_apis.append(api_name)

    has_ad_id = bool(AD_ID_PATTERNS.search(text))

    urls = []
    if loc_apis or has_ad_id:
        for match in URL_PATTERN.finditer(text):
            url = match.group(0).rstrip('",);\\\'')
            if not any(noise in url for noise in NOISE_URLS):
                urls.append(url)

    return {
        "cls": cls_name,
        "loc_apis": loc_apis,
        "has_ad_id": has_ad_id,
        "urls": urls,
    }


def scan_sources(pkg):
    """Scan decompiled Java files under data/decompiled/<pkg>/sources."""
    src_root = os.path.join(decompile_dir(pkg), "sources")
    if not os.path.isdir(src_root):
        raise ValueError(f"no decompiled sources at {src_root}")

    java_files = []
    pkg_counts = {}
    pkg_root = ".".join(pkg.split(".")[:2])

    for dirpath, _, filenames in os.walk(src_root):
        for fname in filenames:
            if fname.endswith(".java"):
                full = os.path.join(dirpath, fname)
                cls = _class_name(src_root, full)
                java_files.append((src_root, full))
                if _is_non_framework(cls) and not cls.startswith((pkg + ".", pkg_root + ".")):
                    prefix = _namespace_prefix(cls)
                    if "." in prefix:
                        pkg_counts[prefix] = pkg_counts.get(prefix, 0) + 1

    third_party_packages = [
        {"package": k, "classes": v}
        for k, v in sorted(pkg_counts.items(), key=lambda item: (-item[1], item[0]))
        if v >= 2
    ][:30]

    location_classes = {}
    location_apis_found = set()
    ad_id_classes = []
    endpoints = set()

    with ThreadPoolExecutor(max_workers=8) as pool:
        for item in pool.map(_scan_file, java_files):
            if not item:
                continue
            if item["loc_apis"]:
                location_classes[item["cls"]] = item["loc_apis"]
                location_apis_found.update(item["loc_apis"])
            if item["has_ad_id"]:
                ad_id_classes.append(item["cls"])
            if item["urls"]:
                endpoints.update(item["urls"])

    return {
        "pkg": pkg,
        "scanned_at": store.now(),
        "java_files": len(java_files),
        "location_apis": sorted(location_apis_found),
        "location_classes": [
            {"class": cls, "apis": apis}
            for cls, apis in sorted(location_classes.items())[:30]
        ],
        "ad_id_classes": sorted(ad_id_classes)[:30],
        "packages": third_party_packages,
        "endpoints": sorted(endpoints)[:40],
        "can_join_ad_id": bool(location_classes and ad_id_classes),
    }


def inspect_app(pkg, rid=None, refresh=False):
    """Run manifest + archive inspection + jadx decompile + source scan for one app, caching all results in data/."""
    rid = store.resolve(rid)
    try:
        manifests.run(rid=rid, apps=[pkg])
    except manifests.ManifestError:
        pass

    archive = inspect_archive(pkg)

    cache_file = inspect_cache_path(pkg)
    if not refresh and os.path.exists(cache_file) and is_decompiled(pkg):
        with open(cache_file, encoding="utf-8") as f:
            result = json.load(f)
        result["cached"] = True
    else:
        dec = decompile(pkg, refresh=refresh)
        result = scan_sources(pkg)
        result["cached"] = dec["cached"]

    result["archive"] = archive
    result["engine"] = archive.get("engine", "Standard Dalvik")
    result["confidence"] = archive.get("confidence", "full")
    os.makedirs(os.path.dirname(cache_file), exist_ok=True)
    with open(cache_file, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=1)
        f.write("\n")

    def mutate(doc):
        for key in list(doc["facts"]):
            if key in OWNED_CODE_FACTS or key.startswith("code:"):
                doc["facts"].pop(key, None)

        if result.get("confidence"):
            store.add_fact(doc, "code:decompilation-confidence", result["confidence"],
                           tier="T3", source="zip central directory")
        if result.get("engine"):
            store.add_fact(doc, "code:primary-engine", result["engine"],
                           tier="T3", source="zip central directory")
        if result.get("archive"):
            arc = result["archive"]
            dex_mb = arc.get("dex_bytes", 0) / 1e6
            summary = f"{arc.get('dex_count', 0)} DEX ({dex_mb:.2f} MB), {arc.get('native_count', 0)} .so libs"
            store.add_fact(doc, "code:binary-structure", summary,
                           tier="T3", source="zip central directory")

        if result["location_apis"]:
            store.add_fact(
                doc, "code:location-apis", ", ".join(result["location_apis"]),
                tier="T3", source="jadx",
            )
        if result["location_classes"]:
            names = [item["class"] for item in result["location_classes"][:10]]
            store.add_fact(
                doc, "code:location-classes", ", ".join(names),
                tier="T3", source="jadx", count=len(result["location_classes"]),
            )
        if result["ad_id_classes"]:
            store.add_fact(
                doc, "code:ad-id-classes", ", ".join(result["ad_id_classes"][:10]),
                tier="T3", source="jadx", count=len(result["ad_id_classes"]),
            )
        if result["packages"]:
            pkg_summary = [f"{p['package']} ({p['classes']})" for p in result["packages"][:12]]
            store.add_fact(
                doc, "code:packages", ", ".join(pkg_summary),
                tier="T3", source="jadx",
            )
        if result["endpoints"]:
            store.add_fact(
                doc, "code:endpoints", ", ".join(result["endpoints"][:10]),
                tier="T3", source="jadx", count=len(result["endpoints"]),
            )
        store.add_fact(
            doc, "code:ad-id-join", result["can_join_ad_id"],
            tier="T3", source="jadx",
        )

    store.update_app(pkg, mutate, rid)
    return result


def run(rid=None, apps=None, refresh=False, progress=None):
    """Inspect code for the specified apps."""
    rid = store.resolve(rid)
    if not apps:
        raise ValueError("specify at least one package: uv run locaudit inspect <package> ...")
    results = []
    failures = {}
    for index, pkg in enumerate(apps, 1):
        if progress:
            progress(index, len(apps), pkg)
        try:
            results.append(inspect_app(pkg, rid=rid, refresh=refresh))
        except (ValueError, RuntimeError, OSError) as exc:
            failures[pkg] = str(exc)
    return {"run": rid, "results": results, "failures": failures}
