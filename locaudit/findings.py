"""Build the structured audit digest (digest.json) and Markdown report (FINDINGS.md).

Combines all tiers of evidence recorded in data/runs/<id>/apps/<pkg>.json:
- Tier 0: OS permissions, AD_ID grant, FGS_LOCATION, BOOT_COMPLETED, and component SDKs
- Tier 1: AppOps recorded location access counts, timestamps, and background flags
- Tier 2: Google Play Store Data Safety declarations
- Tier 3: Decompiled bytecode analysis (location API caller classes, Ad-ID callers, endpoints)
"""
import json
import os

from . import paths, store

PLAY = "com.android.vending"

HOW = {
    "T0": "Android package manager settings and registered components (dumpsys package)",
    "T1": "Android AppOps & Location Manager runtime access logs (dumpsys appops / location)",
    "T2": "Developer's Google Play Data Safety disclosure",
    "T3": "Static analysis of decompiled APK bytecode (jadx / aapt2)",
    "T4": "Network traffic capture",
}

READS = ("while closed", "only while open", "refused", "never asked")

READS_WORDS = {
    "while closed": "can read location in the background (while closed)",
    "only while open": "can read location only while in use (foreground)",
    "refused": "requested location permission and was denied",
    "never asked": "does not request location permission",
}


def _value(sheet, subject, default=None):
    return (sheet["facts"].get(subject) or {}).get("value", default)


def store_words(name):
    if not name:
        return "not known"
    if name == PLAY:
        return "Google Play"
    if name == "com.sec.android.app.samsungapps":
        return "Samsung Galaxy Store"
    if name == "none recorded":
        return "no installer recorded"
    return name


def has_ad_id(sheet):
    return (_value(sheet, "perm:AD_ID") == "granted"
            or _value(sheet, "perm:ACCESS_ADSERVICES_AD_ID") == "granted")


def has_fgs_location(sheet):
    if _value(sheet, "perm:FOREGROUND_SERVICE_LOCATION") == "granted":
        return True
    return any(subject.startswith("fgs:") and "location" in (record.get("value") or "")
               for subject, record in sheet["facts"].items())


def has_boot(sheet):
    return (_value(sheet, "perm:RECEIVE_BOOT_COMPLETED") == "granted"
            or "receiver:boot-completed" in sheet["facts"])


def has_ble_wifi_scan(sheet):
    return (_value(sheet, "perm:BLUETOOTH_SCAN") == "granted"
            or _value(sheet, "perm:NEARBY_WIFI_DEVICES") == "granted")


def app_sdks(sheet, compact=False):
    labels = []
    for subject, record in sorted(sheet["facts"].items()):
        if subject.startswith("sdk:") and record.get("value"):
            val = record["value"]
            labels.append(val.split(" (", 1)[0] if compact else val)
    return labels


def can_carry_on(sheet):
    """An app that can track continuously across reboots: background location + location FGS + boot."""
    background = _value(sheet, "perm:ACCESS_BACKGROUND_LOCATION") == "granted"
    return background and has_fgs_location(sheet) and has_boot(sheet)


def one_app(sheet):
    """Consolidated profile of one app across all evidence tiers."""
    facts = sheet["facts"]
    background = _value(sheet, "perm:ACCESS_BACKGROUND_LOCATION")
    fine = _value(sheet, "perm:ACCESS_FINE_LOCATION")
    coarse = _value(sheet, "perm:ACCESS_COARSE_LOCATION")
    if background == "granted":
        reads = "while closed"
    elif "granted" in (fine, coarse):
        reads = "only while open"
    elif "denied" in (fine, coarse, background):
        reads = "refused"
    else:
        reads = "never asked"
    used = facts.get("access:location") or {}
    used_bg = bool(used.get("background"))
    rejected = facts.get("reject:location") or {}
    rejected_bg = bool(rejected.get("background"))
    delivered = (facts.get("delivered:location") or {}).get("value") or 0
    says_collects = _value(sheet, "datasafety:collected:location")
    says_shares = _value(sheet, "datasafety:shared:location")
    undisclosed = (
        reads in ("while closed", "only while open")
        and bool(used.get("value") or delivered)
        and says_collects == "no"
    )
    sdks = app_sdks(sheet)
    inspected = "code:ad-id-join" in facts or "code:location-classes" in facts
    return {
        "pkg": sheet["pkg"],
        "reads": reads,
        "reads_in_words": READS_WORDS[reads],
        "used": used.get("value"),
        "last_used": (used.get("last") or "")[:19],
        "used_in_background": used_bg,
        "rejected": rejected.get("value"),
        "last_rejected": (rejected.get("last") or "")[:19],
        "rejected_in_background": rejected_bg,
        "delivered": delivered,
        "background_anomaly": (used_bg or rejected_bg) and reads != "while closed",
        "undisclosed_location": undisclosed,
        "ad_id": has_ad_id(sheet),
        "fgs_location": has_fgs_location(sheet),
        "boot": has_boot(sheet),
        "ble_wifi_scan": has_ble_wifi_scan(sheet),
        "sdks": sdks,
        "installed_by": store_words(_value(sheet, "install:from")),
        "installed_by_key": _value(sheet, "install:from"),
        "build_arrived": (_value(sheet, "install:got_build") or "")[:10],
        "signed_by": _value(sheet, "sig:signed-by"),
        "play_stamp": bool(_value(sheet, "sig:source-stamp")),
        "says_collects": _value(sheet, "datasafety:collected:location"),
        "says_shares": _value(sheet, "datasafety:shared:location"),
        "for_purposes": _value(sheet, "datasafety:purposes:location"),
        "code_inspected": inspected,
        "code_engine": _value(sheet, "code:primary-engine"),
        "code_confidence": _value(sheet, "code:decompilation-confidence"),
        "code_binary_structure": _value(sheet, "code:binary-structure"),
        "code_location_apis": _value(sheet, "code:location-apis"),
        "code_location_classes": _value(sheet, "code:location-classes"),
        "code_ad_id_classes": _value(sheet, "code:ad-id-classes"),
        "code_packages": _value(sheet, "code:packages"),
        "code_endpoints": _value(sheet, "code:endpoints"),
        "code_ad_id_join": bool(_value(sheet, "code:ad-id-join")),
        "page_unknown": (facts.get("unknown:datasafety") or {}).get("reason"),
        "unknowns": {subject.split(":", 1)[1]: (record.get("reason") or "no reason recorded")
                     for subject, record in facts.items()
                     if subject.startswith("unknown:") and subject != "unknown:datasafety"},
    }


def build(rid=None):
    """Build the complete audit digest dictionary."""
    rid = store.resolve(rid)
    run = store.load_run(rid)
    sheets = store.apps(rid)
    apps = [one_app(sheet) for sheet in sheets]
    after_reboot = sorted(app["pkg"] for app, sheet in zip(apps, sheets) if can_carry_on(sheet))
    by_reads = {name: sorted((app for app in apps if app["reads"] == name),
                             key=lambda app: app["pkg"]) for name in READS}
    anomalies = sorted((app for app in apps if app["background_anomaly"]),
                       key=lambda app: app["pkg"])
    undisclosed = sorted(
        (app for app in apps if app.get("undisclosed_location")),
        key=lambda app: app["pkg"],
    )
    loc_with_ad_id = sorted(
        (app for app in apps
         if app["reads"] in ("while closed", "only while open") and app["ad_id"]),
        key=lambda app: app["pkg"],
    )
    loc_with_sdks = sorted(
        (app for app in apps
         if app["reads"] in ("while closed", "only while open") and app["sdks"]),
        key=lambda app: app["pkg"],
    )
    inspected = sorted((app for app in apps if app["code_inspected"]),
                       key=lambda app: app["pkg"])
    declaring = [app for app in apps if app["says_collects"] == "yes"]
    sharing = sorted((app for app in apps if app["says_shares"] == "yes"),
                     key=lambda app: app["pkg"])
    claiming_only = [app for app in declaring if app["reads"] in ("refused", "never asked")]
    page_gaps = {}
    for app in apps:
        if app["page_unknown"]:
            page_gaps.setdefault(app["page_unknown"], []).append(app["pkg"])
    other_gaps = {}
    for app in apps:
        for subject, reason in app["unknowns"].items():
            other_gaps.setdefault(subject, []).append(app["pkg"])

    device = run.get("device") or {}
    return {
        "run": rid,
        "tool": run.get("tool"),
        "device": {"brand": str(device.get("brand", "")).title(),
                   "model": device.get("model", ""),
                   "android": device.get("android", ""),
                   "build": device.get("build_id", "")},
        "counts": {
            "apps": len(apps),
            "while_closed": len(by_reads["while closed"]),
            "only_while_open": len(by_reads["only while open"]),
            "refused": len(by_reads["refused"]),
            "never_asked": len(by_reads["never asked"]),
            "background_anomalies": len(anomalies),
            "undisclosed_location": len(undisclosed),
            "location_with_ad_id": len(loc_with_ad_id),
            "location_with_sdks": len(loc_with_sdks),
            "code_inspected": len(inspected),
            "says_collects": len(declaring),
            "says_shares": len(sharing),
            "claims_without_permission": len(claiming_only),
            "after_reboot": len(after_reboot),
            "pages_without_answer": sum(len(v) for v in page_gaps.values()),
        },
        "apps": apps,
        "by_reads": by_reads,
        "background_anomalies": anomalies,
        "undisclosed_location": undisclosed,
        "location_with_ad_id": loc_with_ad_id,
        "location_with_sdks": loc_with_sdks,
        "code_inspected": inspected,
        "says_collects": sorted(declaring, key=lambda app: app["pkg"]),
        "says_shares": sharing,
        "after_reboot": after_reboot,
        "claims_without_permission": sorted(claiming_only, key=lambda app: app["pkg"]),
        "gaps": {"pages": page_gaps, "other": other_gaps},
        "how": HOW,
    }


def markdown(doc):
    """Render the audit digest as a structured Markdown report."""
    counts = doc["counts"]
    device = doc["device"]
    phone = f"{device['brand']} {device['model']}, Android {device['android']}".strip()
    out = [
        f"# Location Privacy Audit: {phone}",
        "",
        f"{counts['apps']} apps read from the phone, run `{doc['run']}`.",
        "",
        "## Executive Summary",
        "",
        f"- **Background location (`ACCESS_BACKGROUND_LOCATION`)**: {counts['while_closed']} apps",
        f"- **Foreground-only location**: {counts['only_while_open']} apps",
        f"- **Background access anomalies** (logged or attempted in background with only foreground permission): {counts['background_anomalies']} apps",
        f"- **Undisclosed location collection** (reads location on device, declares none on Google Play): {counts.get('undisclosed_location', 0)} apps",
        f"- **Survives reboot with background location service**: {counts['after_reboot']} apps",
        f"- **Can join location with Google Advertising ID (`AD_ID`)**: {counts['location_with_ad_id']} apps",
        f"- **Location-capable apps with embedded tracker/analytics SDKs**: {counts['location_with_sdks']} apps",
        f"- **Deep-dive code inspected (`jadx`)**: {counts['code_inspected']} apps",
        "",
    ]

    closed = doc["by_reads"]["while closed"]
    out += ["## 1. Apps that can read your location while closed (Background Location)", "",
            f"{len(closed)} apps.", ""]
    if closed:
        out += ["| App | Uses | Last Use | BG Logged | Ad-ID | Reboot+FGS | Detected SDKs |",
                "|---|---:|---|---|---|---|---|"]
        for app in closed:
            out.append(
                f"| `{app['pkg']}` | {app['used'] or 0} | {app['last_used'] or '-'} | "
                f"{'yes' if app['used_in_background'] else 'no'} | "
                f"{'yes' if app['ad_id'] else 'no'} | "
                f"{'yes' if app['pkg'] in doc['after_reboot'] else 'no'} | "
                f"{', '.join(app['sdks']) or '-'} |"
            )
        out.append("")

    if doc["background_anomalies"]:
        out += [
            "## 2. Background Access Anomalies",
            "",
            "These apps hold only foreground permission (`while open`), yet Android AppOps recorded "
            "background location accesses or blocked background attempts:",
            "",
            "| App | Permission | Uses | Blocked BG | Last Event | Ad-ID | Detected SDKs |",
            "|---|---|---:|---:|---|---|---|",
        ]
        for app in doc["background_anomalies"]:
            last_ev = app['last_used'] or app.get('last_rejected') or '-'
            out.append(
                f"| `{app['pkg']}` | {app['reads']} | {app['used'] or 0} | "
                f"{app.get('rejected') or 0} | {last_ev} | {'yes' if app['ad_id'] else 'no'} | "
                f"{', '.join(app['sdks']) or '-'} |"
            )
        out.append("")

    if doc.get("undisclosed_location"):
        out += [
            "## 3. Discrepancies: Undisclosed Location Collection",
            "",
            f"{counts.get('undisclosed_location', len(doc['undisclosed_location']))} apps hold granted location permissions and actively accessed "
            "location on this device, yet state on their Google Play Data Safety page that they do **not** "
            "collect location data (`collected: no`):",
            "",
            "| App | Permission | Uses | Delivered Fixes | Ad-ID | Detected SDKs |",
            "|---|---|---:|---:|---|---|",
        ]
        for app in doc["undisclosed_location"]:
            out.append(
                f"| `{app['pkg']}` | {app['reads']} | {app['used'] or 0} | "
                f"{app.get('delivered') or 0} | {'yes' if app['ad_id'] else 'no'} | "
                f"{', '.join(app['sdks']) or '-'} |"
            )
        out.append("")

    if doc["code_inspected"]:
        out += [
            "## 4. Deep-Dive Bytecode Inspection (`jadx`)",
            "",
            f"{len(doc['code_inspected'])} apps decompiled and scanned.",
            "",
        ]
        for app in doc["code_inspected"]:
            engine_str = f" (Engine: {app['code_engine'] or 'Dalvik'}, Decompilation: {app['code_confidence'] or 'full'})" if app.get('code_engine') else ""
            out += [
                f"### `{app['pkg']}`",
                f"- **Permission**: {app['reads']} (Recorded uses: {app['used'] or 0}, "
                f"Background logged: {'yes' if app['used_in_background'] else 'no'})",
            ]
            if app.get("code_binary_structure"):
                out.append(f"- **Binary Structure**: {app['code_binary_structure']}{engine_str}")
            out += [
                f"- **Location APIs in code**: {app['code_location_apis'] or 'none found'}",
                f"- **Location caller classes**: `{app['code_location_classes'] or 'none'}`",
                f"- **Advertising ID caller classes**: `{app['code_ad_id_classes'] or 'none'}`",
                f"- **Can join Location + Ad-ID in code**: {'YES' if app['code_ad_id_join'] else 'no'}",
                f"- **Registered 3rd-party components**: {', '.join(app['sdks']) or 'none'}",
                f"- **Compiled 3rd-party packages**: {app['code_packages'] or 'none'}",
                f"- **Endpoints in location/tracker classes**: {app['code_endpoints'] or 'none found'}",
                "",
            ]

    open_apps = doc["by_reads"]["only while open"]
    out += ["## 5. Apps with Foreground-Only Location Permission", "",
            f"{len(open_apps)} apps.", ""]
    if open_apps:
        out += ["| App | Uses | Last Use | Ad-ID | Shares (Play) | Detected SDKs |",
                "|---|---:|---|---|---|---|"]
        for app in open_apps:
            out.append(
                f"| `{app['pkg']}` | {app['used'] or 0} | {app['last_used'] or '-'} | "
                f"{'yes' if app['ad_id'] else 'no'} | {app['says_shares'] or '-'} | "
                f"{', '.join(app['sdks']) or '-'} |"
            )
        out.append("")

    if doc["says_shares"]:
        out += [
            "## 6. Apps Declaring Location Sharing on Google Play",
            "",
            f"{counts['says_shares']} apps state on their Google Play Data Safety page that they share "
            "location with third parties.",
            "",
            "| App | Permission on Phone | Declared Purposes |",
            "|---|---|---|",
        ]
        for app in doc["says_shares"]:
            out.append(f"| `{app['pkg']}` | {app['reads']} | {app['for_purposes'] or '-'} |")
        out.append("")

    if doc["claims_without_permission"]:
        out += [
            "## 7. Apps Declaring Location Collection Without Device Permission",
            "",
            f"{counts['claims_without_permission']} apps declare collecting location on Play, but do not "
            "hold location permission on this phone (may infer coarse location from IP address):",
            "",
        ]
        out += [f"- `{app['pkg']}` ({app['reads_in_words']})"
                for app in doc["claims_without_permission"]]
        out.append("")

    out += ["## Evidence Tiers", ""]
    out += [f"- **{tier}**: {words}" for tier, words in doc["how"].items()]
    return "\n".join(out) + "\n"


def write(rid=None):
    """Write digest.json and FINDINGS.md."""
    doc = build(rid)
    folder = paths.reports()
    os.makedirs(folder, exist_ok=True)
    digest_path = os.path.join(folder, "digest.json")
    md_path = os.path.join(folder, "FINDINGS.md")
    with open(digest_path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1, sort_keys=False)
        f.write("\n")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(markdown(doc))
    return {"run": doc["run"], "digest": digest_path, "markdown": md_path, "doc": doc}
