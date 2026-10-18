# Agent Guidelines: Android Location Privacy Audit

This document is the complete operational manual and technical reference for the LLM agent conducting location privacy audits on Android devices.

---

## 1. Roles and Architecture

- **The User** drives high-level goals, decides which suspects to investigate further, and grants explicit consent before heavy operations (such as pulling APK binaries from the phone).
- **The Agent** steers the technical investigation autonomously using `uv run locaudit` commands, interprets evidence across tiers, and explains findings clearly.
- **The Tool (`locaudit`)** is a sharp CLI instrument run via `uv run locaudit` with 9 commands and zero flags. It communicates with the phone via `adb`, parses system dumps, queries Google Play disclosures, pulls and verifies APKs, decompiles bytecode with `jadx`, dissects network traffic captures, and caches all state in `data/`.

---

## 2. Supported Audit Use Cases & Capabilities

The project supports the following concrete privacy audit use cases:

1. **Audit Workspace Triage & Target Prioritization (`uv run locaudit status`)**:
   - Inspects cached state in `data/`, reports device metadata (model, OS version, build ID), permission breakdowns, and active signal counts.
   - Computes and lists high-priority investigation targets: all apps holding unrestricted background location (`while closed`) plus all foreground apps with recorded background AppOps access (`background anomalies`).
   - Tracks audit progress by reporting which priority targets have completed deep-dive inspection vs. which are still pending.

2. **Zero-Pull Device Capture (`uv run locaudit capture`)**:
   - Snapshots the phone's full permission, AppOps, and package manager state over `adb` into `data/device/` without downloading APK files or altering device state.
   - Automatically downloads and caches authoritative reference feeds (`iab_gvl.json`, `disconnect.json`, `ddg_entities.json`, `exodus_trackers.json`) into `data/refdata/`.
   - Initializes an audit run in `data/runs/<id>/` and populates baseline facts for all installed third-party apps.

3. **Location Privilege & Usage Matrix (`uv run locaudit location`)**:
   - Displays a risk-sorted table of all apps that requested location permissions (`while closed` first, then foreground apps with background AppOps access, then by total usage count).
   - Shows granted permission state, AppOps allowed access counts, last access timestamps, background access flag (`bg`), Advertising ID permission (`ad-id`), reboot persistence with a location service (`fgs+boot`), Google Play location sharing declaration (`shares`), and extracted 3rd-party component namespaces.

4. **Installed Package & Signature Inventory (`uv run locaudit apps`)**:
   - Lists all third-party apps installed on the phone with their location permission state.
   - Identifies the installer package (`com.android.vending` for Google Play, `com.sec.android.app.samsungapps` for Galaxy Store, or sideloaded).
   - Identifies the cryptographic signer organization (`O=`) or common name (`CN=`) from APK certificates.

5. **Single-App Evidentiary Dossier (`uv run locaudit show <package>`)**:
   - Outputs every recorded fact for a single package grouped by category (permissions, AppOps modes, live listeners, historical delivery counters, manifest components, signature verification, network traffic, and bytecode scan results) with its evidence tier (`T0`–`T4`) and provenance.

6. **Play Store Data Safety Verification (`uv run locaudit page <package> ...`)**:
   - Fetches official Google Play Data Safety web disclosures into `data/cache/<pkg>/`.
   - Records whether the developer claims to collect or share precise/approximate location and for what declared purposes (`App functionality`, `Analytics`, `Advertising or marketing`, `Personalization`).
   - Enables auditing whether developer disclosures match actual OS grants and third-party SDK components.

7. **Consensual APK Binary Retrieval & Signature Verification (`uv run locaudit pull <package> ...`)**:
   - Enforces user consent before copying heavy APK files over `adb`.
   - Caches pulled base and split APKs in `data/apks/<pkg>/` with file sizes and SHA-256 hashes.
   - Cryptographically verifies APK signatures via `apksigner` (v2/v3 scheme, certificate fingerprint, signer identity, and Play Store source stamp).

8. **Static Bytecode & Call-Graph Inspection (`uv run locaudit inspect <package> ...`)**:
   - Extracts binary manifest declarations via `aapt2` and decompiles APKs into Java sources via `jadx` (cached in `data/decompiled/<pkg>/sources/`).
   - Scans Java sources in parallel for exact location API caller classes (`FusedLocationProviderClient`, `LocationRequest`, `GeofencingClient`, BLE/Wi-Fi scans), Advertising ID callers (`AdvertisingIdClient`, `AdIdManager`, `"advertising_id"`, `"gaid"`), co-occurrence (`loc + ad-id`), compiled third-party package trees with class counts, and hardcoded HTTPS endpoints.

9. **Live Network Traffic & Telemetry Audit (`uv run locaudit pcap <file.pcap>`)**:
   - Dissects a specified PCAP capture file (`.pcap`) recorded via PCAPdroid without root or invasive cert unpinning.
   - Extracts plaintext TLS ClientHello SNIs across standard (443) and IoT ports (1883, 3083).
   - Unmasks cloud backend and WAF/GTM infrastructure through recursive DNS CNAME chaining.
   - Flags unencrypted local LAN discovery probes (CoAP on UDP 5683) and ICMP connectivity pings (e.g. Baidu).
   - If the file is under `data/cache/<package>/`, automatically records Tier 4 evidence facts into the target app's dossier.

10. **Authoritative Vendor & Geolocation Profiling (Agent-Led via `data/refdata/`)**:
    - The LLM agent queries local reference feeds in `data/refdata/` (`iab_gvl.json` for GDPR Special Feature 1 "Use precise geolocation data", `disconnect.json` for tracker categorization, `ddg_entities.json` for corporate parent ownership, and Exodus for legacy tracker signatures).
    - Resolves unlisted Java package prefixes via Maven Central and the Google Play SDK Index.

11. **Source-Level Data-Flow Verification (Agent-Led via `data/decompiled/`)**:
    - The LLM agent inspects the decompiled Java source code of caller classes identified by `uv run locaudit inspect` to verify whether coordinates flow strictly to first-party functional features or are bundled into analytics/ad payloads and sent to remote tracking servers.

12. **Comprehensive Report & Audit Trail Generation (`uv run locaudit report`)**:
    - Generates a machine-readable summary (`data/reports/digest.json`) and a structured Markdown audit report (`data/reports/FINDINGS.md`) covering background trackers, background anomalies, deep-dive code findings, foreground apps, and Play Store disclosure discrepancies.

---

## 3. Communicating with the User

1. **Lead with the finding, not the command log**: Start with what was discovered and why it matters for privacy before mentioning how it was obtained.
2. **Give concrete technical details in plain English**: Always include exact package names, Java class names, permissions, SDK names, and endpoint URLs—but explain what they do in plain, direct language.
3. **Explain Android concepts on first mention**:
   - *AppOps*: Android's internal audit log showing when an app actually accessed location and whether the app was in the foreground or background.
   - *Advertising ID (`AD_ID`)*: A resettable, device-wide identifier (`gaid`). When an app accesses both GPS location and the Advertising ID, data brokers can link physical movements to an advertising profile across different apps.
   - *Foreground Location Service (`FOREGROUND_SERVICE_LOCATION`)*: A mechanism allowing an app to keep tracking location after you leave the app by keeping a background service alive.
4. **Offer 2–3 clear next steps**: End each milestone by presenting clear, actionable options and what each option will uncover.
5. **Strict Consent Gate**: Never run `uv run locaudit pull` without first explaining why the target app is suspicious and receiving explicit user confirmation.

---

## 4. How the Signals Work Under the Hood

Understanding *how* Android stores and exposes these signals is essential for interpreting the tool's output accurately:

### A. How Tier 1 Detects Permissions, `AD_ID`, and Persistence Without Pulling APKs
When an app is installed on Android, the OS Package Manager parses its binary `AndroidManifest.xml` and records all requested permissions, install-time grants, and per-user runtime grants. Running `adb shell dumpsys package <pkg>` prints this internal state:
- **Runtime Location Grants**: `ACCESS_FINE_LOCATION` (precise GPS), `ACCESS_COARSE_LOCATION` (approximate cell/Wi-Fi), and `ACCESS_BACKGROUND_LOCATION` (tracking while the app is closed). Only `ACCESS_BACKGROUND_LOCATION: granted=true` under the user's `runtime permissions:` block grants unrestricted background access.
- **Proximity / Beacon Location Grants**: `BLUETOOTH_SCAN` and `NEARBY_WIFI_DEVICES`. Retail and indoor location SDKs use Bluetooth Low Energy (BLE) beacons and nearby Wi-Fi router MAC addresses (BSSIDs) to pinpoint physical store visits even without GPS.
- **Advertising ID Gate (`AD_ID`)**: Starting with Android 13 (API 33), Google Play Services enforces a hard OS permission check: an app cannot read the Google Advertising ID unless it holds `com.google.android.gms.permission.AD_ID` (which appears as an install-time grant in `dumpsys package`). If `ad-id` is `no`, the OS zeroes out the Advertising ID (`00000000-...`).
- **Continuous Tracking Across Reboots (`fgs+boot`)**: If an app holds both `FOREGROUND_SERVICE_LOCATION` and `RECEIVE_BOOT_COMPLETED`, it can start itself automatically when the phone turns on and run a persistent location service.

### B. How Tier 1 Surfaces Embedded 3rd-Party Components Without Pulling APKs
When Android installs an app, it registers every `<activity>`, `<service>`, `<receiver>`, and `<provider>` declared in the app's manifest into the OS resolver tables (`Activity Resolver Table`, `Receiver Resolver Table`, `Service Resolver Table`, and `Registered ContentProviders`).

Almost all commercial analytics, attribution, and location SDKs register at least one component in the host app's manifest so they can auto-initialize on app launch (typically via a `ContentProvider` like `com.facebook.internal.FacebookInitProvider` or `com.appsflyer.referrer.InstallReferrerProvider`) or receive background location/push intents (like `com.mapbox.common.location.LocationUpdatesReceiver`, `org.matomo.sdk.extra.InstallReferrerReceiver`, or `com.braze.BrazeFlushPushDeliveryReceiver`).

**No Black-Box SDK List in Python:**
Instead of matching against a static, hardcoded list of tracker names (which goes stale when new SDKs appear or packages rename), `locaudit` acts as a **deterministic, transparent extractor**:
1. It parses the component registration tables in `dumpsys package <pkg>` (explicitly ignoring the `Packages:` metadata section and stripping `queriesPackages=[...]` so apps that merely query if Facebook or Maps is installed are never falsely flagged).
2. It filters out the app's own package namespace and standard Android/Java/Kotlin/UI framework plumbing (`androidx.*`, `kotlin.*`, `com.google.android.gms.common`, `com.google.firebase.provider`, `expo.modules`, etc.).
3. It outputs **every remaining raw 3rd-party component namespace and its short class names** (e.g., `com.mapbox.common.location (LocationUpdatesReceiver, LocationService)`, `org.matomo.sdk (InstallReferrerReceiver)`, `no.nordicsemi.android (PendingIntentReceiver)`).
- *Boundary*: Tier 1 sees any 3rd-party SDK that registers an Android manifest component (`Service`, `Receiver`, `Activity`, or `ContentProvider`). Quiet Java libraries that register zero manifest components are surfaced in Tier 2 (`uv run locaudit inspect`) under `3rd-party packages`.

### C. How Tier 1 Detects Actual Location Usage, Blocked Attempts, and Anomalies (`AppOps`)
Android's `AppOpsService` (`adb shell dumpsys appops`) logs recent runtime operations per UID and per package across location operations (`FINE_LOCATION`, `COARSE_LOCATION`, `MONITOR_LOCATION`, `MONITOR_HIGH_POWER_LOCATION`). Each entry logs either an `Access:` (allowed) or a `Reject:` (blocked) event with a process-state tag:
- `[top-s]` / `[fgsvc-s]`: The app queried location while visible on screen or running an active foreground service.
- `[bg-s]` / `[cch-s]`: The app queried location while in the **background** (`bg`) or cached (`cch`) state.

**What a "Background Anomaly" means:**
A background anomaly occurs when an app holds only foreground location permission (`only while open`), yet AppOps recorded background activity:
1. **Allowed background access (`bg access` / `Bg: yes`)**: The app received location updates or geofence monitoring (`MONITOR_LOCATION`) while backgrounded or cached.
2. **Blocked background attempt (`bg blocked` / `Bg: blck`)**: The app actively attempted to read GPS coordinates while closed, but Android's AppOps policy intercepted and blocked the call (`Reject: [bg-s]`).

**Undisclosed Location Discrepancies:**
When an app actively reads location or receives delivered fixes on the phone, but its Google Play Data Safety declaration asserts that it collects zero location data (`collected: no`), it is flagged under **Undisclosed location** (`undisclosed loc`) in `uv run locaudit status` and detailed in `uv run locaudit report`.

---

## 5. Step-by-Step Investigation Playbook

### Step 0: Check Existing State (Always Run First)
```bash
uv run locaudit status
```
Check what is already cached in `data/` before running any command. If a capture already exists in `data/`, resume from it rather than re-capturing unless the user requests a fresh phone read.

### Step 1: Fast Zero-Pull Device Audit (Tier 1 — Default)
```bash
uv run locaudit capture    # Only if no capture exists in data/ yet
uv run locaudit location   # Rank all location-capable apps and their signals
```
Optionally inspect a single app's complete fact sheet or fetch Google Play disclosures for top suspects:
```bash
uv run locaudit show <package>
uv run locaudit page <package> ...
```

### Step 2: Deep-Dive Bytecode Inspection (Tier 2 — Requires Explicit User Consent)
When Tier 1 flags suspicious apps, explain the evidence to the user and ask for consent to pull and inspect their code. Once the user consents:

```bash
uv run locaudit pull <package> ...
uv run locaudit inspect <package> ...
```

After `uv run locaudit inspect` prints the exact Java classes calling location APIs and reading the Advertising ID, open or `rg` those specific classes under `data/decompiled/<package>/sources/` to verify:
1. Whether the location call serves a legitimate user feature or third-party tracking.
2. Whether latitude/longitude coordinates are attached to the same payload or analytics event as the Advertising ID (`gaid`) or user ID.
3. Which remote domain receives the payload.

---

## 6. How the Agent Performs SDK & Data-Flow Matching

Because `locaudit` outputs raw component namespaces in Tier 1 and exact caller classes + compiled package trees in Tier 2, **you (the LLM Agent) are the classifier**. Use this two-stage matching methodology:

### Stage 1: Tier 1 Component Namespace Classification (`uv run locaudit location` & `uv run locaudit show`)
When reviewing the raw components for an app, classify each namespace `<prefix> (<ClassNames>)` into one of four buckets:

1. **First-Party / Parent Company Platform (Low Risk)**:
   - Shared corporate SDKs from the same company under a different domain prefix (e.g., `com.aaecosystem.luna` inside `com.assaabloy.yale` for Assa Abloy smart locks, or `com.schibsted.*` inside a Nordic marketplace app).
2. **Functional / Hardware / Map Engine SDKs (Low–Medium Risk)**:
   - Hardware/BLE libraries (`no.nordicsemi.android` for Bluetooth Low Energy peripherals), cross-platform bridges (`com.margelo.nitro`), or map rendering/location engines (`com.mapbox.common.location`, `com.huawei.hms.location`). Note: Mapbox telemetry may collect location unless disabled.
3. **Marketing, Attribution, Analytics & Ad Networks (Medium–High Risk)**:
   - **Attribution Trackers**: `com.appsflyer`, `com.adjust.sdk`, `com.kochava`, `io.branch`, `com.singular.sdk` (read `AD_ID` and install referrer; can attach location events to cross-app attribution profiles).
   - **Engagement / Push / Analytics**: `com.braze`, `com.salesforce.marketingcloud`, `com.onesignal`, `com.urbanairship`, `com.clevertap`, `com.moengage`, `org.matomo.sdk`, `com.amplitude`, `com.mixpanel`.
   - **Ad Networks**: `com.google.android.gms.ads`, `com.facebook.ads`, `com.applovin`, `com.unity3d.services`, `com.ironsource`, `com.vungle`, `com.inmobi`, `com.criteo`.
4. **Dedicated Location Brokers & Geofencing Monetizers (Critical Risk)**:
   - `com.inmarket`, `com.cuebiq`, `io.xmode`, `com.foursquare.pilgrim`, `io.huq`, `com.predicio`, `com.tamoco`, `io.radar.sdk`, `com.gimbal`, `io.bluedot`, `com.plotprojects`.

*If you encounter an unfamiliar package prefix*: Inspect the component class names in parentheses (e.g., `GeofenceTransitionsIntentService` vs. `PushReceiver`), and cross-reference the prefix against the **Authoritative External Intelligence Feeds** in Section 7.

### Stage 2: Tier 2 Caller & Data-Flow Matching (`uv run locaudit inspect`)
Presence of a 3rd-party SDK in an app does **not** automatically prove that the SDK receives GPS coordinates. After running `uv run locaudit inspect <pkg>`, compare `loc callers`, `ad-id callers`, `3rd-party packages`, and `endpoints` to determine which of the three data-flow patterns applies:

- **Pattern A — Direct 3rd-Party SDK Collection**:
  - A 3rd-party SDK class appears directly inside `loc callers` (e.g., `com.mapbox.common.location.*`, `io.radar.sdk.*`, `com.salesforce.marketingcloud.*`, `com.google.android.gms.ads.*`). The SDK itself requests GPS/BLE/Wi-Fi fixes from Android.
- **Pattern B — 1st-Party Collection Handed Off to 3rd-Party Tracker (or Joined with `AD_ID`)**:
  - Only the app's own classes appear in `loc callers`, while a tracker/analytics SDK appears in `ad-id callers` or `3rd-party packages`.
  - Open the `loc callers` Java files in `data/decompiled/<pkg>/sources/` and trace where the `Location` object or `getLatitude()` / `getLongitude()` values flow. Check whether coordinates are passed into an analytics event (`Braze`, `AppsFlyer`, `FirebaseAnalytics`, `Matomo`), attached to an ad request, or sent alongside `AdvertisingIdClient` (`gaid`) to a remote endpoint.
- **Pattern C — Pure 1st-Party Functional Use**:
  - Only the app's own classes (or functional map/BLE libraries) appear in `loc callers`, and source inspection confirms coordinates are used solely for the app's user-facing feature (e.g., local weather forecast, transit routing, or home lock geofence) and are never passed to ad/attribution SDKs.

---

## 7. Authoritative Reference Feeds (`data/refdata/`) & How the Agent Queries Them

The tool (`locaudit`) acts as a pure, deterministic extractor of phone facts and leaves the raw authoritative feeds in `data/refdata/`. **You (the LLM Agent) are the investigator and classifier.**

When `uv run locaudit capture` runs, `locaudit/refdata.py` ensures the following four raw JSON feeds are downloaded into `data/refdata/` (refreshed if older than 7 days):

1. **IAB Europe TCF Global Vendor List (GVL v3)** (`data/refdata/iab_gvl.json`)
   - **Source**: `https://vendor-list.consensu.org/v3/vendor-list.json`
   - **Authority**: Legally binding GDPR Transparency & Consent Framework (TCF v2.2) registry, updated weekly by IAB Europe.
   - **How the Agent Queries It**: When investigating an ad network or tracking vendor, check whether its entry in `vendors` declares **`specialFeatures: [1]` ("Use precise geolocation data")**. If `1` is present, the vendor legally acknowledges processing GPS/Wi-Fi fixes accurate to within meters for ad targeting or audience measurement. Also check declared `purposes` (`2, 3, 4, 7, 9`).
2. **Disconnect Tracking Protection** (`data/refdata/disconnect.json`)
   - **Source**: `https://raw.githubusercontent.com/disconnectme/disconnect-tracking-protection/master/services.json`
   - **Authority**: Tracker list powering Firefox Enhanced Tracking Protection, Edge, and Brave.
   - **How the Agent Queries It**: Cross-reference extracted hostnames from `code:endpoints` or company names to classify the receiving server into canonical categories (`Advertising`, `Analytics`, `FingerprintingInvasive`, `FingerprintingGeneral`, `Social`).
3. **DuckDuckGo Tracker Radar Entity Map** (`data/refdata/ddg_entities.json`)
   - **Source**: `https://raw.githubusercontent.com/duckduckgo/tracker-radar/main/build-data/generated/entity_map.json`
   - **Authority**: Continuously crawled domain-to-owner graph maintained by DuckDuckGo.
   - **How the Agent Queries It**: Map obscure tracking domains and acquired subsidiaries (`properties`) to their parent conglomerate (`displayName`, e.g. `adjust.com` $\rightarrow$ `AppLovin`).
4. **Exodus Privacy Trackers** (`data/refdata/exodus_trackers.json`)
   - **Source**: `https://reports.exodus-privacy.eu.org/api/trackers`
   - **Authority**: Community-maintained mapping of ~440 Android `code_signature` package prefixes and `network_signature` regexes.
   - **How the Agent Queries It**: Fast first-pass lookup for older/classic Android tracker prefixes (e.g. `com.batch.android` $\rightarrow$ Batch, `cn.jpush.android` $\rightarrow$ Aurora JPush). Note: Absence from Exodus does **not** mean an app is clean.

### Resolving Unlisted Package Prefixes
When an extracted component namespace or decompiled package prefix is not present in the local feeds above (e.g., `com.transistorsoft.locationmanager`, `no.nordicsemi.android`, `io.customer.messagingpush`):
- **Maven Central API**: `https://search.maven.org/solrsearch/select?q=g:<package_prefix>&rows=5&wt=json`
- **Google Play SDK Index**: `https://play.google.com/sdks`

---

## 8. Working Data Directory (`data/`): Producer $\rightarrow$ Consumer Contract

**`data/` is git-ignored working storage and starts completely empty on a fresh checkout.** Nothing exists in `data/` unless explicitly created by a Producer command below:

| Path in `data/` | Producer (Creates / Updates) | Consumer (Reads / Uses) | Contents |
|---|---|---|---|
| `data/device/device.json` | `uv run locaudit capture` (`capture.run`) | `uv run locaudit status`, `report` | Phone brand, model, Android version, build ID, capture timestamp |
| `data/device/third_party_pkgs.txt` | `uv run locaudit capture` (`capture.run`) | `grants.run`, `meta.run`, `pull` | Sorted list of installed third-party packages (`pm list packages -3`) |
| `data/device/dumpsys_location.txt` | `uv run locaudit capture` (`capture.run`) | `uv run locaudit capture` (`grants.run`) | Active location listeners & historical delivery counters |
| `data/device/dumpsys_appops.txt` | `uv run locaudit capture` (`capture.run`) | `uv run locaudit capture` (`grants.run`) | Per-UID and per-package runtime location access timestamps & `[bg-*]` flags |
| `data/device/dumpsys_package/<pkg>.txt` | `uv run locaudit capture` (`capture.run`) | `uv run locaudit capture` (`grants.run`, `meta.run`) | Full OS package dump: permissions, component resolver tables, installer info |
| `data/refdata/*.json` | `uv run locaudit capture` (`refdata.ensure`) | **LLM Agent** (queries vendor geolocation/tracker disclosures) | Raw reference feeds (`iab_gvl.json`, `disconnect.json`, `ddg_entities.json`, `exodus_trackers.json`) |
| `data/runs/LATEST` & `<run-id>/run.json` | `uv run locaudit capture` (`store.start_run`) | All `uv run locaudit` commands | Active run pointer, device metadata, and phase completion gates |
| `data/runs/<run-id>/apps/<pkg>.json` | `uv run locaudit capture`, `page`, `pull`, `inspect`, `pcap` | `status`, `location`, `apps`, `show`, `report` | Consolidated per-app fact sheet across tiers `T0`–`T4` |
| `data/cache/<pkg>/datasafety.{html,txt,json}` | `uv run locaudit page <pkg>` (`datasafety.run`) | `page`, `location`, `show`, `report` | Cached Google Play Data Safety page, parsed text, and verbatim quote |
| `data/apks/<pkg>/*.apk` & `artifacts.json` | `uv run locaudit pull <pkg>` (`pull.run`) | `pull` (`signing.run`), `inspect` (`manifests.run`, `jadx`) | Pulled base + split APK binaries and SHA-256 hashes |
| `data/decompiled/<pkg>/sources/` | `uv run locaudit inspect <pkg>` (`sdks.decompile`) | `inspect` (`sdks.scan_sources`) & **LLM Agent** (manual source trace) | Full Java source tree decompiled from `data/apks/<pkg>/*.apk` via `jadx` |
| `data/cache/<pkg>/inspect.json` | `uv run locaudit inspect <pkg>` (`sdks.inspect_app`) | `inspect`, `show`, `report` | Cached bytecode scan results (location callers, Ad-ID callers, packages, endpoints) |
| `data/cache/<pkg>/traffic.pcap` | PCAPdroid on phone / `uv run locaudit pcap` | `uv run locaudit pcap`, `show`, `report` | Network traffic capture, TLS SNIs, DNS CNAME chains, broadcasts |
| `data/reports/digest.json` & `FINDINGS.md` | `uv run locaudit report` (`findings.write`) | User & LLM Agent | Machine-readable run digest and structured Markdown audit report |
| `data/reports/audit_log.md` | **LLM Agent** (written during deep-dive trace) | User & LLM Agent (future sessions) | Narrative log of human-verified source code traces and user decisions |

---

## 9. Beyond Static Bytecode: Specialized Frameworks & Deep Reverse Engineering

When `uv run locaudit inspect` analyzes an APK, it checks the ZIP central directory and Dalvik bytecode to evaluate decompilation confidence:
- **`full` (Standard Dalvik)**: Java/Kotlin codebase decompiled directly by `jadx`. Location callers and Ad-ID callers in `inspect.json` reflect the full application logic.
- **`partial` (React Native, Flutter, Unity)**: Core business and network logic resides outside Dalvik (in JavaScript, Dart AOT, or native game assemblies).
- **`obstructed` (Minimal DEX stub / Packer)**: Dalvik contains only a tiny bootstrap stub (<50 KB); application code is loaded dynamically from native libraries or encrypted assets.

Whenever `uv run locaudit inspect` reports `partial` or `obstructed`, static Dalvik decompilation via `jadx` is insufficient to see the complete data flow. The agent should consult the following ad-hoc playbook to inspect the real application logic:

### 1. React Native Applications (`assets/index.android.bundle`)
React Native applications compile JavaScript into a single bundle asset packaged inside the APK. Dalvik contains only framework bridge classes (`com.facebook.react.*`).

- **Fast Extraction**:
  ```bash
  unzip -p data/apks/<pkg>/base.apk assets/index.android.bundle > bundle.js
  ```
- **Plaintext JavaScript Bundle**:
  If the bundle is plaintext JS (first 4 bytes are text, not Hermes magic), search it directly:
  ```bash
  rg -i "(geolocation|watchposition|getcurrentposition|locationmanager)" bundle.js
  rg -i "(advertisingid|gaid|adid)" bundle.js
  rg "https?://[a-zA-Z0-9.-]+" bundle.js | sort -u
  ```
- **Hermes Bytecode (`libhermes.so` / Magic `c6 1f bc 03`)**:
  Modern React Native apps compile JavaScript into Hermes bytecode.
  - Use `hermes-dec` or `hbctool` to disassemble Hermes bytecode into readable assembly instructions and extract string literals:
    ```bash
    hbctool disasm bundle.js disassembled_bundle/
    ```
  - Or extract strings directly from the binary bundle:
    ```bash
    strings bundle.js | grep -E "https?://"
    strings bundle.js | grep -iE "(latitude|longitude|coords|location|tracker)"
    ```

### 2. Flutter Applications (`lib/<arch>/libapp.so`)
Flutter apps do not compile to Dalvik or JavaScript. All UI and business logic is compiled ahead-of-time (AOT) into native ARM machine code: `libapp.so` (app logic) and `libflutter.so` (Flutter engine).

- **Fast Static Triage (Strings & Endpoints)**:
  Extract `libapp.so` from the APK and search for hardcoded strings:
  ```bash
  unzip -p data/apks/<pkg>/base.apk lib/arm64-v8a/libapp.so > libapp.so
  strings libapp.so | grep -E "https?://"
  strings libapp.so | grep -iE "(geolocator|location|gps|ad_id|gaid)"
  ```
- **Dedicated Dart Decompilation (`blutter`)**:
  Use `blutter` (Boring Flutter Decompiler) targeting the specific Flutter engine version:
  ```bash
  blutter lib/arm64-v8a/ out_dart/
  ```
  This reconstructs Dart class definitions, method names, and package dependencies.
- **Disassembly via Ghidra / IDA Pro**:
  Analyze `libapp.so` in Ghidra using Dart symbol recovery plugins to map function entry points.

### 3. Native Shared Libraries (`.so`) & JNI Bridges
Many location SDKs or hardened apps implement tracking and cryptography in C/C++ native libraries (`lib/<arch>/*.so`).

- **Locating JNI Bridge Methods**:
  Search decompiled Java sources (`data/decompiled/<pkg>/sources/`) for `native ` keyword declarations (e.g. `public native String getDeviceSignature();`) and `System.loadLibrary(...)`.
- **Finding Endpoints & Symbols**:
  ```bash
  nm -D lib/<arch>/libcustom.so | grep -i "location"
  strings lib/<arch>/libcustom.so | grep -E "https?://"
  ```
- **Native Decompilation**:
  Load the `.so` binary into **Ghidra** (or call the Ghidra MCP server) to decompile the exported JNI functions (convention: `Java_<package>_<class>_<method>`).

### 4. Minimal DEX Stubs & Hardened Loaders
When an app uses a commercial protector (e.g. Bangcle, Ijiami, Qihoo 360, SecNeo, DexGuard) or custom dynamic DEX loading, Dalvik code is a shell:

- **Tier 1 Ground Truth is Unbypassable**:
  Even when bytecode is encrypted or dynamically decrypted into RAM, **the Android OS cannot be deceived**:
  - The Package Manager (`dumpsys package`) reveals all requested and granted permissions, Advertising ID gates, and registered component namespaces.
  - Android AppOps (`dumpsys appops`) logs actual GPS/Wi-Fi/cell accesses, timestamps, background tags (`[bg-s]`, `[cch-s]`), and blocked attempts (`Reject: [bg-s]`).
  - Android LocationManager (`dumpsys location`) records active location listeners and delivered fix counters.
  **Always lead with Tier 1 facts**—they prove real-world behavior regardless of code obfuscation.
- **Dynamic Runtime Tracing (Frida)**:
  If exact runtime arguments and network payloads must be intercepted from a hardened app running on a test device, use Frida to hook Android location and advertising APIs:
  ```bash
  frida-trace -U -f <package> \
    -j "android.location.LocationManager*!get*" \
    -j "com.google.android.gms.location.*!request*" \
    -j "com.google.android.gms.ads.identifier.AdvertisingIdClient*!get*"
  ```

---

## 10. Tier 4: Live Network Capture & TLS SNI Analysis (PCAPdroid)

When an app asserts "No data collected" or "No data shared" on Google Play, or when bytecode analysis reveals analytics/location SDKs whose exact runtime endpoints need verification, **Tier 4 network traffic analysis provides empirical proof of runtime communication**.

Because modern apps enforce TLS certificate pinning, full MITM payload decryption often fails without modifying APK binaries. However, **TLS ClientHello Server Name Indication (SNI)** is transmitted in plaintext during the TLS handshake, exposing all remote hostnames contacted by the app.

### Generic Capture Workflow

1. **Prerequisite (PCAPdroid)**:
   - Install PCAPdroid (`com.emanuelef.remote_capture`) on the unrooted phone via Play Store, F-Droid, or ADB:
     ```bash
     adb install -r data/cache/pcapdroid/PCAPdroid_v2.0.2.apk
     ```
   - Uses local `VpnService` loopback; zero traffic is routed to external servers.

2. **Configure Capture on Phone**:
   - Open PCAPdroid.
   - **Target App / App Filter**: Select the target package (e.g. `<package>`) to isolate its traffic and eliminate OS/background noise.
   - **Dump Mode**: Select **PCAP File** (writes directly to storage without network port conflicts).
   - Tap **Start** (grant one-time Android VPN prompt).

3. **Exercise App & Stop Capture**:
   - Open the target app for 20–30 seconds, trigger features, and return to PCAPdroid to tap **Stop**.

4. **Pull PCAP to Host**:
   ```bash
   adb pull /sdcard/Download/PCAPdroid/*.pcap data/cache/<package>/traffic.pcap
   adb shell rm /sdcard/Download/PCAPdroid/*.pcap
   ```

5. **Analyze Capture & Record Tier 4 Facts (`uv run locaudit pcap <file.pcap>`)**:
   Pass the specific `.pcap` capture file path as the parameter:
   ```bash
   uv run locaudit pcap data/cache/<package>/traffic.pcap
   ```
   (If you have multiple captures—such as `traffic_active.pcap` or `traffic_background.pcap`—pass whichever file you wish to inspect.)

   The tool automatically:
   - Parses the given `.pcap` file.
   - Extracts plaintext **TLS ClientHello SNIs** across standard HTTPS (443) and IoT ports (1883, 3083).
   - Unmasks **DNS CNAME chains** to expose the true hosting infrastructure (e.g. Alibaba Cloud WAF & GTM nodes behind first-party subdomains).
   - Detects **unencrypted local LAN discovery** (CoAP broadcasts on UDP 5683 with JSON payloads like `core.service.dev` sent to `255.255.255.255`) and direct device probes to local IP subnets (`192.168.x.x`).
   - Identifies **ICMP connectivity checks** (e.g. Baidu ping targets `103.235.47.188`).
   - Detects modern transport protocols (`QUIC` / HTTP/3 on UDP 443).
   - Summarizes **top remote endpoints** by traffic volume (packets & bytes) correlated with their resolved hostnames.
   - If the file is stored under `data/cache/<package>/`, automatically records all Tier 4 evidence facts into that app's audit dossier (`data/runs/<id>/apps/<package>.json`).

6. **Authoritative Intelligence Matching**:
   Cross-reference extracted SNI hostnames and CNAME targets against local intelligence in `data/refdata/`:
   - `data/refdata/disconnect.json`: Identifies canonical `Analytics`, `Advertising`, and `Fingerprinting` endpoints.
   - `data/refdata/ddg_entities.json`: Maps CDNs, WAFs, and tracking domains to corporate parent owners (e.g. Alibaba Cloud, AWS, Google, Baidu).
   - `data/refdata/iab_gvl.json`: Flags vendors registered for GDPR Special Feature 1 ("Use precise geolocation data").

7. **Review Updated Evidentiary Dossier**:
   Review all combined facts across Tiers `T0`–`T4` in the app's updated dossier:
   ```bash
   uv run locaudit show <package>
   ```


