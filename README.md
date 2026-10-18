# android-loc-audit

A location privacy audit tool for unrooted Android devices. It inspects location permissions, runtime usage logs, Play Store disclosures, decompiled bytecode, and network captures to analyze how installed applications handle location data.

> **Agent-Driven**: This project is designed to be operated by an LLM agent paired with a user. See [**`AGENTS.md`**](AGENTS.md) for instructions, playbooks, and decision rules.

---

## Capabilities & Use Cases

- **Permission & Runtime Usage Inspection**: Read permission grants and AppOps access logs over ADB to check background location grants, recent usage timestamps, reboot persistence, and Advertising ID access.
- **Play Store Disclosure Verification**: Compare developer Data Safety declarations against actual location access and embedded components.
- **Bytecode Inspection**: Decompile APKs with `jadx` to locate code calling location APIs (GPS, BLE, Wi-Fi), Advertising ID callers, and third-party libraries.
- **Network Traffic Analysis**: Parse packet captures (`.pcap`) to extract TLS SNIs, resolved DNS CNAME chains, local discovery probes (such as CoAP), and destination endpoints.

---

## Commands

All commands run via `uv`:

```bash
uv run locaudit status                 # Device metadata, progress, and priority targets
uv run locaudit capture                # Snapshot phone state via ADB into data/
uv run locaudit location               # Location permission and usage matrix
uv run locaudit apps                   # List installed 3rd-party apps and signer origins
uv run locaudit show <package>         # Recorded facts and evidence for one app
uv run locaudit page <package> ...     # Fetch Google Play Data Safety disclosures
uv run locaudit pull <package> ...     # Pull APKs and verify signatures (requires user consent)
uv run locaudit inspect <package> ...  # Decompile via jadx and scan bytecode for callers/SDKs
uv run locaudit pcap <file.pcap>       # Parse .pcap for TLS SNIs, CNAME chains, CoAP & endpoints
uv run locaudit report                 # Generate digest.json and FINDINGS.md report
```

---

## Requirements

- Python 3.11+ via [`uv`](https://docs.astral.sh/uv/)
- `adb` (USB debugging enabled)
- `apksigner`, `aapt2` (Android SDK build-tools), and `jadx` (for code inspection)
