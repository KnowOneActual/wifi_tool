# Changelog

All notable changes to the **Wi-Fi Site Survey Toolkit** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [2.1.0-beta] - 2026-11-24

### Added
- **Local Browser Field Console (`survey_web_ui.py`, `LAUNCH_WEB_UI.bat`):** Zero-dependency Python `http.server` web app (`http://127.0.0.1:8765`) featuring a live RF signal meter, one-click Floor / Phase (`Pre-Fix`/`Post-Fix`) / Room presets, resumable jobs, inline job metadata editing, and inline waypoint **Rename / Re-Scan / Delete** correction.
- **Floorplan Pin-Drop RF Heatmaps (`survey_web_ui.py`, `generate_job_summary.py`):** Upload PNG/JPG/WebP floorplans per floor, click to pin existing waypoints or click-to-capture new rooms, view live HTML5 Canvas IDW 5/6 GHz and 2.4 GHz heatmaps, and embed base64 floorplans + heatmaps directly into self-contained `PM_SITE_SURVEY_REPORT.html` reports.
- **Continuous Roaming Walk-Test Mode (`roaming_walk_test.py`, `survey_web_ui.py`, `generate_job_summary.py`):** Polls active Wi-Fi link telemetry and gateway pings every `0.5s` while walking between APs, charting live RSSI/ping/roams, grading every BSSID handoff (`Seamless`, `Minor Glitch`, `Drop Detected`), saving `roaming_walk_test.csv` & `roaming_walk_summary.json`, and embedding an inline SVG timeline + handoff table into reports.
- **Before vs. After Job Comparison (`compare_jobs.py`):** Compares any two survey job folders with fuzzy room-name matching and outputs `COMPARISON_REPORT.html` and `COMPARISON_REPORT.txt` showing per-room dBm deltas, speedtest/bufferbloat deltas, congestion changes, and AP channel plan updates.
- **Native Windows `WlanGetNetworkBssList` Scanner & 802.11 IE Parser (`survey_scanner.py`):** Queries `wlanapi.dll` directly (with automatic `netsh` fallback) to extract true uncapped `lRssi` (dBm), exact center frequency (MHz), channel width (`20 / 40 / 80 / 160 / 320 MHz`), `802.11k/v/r` fast roaming flags, `802.11w` PMF status, minimum basic rate (Mbps), BSS Load, and Cisco/Aruba beacon-broadcast AP names.
- **Automated RF Design, Interference & Roaming Audits (`generate_job_summary.py`):**
  - Primary + Secondary 5/6 GHz AP coverage per waypoint and automatic **Sticky Client** detection.
  - Exact and bonded-width **Co-Channel Interference (CCI)** detection (e.g., `Ch 36 @ 80 MHz` overlapping `Ch 44 @ 80 MHz`), **2.4 GHz 40 MHz** warnings, **2.4 GHz non-1/6/11 ACI** alerts, **5 GHz DFS** channel notices, **802.11k/v** roaming capability checks, and **legacy 1/2 Mbps basic rate** warnings.
  - Controller `AP List.csv` auto-ingestion for mapping AP MACs to real AP names, models, IPs, PoE modes, uptime, and firmware.
  - Survey adapter capability banner parsed from `wlan_drivers.txt` (flagging Wi-Fi 5 / no-6-GHz / no-WPA3 NIC blind spots) and connected-vs-target SSID context notices.
  - Windows `wlan_roaming_events.txt` parser (UTF-8 & UTF-16LE safe) summarizing connects, disconnects, auth/assoc failures, security re-keys, and handoff latency.
- **LAN Discovery Enhancements (`network_diagnostics.py`):** Subnet-mask-aware ARP sweeping and filtering via `ipaddress.IPv4Interface`, parallel reverse-DNS hostname resolution, expanded OUI vendor prefixes (`Pakedge`, `Yealink`, `Apple`, `Google Nest`, `Netgear`, `eero`, `Comcast/Xfinity`, `Sonos`, `Ubiquiti`), and optional offline Wireshark `manuf` file lookup.

### Fixed
- **Duplicate Waypoint Overwrites (`survey_scanner.py`, `generate_job_summary.py`):** Added monotonic `waypoint_id` tracking and timestamp-batch grouping so re-tested rooms stay distinct instead of merging or overwriting telemetry.
- **Peak Congestion Tracking & Multi-SSID Deduplication (`generate_job_summary.py`):** Collapsed virtual SSIDs sharing the same physical radio and tracked peak (`max`) channel utilization + peak location instead of the first reading.
- **Baseline-Only Report Fallback (`START_SITE_SURVEY.bat`, `generate_job_summary.py`):** Saved `baseline_rf_scan.json` alongside `baseline_rf_scan.txt` and added fallback parsing so baseline-only jobs still populate AP Inventory and RF Health sections.
- **TShark Path Discovery in Batch Script (`START_SITE_SURVEY.bat`):** Replaced hardcoded `C:\Program Files\Wireshark\tshark.exe` check with `capture_packets.resolve_tshark_path()`.
- **Repository Sanitization:** Removed client-specific checklist script from git tracking, added `*.xlsx` to `.gitignore`, and replaced all example/test client names, SSIDs, and device MACs with synthetic placeholders.

---

## [2.0.3-beta] - 2026-11-23

### Fixed
- **Windows Store `python.exe` Stub Detection (`START_SITE_SURVEY.bat`, `1_Quick_Scan.bat`, `2_Log_Waypoint.bat`, `3_Capture_Packets.bat`, `4_Speed_And_Ping_Test.bat`):** Replaced the `where python` pre-flight check (which falsely passed when Microsoft's 0-byte `WindowsApps\python.exe` App Execution Alias appeared earlier in `PATH` than a real Python / `uv` / venv installation) with an executable validation loop that skips broken stubs, falls back to `py -3`, and prepends the verified Python directory to the script's local `PATH`.

---

## [2.0.2-beta] - 2026-11-05

### Added
- **Windows 802.11 Roaming & Handoff Log Collection (`START_SITE_SURVEY.bat`):** Automatically exports the Windows `Microsoft-Windows-WLAN-AutoConfig/Operational` roaming event log (`wlan_roaming_events.txt` via `wevtutil qe`, no elevation required) and `wlan_roaming_report.html` (`netsh wlan show wlanreport`) at the end of every room-by-room waypoint survey.
- **AV & Custom Integrator OUI Database Expansion (`network_diagnostics.py`):** Added MAC OUI signatures for **Access Networks / Ruckus AP** (`78:9f:6a`, `40:b8:2d`), **Araknis Networks** (`14:3f:c3`), **Control4** (`00:0f:ff`), **Denon / Marantz (HEOS)** (`8c:a9:6f`), and additional **Sonos** ZonePlayer prefixes (`74:ca:60`, `38:42:0b`, `80:4a:f2`).

### Fixed
- **Access Networks / Ruckus Physical AP Consolidation (`generate_job_summary.py`):** Normalized Ruckus/Access Networks 4th-octet band offsets (`+0x40` for 2.4 GHz, `+0x80` for 5 GHz) back to the base wired Ethernet MAC so dual-band APs are grouped as a single physical Access Point (`AP 1`..`AP N`) instead of splitting 2.4 GHz and 5 GHz radios into separate AP entries.
- **Sonos OUI Classification (`network_diagnostics.py`):** Fixed `74:ca:60` being misclassified as `"Router / Mesh AP"` instead of `"Sonos"`.

---

## [2.0.1-beta] - 2026-10-28

### Added
- **HTML Report Sections (`generate_job_summary.py`):** Added **RF Congestion & Interference Alerts ($\ge 35\%$ Channel Utilization)** and **Discovered LAN Devices** tables to `PM_SITE_SURVEY_REPORT.html` to match the text engineering hand-off summary.
- **Dead-Zone Waypoint Logging (`survey_scanner.py`):** Rooms with zero detected networks or zero target-SSID signal now log a dead-zone placeholder record alongside active link and split-hop ping telemetry instead of returning early and omitting the room from the report.
- **TShark Path Discovery (`capture_packets.py`):** Added `resolve_tshark_path()` to automatically locate `tshark.exe` via system `PATH` and `C:\Program Files (x86)\Wireshark\tshark.exe` in addition to `C:\Program Files\Wireshark\tshark.exe`.
- **Expanded Unit Tests (`tests/test_toolkit.py`):** Added unit test coverage for multi-adapter `ipconfig` parsing, sub-millisecond ping parsing (`time<1ms`), multi-interface ARP table filtering, multi-radio AP inventories, and backup-SSID isolation.

### Changed / Performance
- **Faster Layer-2 LAN Discovery (`network_diagnostics.py`):** Added a non-blocking UDP datagram sweep across `.1–.254` to trigger immediate OS kernel ARP requests in $< 50\text{ ms}$, paired with a 32-worker ICMP ping sweep (`180ms` timeout) to wake sleeping Wi-Fi clients with lower CPU/process overhead.
- **Resilient Speedtest Upload & Threading (`network_diagnostics.py`):**
  - Reduced upload chunk size from `1 MB` to `256 KB` so slower residential/field uplinks ($< 2\text{ Mbps}$) do not hit the 5-second socket timeout and report `0.0 Mbps`.
  - Replaced shared `nonlocal` byte counters with thread-safe worker return values and guarded background loaded-ping futures against `TimeoutError`.
- **Faster Timestamp & Safe Job Folder Sanitization (`START_SITE_SURVEY.bat`):** Replaced PowerShell timestamp invocation with Python and sanitized illegal Windows path characters from `JOB_NAME`.

### Fixed
- **64-Bit `ctypes` Safety & Handle Cleanup (`survey_scanner.py`):** Defined explicit 64-bit `argtypes` and `restype` signatures for `wlanapi.dll` functions (`WlanOpenHandle`, `WlanEnumInterfaces`, `WlanScan`, `WlanFreeMemory`, `WlanCloseHandle`) and ensured native handles/buffers are always freed in a `finally` block.
- **Active Wi-Fi Adapter Isolation in `ipconfig` (`network_diagnostics.py`):** Fixed a parser bug where VPN, Ethernet, or virtual `Local Area Connection*` Wi-Fi Direct adapters could overwrite the active `Wi-Fi` interface's IPv4 address or gateway, and added support for multi-line IPv6 + IPv4 `Default Gateway` entries.
- **Sub-Millisecond Ping Parsing (`network_diagnostics.py`):** Fixed unreachable `time<1ms` branch in `ping_target()` so sub-millisecond local gateway pings accurately record `0.5 ms` instead of `1.0 ms`.
- **Multi-Interface ARP Filtering (`network_diagnostics.py`):** Filtered `arp -a` parsing to the active Wi-Fi interface's subnet, excluding APIPA (`169.254.x.x`), loopback, multicast, and broadcast entries.
- **Artifact Inventory & Multi-Radio AP Reporting (`generate_job_summary.py`):**
  - Fixed `ENGINEERING_HANDOFF_SUMMARY.txt` listing itself as `(0 bytes)` and omitting `PM_SITE_SURVEY_REPORT.html` on initial generation.
  - Preserved multiple BSSIDs/radios on the same band for a single physical AP instead of overwriting earlier entries.
  - Fixed target-SSID matching so rooms with a dead primary network do not fall back to substring matching and falsely report a backup/guest SSID (e.g., `"CorpWiFi backup"`) as primary coverage.
  - Escaped all dynamic telemetry and speedtest fields in `PM_SITE_SURVEY_REPORT.html` via `html.escape()`.
- **Batch Script Input Handling (`START_SITE_SURVEY.bat`):** Added `cd /d "%~dp0"` and passed user inputs to Python via environment variables so special characters in site notes or SSIDs cannot break command parsing.

---

## [2.0.0-beta] - 2026-10-21

### Added
- Beta testing notice, field laptop prerequisite documentation, and environment pre-flight checks in `START_SITE_SURVEY.bat` and `README.md`.
- GitHub Issue templates (`bug_report.yml`, `feature_request.yml`) for field technicians.
- Initial zero-dependency unit test suite (`tests/test_toolkit.py`).

---

## [1.0.0] - 2026-10-21

### Added
- Initial release of the Windows 11 Wi-Fi Site Survey & Network Diagnostics Toolkit:
  - Live hardware RF scanning across 2.4 GHz, 5 GHz, and 6 GHz (`wlanapi.dll` `WlanScan` + `netsh wlan`).
  - Room-by-room waypoint logging (`survey_scanner.py`).
  - Cloudflare HTTP/HTTPS speedtest, bufferbloat grading, split-hop Gateway vs. WAN ping, and `/24` LAN ARP/OUI discovery (`network_diagnostics.py`).
  - Auto-detected Wi-Fi packet capture wrapper for Wireshark/TShark (`capture_packets.py`).
  - Engineering hand-off text summary and print-ready Executive PM HTML report generator (`generate_job_summary.py`).
