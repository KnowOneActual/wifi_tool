# Changelog

All notable changes to the **Wi-Fi Site Survey Toolkit** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
  - Fixed target-SSID matching so rooms with a dead primary network do not fall back to substring matching and falsely report a backup/guest SSID (e.g., `"HomeWifi1 backup"`) as primary coverage.
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
