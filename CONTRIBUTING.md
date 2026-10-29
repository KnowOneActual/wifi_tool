# Contributing to Wi-Fi Site Survey Toolkit

Contributions from field technicians and network engineers are welcome—especially bug reports from real job sites, new MAC OUI vendor prefixes, and parser fixes for different Windows adapter drivers.

---

## Core Design Constraints

1. **Zero External Python Dependencies:** All Python scripts must run using only the Python 3.8+ standard library. Do not add third-party packages that require `pip install` on field laptops.
2. **Windows 10/11 Native Tooling:** Rely on built-in Windows interfaces (`wlanapi.dll`, `netsh`, `ipconfig`, `arp`, `ping`) and keep TShark strictly optional so the survey workflow still succeeds when Wireshark is not installed.
3. **Preserve Neighbor RF Data:** Waypoint scans must log all visible BSSIDs to `survey_waypoints.csv` so co-channel and adjacent-channel interference can be analyzed during report generation.

---

## Common Contributions

### 1. Adding Hardware Vendor MAC Prefixes (OUIs)

If a router, mesh node, or IoT device shows up as `Standard OUI` in reports:
1. Open `network_diagnostics.py` and locate the `OUI_VENDORS` dictionary.
2. Add the lowercase 3-octet prefix (`"xx:xx:xx": "Vendor / Model"`).
3. Run the unit tests or open a [Feature Request](https://github.com/KnowOneActual/wifi_tool/issues/new?template=feature_request.yml) with the BSSID prefix and hardware model.

### 2. Reporting Field Parser Bugs

Different Wi-Fi drivers or Windows builds can format `netsh wlan` or `ipconfig` output slightly differently. When submitting a [Bug Report](https://github.com/KnowOneActual/wifi_tool/issues/new?template=bug_report.yml), include:
- Windows version (`winver`) and Wi-Fi adapter model (from `wlan_drivers.txt`).
- Redacted/anonymized snippet of `wlan_interfaces.txt`, `lan_ipconfig.txt`, or `baseline_rf_scan.txt` that triggered the issue.

---

## Pull Request Checklist

1. Create a branch from `main`:
   ```powershell
   git checkout -b fix/short-description
   ```
2. Add or update unit tests in `tests/test_toolkit.py` for any parser or report logic changes.
3. Run the test suite locally and verify all tests pass:
   ```powershell
   python -m unittest discover -s tests -v
   ```
4. Update `CHANGELOG.md` under an `[Unreleased]` or versioned section if introducing user-facing changes.
5. Keep `.bat` files formatted with Windows `CRLF` line endings.
