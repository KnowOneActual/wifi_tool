# Wi-Fi Site Survey Toolkit (Windows 10/11)

> [!CAUTION]
> **Beta Software (`v2.0.1-beta`)** — Currently in field validation. Verify results before using as a sole production deliverable.
> - [Report a Bug](https://github.com/KnowOneActual/wifi_tool/issues/new?template=bug_report.yml)
> - [Request a Feature](https://github.com/KnowOneActual/wifi_tool/issues/new?template=feature_request.yml)
> - [Contributing Guide](CONTRIBUTING.md)
> - [Changelog](CHANGELOG.md)

A Windows command-line site survey and network diagnostics toolkit for field technicians. Captures 2.4 GHz, 5 GHz, and 6 GHz (802.11n/ac/ax/be) RF scans, active link telemetry, split-hop latency, Cloudflare throughput/bufferbloat, and local subnet ARP inventories using only the Python standard library.

---

## Requirements

1. **Windows 10 or 11** with a Wi-Fi adapter (Wi-Fi 6E/7 adapter required to scan 6 GHz channels).
2. **Windows Location Services enabled** (required by Windows for `wlanapi.dll` and `netsh wlan` to expose BSSIDs):
   - Open **Settings -> Privacy & security -> Location**
   - Enable **Location services** and **Let desktop apps access your location**
3. **Python 3.8+** (`python.exe` added to `PATH`):
   ```powershell
   winget install Python.Python.3.12
   ```
4. **Wireshark / TShark** *(optional, only used for Step 3 packet capture)*:
   ```powershell
   winget install WiresharkFoundation.Wireshark
   ```

---

## Usage

### Full Site Survey Workflow

Run **`START_SITE_SURVEY.bat`**. The script walks through four stages and writes all outputs to `Jobs\<JobName>_<Timestamp>\`:

1. **Baseline Hardware & Throughput Check**
   - Saves adapter and driver capabilities (`wlan_interfaces.txt`, `wlan_drivers.txt`).
   - Triggers a hardware scan via `wlanapi.dll` (`WlanScan`) and writes `baseline_rf_scan.txt`.
   - Runs a baseline split-hop ping (local gateway vs. `1.1.1.1`) and Cloudflare speedtest/bufferbloat check (`speedtest_results.json`).
2. **Room-by-Room Walkthrough**
   - Enter each room or location name to trigger a fresh hardware scan and log visible BSSIDs (`survey_waypoints.csv`) alongside active link rate, RSSI, and gateway/WAN ping (`waypoint_telemetry.csv`).
   - Append `*` to a location name (for example, `Office*`) to also run a speedtest at that location.
   - Type `DONE` when finished.
3. **Packet Capture (Optional)**
   - If TShark is installed, auto-detects the `Wi-Fi` capture interface and records a `.pcapng` trace.
4. **LAN Discovery & Report Generation**
   - Sweeps the local `/24` subnet via UDP ARP triggers and ICMP probes, then maps active IPs and MAC OUIs to `lan_devices.csv`.
   - Generates `ENGINEERING_HANDOFF_SUMMARY.txt` and `PM_SITE_SURVEY_REPORT.html` (print-to-PDF ready).

---

### Standalone Scripts

| Script | Description |
| :--- | :--- |
| `1_Quick_Scan.bat` | Triggers a live `WlanScan` and prints visible 2.4 / 5 / 6 GHz BSSIDs sorted by RSSI. |
| `2_Log_Waypoint.bat` | Logs a single waypoint scan and active link telemetry to `survey_log.csv`. |
| `3_Capture_Packets.bat` | Captures `.pcapng` traffic on the auto-detected Wi-Fi interface via TShark. |
| `4_Speed_And_Ping_Test.bat` | Runs a standalone split-hop ping and Cloudflare speedtest with bufferbloat grading. |

---

### Job Output Files

Each run of `START_SITE_SURVEY.bat` produces a self-contained folder under `Jobs\`:

| File | Contents |
| :--- | :--- |
| `PM_SITE_SURVEY_REPORT.html` | Printable HTML report with coverage tables, speedtests, AP inventory, congestion alerts, and LAN devices. |
| `ENGINEERING_HANDOFF_SUMMARY.txt` | Plain-text engineering summary of all collected metrics and alerts. |
| `survey_waypoints.csv` | Raw per-waypoint BSSID scan records (SSID, BSSID, band, channel, radio type, dBm, channel utilization, station count). |
| `waypoint_telemetry.csv` | Active client link metrics per room (connected BSSID, true RSSI, Tx/Rx PHY rate, gateway/WAN ping and jitter). |
| `speedtest_results.json` | Unloaded/loaded latency, download/upload Mbps, bufferbloat grade, and edge colo data. |
| `lan_devices.csv` | Local subnet ARP table mapped to hardware vendors (OUI) and device roles. |
| `baseline_rf_scan.txt` | Initial full-spectrum BSSID table captured at the start of the job. |
| `wlan_interfaces.txt` / `wlan_drivers.txt` | Output of `netsh wlan show interfaces` and `netsh wlan show drivers`. |
| `lan_ipconfig.txt` / `lan_arp_table.txt` | Raw `ipconfig /all` and `arp -a` snapshots. |

---

## Running Tests

The test suite uses Python's built-in `unittest` module with no external dependencies:

```powershell
python -m unittest discover -s tests -v
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on adding MAC OUI vendor prefixes, reporting field parser edge cases, and submitting pull requests.

