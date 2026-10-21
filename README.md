# Wi-Fi Site Survey Toolkit v2.0-beta (Windows 11)

> [!CAUTION]
> **⚠️ BETA SOFTWARE — DO NOT USE AS SOLE PRODUCTION DELIVERABLE YET**
> This toolkit is currently in **active Beta testing** for internal field evaluation and engineering validation. Do not rely on it as your sole production survey deliverable without verification.
>
> **All feedback, bug reports, and ideas are welcome!**
> - 🐛 [Report a Field Bug / Issue](https://github.com/KnowOneActual/wifi_tool/issues/new?template=bug_report.yml)
> - 💡 [Request a Feature or Workflow Improvement](https://github.com/KnowOneActual/wifi_tool/issues/new?template=feature_request.yml)

A 100% free and open-source Wi-Fi site survey, active link telemetry, Cloudflare speedtest/bufferbloat, and RF auditing toolkit for Windows 11 Pro. Supports **2.4 GHz, 5 GHz, and 6 GHz (Wi-Fi 6E & Wi-Fi 7 / 802.11be)** using only the Python Standard Library (zero `pip install` dependencies).

---

## 💻 Prerequisites & Quick Setup for Field Laptops

1. **Windows 10 / 11 with a Wi-Fi Adapter** (Wi-Fi 6E or Wi-Fi 7 adapter recommended to see 6 GHz channels).
2. **Windows Location Services Enabled:**
   - Windows requires Location Services to be ON for `netsh wlan` to report nearby BSSIDs.
   - Go to **Settings → Privacy & security → Location** and ensure **Location services** and **Let desktop apps access your location** are turned **On**.
3. **Python 3.8+ Installed:**
   - Download from [python.org](https://www.python.org/downloads/) or run `winget install Python.Python.3.12` in PowerShell.
   - *(Make sure **"Add python.exe to PATH"** is checked during installation).*
4. **Wireshark / TShark (Optional — for Step 3 Packet Capture only):**
   - Download from [wireshark.org](https://www.wireshark.org/download.html) or run `winget install WiresharkFoundation.Wireshark`.
   - If TShark is not installed, the survey tool will still run all RF scans, speedtests, LAN sweeps, and HTML reports normally.

### How to Download onto a Field Laptop
- **Option A (No Git required):** Click the green **Code** button at the top of this GitHub page → **Download ZIP**, then extract the folder to your `Desktop`.
- **Option B (With Git):**
  ```powershell
  git clone https://github.com/KnowOneActual/wifi_tool.git
  ```

---

## 🚀 Recommended for Field Techs: Standard Job Workflow

👉 **Double-Click: `START_SITE_SURVEY.bat`**

This script runs a quick environment pre-flight check and guides the technician step-by-step through a standardized site audit:

1. **Job Info Prompt (Auto-Detects Target SSID):** Automatically detects the currently connected Wi-Fi network so the tech can just press Enter, while still logging all neighbor networks for interference analysis.
2. **Dedicated Job Folder:** Automatically creates a timestamped folder inside `wifi_tool\Jobs\<Client_Name>_<Timestamp>\`.
3. **Hardware Baseline + Live `WlanScan` + Cloudflare Speedtest:**
   - Logs the Wi-Fi adapter driver and capabilities (`wlan_drivers.txt`, `wlan_interfaces.txt`).
   - Triggers a **live hardware scan** via Windows `wlanapi.dll` (`WlanScan`) so `baseline_rf_scan.txt` is never stale/cached.
   - Runs a **Baseline Cloudflare Speedtest + Bufferbloat Check** (`speed.cloudflare.com`) and **Split-Hop Ping** (Local Gateway vs. `1.1.1.1`) into `speedtest_results.json`.
4. **Room-by-Room Walkthrough (`survey_waypoints.csv` + `waypoint_telemetry.csv`):**
   - Forces a fresh hardware RF scan at each room.
   - Records all visible 2.4 / 5 / 6 GHz BSSIDs into `survey_waypoints.csv`.
   - Records the laptop's **active roaming BSSID, True RSSI (dBm), PHY Tx/Rx Link Speed (Mbps), and Gateway vs. WAN Ping/Jitter** into `waypoint_telemetry.csv`.
   - **Pro Tip:** Append `*` to any room name (e.g. `Office*`) to also run a Cloudflare Speedtest in that specific room!
5. **Auto-Detected Wi-Fi Packet Capture (`capture_packets.py`):** Automatically finds the `"Wi-Fi"` interface in TShark and captures a `.pcapng` trace (skips gracefully if Wireshark/TShark isn't installed).
6. **Fast Parallel LAN Discovery Sweep (`lan_devices.csv`):** Sweeps `.1–.254` in ~2.5 seconds to populate the ARP table, then maps each device's IP, MAC, and **Hardware Vendor (OUI)** into `lan_devices.csv`.
7. **Executive PM HTML Report + Engineering Hand-Off Package:**
   - Generates `ENGINEERING_HANDOFF_SUMMARY.txt` (with separate 5/6 GHz and 2.4 GHz columns per room).
   - Generates **`PM_SITE_SURVEY_REPORT.html`** (ready to open in any browser or Print to PDF for the Project Manager).

---

## 🛠️ Standalone Quick Tools (Manual Testing)

* **`1_Quick_Scan.bat`**  
  Instant live hardware scan (`WlanScan`) of all visible access points across 2.4, 5, and 6 GHz.
* **`2_Log_Waypoint.bat`**  
  Quickly log a single room waypoint (plus active link speed and gateway/WAN ping) to `survey_log.csv`.
* **`3_Capture_Packets.bat`**  
  Grab a 30-second `.pcapng` capture on the auto-detected Wi-Fi interface.
* **`4_Speed_And_Ping_Test.bat`**  
  Instant standalone **Cloudflare Speedtest + Bufferbloat + Gateway vs. WAN Split-Hop Ping** check.

---

## 💬 Beta Feedback & Contributing

We are actively refining this tool based on real-world field use. If something breaks on a job site, a vendor MAC OUI shows up as `Standard OUI`, or a step feels clunky:
1. Open the [Issues tab](https://github.com/KnowOneActual/wifi_tool/issues) and click **New Issue**.
2. Attach terminal output or anonymized report snippets if helpful.
3. Pull Requests are also welcome!
