# Wi-Fi Site Survey Toolkit v2.0 (Open Source / Windows 11)

A 100% free and open-source Wi-Fi site survey, active link telemetry, Cloudflare speedtest/bufferbloat, and RF auditing toolkit for Windows 11 Pro. Supports **2.4 GHz, 5 GHz, and 6 GHz (Wi-Fi 6E & Wi-Fi 7 / 802.11be)**.

---

## 🚀 Recommended for Field Techs: Standard Job Workflow

👉 **Double-Click: `START_SITE_SURVEY.bat`**

This script guides any technician step-by-step through a standardized site audit:
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
5. **Auto-Detected Wi-Fi Packet Capture (`capture_packets.py`):** Automatically finds the `"Wi-Fi"` interface in TShark and captures a `.pcapng` trace.
6. **Fast Parallel LAN Discovery Sweep (`lan_devices.csv`):** Sweeps `.1–.254` in ~2.5 seconds to populate the ARP table, then maps each device's IP, MAC, and **Hardware Vendor (OUI)** into `lan_devices.csv`.
7. **Executive PM HTML Report + Engineering Hand-Off Package:**
   - Generates `ENGINEERING_HANDOFF_SUMMARY.txt` (with separate 5/6 GHz and 2.4 GHz columns per room).
   - Generates **`PM_SITE_SURVEY_REPORT.html`** (ready to open in any browser or Print to PDF for the Project Manager).

---

## Standalone Quick Tools (Manual Testing)

* **`1_Quick_Scan.bat`**  
  Instant live hardware scan (`WlanScan`) of all visible access points across 2.4, 5, and 6 GHz.
* **`2_Log_Waypoint.bat`**  
  Quickly log a single room waypoint (plus active link speed and gateway/WAN ping) to `survey_log.csv`.
* **`3_Capture_Packets.bat`**  
  Grab a 30-second `.pcapng` capture on the auto-detected Wi-Fi interface.
* **`4_Speed_And_Ping_Test.bat`**  
  Instant standalone **Cloudflare Speedtest + Bufferbloat + Gateway vs. WAN Split-Hop Ping** check.
* **`AI_PARSE_PROMPT.md`**  
  Copy-and-paste prompts for deep AI parsing of any completed job folder.
