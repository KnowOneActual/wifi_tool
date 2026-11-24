"""
Automated unit tests for the Wi-Fi Site Survey Toolkit (v2.0-beta).
Runs with zero external dependencies using Python's built-in `unittest` module.
"""

import csv
import json
import os
import sys
import tempfile
import unittest

# Ensure repo root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import capture_packets
import compare_jobs
import generate_job_summary
import network_diagnostics
import roaming_walk_test
import survey_scanner
import survey_web_ui
import base64
import threading
import urllib.request


class TestWifiToolkit(unittest.TestCase):
    def test_oui_lookup_known_vendors(self):
        self.assertIn("Ubiquiti", network_diagnostics.lookup_oui("78:8a:20:11:22:33"))
        self.assertIn("eero", network_diagnostics.lookup_oui("50-61-3F-AA-BB-CC"))
        self.assertIn("Netgear", network_diagnostics.lookup_oui("28:94:01:00:11:22"))
        self.assertIn("Ruckus", network_diagnostics.lookup_oui("78:9f:6a:11:22:30"))
        self.assertIn("Sonos", network_diagnostics.lookup_oui("74:ca:60:11:22:30"))
        self.assertIn("Sonos", network_diagnostics.lookup_oui("b8:e9:37:11:22:30"))
        self.assertIn("Araknis", network_diagnostics.lookup_oui("14:3f:c3:11:22:30"))
        self.assertIn("Control4", network_diagnostics.lookup_oui("00:0f:ff:11:22:30"))
        self.assertIn("Pakedge", network_diagnostics.lookup_oui("90:a7:c1:11:22:30"))
        self.assertIn("Yealink", network_diagnostics.lookup_oui("80:5e:c0:11:22:30"))
        self.assertIn("Apple", network_diagnostics.lookup_oui("a8:51:ab:11:22:30"))

    def test_oui_lookup_laa_and_unknown(self):
        # Locally Administered Address (second hex digit is 2, 6, a, or e)
        self.assertIn("Virtual BSSID", network_diagnostics.lookup_oui("02:11:22:33:44:55"))
        self.assertIn("Virtual BSSID", network_diagnostics.lookup_oui("fa:bb:cc:dd:ee:ff"))
        # Standard globally unique unknown OUI
        self.assertEqual(network_diagnostics.lookup_oui("00:99:88:77:66:55"), "Standard OUI")
        self.assertEqual(network_diagnostics.lookup_oui(""), "Unknown")

    def test_parse_ipconfig_wifi_isolates_correct_adapter(self):
        sample_ipconfig = """
Windows IP Configuration

Ethernet adapter VPN Tunnel:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 10.8.0.5(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . :

Wireless LAN adapter Local Area Connection* 1:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :

Wireless LAN adapter Wi-Fi:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 192.168.1.153(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : fe80::1%21
                                       192.168.1.1

Ethernet adapter Ethernet 2:

   IPv4 Address. . . . . . . . . . . : 172.16.0.10
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 172.16.0.1
"""
        parsed = network_diagnostics._parse_ipconfig_wifi(sample_ipconfig, "Wi-Fi")
        self.assertEqual(parsed["ipv4"], "192.168.1.153")
        self.assertEqual(parsed["subnet_mask"], "255.255.255.0")
        self.assertEqual(parsed["gateway"], "192.168.1.1")

    def test_parse_ping_sample_submillisecond_and_standard(self):
        self.assertEqual(
            network_diagnostics._parse_ping_sample("Reply from 192.168.1.1: bytes=32 time<1ms TTL=64"),
            0.5,
        )
        self.assertEqual(
            network_diagnostics._parse_ping_sample("Reply from 1.1.1.1: bytes=32 time=14ms TTL=58"),
            14.0,
        )
        self.assertIsNone(network_diagnostics._parse_ping_sample("Request timed out."))

    def test_parse_arp_table_filters_virtual_and_multicast(self):
        sample_arp = """
Interface: 169.254.133.98 --- 0x10
  Internet Address      Physical Address      Type
  169.254.1.1           00-11-22-33-44-55     dynamic

Interface: 192.168.1.153 --- 0x15
  Internet Address      Physical Address      Type
  192.168.1.1           50-61-3f-aa-bb-01     dynamic
  192.168.1.50          78-8a-20-11-22-33     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
"""
        devices = network_diagnostics._parse_arp_table(
            sample_arp, local_ipv4="192.168.1.153", gateway_ip="192.168.1.1"
        )
        self.assertEqual(len(devices), 2)
        self.assertEqual(devices[0]["ip"], "192.168.1.1")
        self.assertEqual(devices[0]["role"], "Default Gateway / Router")
        self.assertIn("eero", devices[0]["vendor"])
        self.assertEqual(devices[1]["ip"], "192.168.1.50")
        self.assertIn("Ubiquiti", devices[1]["vendor"])

    def test_generate_job_summary_creates_deliverables(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # 1. Create mock job_meta.json
            meta = {
                "job_name": "Beta_Test_Site",
                "tech_name": "Tester_01",
                "target_ssid": "TestCorpWiFi",
                "notes": "Beta verification test run",
                "date": "20261021_120000",
            }
            with open(os.path.join(tmpdir, "job_meta.json"), "w", encoding="utf-8") as f:
                json.dump(meta, f)

            # 2. Create mock survey_waypoints.csv (including dual 5 GHz radios and a backup SSID)
            waypoints_csv = os.path.join(tmpdir, "survey_waypoints.csv")
            with open(waypoints_csv, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=generate_job_summary.CSV_STANDARD_HEADERS)
                writer.writeheader()
                writer.writerow({
                    "timestamp": "2026-10-21T12:01:00",
                    "waypoint": "Lobby",
                    "ssid": "TestCorpWiFi",
                    "bssid": "78:8a:20:aa:bb:cc",
                    "band": "5 GHz",
                    "channel": "36",
                    "radio_type": "802.11ax",
                    "signal_dbm": "-55",
                    "signal_pct": "90",
                    "cu_pct": "15",
                    "stations": "4",
                    "auth": "WPA3-Personal",
                    "enc": "CCMP",
                })
                writer.writerow({
                    "timestamp": "2026-10-21T12:01:00",
                    "waypoint": "Lobby",
                    "ssid": "TestCorpWiFi",
                    "bssid": "78:8a:20:aa:bb:ce",
                    "band": "5 GHz",
                    "channel": "149",
                    "radio_type": "802.11ax",
                    "signal_dbm": "-58",
                    "signal_pct": "84",
                    "cu_pct": "12",
                    "stations": "2",
                    "auth": "WPA3-Personal",
                    "enc": "CCMP",
                })
                writer.writerow({
                    "timestamp": "2026-10-21T12:02:00",
                    "waypoint": "DeadZoneRoom",
                    "ssid": "TestCorpWiFi",
                    "bssid": "78:8a:20:aa:bb:cd",
                    "band": "2.4 GHz",
                    "channel": "6",
                    "radio_type": "802.11ax",
                    "signal_dbm": "-78",
                    "signal_pct": "44",
                    "cu_pct": "40",
                    "stations": "2",
                    "auth": "WPA3-Personal",
                    "enc": "CCMP",
                })
                # Neighbor/backup SSID with target_ssid as prefix should NOT be treated as target in DeadZoneRoom
                writer.writerow({
                    "timestamp": "2026-10-21T12:02:00",
                    "waypoint": "DeadZoneRoom",
                    "ssid": "TestCorpWiFi backup",
                    "bssid": "4e:d7:4a:11:22:33",
                    "band": "5 GHz",
                    "channel": "44",
                    "radio_type": "802.11ax",
                    "signal_dbm": "-50",
                    "signal_pct": "99",
                    "cu_pct": "55",
                    "stations": "1",
                    "auth": "WPA2-Personal",
                    "enc": "CCMP",
                })

            # 3. Create mock lan_devices.csv
            lan_csv = os.path.join(tmpdir, "lan_devices.csv")
            with open(lan_csv, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["ip", "mac", "vendor", "role", "type"])
                writer.writeheader()
                writer.writerow({
                    "ip": "192.168.1.1",
                    "mac": "78:8a:20:aa:bb:01",
                    "vendor": "Ubiquiti Inc. (UniFi)",
                    "role": "Default Gateway / Router",
                    "type": "dynamic",
                })

            # 4. Run summary generator
            generate_job_summary.generate_summary(tmpdir)

            txt_report = os.path.join(tmpdir, "ENGINEERING_HANDOFF_SUMMARY.txt")
            html_report = os.path.join(tmpdir, "PM_SITE_SURVEY_REPORT.html")

            self.assertTrue(os.path.exists(txt_report), "ENGINEERING_HANDOFF_SUMMARY.txt was not created")
            self.assertTrue(os.path.exists(html_report), "PM_SITE_SURVEY_REPORT.html was not created")

            with open(txt_report, "r", encoding="utf-8") as f:
                txt_content = f.read()
                self.assertNotIn("(0 bytes)", txt_content)
                self.assertIn("PM_SITE_SURVEY_REPORT.html", txt_content)
                # Both 5 GHz radios on AP 1 should be preserved
                self.assertIn("78:8a:20:aa:bb:cc", txt_content)
                self.assertIn("78:8a:20:aa:bb:ce", txt_content)
                # DeadZoneRoom must report NO 5/6G SIGNAL for TestCorpWiFi (ignoring 'TestCorpWiFi backup')
                self.assertIn("NO 5/6G SIGNAL", txt_content)

            with open(html_report, "r", encoding="utf-8") as f:
                html_content = f.read()
                self.assertIn("Beta_Test_Site", html_content)
                self.assertIn("TestCorpWiFi", html_content)
                self.assertIn("Lobby", html_content)
                self.assertIn("Discovered LAN Devices", html_content)
                self.assertIn("Peak RF Channel Congestion", html_content)

    def test_parse_arp_table_respects_non_24_subnet_mask(self):
        sample_arp = """
Interface: 10.10.0.5 --- 0x15
  Internet Address      Physical Address      Type
  10.10.0.1             14-3f-c3-aa-00-01     dynamic
  10.10.1.50            78-9f-6a-aa-00-02     dynamic
  10.10.2.10            00-0f-ff-aa-00-03     dynamic
  10.10.1.255           ff-ff-ff-ff-ff-ff     static
"""
        # /23 includes 10.10.0.0 - 10.10.1.255, excluding 10.10.2.10
        devices = network_diagnostics._parse_arp_table(
            sample_arp, local_ipv4="10.10.0.5", gateway_ip="10.10.0.1", subnet_mask="255.255.254.0"
        )
        ips = [d["ip"] for d in devices]
        self.assertEqual(ips, ["10.10.0.1", "10.10.1.50"])

    def test_phase1_rf_audits_duplicates_ap_list_roaming_and_nic(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "job_meta.json"), "w", encoding="utf-8") as f:
                json.dump({
                    "job_name": "Estate_Audit",
                    "tech_name": "Tech1",
                    "target_ssid": "ClientWiFi",
                    "notes": "Phase 1 validation",
                    "date": "20261124_080000",
                }, f)

            # Controller AP List.csv (Ruckus format)
            with open(os.path.join(tmpdir, "AP List.csv"), "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["AP Name", "Role", "Status", "AP Group", "Model", "IP Address", "MAC Address", "PoE Operating Mode", "Uptime", "Firmware Version"])
                writer.writerow(["IDF Closet", "Master", "Connected", "Default", "A650", "192.168.1.15", "78:9f:6a:01:11:10", "802.3at", "2d 15h", "200.19"])
                writer.writerow(["East Hallway", "Member", "Connected", "Default", "A650", "192.168.1.17", "78:9f:6a:02:22:20", "802.3at", "2d 18h", "200.19"])

            # Wi-Fi 5 survey laptop driver (no 6 GHz / no WPA3)
            with open(os.path.join(tmpdir, "wlan_drivers.txt"), "w", encoding="utf-8") as f:
                f.write("""Interface name: Wi-Fi
    Driver                    : Intel(R) Dual Band Wireless-AC 8265
    Vendor                    : Intel Corporation
    Version                   : 20.70.25.2
    Date                      : 6/22/2021
    Radio types supported     : 802.11b 802.11g 802.11n 802.11a 802.11ac
    Number of supported bands : 2
                                2.4 GHz [ 0 MHz - 0 MHz]
                                5 GHz [ 0 MHz - 0 MHz]
""")

            # UTF-16LE Windows roaming event log
            roam_text = """Event[0]
  Date: 2026-11-24T08:05:00.1500000Z
  Event ID: 11005
  Network SSID: MgmtSSID

Event[1]
  Date: 2026-11-24T08:05:00.0500000Z
  Event ID: 11010
  Network SSID: MgmtSSID

Event[2]
  Date: 2026-11-24T08:01:00.0000000Z
  Event ID: 8001
  Network SSID: MgmtSSID
"""
            with open(os.path.join(tmpdir, "wlan_roaming_events.txt"), "wb") as f:
                f.write(roam_text.encode("utf-16"))

            # Waypoints: duplicate "Office" room (Before & After), CCI on Ch 11 & Ch 104 (DFS),
            # 2.4G ACI on Ch 4, multi-SSID radio peak CU dedupe, and sticky client on Office #1
            wp_fields = generate_job_summary.CSV_STANDARD_HEADERS + ["waypoint_id"]
            with open(os.path.join(tmpdir, "survey_waypoints.csv"), "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=wp_fields)
                w.writeheader()
                # Office #1: IDF Closet Ch 104 (-55 dBm), East Hallway Ch 104 (-68 dBm)
                w.writerow({"timestamp": "2026-11-24T08:01:00", "waypoint": "Office", "ssid": "ClientWiFi", "bssid": "78:9f:6a:81:11:11", "band": "5 GHz", "channel": "104", "radio_type": "802.11ax", "signal_dbm": "-55", "signal_pct": "90", "cu_pct": "12", "stations": "2", "auth": "WPA2", "enc": "CCMP", "waypoint_id": "1"})
                w.writerow({"timestamp": "2026-11-24T08:01:00", "waypoint": "Office", "ssid": "ClientWiFi", "bssid": "78:9f:6a:82:22:21", "band": "5 GHz", "channel": "104", "radio_type": "802.11ax", "signal_dbm": "-68", "signal_pct": "64", "cu_pct": "10", "stations": "1", "auth": "WPA2", "enc": "CCMP", "waypoint_id": "1"})
                w.writerow({"timestamp": "2026-11-24T08:01:00", "waypoint": "Office", "ssid": "ClientWiFi", "bssid": "78:9f:6a:41:11:11", "band": "2.4 GHz", "channel": "11", "radio_type": "802.11ax", "signal_dbm": "-52", "signal_pct": "96", "cu_pct": "40", "stations": "1", "auth": "WPA2", "enc": "CCMP", "waypoint_id": "1"})
                # Second SSID on exact same physical 2.4G radio with higher CU -> should collapse & take peak 62%
                w.writerow({"timestamp": "2026-11-24T08:01:00", "waypoint": "Office", "ssid": "MgmtSSID", "bssid": "78:9f:6a:41:11:10", "band": "2.4 GHz", "channel": "11", "radio_type": "802.11ax", "signal_dbm": "-52", "signal_pct": "96", "cu_pct": "62", "stations": "0", "auth": "WPA2", "enc": "CCMP", "waypoint_id": "1"})
                # Non-standard 2.4 GHz neighbor on Ch 4 (ACI)
                w.writerow({"timestamp": "2026-11-24T08:01:00", "waypoint": "Office", "ssid": "NeighborCh4", "bssid": "18:a5:ff:11:22:33", "band": "2.4 GHz", "channel": "4", "radio_type": "802.11ax", "signal_dbm": "-68", "signal_pct": "64", "cu_pct": "30", "stations": "2", "auth": "WPA2", "enc": "CCMP", "waypoint_id": "1"})
                # Office #2 (re-test after tweak)
                w.writerow({"timestamp": "2026-11-24T08:05:00", "waypoint": "Office", "ssid": "ClientWiFi", "bssid": "78:9f:6a:81:11:11", "band": "5 GHz", "channel": "104", "radio_type": "802.11ax", "signal_dbm": "-50", "signal_pct": "100", "cu_pct": "10", "stations": "2", "auth": "WPA2", "enc": "CCMP", "waypoint_id": "2"})

            # Telemetry: Office #1 stuck on East Hallway (MgmtSSID != ClientWiFi); Office #2 roamed to IDF Closet
            tel_fields = [
                "timestamp", "waypoint", "connected_ssid", "connected_bssid", "connected_band",
                "connected_channel", "radio_type", "true_rssi_dbm", "signal_pct",
                "tx_rate_mbps", "rx_rate_mbps", "gateway_ip", "gw_avg_ms", "gw_jitter_ms", "gw_loss_pct",
                "wan_avg_ms", "wan_jitter_ms", "wan_loss_pct", "dns_ms", "diagnosis",
                "download_mbps", "upload_mbps", "bufferbloat_grade", "waypoint_id"
            ]
            with open(os.path.join(tmpdir, "waypoint_telemetry.csv"), "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=tel_fields)
                w.writeheader()
                w.writerow({"timestamp": "2026-11-24T08:01:02", "waypoint": "Office", "connected_ssid": "MgmtSSID", "connected_bssid": "78:9f:6a:82:22:20", "connected_band": "5 GHz", "connected_channel": "104", "radio_type": "802.11ac", "true_rssi_dbm": "-68", "signal_pct": "64", "tx_rate_mbps": "200.0", "rx_rate_mbps": "200.0", "gateway_ip": "192.168.1.1", "gw_avg_ms": "4.0", "gw_jitter_ms": "1.0", "gw_loss_pct": "0.0", "wan_avg_ms": "18.0", "wan_jitter_ms": "2.0", "wan_loss_pct": "0.0", "dns_ms": "20.0", "diagnosis": "Healthy", "waypoint_id": "1"})
                w.writerow({"timestamp": "2026-11-24T08:05:02", "waypoint": "Office", "connected_ssid": "MgmtSSID", "connected_bssid": "78:9f:6a:81:11:10", "connected_band": "5 GHz", "connected_channel": "104", "radio_type": "802.11ac", "true_rssi_dbm": "-48", "signal_pct": "92", "tx_rate_mbps": "400.0", "rx_rate_mbps": "400.0", "gateway_ip": "192.168.1.1", "gw_avg_ms": "2.0", "gw_jitter_ms": "0.5", "gw_loss_pct": "0.0", "wan_avg_ms": "15.0", "wan_jitter_ms": "1.0", "wan_loss_pct": "0.0", "dns_ms": "18.0", "diagnosis": "Healthy", "waypoint_id": "2"})

            generate_job_summary.generate_summary(tmpdir)

            with open(os.path.join(tmpdir, "ENGINEERING_HANDOFF_SUMMARY.txt"), "r", encoding="utf-8") as f:
                txt = f.read()

            # Duplicate waypoints both preserved
            self.assertIn("Office (#1)", txt)
            self.assertIn("Office (#2)", txt)
            # Controller AP List names ingested
            self.assertIn("IDF Closet", txt)
            self.assertIn("East Hallway", txt)
            # Survey NIC capability warning
            self.assertIn("Wi-Fi 5 (802.11ac)", txt)
            # SSID context mismatch notice
            self.assertIn("MgmtSSID", txt)
            # CCI, DFS, ACI, and Sticky Client alerts all triggered
            self.assertIn("[CCI]", txt)
            self.assertIn("[DFS]", txt)
            self.assertIn("[ACI 2.4G]", txt)
            self.assertIn("[STICKY]", txt)
            # Peak CU deduplicated to 1 entry at 62% combining ClientWiFi & MgmtSSID
            self.assertIn("Peak  62%", txt)
            self.assertEqual(txt.count("Ch 11  (2.4 GHz)"), 1)
            # UTF-16LE roaming log parsed with 100.0 ms re-key latency
            self.assertIn("Security Re-keys/Roams: 1", txt)
            self.assertIn("Avg 100.0 ms", txt)

    def test_baseline_only_job_falls_back_to_baseline_rf_scan(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "job_meta.json"), "w", encoding="utf-8") as f:
                json.dump({"job_name": "QuickCheck", "tech_name": "Tech1", "target_ssid": "SiteCorpWiFi", "date": "20261124"}, f)
            with open(os.path.join(tmpdir, "baseline_rf_scan.txt"), "w", encoding="utf-8") as f:
                f.write("""===================================================================================================================
SSID                      | BSSID             | Band    | Ch   | Radio    | RSSI            | Util   | STAs | Security
===================================================================================================================
SiteCorpWiFi              | 90:a7:c1:aa:bb:1d | 5 GHz   |  149 | 802.11ac | -58 dBm (84%)   |     0% |    8 | WPA2-Personal/CCMP
SiteCorpWiFi              | 90:a7:c1:aa:bb:14 | 2.4 GHz |    1 | 802.11n  | -59 dBm (81%)   |    38% |    0 | WPA2-Personal/CCMP
===================================================================================================================
Total Detected BSSIDs: 2 | Timestamp: 2026-11-24 08:00:00
""")
            generate_job_summary.generate_summary(tmpdir)
            with open(os.path.join(tmpdir, "ENGINEERING_HANDOFF_SUMMARY.txt"), "r", encoding="utf-8") as f:
                txt = f.read()
            self.assertIn("Baseline Scan", txt)
            self.assertIn("Pakedge", txt)
            self.assertIn("Peak  38%", txt)

    def test_freq_khz_to_band_channel_all_bands(self):
        self.assertEqual(survey_scanner.freq_khz_to_band_channel(2412000), ("2.4 GHz", "1", 2412))
        self.assertEqual(survey_scanner.freq_khz_to_band_channel(2437000), ("2.4 GHz", "6", 2437))
        self.assertEqual(survey_scanner.freq_khz_to_band_channel(2462000), ("2.4 GHz", "11", 2462))
        self.assertEqual(survey_scanner.freq_khz_to_band_channel(2484000), ("2.4 GHz", "14", 2484))
        self.assertEqual(survey_scanner.freq_khz_to_band_channel(5180000), ("5 GHz", "36", 5180))
        self.assertEqual(survey_scanner.freq_khz_to_band_channel(5745000), ("5 GHz", "149", 5745))
        self.assertEqual(survey_scanner.freq_khz_to_band_channel(5955000), ("6 GHz", "1", 5955))
        self.assertEqual(survey_scanner.freq_khz_to_band_channel(6135000), ("6 GHz", "37", 6135))

    def test_parse_ie_bytes_5ghz_80mhz_roaming_rsn_and_cisco_name(self):
        def tlv(eid, payload):
            return bytes([eid, len(payload)]) + payload

        # Supported Rates: 6 Mbps basic (0x8c), 12 Mbps basic (0x98), 24 Mbps basic (0xb0)
        ie_rates = tlv(1, bytes([0x8C, 0x98, 0xB0, 0x6C]))
        # BSS Load: 7 stations, CU raw 102 (~40%), admission cap 0
        ie_bss_load = tlv(11, bytes([0x07, 0x00, 102, 0x00, 0x00]))
        # RSN (IE 48): WPA2/WPA3-Personal Transition (PSK=2 + SAE=8), CCMP=4, PMF Capable (0x0080)
        rsn_payload = (
            b"\x01\x00"              # version 1
            b"\x00\x0f\xac\x04"      # group cipher CCMP
            b"\x01\x00"              # 1 pairwise cipher
            b"\x00\x0f\xac\x04"      # CCMP
            b"\x02\x00"              # 2 AKMs
            b"\x00\x0f\xac\x02"      # PSK
            b"\x00\x0f\xac\x08"      # SAE
            b"\x80\x00"              # RSN caps: MFPC=1, MFPR=0
        )
        ie_rsn = tlv(48, rsn_payload)
        # Mobility Domain (802.11r)
        ie_md = tlv(54, b"\x12\x34\x01")
        # HT Operation (40 MHz SCA)
        ie_ht_op = tlv(61, bytes([36, 0x05]) + b"\x00" * 20)
        # RM Enabled Capabilities (802.11k)
        ie_11k = tlv(70, b"\x73\x00\x00\x00\x00")
        # Extended Capabilities (802.11v BSS Transition = byte 2 bit 3 = 0x08)
        ie_11v = tlv(127, b"\x00\x00\x08\x00")
        # Cisco CCX AP Name (IE 133): 10 prefix bytes + 16-byte ASCII name
        ie_cisco = tlv(133, b"\x00" * 10 + b"Lobby-AP-01".ljust(16, b"\x00") + b"\x00\x00")
        # VHT Operation (80 MHz: cw=1, ccfs0=42, ccfs1=0)
        ie_vht_op = tlv(192, bytes([1, 42, 0, 0, 0]))

        blob = ie_rates + ie_bss_load + ie_rsn + ie_md + ie_ht_op + ie_11k + ie_11v + ie_cisco + ie_vht_op
        parsed = survey_scanner.parse_ie_bytes(blob, band="5 GHz", capability_info=0x0010)

        self.assertEqual(parsed["channel_width_mhz"], 80)
        self.assertEqual(parsed["stations"], 7)
        self.assertEqual(parsed["cu_pct"], 40)
        self.assertEqual(parsed["roaming_flags"], "11k/11v/11r")
        self.assertEqual(parsed["auth"], "WPA2/WPA3-Personal")
        self.assertEqual(parsed["enc"], "CCMP")
        self.assertEqual(parsed["pmf"], "Capable")
        self.assertEqual(parsed["min_basic_rate_mbps"], 6.0)
        self.assertEqual(parsed["ap_name"], "Lobby-AP-01")
        self.assertEqual(parsed["radio_hint"], "802.11ac")

    def test_parse_ie_bytes_wifi7_320mhz_and_legacy_24ghz(self):
        def tlv(eid, payload):
            return bytes([eid, len(payload)]) + payload

        # Wi-Fi 7 EHT Operation (IE 255 Ext 106): eht_op_info_present=1, control=4 (320 MHz)
        ie_eht_op = tlv(255, bytes([106, 0x01, 0, 0, 0, 0, 0x04, 31, 0]))
        parsed_7 = survey_scanner.parse_ie_bytes(ie_eht_op, band="6 GHz")
        self.assertEqual(parsed_7["channel_width_mhz"], 320)
        self.assertEqual(parsed_7["radio_hint"], "802.11be")

        # 2.4 GHz 40 MHz HT + legacy 1 Mbps basic rate (0x82)
        ie_legacy = tlv(1, bytes([0x82, 0x84, 0x8B, 0x96])) + tlv(61, bytes([6, 0x05]) + b"\x00" * 20)
        parsed_24 = survey_scanner.parse_ie_bytes(ie_legacy, band="2.4 GHz")
        self.assertEqual(parsed_24["channel_width_mhz"], 40)
        self.assertEqual(parsed_24["min_basic_rate_mbps"], 1.0)

    def test_phase2_bonded_cci_40mhz_24g_roaming_and_legacy_rate_alerts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "job_meta.json"), "w", encoding="utf-8") as f:
                json.dump({"job_name": "Phase2_Audit", "tech_name": "Tech1", "target_ssid": "SiteWiFi", "date": "20261124"}, f)

            fields = generate_job_summary.CSV_STANDARD_HEADERS + [
                "waypoint_id", "channel_width_mhz", "roaming_flags", "pmf",
                "min_basic_rate_mbps", "ap_name", "freq_mhz"
            ]
            with open(os.path.join(tmpdir, "survey_waypoints.csv"), "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=fields)
                w.writeheader()
                # AP 1: 5 GHz Ch 36 @ 80 MHz (occupies 36,40,44,48), missing 11v, beacon name "GreatRoomAP"
                w.writerow({
                    "timestamp": "2026-11-24T09:00:00", "waypoint": "Great Room", "ssid": "SiteWiFi",
                    "bssid": "78:8a:20:aa:11:01", "band": "5 GHz", "channel": "36", "radio_type": "802.11ax",
                    "signal_dbm": "-44", "signal_pct": "100", "cu_pct": "10", "stations": "3",
                    "auth": "WPA2/WPA3-Personal", "enc": "CCMP", "waypoint_id": "1",
                    "channel_width_mhz": "80", "roaming_flags": "11k", "pmf": "Capable",
                    "min_basic_rate_mbps": "6.0", "ap_name": "GreatRoomAP", "freq_mhz": "5180"
                })
                # AP 2: 5 GHz Ch 44 @ 80 MHz -> DIFFERENT primary channel, SAME 80 MHz block -> Bonded CCI!
                w.writerow({
                    "timestamp": "2026-11-24T09:00:00", "waypoint": "Great Room", "ssid": "SiteWiFi",
                    "bssid": "78:8a:20:bb:22:01", "band": "5 GHz", "channel": "44", "radio_type": "802.11ax",
                    "signal_dbm": "-58", "signal_pct": "84", "cu_pct": "12", "stations": "2",
                    "auth": "WPA2/WPA3-Personal", "enc": "CCMP", "waypoint_id": "1",
                    "channel_width_mhz": "80", "roaming_flags": "11k/11v", "pmf": "Capable",
                    "min_basic_rate_mbps": "6.0", "ap_name": "KitchenAP", "freq_mhz": "5220"
                })
                # AP 1: 2.4 GHz Ch 6 @ 40 MHz + 1.0 Mbps legacy basic rate
                w.writerow({
                    "timestamp": "2026-11-24T09:00:00", "waypoint": "Great Room", "ssid": "SiteWiFi",
                    "bssid": "78:8a:20:aa:11:02", "band": "2.4 GHz", "channel": "6", "radio_type": "802.11ax",
                    "signal_dbm": "-42", "signal_pct": "100", "cu_pct": "28", "stations": "5",
                    "auth": "WPA2-Personal", "enc": "CCMP", "waypoint_id": "1",
                    "channel_width_mhz": "40", "roaming_flags": "11k", "pmf": "None",
                    "min_basic_rate_mbps": "1.0", "ap_name": "GreatRoomAP", "freq_mhz": "2437"
                })

            generate_job_summary.generate_summary(tmpdir)
            with open(os.path.join(tmpdir, "ENGINEERING_HANDOFF_SUMMARY.txt"), "r", encoding="utf-8") as f:
                txt = f.read()

            # Bonded 80 MHz CCI caught despite different primary channels (36 vs 44)
            self.assertIn("Ch 36/44", txt)
            self.assertIn("bonded spectrum overlap", txt)
            # 2.4 GHz 40 MHz red flag
            self.assertIn("[2.4G 40MHz]", txt)
            # 802.11k/v roaming gap warning (AP 1 lacks 11v)
            self.assertIn("[ROAMING 11k/v]", txt)
            # Legacy 1 Mbps basic rate warning
            self.assertIn("[LEGACY RATES]", txt)
            # Beacon AP name automatically picked up
            self.assertIn("GreatRoomAP", txt)
            self.assertIn("@80MHz", txt)

    def test_compare_jobs_fuzzy_room_matching_and_deltas(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            b_dir = os.path.join(tmpdir, "Site_Before")
            a_dir = os.path.join(tmpdir, "Site_After")
            os.makedirs(b_dir)
            os.makedirs(a_dir)

            with open(os.path.join(b_dir, "job_meta.json"), "w", encoding="utf-8") as f:
                json.dump({"job_name": "ClientA", "target_ssid": "HomeNet", "date": "20261101"}, f)
            with open(os.path.join(a_dir, "job_meta.json"), "w", encoding="utf-8") as f:
                json.dump({"job_name": "ClientA", "target_ssid": "HomeNet", "date": "20261105"}, f)

            # Before: Kitchen typo ("1st Floor Kithen") -72 dBm on Ch 36; After: "1st Floor Kitchen" -58 dBm on Ch 149 (+14 dB)
            with open(os.path.join(b_dir, "survey_waypoints.csv"), "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=generate_job_summary.CSV_STANDARD_HEADERS)
                w.writeheader()
                w.writerow({"timestamp": "2026-11-01T10:00:00", "waypoint": "1st Floor Kithen", "ssid": "HomeNet", "bssid": "78:8a:20:aa:11:01", "band": "5 GHz", "channel": "36", "radio_type": "802.11ax", "signal_dbm": "-72", "signal_pct": "56", "cu_pct": "45", "stations": "2", "auth": "WPA2", "enc": "CCMP"})
            with open(os.path.join(a_dir, "survey_waypoints.csv"), "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=generate_job_summary.CSV_STANDARD_HEADERS)
                w.writeheader()
                w.writerow({"timestamp": "2026-11-05T10:00:00", "waypoint": "1st Floor Kitchen", "ssid": "HomeNet", "bssid": "78:8a:20:aa:11:01", "band": "5 GHz", "channel": "149", "radio_type": "802.11ax", "signal_dbm": "-58", "signal_pct": "84", "cu_pct": "12", "stations": "2", "auth": "WPA2", "enc": "CCMP"})

            res = compare_jobs.compare_job_folders(b_dir, a_dir)
            self.assertEqual(res["avg_delta_5_db"], 14.0)
            self.assertEqual(len(res["ap_changes"]), 1)
            self.assertEqual(res["ap_changes"][0]["status"], "Channel Changed")
            self.assertTrue(os.path.exists(res["html_path"]))
            self.assertTrue(os.path.exists(res["txt_path"]))
            with open(res["txt_path"], "r", encoding="utf-8") as f:
                txt = f.read()
            self.assertIn("+14 dB", txt)
            self.assertIn("Channel Changed", txt)

    def test_web_ui_rename_delete_meta_and_http_api(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            job_id = "Demo_20261124_100000"
            job_dir = os.path.join(tmpdir, job_id)
            os.makedirs(job_dir)
            with open(os.path.join(job_dir, "job_meta.json"), "w", encoding="utf-8") as f:
                json.dump({"job_name": "Demo", "tech_name": "T1", "target_ssid": "SiteWiFi", "notes": "", "date": "20261124_100000"}, f)

            wp_fields = generate_job_summary.CSV_STANDARD_HEADERS + ["waypoint_id"]
            with open(os.path.join(job_dir, "survey_waypoints.csv"), "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=wp_fields)
                w.writeheader()
                w.writerow({"timestamp": "2026-11-24T10:01:00", "waypoint": "Kithen", "ssid": "SiteWiFi", "bssid": "78:8a:20:aa:11:01", "band": "5 GHz", "channel": "36", "radio_type": "802.11ax", "signal_dbm": "-55", "signal_pct": "90", "cu_pct": "10", "stations": "1", "auth": "WPA2", "enc": "CCMP", "waypoint_id": "1"})
                w.writerow({"timestamp": "2026-11-24T10:02:00", "waypoint": "BadScan", "ssid": "SiteWiFi", "bssid": "78:8a:20:aa:11:01", "band": "5 GHz", "channel": "36", "radio_type": "802.11ax", "signal_dbm": "-85", "signal_pct": "30", "cu_pct": "10", "stations": "1", "auth": "WPA2", "enc": "CCMP", "waypoint_id": "2"})

            tel_fields = ["timestamp", "waypoint", "connected_ssid", "tx_rate_mbps", "rx_rate_mbps", "gw_avg_ms", "wan_avg_ms", "waypoint_id"]
            with open(os.path.join(job_dir, "waypoint_telemetry.csv"), "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=tel_fields)
                w.writeheader()
                w.writerow({"timestamp": "2026-11-24T10:01:02", "waypoint": "Kithen", "connected_ssid": "SiteWiFi", "tx_rate_mbps": "400", "rx_rate_mbps": "400", "gw_avg_ms": "2.0", "wan_avg_ms": "15.0", "waypoint_id": "1"})
                w.writerow({"timestamp": "2026-11-24T10:02:02", "waypoint": "BadScan", "connected_ssid": "SiteWiFi", "tx_rate_mbps": "100", "rx_rate_mbps": "100", "gw_avg_ms": "9.0", "wan_avg_ms": "22.0", "waypoint_id": "2"})

            # Path traversal guard
            with self.assertRaises(ValueError):
                survey_web_ui._safe_job_path(tmpdir, "../outside")

            # Live HTTP server round-trip on ephemeral port
            srv = survey_web_ui.create_server(jobs_root=tmpdir, host="127.0.0.1", port=0)
            port = srv.server_address[1]
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            try:
                base = f"http://127.0.0.1:{port}"
                # GET / returns UI HTML
                with urllib.request.urlopen(f"{base}/", timeout=5) as resp:
                    self.assertEqual(resp.status, 200)
                    self.assertIn("Wi-Fi Site Survey", resp.read().decode("utf-8"))

                # GET /api/jobs
                with urllib.request.urlopen(f"{base}/api/jobs", timeout=5) as resp:
                    jobs_data = json.loads(resp.read().decode("utf-8"))
                    self.assertEqual(len(jobs_data["jobs"]), 1)

                # PATCH rename waypoint 0 ("Kithen" -> "1st Fl - Kitchen")
                req = urllib.request.Request(
                    f"{base}/api/jobs/{job_id}/waypoints/0",
                    data=json.dumps({"waypoint": "1st Fl - Kitchen"}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="PATCH",
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    st = json.loads(resp.read().decode("utf-8"))
                    self.assertEqual(st["waypoints"][0]["waypoint"], "1st Fl - Kitchen")

                # DELETE waypoint 1 ("BadScan")
                req_del = urllib.request.Request(f"{base}/api/jobs/{job_id}/waypoints/1", method="DELETE")
                with urllib.request.urlopen(req_del, timeout=5) as resp:
                    st = json.loads(resp.read().decode("utf-8"))
                    self.assertEqual(len(st["waypoints"]), 1)
                    self.assertEqual(st["waypoints"][0]["waypoint"], "1st Fl - Kitchen")

                # Verify telemetry CSV stayed in sync
                tel_after = generate_job_summary.load_csv_generic(os.path.join(job_dir, "waypoint_telemetry.csv"))
                self.assertEqual(len(tel_after), 1)
                self.assertEqual(tel_after[0]["waypoint"], "1st Fl - Kitchen")
            finally:
                srv.shutdown()
                srv.server_close()

    def test_roaming_walk_test_analysis_save_and_report_embedding(self):
        samples = [
            {"seq": 1, "timestamp": "2026-11-24T10:00:00", "elapsed_sec": 0.0, "ssid": "ClientWiFi", "bssid": "78:9f:6a:81:11:11", "band": "5 GHz", "channel": "104", "rssi_dbm": -52, "gw_ms": 2.0, "packet_lost": False, "event": "START"},
            {"seq": 2, "timestamp": "2026-11-24T10:00:00.5", "elapsed_sec": 0.5, "ssid": "ClientWiFi", "bssid": "78:9f:6a:81:11:11", "band": "5 GHz", "channel": "104", "rssi_dbm": -64, "gw_ms": 3.5, "packet_lost": False, "event": ""},
            {"seq": 3, "timestamp": "2026-11-24T10:00:01.0", "elapsed_sec": 1.0, "ssid": "ClientWiFi", "bssid": "78:9f:6a:81:11:11", "band": "5 GHz", "channel": "104", "rssi_dbm": -73, "gw_ms": None, "packet_lost": True, "event": ""},
            {"seq": 4, "timestamp": "2026-11-24T10:00:01.5", "elapsed_sec": 1.5, "ssid": "ClientWiFi", "bssid": "78:9f:6a:82:22:21", "band": "5 GHz", "channel": "36", "rssi_dbm": -56, "gw_ms": 14.0, "packet_lost": False, "event": "ROAM"},
            {"seq": 5, "timestamp": "2026-11-24T10:00:02.0", "elapsed_sec": 2.0, "ssid": "ClientWiFi", "bssid": "78:9f:6a:82:22:21", "band": "5 GHz", "channel": "36", "rssi_dbm": -54, "gw_ms": 2.5, "packet_lost": False, "event": ""},
        ]
        summary = roaming_walk_test.analyze_walk_samples(samples, interval_sec=0.5, walk_label="Basement -> Kitchen")
        self.assertEqual(summary["roam_count"], 1)
        self.assertEqual(summary["min_rssi_dbm"], -73)
        self.assertEqual(summary["packet_loss_pct"], 20.0)
        ev = summary["roam_events"][0]
        self.assertEqual(ev["from_channel"], "104")
        self.assertEqual(ev["to_channel"], "36")
        self.assertEqual(ev["dropped_pings"], 1)
        self.assertEqual(ev["est_outage_ms"], 500)
        self.assertEqual(ev["grade"], "Minor Glitch")

        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "job_meta.json"), "w", encoding="utf-8") as f:
                json.dump({"job_name": "WalkSite", "target_ssid": "ClientWiFi", "date": "20261124"}, f)
            roaming_walk_test.save_walk_results(tmpdir, summary)
            self.assertTrue(os.path.exists(os.path.join(tmpdir, "roaming_walk_test.csv")))
            self.assertTrue(os.path.exists(os.path.join(tmpdir, "roaming_walk_summary.json")))

            generate_job_summary.generate_summary(tmpdir)
            with open(os.path.join(tmpdir, "ENGINEERING_HANDOFF_SUMMARY.txt"), "r", encoding="utf-8") as f:
                txt = f.read()
            self.assertIn("CONTINUOUS ROAMING WALK-TEST RESULTS", txt)
            self.assertIn("Basement -> Kitchen", txt)
            self.assertIn("Minor Glitch", txt)
            with open(os.path.join(tmpdir, "PM_SITE_SURVEY_REPORT.html"), "r", encoding="utf-8") as f:
                html_doc = f.read()
            self.assertIn("Continuous Roaming Walk-Test Results", html_doc)
            self.assertIn("<svg", html_doc)

    def test_floorplan_upload_pin_rename_sync_and_html_embedding(self):
        # Minimal valid 1x1 PNG
        tiny_png_b64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aU9sAAAAASUVORK5CYII="
        data_url = f"data:image/png;base64,{tiny_png_b64}"

        with tempfile.TemporaryDirectory() as tmpdir:
            job_id = "FloorSite_20261124"
            job_dir = os.path.join(tmpdir, job_id)
            os.makedirs(job_dir)
            with open(os.path.join(job_dir, "job_meta.json"), "w", encoding="utf-8") as f:
                json.dump({"job_name": "FloorSite", "target_ssid": "HomeWiFi", "date": "20261124"}, f)
            wp_fields = generate_job_summary.CSV_STANDARD_HEADERS + ["waypoint_id"]
            with open(os.path.join(job_dir, "survey_waypoints.csv"), "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=wp_fields)
                w.writeheader()
                w.writerow({
                    "timestamp": "2026-11-24T10:00:00", "waypoint": "Kithen", "ssid": "HomeWiFi",
                    "bssid": "78:8a:20:aa:11:01", "band": "5 GHz", "channel": "36", "radio_type": "802.11ax",
                    "signal_dbm": "-58", "signal_pct": "84", "cu_pct": "10", "stations": "2",
                    "auth": "WPA2", "enc": "CCMP", "waypoint_id": "1"
                })

            st = survey_web_ui.upload_floorplan(tmpdir, job_id, "1st Floor", "first.png", data_url)
            self.assertEqual(len(st["floorplans"]), 1)
            fp_id = st["floorplans"][0]["id"]

            st = survey_web_ui.upsert_floorplan_pin(tmpdir, job_id, fp_id, "Kithen", 0.42, 0.65, waypoint_id="1")
            self.assertEqual(len(st["pins"]), 1)

            # Renaming the waypoint should automatically sync the pin's label
            st = survey_web_ui.modify_waypoint_batch(tmpdir, job_id, 0, new_name="1st Fl - Kitchen")
            self.assertEqual(st["pins"][0]["waypoint"], "1st Fl - Kitchen")

            # Generate report and confirm embedded base64 floorplan & heatmap canvas
            generate_job_summary.generate_summary(job_dir)
            with open(os.path.join(job_dir, "PM_SITE_SURVEY_REPORT.html"), "r", encoding="utf-8") as f:
                html_doc = f.read()
            self.assertIn("Floorplan RF Coverage Heatmaps", html_doc)
            self.assertIn("data:image/png;base64,", html_doc)
            self.assertIn("1st Fl - Kitchen", html_doc)
            self.assertIn("renderReportHeatmap", html_doc)
            # Script defining renderReportHeatmap must precede <img id="fpImg_0"> so synchronous data-URI onload works
            self.assertLess(html_doc.index("window.renderReportHeatmap"), html_doc.index('id="fpImg_0"'))

    def test_corrupt_truncated_csv_and_room_key_normalization(self):
        # Truncated/short CSV rows must not crash with NoneType errors
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "job_meta.json"), "w", encoding="utf-8") as f:
                f.write("{corrupt json")
            with open(os.path.join(tmpdir, "survey_waypoints.csv"), "w", encoding="utf-8") as f:
                f.write("2026-11-24T10:00:00,TruncatedRoom,SiteWiFi\n")
            generate_job_summary.generate_summary(tmpdir)
            self.assertTrue(os.path.exists(os.path.join(tmpdir, "PM_SITE_SURVEY_REPORT.html")))

        # Room key normalization matches floor/fl/flr consistently
        self.assertEqual(
            compare_jobs._normalize_room_key("1st Floor Kitchen"),
            compare_jobs._normalize_room_key("1st Fl Kitchen"),
        )
        self.assertEqual(
            compare_jobs._normalize_room_key("1st Floor Kitchen"),
            compare_jobs._normalize_room_key("1st Flr Kitchen"),
        )


if __name__ == "__main__":
    unittest.main()
