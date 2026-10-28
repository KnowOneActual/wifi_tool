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
import generate_job_summary
import network_diagnostics
import survey_scanner


class TestWifiToolkit(unittest.TestCase):
    def test_oui_lookup_known_vendors(self):
        self.assertIn("Ubiquiti", network_diagnostics.lookup_oui("78:8a:20:11:22:33"))
        self.assertIn("eero", network_diagnostics.lookup_oui("50-61-3F-AA-BB-CC"))
        self.assertIn("Netgear", network_diagnostics.lookup_oui("28:94:01:00:11:22"))

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
  192.168.1.1           50-61-3f-d8-f3-84     dynamic
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
                self.assertIn("RF Congestion", html_content)


if __name__ == "__main__":
    unittest.main()
