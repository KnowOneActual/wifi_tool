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

            # 2. Create mock survey_waypoints.csv
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

            # 3. Run summary generator
            generate_job_summary.generate_summary(tmpdir)

            txt_report = os.path.join(tmpdir, "ENGINEERING_HANDOFF_SUMMARY.txt")
            html_report = os.path.join(tmpdir, "PM_SITE_SURVEY_REPORT.html")

            self.assertTrue(os.path.exists(txt_report), "ENGINEERING_HANDOFF_SUMMARY.txt was not created")
            self.assertTrue(os.path.exists(html_report), "PM_SITE_SURVEY_REPORT.html was not created")

            with open(html_report, "r", encoding="utf-8") as f:
                html_content = f.read()
                self.assertIn("Beta_Test_Site", html_content)
                self.assertIn("TestCorpWiFi", html_content)
                self.assertIn("Lobby", html_content)


if __name__ == "__main__":
    unittest.main()
