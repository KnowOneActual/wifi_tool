"""
Continuous Wi-Fi Roaming Walk-Test Engine
Polls active Wi-Fi link telemetry (true RSSI, BSSID, band, channel, Tx/Rx PHY rate)
and fast single-packet default-gateway pings at ~0.5s intervals while a technician walks
between rooms/APs. Detects exact BSSID roams, disconnects, band downshifts, packet drops,
and latency spikes during handoffs.

100% Python standard library — zero external dependencies.
"""

import argparse
import csv
import json
import os
import threading
import time
from datetime import datetime

import network_diagnostics as nd

WALK_CSV_FIELDS = [
    "walk_id", "walk_label", "seq", "timestamp", "elapsed_sec",
    "ssid", "bssid", "band", "channel", "radio_type",
    "rssi_dbm", "tx_mbps", "rx_mbps", "gateway_ip", "gw_ms", "packet_lost", "event"
]


def analyze_walk_samples(samples: list, interval_sec: float = 0.5, walk_label: str = "Roaming Walk") -> dict:
    """
    Analyze a chronological list of walk-test samples and extract roam events,
    disconnects, handoff packet loss/outage estimates, and overall RSSI/ping stats.
    """
    if not samples:
        return {
            "walk_label": walk_label,
            "timestamp": datetime.now().isoformat(),
            "duration_sec": 0.0,
            "sample_count": 0,
            "roam_count": 0,
            "disconnect_count": 0,
            "min_rssi_dbm": None,
            "avg_rssi_dbm": None,
            "packet_loss_pct": 0.0,
            "avg_gw_ms": None,
            "max_gw_ms": None,
            "roam_events": [],
            "samples": [],
        }

    roam_events = []
    disconnect_count = 0
    prev_connected = None

    for idx, s in enumerate(samples):
        bssid = (s.get("bssid") or "").strip().lower()
        if not bssid:
            if prev_connected is not None:
                disconnect_count += 1
            continue

        if prev_connected is not None and bssid != prev_connected["bssid"]:
            # Inspect window [-2, +2] samples around handoff for packet loss & ping spikes
            w_start = max(0, idx - 2)
            w_end = min(len(samples), idx + 3)
            window = samples[w_start:w_end]
            dropped = sum(1 for x in window if x.get("packet_lost"))
            gw_vals = [x["gw_ms"] for x in window if x.get("gw_ms") is not None]
            peak_ping = max(gw_vals) if gw_vals else None
            est_outage_ms = round(dropped * interval_sec * 1000.0)

            had_disconnect = any(not (x.get("bssid") or "").strip() for x in samples[prev_connected["idx"] + 1 : idx])
            if had_disconnect or dropped >= 3:
                grade = "Drop Detected"
            elif dropped >= 1 or (peak_ping is not None and peak_ping >= 80.0):
                grade = "Minor Glitch"
            else:
                grade = "Seamless"

            roam_events.append({
                "seq": s.get("seq", idx + 1),
                "elapsed_sec": s.get("elapsed_sec", 0.0),
                "timestamp": s.get("timestamp", ""),
                "from_bssid": prev_connected["bssid"],
                "from_band": prev_connected["band"],
                "from_channel": prev_connected["channel"],
                "rssi_before_dbm": prev_connected["rssi_dbm"],
                "to_bssid": bssid,
                "to_band": s.get("band", ""),
                "to_channel": s.get("channel", ""),
                "rssi_after_dbm": s.get("rssi_dbm"),
                "band_changed": prev_connected["band"] != s.get("band", ""),
                "had_disconnect": had_disconnect,
                "dropped_pings": dropped,
                "est_outage_ms": est_outage_ms,
                "peak_ping_ms": peak_ping,
                "grade": grade,
            })

        prev_connected = {
            "idx": idx,
            "bssid": bssid,
            "band": s.get("band", ""),
            "channel": s.get("channel", ""),
            "rssi_dbm": s.get("rssi_dbm"),
        }

    rssis = [s["rssi_dbm"] for s in samples if s.get("rssi_dbm") is not None]
    gw_pings = [s["gw_ms"] for s in samples if s.get("gw_ms") is not None]
    lost_cnt = sum(1 for s in samples if s.get("packet_lost"))
    duration_sec = round(samples[-1].get("elapsed_sec", 0.0), 1)

    return {
        "walk_label": walk_label,
        "timestamp": samples[0].get("timestamp", datetime.now().isoformat()),
        "duration_sec": duration_sec,
        "sample_count": len(samples),
        "roam_count": len(roam_events),
        "disconnect_count": disconnect_count,
        "min_rssi_dbm": min(rssis) if rssis else None,
        "avg_rssi_dbm": round(sum(rssis) / len(rssis), 1) if rssis else None,
        "packet_loss_pct": round((lost_cnt / len(samples)) * 100.0, 1),
        "avg_gw_ms": round(sum(gw_pings) / len(gw_pings), 1) if gw_pings else None,
        "max_gw_ms": round(max(gw_pings), 1) if gw_pings else None,
        "roam_events": roam_events,
        "samples": samples,
    }


def save_walk_results(job_folder: str, summary: dict) -> str:
    """Persist walk-test raw samples to `roaming_walk_test.csv` and summary to `roaming_walk_summary.json`."""
    os.makedirs(job_folder, exist_ok=True)
    json_path = os.path.join(job_folder, "roaming_walk_summary.json")
    csv_path = os.path.join(job_folder, "roaming_walk_test.csv")

    existing = []
    if os.path.exists(json_path):
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                d = json.load(f)
                existing = d if isinstance(d, list) else [d]
        except Exception:
            existing = []

    walk_id = len(existing) + 1
    entry = dict(summary)
    entry["walk_id"] = walk_id
    existing.append(entry)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2)

    file_exists = os.path.exists(csv_path) and os.path.getsize(csv_path) > 0
    with open(csv_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=WALK_CSV_FIELDS, extrasaction="ignore")
        if not file_exists:
            writer.writeheader()
        for s in summary.get("samples", []):
            row = dict(s)
            row["walk_id"] = walk_id
            row["walk_label"] = summary.get("walk_label", "Roaming Walk")
            writer.writerow(row)

    return json_path


class RoamingWalkSession:
    """Thread-safe live continuous roaming walk-test session (used by Web UI & CLI)."""

    def __init__(self, job_folder: str, walk_label: str = "Roaming Walk", interval_sec: float = 0.5):
        self.job_folder = job_folder
        self.walk_label = (walk_label or "Roaming Walk").strip()
        self.interval_sec = max(0.25, float(interval_sec))
        self._stop_evt = threading.Event()
        self._lock = threading.Lock()
        self._samples = []
        self._running = False
        self._thread = None
        self._t0 = None
        self._last_bssid = None

    @property
    def is_running(self) -> bool:
        return self._running

    def start(self):
        if self._running:
            return
        self._running = True
        self._stop_evt.clear()
        self._t0 = time.perf_counter()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def _run_loop(self):
        seq = 0
        cached_gw = ""
        try:
            while not self._stop_evt.is_set():
                loop_start = time.perf_counter()
                seq += 1
                wifi = nd.get_active_wifi_interface()
                gw_ip = wifi.get("gateway") or cached_gw
                if wifi.get("gateway"):
                    cached_gw = wifi["gateway"]

                gw_ms = None
                packet_lost = True
                if gw_ip:
                    p = nd.ping_target(gw_ip, count=1, timeout_ms=250)
                    if p.get("avg_ms") is not None:
                        gw_ms = p["avg_ms"]
                        packet_lost = False

                bssid = (wifi.get("bssid") or "").strip().lower()
                event = ""
                if seq == 1:
                    event = "START"
                elif not bssid and self._last_bssid:
                    event = "DISCONNECT"
                elif bssid and not self._last_bssid:
                    event = "RECONNECT"
                elif bssid and self._last_bssid and bssid != self._last_bssid:
                    event = "ROAM"
                if bssid:
                    self._last_bssid = bssid
                elif event == "DISCONNECT":
                    self._last_bssid = ""

                sample = {
                    "seq": seq,
                    "timestamp": datetime.now().isoformat(),
                    "elapsed_sec": round(time.perf_counter() - self._t0, 2),
                    "ssid": wifi.get("ssid", ""),
                    "bssid": bssid,
                    "band": wifi.get("band", ""),
                    "channel": wifi.get("channel", ""),
                    "radio_type": wifi.get("radio_type", ""),
                    "rssi_dbm": wifi.get("true_rssi_dbm"),
                    "tx_mbps": wifi.get("tx_rate_mbps", 0.0),
                    "rx_mbps": wifi.get("rx_rate_mbps", 0.0),
                    "gateway_ip": gw_ip,
                    "gw_ms": gw_ms,
                    "packet_lost": packet_lost,
                    "event": event,
                }
                with self._lock:
                    self._samples.append(sample)

                elapsed_tick = time.perf_counter() - loop_start
                sleep_for = max(0.05, self.interval_sec - elapsed_tick)
                self._stop_evt.wait(sleep_for)
        finally:
            self._running = False

    def snapshot(self) -> dict:
        with self._lock:
            samples_copy = list(self._samples)
        summary = analyze_walk_samples(samples_copy, interval_sec=self.interval_sec, walk_label=self.walk_label)
        summary["running"] = self._running
        return summary

    def stop_and_save(self) -> dict:
        self._stop_evt.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        self._running = False
        summary = self.snapshot()
        summary["running"] = False
        if self.job_folder and summary["sample_count"] > 0:
            save_walk_results(self.job_folder, summary)
        return summary


def main():
    parser = argparse.ArgumentParser(description="Continuous Wi-Fi Roaming Walk-Test")
    parser.add_argument("--job-folder", required=True, help="Job folder to save roaming_walk_test.csv & summary JSON")
    parser.add_argument("--label", default="Roaming Walk", help="Walk route label (e.g. 'Kitchen -> Office')")
    parser.add_argument("--duration", type=int, default=30, help="Duration in seconds (default: 30)")
    parser.add_argument("--interval", type=float, default=0.5, help="Polling interval in seconds (default: 0.5)")
    args = parser.parse_args()

    print(f"[*] Starting {args.duration}s Continuous Roaming Walk-Test ('{args.label}')... Walk steadily now!")
    sess = RoamingWalkSession(args.job_folder, walk_label=args.label, interval_sec=args.interval)
    sess.start()
    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        print("\n[!] Stopping walk test early...")
    summary = sess.stop_and_save()
    print(f"[+] Walk complete: {summary['sample_count']} samples | {summary['roam_count']} roam(s) | "
          f"Loss: {summary['packet_loss_pct']}% | Min RSSI: {summary['min_rssi_dbm']} dBm | Max GW Ping: {summary['max_gw_ms']} ms")
    for r in summary["roam_events"]:
        print(f"    -> [{r['elapsed_sec']}s] {r['from_bssid']} (Ch {r['from_channel']}, {r['rssi_before_dbm']} dBm) "
              f"--> {r['to_bssid']} (Ch {r['to_channel']}, {r['rssi_after_dbm']} dBm) | "
              f"Dropped: {r['dropped_pings']} | Grade: {r['grade']}")


if __name__ == "__main__":
    main()
