"""
Zero-Dependency Local Web UI for the Wi-Fi Site Survey Toolkit
Runs on http://127.0.0.1:8765 using only the Python standard library.

Features for Field Deployment & Troubleshooting:
- Live RF Signal Meter & Connected Link Strip (auto-refresh + manual hardware scan)
- New Survey creation or Resume Existing Job
- One-Click Floor / Phase / Room Presets (eliminates field typos!)
- Inline Waypoint Correction: Rename, Re-scan in place, or Delete any logged waypoint
- Inline Job Metadata editing (fix blank/wrong Target SSID or site notes anytime)
- Floorplan Pin-Drop Heatmaps: Upload floorplans, click-to-pin or click-to-survey,
  live IDW 5/6 GHz & 2.4 GHz heatmap overlay, embedded into PM_SITE_SURVEY_REPORT.html
- Continuous Roaming Walk-Test Mode: Live 0.5s RSSI + Gateway Ping + Roam handoff graph
- One-Click Baseline Speedtest, LAN Discovery Sweep, Roaming Log Export, and PM HTML Report
- Built-in Before vs. After Job Comparison tab

100% Standard Library Python — Zero external pip dependencies required.
"""

import argparse
import base64
import csv
import json
import os
import re
import socket
import subprocess
import sys
import threading
import urllib.parse
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import compare_jobs
import generate_job_summary as gjs
import network_diagnostics as nd
import roaming_walk_test as rwt
import survey_scanner as sc

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_JOBS_DIR = os.path.join(BASE_DIR, "Jobs")

# Serialize hardware Wi-Fi scans / mutations so overlapping clicks never corrupt CSVs
_SURVEY_LOCK = threading.Lock()
_WALK_LOCK = threading.Lock()
_ACTIVE_WALK = {"session": None, "job_id": ""}


def _safe_job_path(jobs_root: str, job_id: str) -> str:
    """Resolve `job_id` strictly within `jobs_root`, blocking path traversal."""
    if not job_id or "/" in job_id or "\\" in job_id or ".." in job_id:
        raise ValueError("Invalid job_id")
    root_abs = os.path.abspath(jobs_root)
    cand = os.path.abspath(os.path.join(root_abs, job_id))
    if not cand.startswith(root_abs + os.sep):
        raise ValueError("Path escapes jobs directory")
    return cand


def _safe_floorplan_file(job_folder: str, filename: str) -> str:
    if not filename or "/" in filename or "\\" in filename or ".." in filename:
        raise ValueError("Invalid floorplan filename")
    fp_dir = os.path.abspath(os.path.join(job_folder, "floorplans"))
    cand = os.path.abspath(os.path.join(fp_dir, filename))
    if not cand.startswith(fp_dir + os.sep):
        raise ValueError("Invalid floorplan path")
    return cand


def _save_floorplan_data(job_folder: str, data: dict):
    path = os.path.join(job_folder, "floorplan_pins.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def upload_floorplan(jobs_root: str, job_id: str, label: str, filename: str, data_url: str) -> dict:
    """Decode a base64 data URL image and attach it as a floorplan for `job_id`."""
    job_folder = _safe_job_path(jobs_root, job_id)
    if not data_url or "," not in data_url:
        raise ValueError("Invalid image data_url")
    header, b64_part = data_url.split(",", 1)
    ext = os.path.splitext(filename or "")[1].lower().lstrip(".")
    if ext not in ("png", "jpg", "jpeg", "webp"):
        if "jpeg" in header or "jpg" in header:
            ext = "jpg"
        elif "webp" in header:
            ext = "webp"
        else:
            ext = "png"

    raw_bytes = base64.b64decode(b64_part)
    if len(raw_bytes) > 15 * 1024 * 1024:
        raise ValueError("Floorplan image exceeds 15 MB limit")

    clean_label = (label or os.path.splitext(os.path.basename(filename or "Floorplan"))[0]).strip() or "Floorplan"
    slug = re.sub(r"[^a-zA-Z0-9_-]+", "_", clean_label).strip("_").lower() or "floor"
    fp_data = gjs.load_floorplan_data(job_folder)
    existing_ids = {f.get("id") for f in fp_data["floorplans"]}
    fp_id = slug
    suffix = 2
    while fp_id in existing_ids:
        fp_id = f"{slug}_{suffix}"
        suffix += 1

    fp_dir = os.path.join(job_folder, "floorplans")
    os.makedirs(fp_dir, exist_ok=True)
    out_fname = f"{fp_id}.{ext}"
    with open(os.path.join(fp_dir, out_fname), "wb") as f:
        f.write(raw_bytes)

    fp_data["floorplans"].append({
        "id": fp_id,
        "label": clean_label,
        "filename": out_fname,
    })
    _save_floorplan_data(job_folder, fp_data)
    return get_job_state(jobs_root, job_id)


def upsert_floorplan_pin(jobs_root: str, job_id: str, floor_id: str, waypoint: str, x: float, y: float, waypoint_id: str = "") -> dict:
    """Place or move a waypoint pin on a floorplan using normalized [0.0, 1.0] coordinates."""
    job_folder = _safe_job_path(jobs_root, job_id)
    nx = max(0.0, min(1.0, float(x)))
    ny = max(0.0, min(1.0, float(y)))
    wp_clean = (waypoint or "").strip()
    wid_clean = str(waypoint_id or "").strip()
    if not floor_id or not wp_clean:
        raise ValueError("floor_id and waypoint are required")

    fp_data = gjs.load_floorplan_data(job_folder)
    pins = fp_data["pins"]
    updated = False
    for p in pins:
        same_floor = p.get("floor_id") == floor_id
        same_wp = (wid_clean and str(p.get("waypoint_id", "")).strip() == wid_clean) or (
            not wid_clean and (p.get("waypoint") or "").strip().lower() == wp_clean.lower()
        )
        if same_floor and same_wp:
            p["x"] = round(nx, 4)
            p["y"] = round(ny, 4)
            p["waypoint"] = wp_clean
            if wid_clean:
                p["waypoint_id"] = wid_clean
            updated = True
            break
    if not updated:
        pins.append({
            "floor_id": floor_id,
            "waypoint_id": wid_clean,
            "waypoint": wp_clean,
            "x": round(nx, 4),
            "y": round(ny, 4),
        })
    _save_floorplan_data(job_folder, fp_data)
    return get_job_state(jobs_root, job_id)


def delete_floorplan_pin(jobs_root: str, job_id: str, floor_id: str, waypoint: str = "", waypoint_id: str = "") -> dict:
    job_folder = _safe_job_path(jobs_root, job_id)
    fp_data = gjs.load_floorplan_data(job_folder)
    wid_clean = str(waypoint_id or "").strip()
    wp_low = (waypoint or "").strip().lower()
    new_pins = []
    for p in fp_data["pins"]:
        if p.get("floor_id") == floor_id:
            if wid_clean and str(p.get("waypoint_id", "")).strip() == wid_clean:
                continue
            if wp_low and (p.get("waypoint") or "").strip().lower() == wp_low:
                continue
        new_pins.append(p)
    fp_data["pins"] = new_pins
    _save_floorplan_data(job_folder, fp_data)
    return get_job_state(jobs_root, job_id)


def list_jobs(jobs_root: str) -> list:
    """Return metadata summaries for all job folders in `jobs_root` (newest first)."""
    if not os.path.isdir(jobs_root):
        return []
    out = []
    for entry in os.listdir(jobs_root):
        full = os.path.join(jobs_root, entry)
        if not os.path.isdir(full):
            continue
        meta = {}
        meta_p = os.path.join(full, "job_meta.json")
        if os.path.exists(meta_p):
            try:
                with open(meta_p, "r", encoding="utf-8-sig", errors="replace") as f:
                    meta = json.load(f)
            except Exception:
                meta = {}
        wp_records = gjs.load_waypoints_csv(os.path.join(full, "survey_waypoints.csv"))
        tel_rows = gjs.load_csv_generic(os.path.join(full, "waypoint_telemetry.csv"))
        batches = gjs._group_waypoint_batches(wp_records, tel_rows)
        out.append({
            "job_id": entry,
            "job_name": meta.get("job_name") or entry,
            "tech_name": meta.get("tech_name") or "",
            "target_ssid": meta.get("target_ssid") or gjs.detect_connected_ssid(full),
            "date": meta.get("date") or "",
            "notes": meta.get("notes") or "",
            "waypoint_count": len(batches),
            "has_report": os.path.exists(os.path.join(full, "PM_SITE_SURVEY_REPORT.html")),
            "mtime": os.path.getmtime(full),
        })
    out.sort(key=lambda x: (x["date"], x["mtime"]), reverse=True)
    return out


def create_new_job(jobs_root: str, job_name: str, tech_name: str, target_ssid: str, notes: str) -> dict:
    """Create a new job folder, save metadata, adapter info, and baseline RF scan."""
    os.makedirs(jobs_root, exist_ok=True)
    clean_job = re.sub(r"[^A-Za-z0-9_-]+", "_", (job_name or "").strip()).strip("_") or "Job"
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    job_id = f"{clean_job}_{stamp}"
    job_folder = os.path.join(jobs_root, job_id)
    os.makedirs(job_folder, exist_ok=True)

    meta = {
        "job_name": (job_name or clean_job).strip(),
        "tech_name": (tech_name or "Field_Tech").strip(),
        "target_ssid": (target_ssid or "").strip(),
        "notes": (notes or "").strip(),
        "date": stamp,
    }
    with open(os.path.join(job_folder, "job_meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    for fname, cmd in (
        ("wlan_interfaces.txt", ["netsh", "wlan", "show", "interfaces"]),
        ("wlan_drivers.txt", ["netsh", "wlan", "show", "drivers"]),
    ):
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=10)
            with open(os.path.join(job_folder, fname), "w", encoding="utf-8") as f:
                f.write(proc.stdout)
        except Exception:
            pass

    try:
        nets = sc.run_netsh_scan(live_refresh=True)
        with open(os.path.join(job_folder, "baseline_rf_scan.json"), "w", encoding="utf-8") as jf:
            json.dump(nets, jf, indent=2)
    except Exception:
        pass

    return get_job_state(jobs_root, job_id)


def update_job_meta(jobs_root: str, job_id: str, updates: dict) -> dict:
    """Update job_meta.json fields cleanly."""
    job_folder = _safe_job_path(jobs_root, job_id)
    meta_path = os.path.join(job_folder, "job_meta.json")
    meta = {}
    if os.path.exists(meta_path):
        try:
            with open(meta_path, "r", encoding="utf-8-sig", errors="replace") as f:
                meta = json.load(f)
        except Exception:
            meta = {}
    for key in ("job_name", "tech_name", "target_ssid", "notes"):
        if key in updates and updates[key] is not None:
            meta[key] = str(updates[key]).strip()
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    return get_job_state(jobs_root, job_id)


def _rewrite_csv(path: str, fieldnames: list, rows: list):
    """Atomically rewrite a CSV preserving exact column names."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in rows:
            writer.writerow(r)


def _find_matching_tel_index(batch: dict, tel_rows: list, used_tel: set):
    """Locate the telemetry row index corresponding to a waypoint batch."""
    b_wid = batch.get("waypoint_id", "")
    b_wp = batch.get("waypoint", "")
    b_dt = batch.get("first_dt")
    if b_wid:
        for idx, t in enumerate(tel_rows):
            if idx not in used_tel and str(t.get("waypoint_id", "") or "").strip() == b_wid:
                return idx
    best_diff = None
    best_idx = None
    for idx, t in enumerate(tel_rows):
        if idx in used_tel:
            continue
        if (t.get("waypoint") or "").strip() != b_wp:
            continue
        t_dt = gjs._parse_iso_ts(t.get("timestamp", ""))
        if b_dt is not None and t_dt is not None:
            diff = abs((t_dt - b_dt).total_seconds())
            if diff <= 90.0 and (best_diff is None or diff < best_diff):
                best_diff = diff
                best_idx = idx
        elif best_idx is None:
            best_idx = idx
    return best_idx


def modify_waypoint_batch(jobs_root: str, job_id: str, batch_idx: int, new_name: str = None, delete: bool = False) -> dict:
    """
    Rename or delete a specific waypoint batch across `survey_waypoints.csv`,
    `waypoint_telemetry.csv`, `speedtest_results.json`, and `floorplan_pins.json`.
    """
    job_folder = _safe_job_path(jobs_root, job_id)
    wp_csv = os.path.join(job_folder, "survey_waypoints.csv")
    tel_csv = os.path.join(job_folder, "waypoint_telemetry.csv")

    wp_records = gjs.load_waypoints_csv(wp_csv)
    tel_rows = gjs.load_csv_generic(tel_csv)
    batches = gjs._group_waypoint_batches(wp_records, tel_rows)

    if batch_idx < 0 or batch_idx >= len(batches):
        raise IndexError(f"Waypoint batch index {batch_idx} out of range")

    used_tel = set()
    batch_tel_map = []
    for b in batches:
        t_idx = _find_matching_tel_index(b, tel_rows, used_tel)
        if t_idx is not None:
            used_tel.add(t_idx)
        batch_tel_map.append(t_idx)

    target_batch = batches[batch_idx]
    target_tel_idx = batch_tel_map[batch_idx]
    old_name = target_batch["waypoint"]
    b_wid = target_batch.get("waypoint_id", "")
    clean_new = (new_name or "").strip()

    wp_headers = sc._get_existing_csv_headers(wp_csv) or (
        list(wp_records[0].keys()) if wp_records else gjs.CSV_STANDARD_HEADERS
    )
    new_wp_rows = []
    for idx, b in enumerate(batches):
        if idx == batch_idx:
            if delete:
                continue
            for r in b["records"]:
                row_copy = dict(r)
                if clean_new:
                    row_copy["waypoint"] = clean_new
                new_wp_rows.append(row_copy)
        else:
            new_wp_rows.extend(b["records"])
    _rewrite_csv(wp_csv, wp_headers, new_wp_rows)

    if tel_rows and os.path.exists(tel_csv):
        tel_headers = sc._get_existing_csv_headers(tel_csv) or list(tel_rows[0].keys())
        new_tel_rows = []
        for idx, t in enumerate(tel_rows):
            if idx == target_tel_idx:
                if delete:
                    continue
                t_copy = dict(t)
                if clean_new:
                    t_copy["waypoint"] = clean_new
                new_tel_rows.append(t_copy)
            else:
                new_tel_rows.append(t)
        _rewrite_csv(tel_csv, tel_headers, new_tel_rows)

    st_path = os.path.join(job_folder, "speedtest_results.json")
    if clean_new and not delete and os.path.exists(st_path):
        try:
            st_runs = gjs.load_json_safe(st_path)
            changed = False
            for sr in st_runs:
                if b_wid and str(sr.get("waypoint_id", "")) == b_wid:
                    sr["waypoint"] = clean_new
                    changed = True
                elif not b_wid and sr.get("waypoint") == old_name:
                    sr["waypoint"] = clean_new
                    changed = True
            if changed:
                with open(st_path, "w", encoding="utf-8") as sf:
                    json.dump(st_runs, sf, indent=2)
        except Exception:
            pass

    # Keep floorplan_pins.json synchronized on rename / delete
    fp_path = os.path.join(job_folder, "floorplan_pins.json")
    if os.path.exists(fp_path):
        fp_data = gjs.load_floorplan_data(job_folder)
        new_pins = []
        for p in fp_data["pins"]:
            matches = (b_wid and str(p.get("waypoint_id", "")).strip() == b_wid) or (
                not b_wid and (p.get("waypoint") or "").strip() == old_name
            )
            if matches:
                if delete:
                    continue
                if clean_new:
                    p["waypoint"] = clean_new
            new_pins.append(p)
        fp_data["pins"] = new_pins
        _save_floorplan_data(job_folder, fp_data)

    return get_job_state(jobs_root, job_id)


def get_job_state(jobs_root: str, job_id: str) -> dict:
    """Return full JSON state for a job folder for the Web UI."""
    job_folder = _safe_job_path(jobs_root, job_id)
    if not os.path.isdir(job_folder):
        raise FileNotFoundError(f"Job folder not found: {job_id}")

    meta = {}
    meta_path = os.path.join(job_folder, "job_meta.json")
    if os.path.exists(meta_path):
        try:
            with open(meta_path, "r", encoding="utf-8-sig", errors="replace") as f:
                meta = json.load(f)
        except Exception:
            meta = {}

    records = gjs.load_waypoints_csv(os.path.join(job_folder, "survey_waypoints.csv"))
    telemetry_rows = gjs.load_csv_generic(os.path.join(job_folder, "waypoint_telemetry.csv"))
    lan_devices = gjs.load_csv_generic(os.path.join(job_folder, "lan_devices.csv"))
    speedtests = gjs.load_json_safe(os.path.join(job_folder, "speedtest_results.json"))
    walk_tests = gjs.load_json_safe(os.path.join(job_folder, "roaming_walk_summary.json"))
    floorplan_data = gjs.load_floorplan_data(job_folder)
    controller_aps = gjs.load_ap_list_csv(job_folder)
    nic_info = gjs.parse_wlan_drivers(job_folder)

    target_ssid = (meta.get("target_ssid") or "").strip() or gjs.detect_connected_ssid(job_folder)

    def matches_target(ssid_val: str) -> bool:
        if not target_ssid:
            return ssid_val not in ("<Hidden / Broadcast>", "<Dead Zone>", "")
        return (ssid_val or "").strip().lower() == target_ssid.lower()

    use_sub = False
    if records and target_ssid:
        if not [r for r in records if matches_target(r.get("ssid", "")) and r.get("bssid")]:
            use_sub = True

    def rec_matches(r: dict) -> bool:
        s = r.get("ssid", "")
        return matches_target(s) or (use_sub and target_ssid and target_ssid.lower() in (s or "").lower())

    ap_names = {}
    target_recs = [r for r in records if rec_matches(r) and len(r.get("bssid", "")) >= 14]
    prefixes = sorted(set(gjs._normalize_ap_prefix(r.get("bssid", "")) for r in target_recs))
    for idx, pref in enumerate(prefixes, start=1):
        ctrl = controller_aps.get(pref, {})
        ap_names[pref] = ctrl.get("name") or f"AP {idx}"

    batches = gjs._group_waypoint_batches(records, telemetry_rows)
    wp_list = []
    for idx, b in enumerate(batches):
        wp_recs = b["records"]
        t_recs = [r for r in wp_recs if (rec_matches(r) if target_ssid else True) and r.get("bssid")]
        r5 = sorted(
            [r for r in t_recs if "5" in r.get("band", "") or "6" in r.get("band", "")],
            key=lambda x: gjs._safe_int(x.get("signal_dbm", -100)),
            reverse=True,
        )
        r24 = [r for r in t_recs if "2.4" in r.get("band", "")]
        best_5 = r5[0] if r5 else None
        second_5 = None
        if best_5:
            bp = gjs._normalize_ap_prefix(best_5.get("bssid", ""))
            for cand in r5[1:]:
                if gjs._normalize_ap_prefix(cand.get("bssid", "")) != bp:
                    second_5 = cand
                    break
        best_24 = max(r24, key=lambda x: gjs._safe_int(x.get("signal_dbm", -100))) if r24 else None
        tel = b["telemetry"]

        def _fmt_sig(rec):
            if not rec:
                return None
            pref = gjs._normalize_ap_prefix(rec.get("bssid", ""))
            return {
                "dbm": gjs._safe_int(rec.get("signal_dbm", -100)),
                "channel": rec.get("channel", ""),
                "width": rec.get("channel_width_mhz", ""),
                "ap": ap_names.get(pref, rec.get("bssid", "")[-5:]),
                "bssid": rec.get("bssid", ""),
            }

        ts_raw = b["first_ts"] or ""
        wp_list.append({
            "batch_idx": idx,
            "waypoint_id": b["waypoint_id"],
            "waypoint": b["waypoint"],
            "display_name": b["display_name"],
            "time": ts_raw[11:19] if len(ts_raw) >= 19 else ts_raw,
            "bssid_count": len(wp_recs),
            "best_5": _fmt_sig(best_5),
            "second_5": _fmt_sig(second_5),
            "best_24": _fmt_sig(best_24),
            "telemetry": {
                "connected_ssid": tel.get("connected_ssid", ""),
                "tx_mbps": tel.get("tx_rate_mbps", ""),
                "rx_mbps": tel.get("rx_rate_mbps", ""),
                "true_rssi_dbm": tel.get("true_rssi_dbm", ""),
                "gw_avg_ms": tel.get("gw_avg_ms", ""),
                "wan_avg_ms": tel.get("wan_avg_ms", ""),
                "download_mbps": tel.get("download_mbps", ""),
            } if tel else {},
        })

    # Attach serving URLs to floorplan metadata
    fps_out = []
    for fp in floorplan_data.get("floorplans", []):
        fp_copy = dict(fp)
        fp_copy["url"] = f"/jobs/{urllib.parse.quote(job_id)}/floorplans/{urllib.parse.quote(fp.get('filename', ''))}"
        fps_out.append(fp_copy)

    # Compact walk summaries (without full sample arrays to keep job state snappy)
    walks_compact = [
        {k: v for k, v in w.items() if k != "samples"}
        for w in walk_tests if isinstance(w, dict)
    ]

    return {
        "job_id": job_id,
        "folder": job_folder,
        "meta": {
            "job_name": meta.get("job_name") or job_id,
            "tech_name": meta.get("tech_name") or "",
            "target_ssid": target_ssid,
            "notes": meta.get("notes") or "",
            "date": meta.get("date") or "",
        },
        "nic_warnings": nic_info.get("warnings", []),
        "ap_count": len(prefixes),
        "controller_ap_list_loaded": bool(controller_aps),
        "waypoints": wp_list,
        "floorplans": fps_out,
        "pins": floorplan_data.get("pins", []),
        "walk_tests": walks_compact,
        "speedtests": speedtests,
        "lan_count": len(lan_devices),
        "has_report": os.path.exists(os.path.join(job_folder, "PM_SITE_SURVEY_REPORT.html")),
        "has_roaming_log": os.path.exists(os.path.join(job_folder, "wlan_roaming_events.txt")),
    }


UI_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Wi-Fi Site Survey — Field Console</title>
<style>
  :root {
    --bg: #0f172a; --card: #1e293b; --card2: #263349; --border: #334155;
    --text: #f1f5f9; --muted: #94a3b8; --accent: #3b82f6; --accent2: #2563eb;
    --good: #22c55e; --warn: #f59e0b; --bad: #ef4444;
  }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); }
  header { background: #0b1220; border-bottom: 1px solid var(--border); padding: 14px 22px; display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 12px; }
  header h1 { margin: 0; font-size: 18px; letter-spacing: 0.2px; }
  .tabs { display: flex; flex-wrap: wrap; gap: 8px; }
  .tab-btn { background: var(--card); color: var(--text); border: 1px solid var(--border); padding: 7px 13px; border-radius: 8px; cursor: pointer; font-weight: 600; font-size: 13px; }
  .tab-btn.active { background: var(--accent); border-color: var(--accent); color: #fff; }
  .wrap { max-width: 1240px; margin: 0 auto; padding: 18px; display: grid; gap: 16px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 16px 18px; }
  .card h2 { margin: 0 0 12px 0; font-size: 15px; color: #cbd5e1; display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 8px; }
  .live-bar { display: grid; grid-template-columns: 200px repeat(4, 1fr) auto; gap: 12px; align-items: center; }
  @media (max-width: 900px) { .live-bar { grid-template-columns: 1fr 1fr; } }
  .meter-box { background: #0b1220; border: 1px solid var(--border); border-radius: 10px; padding: 10px 12px; }
  .meter-val { font-size: 24px; font-weight: 800; line-height: 1.1; }
  .meter-bar-bg { height: 7px; background: #334155; border-radius: 99px; margin-top: 6px; overflow: hidden; }
  .meter-bar { height: 100%; width: 0%; transition: width 0.3s; }
  .kv-label { font-size: 11px; text-transform: uppercase; color: var(--muted); display: block; }
  .kv-val { font-size: 13.5px; font-weight: 600; }
  .row { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
  input, select { background: #0f172a; color: var(--text); border: 1px solid var(--border); border-radius: 8px; padding: 8px 10px; font-size: 13.5px; }
  input:focus, select:focus { outline: 2px solid var(--accent); border-color: var(--accent); }
  button { background: var(--accent); color: #fff; border: none; border-radius: 8px; padding: 8px 14px; font-weight: 600; font-size: 13px; cursor: pointer; }
  button:hover { background: var(--accent2); }
  button:disabled { opacity: 0.5; cursor: not-allowed; }
  button.sec { background: var(--card2); border: 1px solid var(--border); color: var(--text); }
  button.sec:hover { background: #334155; }
  button.danger { background: #7f1d1d; color: #fecaca; }
  button.danger:hover { background: #991b1b; }
  button.good { background: #15803d; }
  button.good:hover { background: #166534; }
  .chip-group { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 10px; }
  .chip { background: #0f172a; border: 1px solid var(--border); color: #cbd5e1; padding: 6px 11px; border-radius: 99px; font-size: 12.5px; cursor: pointer; }
  .chip:hover { border-color: var(--accent); color: #fff; }
  .chip.active { background: var(--accent); border-color: var(--accent); color: #fff; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 9px 10px; border-bottom: 1px solid var(--border); vertical-align: middle; }
  th { font-size: 11px; text-transform: uppercase; color: var(--muted); background: #0f172a; }
  .sub { font-size: 11.5px; color: var(--muted); }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 99px; font-weight: 700; font-size: 11.5px; }
  .b-good { background: #14532d; color: #86efac; }
  .b-warn { background: #78350f; color: #fde68a; }
  .b-bad { background: #7f1d1d; color: #fecaca; }
  .b-purple { background: #4c1d95; color: #ddd6fe; }
  .toast { position: fixed; bottom: 18px; right: 18px; background: #0b1220; border: 1px solid var(--accent); color: #fff; padding: 10px 16px; border-radius: 10px; font-size: 13px; box-shadow: 0 8px 24px rgba(0,0,0,0.4); display: none; z-index: 99; }
  .hidden { display: none !important; }
  .warn-banner { background: #451a03; border: 1px solid #d97706; color: #fde68a; border-radius: 8px; padding: 9px 12px; font-size: 12.5px; margin-bottom: 10px; }
  .fp-stage { position: relative; display: inline-block; max-width: 100%; border: 2px solid var(--border); border-radius: 10px; overflow: hidden; cursor: crosshair; background: #0b1220; }
  .fp-stage img { display: block; max-width: 100%; max-height: 620px; width: auto; height: auto; user-select: none; }
  .fp-stage canvas { position: absolute; top: 0; left: 0; width: 100%; height: 100%; pointer-events: none; }
  .stat-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin-bottom: 12px; }
  @media (max-width: 850px) { .stat-grid { grid-template-columns: repeat(2, 1fr); } }
  .stat-pill { background: #0f172a; border: 1px solid var(--border); border-radius: 8px; padding: 9px 12px; }
  .stat-pill strong { font-size: 18px; display: block; margin-top: 2px; }
</style>
</head>
<body>
<header>
  <h1>Wi-Fi Site Survey — Field Console</h1>
  <div class="tabs">
    <button class="tab-btn active" id="tabSurveyBtn" onclick="switchTab('survey')">1. Survey &amp; Edit</button>
    <button class="tab-btn" id="tabFloorplanBtn" onclick="switchTab('floorplan')">2. Floorplan Heatmap</button>
    <button class="tab-btn" id="tabWalkBtn" onclick="switchTab('walk')">3. Roaming Walk-Test</button>
    <button class="tab-btn" id="tabCompareBtn" onclick="switchTab('compare')">4. Before vs. After</button>
  </div>
</header>

<div class="wrap">
  <!-- LIVE SIGNAL METER -->
  <div class="card">
    <div class="live-bar">
      <div class="meter-box">
        <span class="kv-label">Active True RSSI</span>
        <div class="meter-val" id="liveRssi">— dBm</div>
        <div class="meter-bar-bg"><div class="meter-bar" id="liveRssiBar"></div></div>
      </div>
      <div><span class="kv-label">Connected SSID</span><span class="kv-val" id="liveSsid">—</span></div>
      <div><span class="kv-label">Connected BSSID / Ch</span><span class="kv-val" id="liveBssid">—</span></div>
      <div><span class="kv-label">Link Rate (Tx / Rx)</span><span class="kv-val" id="liveRate">—</span></div>
      <div><span class="kv-label">Strongest Scan 5/6G</span><span class="kv-val" id="liveBest">—</span></div>
      <div class="row">
        <button class="sec" onclick="pollLive(true)" id="btnForceScan">Force RF Scan</button>
      </div>
    </div>
  </div>

  <!-- ACTIVE JOB HEADER (Shared across Survey, Floorplan, and Walk-Test tabs) -->
  <div class="card" id="jobHeaderCard">
    <h2>
      <span>Active Job Folder</span>
      <div class="row">
        <select id="jobSelect" onchange="loadJob(this.value)" style="min-width:280px;"></select>
        <button class="sec" onclick="toggleNewJobForm()">+ New Survey Job</button>
        <button onclick="runAction('generate-report')" id="btnTopRep">Generate &amp; Open PM Report</button>
      </div>
    </h2>

    <div id="newJobForm" class="hidden" style="background:#0f172a; padding:12px; border-radius:8px; margin-bottom:12px;">
      <div class="row">
        <input id="njName" placeholder="Client / Job Name (e.g. Smith_Residence)" style="flex:1; min-width:180px;">
        <input id="njTech" placeholder="Tech Name" value="Field_Tech" style="width:140px;">
        <input id="njSsid" placeholder="Target SSID" style="flex:1; min-width:150px;">
        <input id="njNotes" placeholder="Site Notes (optional)" style="flex:1; min-width:180px;">
        <button class="good" onclick="createJob()" id="btnCreateJob">Create &amp; Run Baseline Scan</button>
      </div>
    </div>

    <div id="jobMetaBar" class="hidden">
      <div id="nicWarnings"></div>
      <div class="row">
        <input id="emName" placeholder="Job Name" style="width:180px;">
        <input id="emTech" placeholder="Tech" style="width:120px;">
        <input id="emSsid" placeholder="Target SSID" style="width:170px;">
        <input id="emNotes" placeholder="Site Notes" style="flex:1; min-width:200px;">
        <button class="sec" onclick="saveJobMeta()">Save Meta</button>
      </div>
    </div>
  </div>

  <!-- TAB 1: SURVEY & CORRECTION -->
  <div id="viewSurvey" style="display:grid; gap:16px;">
    <div class="card">
      <h2>Log Room / Waypoint <span class="sub" id="activeJobStats"></span></h2>
      <div class="sub" style="margin-bottom:6px;">Floor / Area Prefix:</div>
      <div class="chip-group" id="floorChips"></div>
      <div class="sub" style="margin-bottom:6px;">Phase Tag (Optional — great for troubleshooting Before/After):</div>
      <div class="chip-group" id="phaseChips"></div>
      <div class="sub" style="margin-bottom:6px;">One-Click Room Presets (click to fill):</div>
      <div class="chip-group" id="roomChips"></div>

      <div class="row" style="margin-top:10px;">
        <input id="wpInput" placeholder="Room / Waypoint Name (e.g. 1st Fl - Kitchen)" style="flex:1; min-width:240px; font-size:15px; padding:10px 12px;">
        <label style="font-size:13px; display:flex; align-items:center; gap:6px; cursor:pointer;">
          <input type="checkbox" id="wpSpeedtest"> Run Speedtest here
        </label>
        <button class="good" id="btnCapture" onclick="captureWaypoint()" style="padding:10px 20px; font-size:14px;">Capture Waypoint</button>
      </div>
    </div>

    <div class="card">
      <h2>
        <span>Recorded Waypoints (Inline Edit / Re-Scan / Delete)</span>
        <div class="row">
          <button class="sec" onclick="runAction('speedtest')">Run Baseline Speedtest</button>
          <button class="sec" onclick="runAction('lan-sweep')">LAN Discovery Sweep</button>
          <button class="sec" onclick="runAction('export-roaming')">Export Roaming Log</button>
        </div>
      </h2>
      <div style="overflow-x:auto;">
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Time</th>
              <th>Room / Waypoint</th>
              <th>Primary 5/6 GHz</th>
              <th>2nd 5/6 GHz</th>
              <th>Best 2.4 GHz</th>
              <th>Active Link &amp; Ping</th>
              <th>Correct / Actions</th>
            </tr>
          </thead>
          <tbody id="wpTableBody">
            <tr><td colspan="8" class="sub">Select or create a job above to begin logging waypoints.</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- TAB 2: FLOORPLAN PIN-DROP HEATMAP -->
  <div id="viewFloorplan" class="hidden" style="display:grid; gap:16px;">
    <div class="card">
      <h2>
        <span>Floorplan Pin-Drop RF Heatmap</span>
        <div class="row">
          <input id="fpLabel" placeholder="Floor Name (e.g. 1st Floor)" style="width:170px;">
          <input type="file" id="fpFile" accept="image/png,image/jpeg,image/webp" style="max-width:230px;">
          <button class="good" onclick="uploadFloorplan()">Upload Floorplan</button>
        </div>
      </h2>

      <div class="row" style="margin-bottom:12px; background:#0f172a; padding:10px 12px; border-radius:8px;">
        <select id="fpSelect" onchange="selectFloorplan(this.value)" style="min-width:180px;"></select>
        <select id="fpMode" onchange="updateFpModeUI()">
          <option value="pin_existing">Mode: Click Map to Pin Existing Waypoint</option>
          <option value="capture_click">Mode: Click Map to Capture NEW Waypoint</option>
        </select>
        <select id="fpWaypointSelect" style="min-width:200px;"></select>
        <input id="fpNewWpName" class="hidden" placeholder="New room name to capture at click..." style="min-width:220px;">
        <select id="fpBand" onchange="drawFloorplanHeatmap()">
          <option value="5">Heatmap Band: 5 / 6 GHz</option>
          <option value="24">Heatmap Band: 2.4 GHz</option>
        </select>
        <label style="font-size:12.5px; display:flex; align-items:center; gap:5px;">
          Opacity <input type="range" id="fpOpacity" min="0" max="100" value="65" oninput="drawFloorplanHeatmap()" style="width:80px; padding:0;">
        </label>
      </div>

      <div id="fpEmptyMsg" class="sub" style="padding:20px 0;">Upload a PNG/JPG floorplan image above, then click anywhere on the plan to drop waypoint pins and generate an interactive RF coverage heatmap (auto-embedded in <code>PM_SITE_SURVEY_REPORT.html</code>).</div>

      <div id="fpStageWrap" class="hidden" style="text-align:center;">
        <div class="fp-stage" id="fpStage" onclick="onFloorplanClick(event)">
          <img id="fpImg" src="" onload="drawFloorplanHeatmap()" alt="Floorplan">
          <canvas id="fpCanvas"></canvas>
        </div>
        <div class="sub" style="margin-top:8px;">
          <span class="badge b-good">&ge; -65 dBm Strong</span>
          <span class="badge b-warn">-66 to -75 dBm Fair</span>
          <span class="badge b-bad">&le; -76 dBm Weak</span>
          &bull; Click anywhere on the map to place/move the selected waypoint pin.
        </div>
      </div>

      <div id="fpPinsList" style="margin-top:14px;"></div>
    </div>
  </div>

  <!-- TAB 3: CONTINUOUS ROAMING WALK-TEST -->
  <div id="viewWalk" class="hidden" style="display:grid; gap:16px;">
    <div class="card">
      <h2>
        <span>Continuous Roaming Walk-Test (Live 0.5s RSSI + Gateway Ping + Handoff Detection)</span>
        <div class="row">
          <input id="walkLabel" placeholder="Walk Route Label (e.g. Kitchen -> Master Bed)" value="1st Fl -> 2nd Fl Walk" style="min-width:260px;">
          <button class="good" id="btnWalkStart" onclick="startWalkTest()">Start Walk-Test</button>
          <button class="danger hidden" id="btnWalkStop" onclick="stopWalkTest()">Stop &amp; Save Walk-Test</button>
        </div>
      </h2>

      <div class="stat-grid">
        <div class="stat-pill"><span class="kv-label">Elapsed / Samples</span><strong id="wkElapsed">0.0s (0)</strong></div>
        <div class="stat-pill"><span class="kv-label">BSSID Roams</span><strong id="wkRoams">0</strong></div>
        <div class="stat-pill"><span class="kv-label">GW Packet Loss</span><strong id="wkLoss">0.0%</strong></div>
        <div class="stat-pill"><span class="kv-label">Min / Avg RSSI</span><strong id="wkRssi">—</strong></div>
        <div class="stat-pill"><span class="kv-label">Avg / Max GW Ping</span><strong id="wkPing">—</strong></div>
      </div>

      <canvas id="walkChart" width="1140" height="270" style="width:100%; height:270px; background:#0b1220; border:1px solid var(--border); border-radius:10px; display:block;"></canvas>
      <div class="sub" style="margin-top:6px;">Top: True RSSI (Blue, dashed amber = -67 dBm, vertical purple = BSSID Roam) &bull; Bottom: Gateway Ping ms (Green bars, red spikes = dropped ping)</div>

      <h2 style="margin-top:16px;">Detected Roam Handoffs (Live &amp; Saved Walks)</h2>
      <div style="overflow-x:auto;">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>From AP (Ch / RSSI)</th>
              <th>To AP (Ch / RSSI)</th>
              <th>Dropped Pings (~Outage)</th>
              <th>Peak GW Ping</th>
              <th>Grade</th>
            </tr>
          </thead>
          <tbody id="walkEventsBody">
            <tr><td colspan="6" class="sub">Click <strong>Start Walk-Test</strong> and walk steadily between rooms/APs. All handoffs and ping drops appear live and save directly to the active job folder.</td></tr>
          </tbody>
        </table>
      </div>
      <div id="savedWalksList" class="sub" style="margin-top:12px;"></div>
    </div>
  </div>

  <!-- TAB 4: COMPARE -->
  <div id="viewCompare" class="hidden" style="display:grid; gap:16px;">
    <div class="card">
      <h2>Before vs. After Site Survey Comparison</h2>
      <div class="row">
        <div>
          <span class="kv-label">Before (Baseline) Job</span>
          <select id="cmpBefore" style="min-width:280px;"></select>
        </div>
        <div>
          <span class="kv-label">After (Post-Fix) Job</span>
          <select id="cmpAfter" style="min-width:280px;"></select>
        </div>
        <div style="align-self:flex-end;">
          <button onclick="runComparison()" id="btnCompare">Compare Jobs</button>
        </div>
      </div>
    </div>
    <div class="card hidden" id="cmpResultsCard">
      <h2>
        <span>Comparison Summary</span>
        <a id="cmpReportLink" href="#" target="_blank" style="color:#93c5fd; font-size:13px;">Open Printable HTML Report &nearr;</a>
      </h2>
      <div id="cmpSummaryBar" class="row" style="margin-bottom:14px; gap:18px;"></div>
      <div style="overflow-x:auto;">
        <table>
          <thead>
            <tr>
              <th>Room / Waypoint</th>
              <th>Before 5/6 GHz</th>
              <th>After 5/6 GHz</th>
              <th>5/6 GHz Delta</th>
              <th>Before 2.4 GHz</th>
              <th>After 2.4 GHz</th>
              <th>2.4 GHz Delta</th>
            </tr>
          </thead>
          <tbody id="cmpTableBody"></tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
const FLOORS = ["", "Basement", "1st Fl", "2nd Fl", "3rd Fl", "Outdoor", "Garage"];
const PHASES = ["", "Pre-Fix", "Post-Fix"];
const ROOMS = [
  "Rack / Head-End", "Living Room", "Family Room", "Kitchen", "Dining Room",
  "Office", "Primary Bed", "Bedroom 2", "Media / Game Room",
  "Patio / Deck", "Backyard", "Hallway / Landing"
];

let selectedFloor = "";
let selectedPhase = "";
let currentJobId = "";
let currentJobState = null;
let selectedFloorplanId = "";
let walkPollTimer = null;
let allJobs = [];

function toast(msg) {
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.style.display = "block";
  clearTimeout(window._toastTimer);
  window._toastTimer = setTimeout(() => { el.style.display = "none"; }, 3800);
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function switchTab(tab) {
  ["survey", "floorplan", "walk", "compare"].forEach(t => {
    const viewId = "view" + t.charAt(0).toUpperCase() + t.slice(1);
    const btnId = "tab" + t.charAt(0).toUpperCase() + t.slice(1) + "Btn";
    document.getElementById(viewId).classList.toggle("hidden", t !== tab);
    document.getElementById(btnId).classList.toggle("active", t === tab);
  });
  document.getElementById("jobHeaderCard").classList.toggle("hidden", tab === "compare");
  if (tab === "floorplan") setTimeout(drawFloorplanHeatmap, 50);
}

function renderChips() {
  document.getElementById("floorChips").innerHTML = FLOORS.map(f =>
    `<span class="chip ${selectedFloor === f ? 'active' : ''}" onclick="setFloor('${esc(f)}')">${f || 'No Floor Prefix'}</span>`
  ).join("");
  document.getElementById("phaseChips").innerHTML = PHASES.map(p =>
    `<span class="chip ${selectedPhase === p ? 'active' : ''}" onclick="setPhase('${esc(p)}')">${p || 'No Phase Tag'}</span>`
  ).join("");
  document.getElementById("roomChips").innerHTML = ROOMS.map(r =>
    `<span class="chip" onclick="applyRoomPreset('${esc(r)}')">${esc(r)}</span>`
  ).join("");
}

function setFloor(f) { selectedFloor = f; renderChips(); }
function setPhase(p) { selectedPhase = p; renderChips(); }
function applyRoomPreset(room) {
  const parts = [];
  if (selectedPhase) parts.push(`[${selectedPhase}]`);
  if (selectedFloor) parts.push(selectedFloor);
  parts.push(room);
  document.getElementById("wpInput").value = parts.join(" - ").replace("] - ", "] ");
  document.getElementById("wpInput").focus();
}

function toggleNewJobForm() {
  document.getElementById("newJobForm").classList.toggle("hidden");
}

async function api(url, opts = {}) {
  const res = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

async function pollLive(forceRefresh = false) {
  const btn = document.getElementById("btnForceScan");
  if (forceRefresh) { btn.disabled = true; btn.textContent = "Scanning..."; }
  try {
    const d = await api(`/api/live${forceRefresh ? '?refresh=1' : ''}`);
    const w = d.wifi || {};
    const rssi = w.true_rssi_dbm;
    const rssiEl = document.getElementById("liveRssi");
    const barEl = document.getElementById("liveRssiBar");
    if (rssi !== null && rssi !== undefined) {
      rssiEl.textContent = `${rssi} dBm`;
      const pct = Math.max(0, Math.min(100, Math.round(((rssi + 95) / 55) * 100)));
      barEl.style.width = `${pct}%`;
      barEl.style.background = rssi >= -65 ? "var(--good)" : (rssi >= -74 ? "var(--warn)" : "var(--bad)");
    } else {
      rssiEl.textContent = "Disconnected";
      barEl.style.width = "0%";
    }
    document.getElementById("liveSsid").textContent = w.ssid || "Disconnected";
    document.getElementById("liveBssid").textContent = w.bssid ? `${w.bssid} (${w.band} Ch ${w.channel})` : "—";
    document.getElementById("liveRate").textContent = w.tx_rate_mbps ? `${w.tx_rate_mbps} / ${w.rx_rate_mbps} Mbps` : "—";
    if (d.best_5g) {
      const b = d.best_5g;
      document.getElementById("liveBest").textContent = `${b.ssid} (${b.signal_dbm} dBm, Ch ${b.channel}${b.channel_width_mhz ? ' @' + b.channel_width_mhz + 'M' : ''})`;
    } else {
      document.getElementById("liveBest").textContent = "—";
    }
    if (!document.getElementById("njSsid").value && w.ssid) {
      document.getElementById("njSsid").value = w.ssid;
    }
  } catch (e) {
    if (forceRefresh) toast("Live scan error: " + e.message);
  } finally {
    if (forceRefresh) { btn.disabled = false; btn.textContent = "Force RF Scan"; }
  }
}

async function refreshJobsList(selectJobId = null) {
  const data = await api("/api/jobs");
  allJobs = data.jobs || [];
  const opts = allJobs.map(j =>
    `<option value="${esc(j.job_id)}">${esc(j.job_name)} (${esc(j.target_ssid || 'ALL')} • ${j.waypoint_count} rooms) [${esc(j.date)}]</option>`
  ).join("");
  document.getElementById("jobSelect").innerHTML = opts || `<option value="">-- No Jobs Yet --</option>`;
  document.getElementById("cmpBefore").innerHTML = opts;
  document.getElementById("cmpAfter").innerHTML = opts;
  if (allJobs.length >= 2) {
    document.getElementById("cmpBefore").value = allJobs[1].job_id;
    document.getElementById("cmpAfter").value = allJobs[0].job_id;
  }
  const target = selectJobId || currentJobId || (allJobs[0] && allJobs[0].job_id);
  if (target) {
    document.getElementById("jobSelect").value = target;
    await loadJob(target);
  }
}

async function createJob() {
  const btn = document.getElementById("btnCreateJob");
  const name = document.getElementById("njName").value.trim();
  if (!name) { toast("Please enter a Client / Job Name."); return; }
  btn.disabled = true; btn.textContent = "Creating...";
  try {
    const st = await api("/api/jobs", {
      method: "POST",
      body: JSON.stringify({
        job_name: name,
        tech_name: document.getElementById("njTech").value.trim() || "Field_Tech",
        target_ssid: document.getElementById("njSsid").value.trim(),
        notes: document.getElementById("njNotes").value.trim(),
      })
    });
    document.getElementById("newJobForm").classList.add("hidden");
    document.getElementById("njName").value = "";
    document.getElementById("njNotes").value = "";
    toast(`Created job '${st.meta.job_name}' with live baseline scan.`);
    await refreshJobsList(st.job_id);
  } catch (e) {
    toast("Error creating job: " + e.message);
  } finally {
    btn.disabled = false; btn.textContent = "Create & Run Baseline Scan";
  }
}

async function loadJob(jobId) {
  if (!jobId) return;
  currentJobId = jobId;
  selectedFloorplanId = "";
  try {
    const st = await api(`/api/jobs/${encodeURIComponent(jobId)}`);
    renderJobState(st);
  } catch (e) {
    toast("Error loading job: " + e.message);
  }
}

function renderJobState(st) {
  currentJobState = st;
  document.getElementById("jobMetaBar").classList.remove("hidden");
  document.getElementById("emName").value = st.meta.job_name || "";
  document.getElementById("emTech").value = st.meta.tech_name || "";
  document.getElementById("emSsid").value = st.meta.target_ssid || "";
  document.getElementById("emNotes").value = st.meta.notes || "";

  document.getElementById("nicWarnings").innerHTML = (st.nic_warnings || []).map(w => `<div class="warn-banner">${esc(w)}</div>`).join("");

  document.getElementById("activeJobStats").textContent =
    `${st.waypoints.length} waypoints • ${st.ap_count} target APs • ${st.lan_count} LAN hosts` +
    (st.floorplans.length ? ` • ${st.floorplans.length} floorplan(s)` : "") +
    (st.walk_tests.length ? ` • ${st.walk_tests.length} walk(s)` : "");

  // Render Waypoints Table
  const tbody = document.getElementById("wpTableBody");
  if (!st.waypoints.length) {
    tbody.innerHTML = `<tr><td colspan="8" class="sub">No waypoints logged yet for this job. Pick a floor &amp; room above and click Capture Waypoint!</td></tr>`;
  } else {
    tbody.innerHTML = st.waypoints.map((w, i) => {
      const fmtSig = (s) => {
        if (!s) return `<span class="badge b-bad">None</span>`;
        const cls = s.dbm >= -67 ? "b-good" : (s.dbm >= -74 ? "b-warn" : "b-bad");
        const wTag = s.width ? ` @${s.width}M` : "";
        return `<span class="badge ${cls}">${s.dbm} dBm</span><br><span class="sub">${esc(s.ap)} • Ch ${esc(s.channel)}${wTag}</span>`;
      };
      const tel = w.telemetry || {};
      const telHtml = tel.tx_mbps
        ? `${esc(tel.tx_mbps)}/${esc(tel.rx_mbps)} Mbps<br><span class="sub">GW ${esc(tel.gw_avg_ms)}ms | WAN ${esc(tel.wan_avg_ms)}ms</span>` +
          (tel.download_mbps ? `<br><strong>DL ${esc(tel.download_mbps)} Mbps</strong>` : "")
        : `<span class="sub">—</span>`;
      return `<tr>
        <td>${i + 1}</td>
        <td class="sub">${esc(w.time)}</td>
        <td><strong>${esc(w.display_name)}</strong><br><span class="sub">${w.bssid_count} BSSIDs</span></td>
        <td>${fmtSig(w.best_5)}</td>
        <td>${w.second_5 ? fmtSig(w.second_5) : '<span class="sub">1 AP only</span>'}</td>
        <td>${fmtSig(w.best_24)}</td>
        <td>${telHtml}</td>
        <td>
          <div class="row" style="gap:5px;">
            <button class="sec" onclick="renameWaypoint(${w.batch_idx}, '${esc(w.waypoint)}')">Rename</button>
            <button class="sec" onclick="rescanWaypoint(${w.batch_idx}, '${esc(w.waypoint)}')">Re-Scan</button>
            <button class="danger" onclick="deleteWaypoint(${w.batch_idx}, '${esc(w.display_name)}')">Del</button>
          </div>
        </td>
      </tr>`;
    }).join("");
  }

  // Update Floorplan tab controls
  renderFloorplanControls(st);

  // Update saved walks summary
  const savedDiv = document.getElementById("savedWalksList");
  if (st.walk_tests && st.walk_tests.length) {
    savedDiv.innerHTML = "<strong>Saved Walk-Tests in this Job:</strong> " + st.walk_tests.map(w =>
      `${esc(w.walk_label)} (${w.duration_sec}s, ${w.roam_count} roams, ${w.packet_loss_pct}% loss)`
    ).join(" &bull; ");
  } else {
    savedDiv.innerHTML = "";
  }
}

/* ==================== FLOORPLAN PIN-DROP HEATMAP ==================== */
function updateFpModeUI() {
  const mode = document.getElementById("fpMode").value;
  document.getElementById("fpWaypointSelect").classList.toggle("hidden", mode !== "pin_existing");
  document.getElementById("fpNewWpName").classList.toggle("hidden", mode !== "capture_click");
}

function renderFloorplanControls(st) {
  const fpSel = document.getElementById("fpSelect");
  const fps = st.floorplans || [];
  fpSel.innerHTML = fps.map(f => `<option value="${esc(f.id)}">${esc(f.label)} (${esc(f.filename)})</option>`).join("") ||
    `<option value="">-- No Floorplans Uploaded --</option>`;

  const wpSel = document.getElementById("fpWaypointSelect");
  wpSel.innerHTML = (st.waypoints || []).map(w =>
    `<option value="${esc(w.waypoint_id || '')}||${esc(w.waypoint)}">${esc(w.display_name)}${w.best_5 ? ' (' + w.best_5.dbm + ' dBm)' : ''}</option>`
  ).join("") || `<option value="">-- Log a waypoint first --</option>`;

  if (fps.length) {
    if (!selectedFloorplanId || !fps.some(f => f.id === selectedFloorplanId)) {
      selectedFloorplanId = fps[0].id;
    }
    fpSel.value = selectedFloorplanId;
    selectFloorplan(selectedFloorplanId);
  } else {
    document.getElementById("fpEmptyMsg").classList.remove("hidden");
    document.getElementById("fpStageWrap").classList.add("hidden");
    document.getElementById("fpPinsList").innerHTML = "";
  }
}

function selectFloorplan(fpId) {
  selectedFloorplanId = fpId;
  const fp = (currentJobState && currentJobState.floorplans || []).find(f => f.id === fpId);
  if (!fp) return;
  document.getElementById("fpEmptyMsg").classList.add("hidden");
  document.getElementById("fpStageWrap").classList.remove("hidden");
  const img = document.getElementById("fpImg");
  if (img.getAttribute("data-src") !== fp.url) {
    img.setAttribute("data-src", fp.url);
    img.src = fp.url;
  } else {
    drawFloorplanHeatmap();
  }
  renderPinsList();
}

function rssiToRgb(dbm) {
  if (dbm >= -55) return [22, 163, 74];
  if (dbm >= -65) return [132, 204, 22];
  if (dbm >= -70) return [245, 158, 11];
  if (dbm >= -76) return [249, 115, 22];
  return [220, 38, 38];
}

function getFloorPinsEnriched() {
  if (!currentJobState || !selectedFloorplanId) return [];
  const band = document.getElementById("fpBand").value;
  const wps = currentJobState.waypoints || [];
  return (currentJobState.pins || []).filter(p => p.floor_id === selectedFloorplanId).map(p => {
    const wp = wps.find(w =>
      (p.waypoint_id && String(w.waypoint_id) === String(p.waypoint_id)) ||
      (w.waypoint.toLowerCase() === (p.waypoint || "").toLowerCase())
    );
    const sig = wp ? (band === "5" ? wp.best_5 : wp.best_24) : null;
    return { ...p, dbm: sig ? sig.dbm : null, ap: sig ? sig.ap : "" };
  });
}

function drawFloorplanHeatmap() {
  const img = document.getElementById("fpImg");
  const canvas = document.getElementById("fpCanvas");
  if (!img || !canvas || !img.naturalWidth) return;
  const w = img.naturalWidth, h = img.naturalHeight;
  canvas.width = w; canvas.height = h;
  const ctx = canvas.getContext("2d");
  ctx.clearRect(0, 0, w, h);

  const pins = getFloorPinsEnriched();
  const valid = pins.filter(p => p.dbm !== null && p.dbm !== undefined);
  const opacity = Number(document.getElementById("fpOpacity").value) / 100;

  if (valid.length > 0 && opacity > 0) {
    const gridW = 140, gridH = Math.max(60, Math.round(gridW * (h / w)));
    const off = document.createElement("canvas");
    off.width = gridW; off.height = gridH;
    const octx = off.getContext("2d");
    const idata = octx.createImageData(gridW, gridH);
    const maxRadius = 0.34;

    for (let gy = 0; gy < gridH; gy++) {
      const ny = (gy + 0.5) / gridH;
      for (let gx = 0; gx < gridW; gx++) {
        const nx = (gx + 0.5) / gridW;
        let num = 0, den = 0, minD = 99;
        for (const p of valid) {
          const d = Math.hypot(nx - p.x, ny - p.y);
          if (d < minD) minD = d;
          const wt = 1 / (d * d + 0.0008);
          num += p.dbm * wt;
          den += wt;
        }
        if (minD <= maxRadius && den > 0) {
          const rgb = rssiToRgb(num / den);
          const fade = Math.max(0, Math.min(1, 1 - (minD / maxRadius) * 0.72));
          const pos = (gy * gridW + gx) * 4;
          idata.data[pos] = rgb[0];
          idata.data[pos + 1] = rgb[1];
          idata.data[pos + 2] = rgb[2];
          idata.data[pos + 3] = Math.round(210 * opacity * fade);
        }
      }
    }
    octx.putImageData(idata, 0, 0);
    ctx.drawImage(off, 0, 0, w, h);
  }

  const scale = Math.max(1, w / 900);
  for (const p of pins) {
    const px = p.x * w, py = p.y * h;
    const rgb = p.dbm !== null ? rssiToRgb(p.dbm) : [100, 116, 139];
    ctx.beginPath();
    ctx.arc(px, py, 9 * scale, 0, Math.PI * 2);
    ctx.fillStyle = `rgb(${rgb[0]},${rgb[1]},${rgb[2]})`;
    ctx.fill();
    ctx.lineWidth = 2.5 * scale;
    ctx.strokeStyle = "#ffffff";
    ctx.stroke();

    const tag = p.dbm !== null ? `${p.waypoint} (${p.dbm} dBm)` : p.waypoint;
    ctx.font = `bold ${Math.round(12 * scale)}px sans-serif`;
    const tw = ctx.measureText(tag).width;
    const bx = Math.min(w - tw - 12 * scale, Math.max(4, px + 11 * scale));
    const by = Math.max(18 * scale, py - 8 * scale);
    ctx.fillStyle = "rgba(15, 23, 42, 0.88)";
    ctx.fillRect(bx - 4 * scale, by - 13 * scale, tw + 8 * scale, 18 * scale);
    ctx.fillStyle = "#ffffff";
    ctx.fillText(tag, bx, by);
  }
}

function renderPinsList() {
  const pins = getFloorPinsEnriched();
  const el = document.getElementById("fpPinsList");
  if (!pins.length) { el.innerHTML = ""; return; }
  el.innerHTML = `<div class="chip-group">` + pins.map(p =>
    `<span class="chip">${esc(p.waypoint)} ${p.dbm !== null ? '(' + p.dbm + ' dBm)' : ''} ` +
    `<strong style="color:#fca5a5;margin-left:5px;cursor:pointer;" onclick="removePin('${esc(p.waypoint)}','${esc(p.waypoint_id || '')}')">&times;</strong></span>`
  ).join("") + `</div>`;
}

async function uploadFloorplan() {
  if (!currentJobId) { toast("Select or create a job first."); return; }
  const fileIn = document.getElementById("fpFile");
  if (!fileIn.files || !fileIn.files.length) { toast("Choose a PNG/JPG floorplan image first."); return; }
  const file = fileIn.files[0];
  const label = document.getElementById("fpLabel").value.trim() || file.name.replace(/\.[^.]+$/, "");
  const reader = new FileReader();
  reader.onload = async () => {
    try {
      const st = await api(`/api/jobs/${encodeURIComponent(currentJobId)}/floorplans`, {
        method: "POST",
        body: JSON.stringify({ label, filename: file.name, data_url: reader.result }),
      });
      fileIn.value = "";
      document.getElementById("fpLabel").value = "";
      selectedFloorplanId = st.floorplans[st.floorplans.length - 1].id;
      renderJobState(st);
      toast(`Uploaded floorplan '${label}'!`);
    } catch (e) { toast("Upload error: " + e.message); }
  };
  reader.readAsDataURL(file);
}

async function onFloorplanClick(ev) {
  if (!currentJobId || !selectedFloorplanId) return;
  const img = document.getElementById("fpImg");
  const rect = img.getBoundingClientRect();
  const nx = Math.max(0, Math.min(1, (ev.clientX - rect.left) / rect.width));
  const ny = Math.max(0, Math.min(1, (ev.clientY - rect.top) / rect.height));

  const mode = document.getElementById("fpMode").value;
  if (mode === "pin_existing") {
    const raw = document.getElementById("fpWaypointSelect").value;
    if (!raw || !raw.includes("||")) { toast("Log at least one waypoint first (or switch to Click-to-Capture mode)."); return; }
    const [wid, wpName] = raw.split("||");
    try {
      const st = await api(`/api/jobs/${encodeURIComponent(currentJobId)}/floorplans/pin`, {
        method: "POST",
        body: JSON.stringify({ floor_id: selectedFloorplanId, waypoint_id: wid, waypoint: wpName, x: nx, y: ny }),
      });
      renderJobState(st);
      toast(`Pinned '${wpName}' on floorplan.`);
    } catch (e) { toast("Pin error: " + e.message); }
  } else {
    const wpName = document.getElementById("fpNewWpName").value.trim() || prompt("Enter Room / Waypoint Name for this spot:");
    if (!wpName) return;
    toast(`Capturing live RF scan at '${wpName}'...`);
    try {
      const st = await api(`/api/jobs/${encodeURIComponent(currentJobId)}/floorplans/pin`, {
        method: "POST",
        body: JSON.stringify({ floor_id: selectedFloorplanId, waypoint: wpName.trim(), x: nx, y: ny, capture_new: true }),
      });
      document.getElementById("fpNewWpName").value = "";
      renderJobState(st);
      toast(`Captured & pinned '${wpName.trim()}'!`);
    } catch (e) { toast("Capture+Pin error: " + e.message); }
  }
}

async function removePin(wpName, wid) {
  try {
    const st = await api(`/api/jobs/${encodeURIComponent(currentJobId)}/floorplans/pin`, {
      method: "DELETE",
      body: JSON.stringify({ floor_id: selectedFloorplanId, waypoint: wpName, waypoint_id: wid }),
    });
    renderJobState(st);
    toast(`Removed pin for '${wpName}'.`);
  } catch (e) { toast("Remove pin error: " + e.message); }
}

/* ==================== CONTINUOUS ROAMING WALK-TEST ==================== */
async function startWalkTest() {
  if (!currentJobId) { toast("Create or select a job first."); return; }
  const label = document.getElementById("walkLabel").value.trim() || "Roaming Walk";
  try {
    await api(`/api/jobs/${encodeURIComponent(currentJobId)}/walk/start`, {
      method: "POST",
      body: JSON.stringify({ walk_label: label, interval_sec: 0.5 }),
    });
    document.getElementById("btnWalkStart").classList.add("hidden");
    document.getElementById("btnWalkStop").classList.remove("hidden");
    toast("Walk-test started! Walk steadily between rooms/APs.");
    clearInterval(walkPollTimer);
    walkPollTimer = setInterval(pollWalkStatus, 650);
    pollWalkStatus();
  } catch (e) { toast("Walk start error: " + e.message); }
}

async function stopWalkTest() {
  clearInterval(walkPollTimer);
  try {
    const res = await api("/api/walk/stop", { method: "POST", body: JSON.stringify({}) });
    document.getElementById("btnWalkStart").classList.remove("hidden");
    document.getElementById("btnWalkStop").classList.add("hidden");
    if (res.summary) renderWalkSnapshot(res.summary);
    if (res.state) renderJobState(res.state);
    toast(`Walk-test saved (${res.summary.roam_count} roam(s), ${res.summary.packet_loss_pct}% loss)!`);
  } catch (e) { toast("Walk stop error: " + e.message); }
}

async function pollWalkStatus() {
  try {
    const d = await api("/api/walk/status");
    if (d.summary) renderWalkSnapshot(d.summary);
    if (!d.running) {
      clearInterval(walkPollTimer);
      document.getElementById("btnWalkStart").classList.remove("hidden");
      document.getElementById("btnWalkStop").classList.add("hidden");
    }
  } catch (e) {}
}

function renderWalkSnapshot(s) {
  document.getElementById("wkElapsed").textContent = `${s.duration_sec}s (${s.sample_count})`;
  document.getElementById("wkRoams").textContent = s.roam_count;
  document.getElementById("wkLoss").textContent = `${s.packet_loss_pct}%`;
  document.getElementById("wkRssi").textContent = s.min_rssi_dbm !== null ? `${s.min_rssi_dbm} / ${s.avg_rssi_dbm} dBm` : "—";
  document.getElementById("wkPing").textContent = s.avg_gw_ms !== null ? `${s.avg_gw_ms} / ${s.max_gw_ms} ms` : "—";

  const tbody = document.getElementById("walkEventsBody");
  if (s.roam_events && s.roam_events.length) {
    tbody.innerHTML = s.roam_events.map(r => {
      const cls = r.grade === "Seamless" ? "b-good" : (r.grade.includes("Minor") ? "b-warn" : "b-bad");
      return `<tr>
        <td>${r.elapsed_sec}s</td>
        <td><code>${esc(r.from_bssid)}</code><br><span class="sub">${esc(r.from_band)} Ch ${esc(r.from_channel)} (${r.rssi_before_dbm} dBm)</span></td>
        <td><code>${esc(r.to_bssid)}</code><br><span class="sub">${esc(r.to_band)} Ch ${esc(r.to_channel)} (${r.rssi_after_dbm} dBm)</span></td>
        <td>${r.dropped_pings} (~${r.est_outage_ms} ms)</td>
        <td>${r.peak_ping_ms !== null ? r.peak_ping_ms + ' ms' : '—'}</td>
        <td><span class="badge ${cls}">${esc(r.grade)}</span></td>
      </tr>`;
    }).join("");
  } else if (s.sample_count > 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="sub">Walking... no BSSID roam transition detected yet (${s.sample_count} samples recorded).</td></tr>`;
  }

  drawWalkChart(s);
}

function drawWalkChart(s) {
  const c = document.getElementById("walkChart");
  if (!c) return;
  const ctx = c.getContext("2d");
  const W = c.width, H = c.height;
  ctx.clearRect(0, 0, W, H);
  const samples = s.samples || [];
  if (samples.length < 2) return;

  const padL = 52, padR = 16, padT = 16, splitY = 172, padB = 22;
  const plotW = W - padL - padR;
  const rssiH = splitY - padT;
  const pingTop = splitY + 14, pingH = H - pingTop - padB;
  const maxT = Math.max(1, samples[samples.length - 1].elapsed_sec || 1);
  const xOf = t => padL + (t / maxT) * plotW;
  const yRssi = dbm => padT + ((-30 - Math.max(-95, Math.min(-30, dbm))) / 65) * rssiH;

  // Grid lines for RSSI
  ctx.font = "11px sans-serif";
  for (const db of [-40, -55, -67, -80, -90]) {
    const y = yRssi(db);
    ctx.strokeStyle = db === -67 ? "#f59e0b" : "#1e293b";
    ctx.setLineDash(db === -67 ? [5, 4] : []);
    ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(W - padR, y); ctx.stroke();
    ctx.fillStyle = db === -67 ? "#fbbf24" : "#94a3b8";
    ctx.fillText(`${db} dBm`, 4, y + 4);
  }
  ctx.setLineDash([]);

  // RSSI polyline
  ctx.strokeStyle = "#38bdf8";
  ctx.lineWidth = 2.4;
  ctx.beginPath();
  let started = false;
  for (const pt of samples) {
    if (pt.rssi_dbm === null || pt.rssi_dbm === undefined) continue;
    const x = xOf(pt.elapsed_sec), y = yRssi(pt.rssi_dbm);
    if (!started) { ctx.moveTo(x, y); started = true; } else { ctx.lineTo(x, y); }
  }
  ctx.stroke();

  // Roam vertical markers
  for (const r of (s.roam_events || [])) {
    const rx = xOf(r.elapsed_sec);
    ctx.strokeStyle = "#a855f7";
    ctx.lineWidth = 2;
    ctx.setLineDash([4, 3]);
    ctx.beginPath(); ctx.moveTo(rx, padT); ctx.lineTo(rx, H - padB); ctx.stroke();
    ctx.setLineDash([]);
    ctx.fillStyle = "#d8b4fe";
    ctx.fillText(`ROAM Ch${r.to_channel}`, Math.min(W - 85, rx + 4), padT + 12);
  }

  // Gateway Ping bars (bottom lane)
  const maxPing = Math.max(30, ...samples.map(pt => pt.gw_ms || 0));
  ctx.fillStyle = "#94a3b8";
  ctx.fillText(`${Math.round(maxPing)}ms`, 4, pingTop + 10);
  ctx.fillText("0ms", 16, pingTop + pingH);
  const barW = Math.max(2, Math.min(8, plotW / samples.length - 1));
  for (const pt of samples) {
    const x = xOf(pt.elapsed_sec);
    if (pt.packet_lost) {
      ctx.fillStyle = "#ef4444";
      ctx.fillRect(x - barW / 2, pingTop, barW, pingH);
    } else if (pt.gw_ms !== null) {
      const bh = Math.max(2, (pt.gw_ms / maxPing) * pingH);
      ctx.fillStyle = pt.gw_ms > 25 ? "#f59e0b" : "#22c55e";
      ctx.fillRect(x - barW / 2, pingTop + pingH - bh, barW, bh);
    }
  }
}

/* ==================== SURVEY / EDIT / COMPARE ==================== */
async function saveJobMeta() {
  if (!currentJobId) return;
  try {
    const st = await api(`/api/jobs/${encodeURIComponent(currentJobId)}/meta`, {
      method: "PATCH",
      body: JSON.stringify({
        job_name: document.getElementById("emName").value,
        tech_name: document.getElementById("emTech").value,
        target_ssid: document.getElementById("emSsid").value,
        notes: document.getElementById("emNotes").value,
      })
    });
    renderJobState(st);
    toast("Job metadata updated.");
  } catch (e) { toast("Save error: " + e.message); }
}

async function captureWaypoint() {
  if (!currentJobId) { toast("Create or select a job first."); return; }
  const wp = document.getElementById("wpInput").value.trim();
  if (!wp) { toast("Enter or click a room name first."); return; }
  const btn = document.getElementById("btnCapture");
  btn.disabled = true; btn.textContent = "Scanning & Pinging...";
  try {
    const st = await api(`/api/jobs/${encodeURIComponent(currentJobId)}/waypoints`, {
      method: "POST",
      body: JSON.stringify({
        waypoint: wp,
        run_speedtest: document.getElementById("wpSpeedtest").checked,
      })
    });
    renderJobState(st);
    document.getElementById("wpInput").value = "";
    document.getElementById("wpSpeedtest").checked = false;
    toast(`Captured '${wp}'!`);
  } catch (e) {
    toast("Capture error: " + e.message);
  } finally {
    btn.disabled = false; btn.textContent = "Capture Waypoint";
  }
}

async function renameWaypoint(batchIdx, oldName) {
  const newName = prompt("Correct / rename waypoint:", oldName);
  if (!newName || newName.trim() === oldName) return;
  try {
    const st = await api(`/api/jobs/${encodeURIComponent(currentJobId)}/waypoints/${batchIdx}`, {
      method: "PATCH",
      body: JSON.stringify({ waypoint: newName.trim() }),
    });
    renderJobState(st);
    toast(`Renamed to '${newName.trim()}'.`);
  } catch (e) { toast("Rename error: " + e.message); }
}

async function deleteWaypoint(batchIdx, label) {
  if (!confirm(`Delete waypoint '${label}' from this job?`)) return;
  try {
    const st = await api(`/api/jobs/${encodeURIComponent(currentJobId)}/waypoints/${batchIdx}`, {
      method: "DELETE",
    });
    renderJobState(st);
    toast(`Deleted '${label}'.`);
  } catch (e) { toast("Delete error: " + e.message); }
}

async function rescanWaypoint(batchIdx, name) {
  if (!confirm(`Re-scan '${name}' now? (Replaces the previous reading for this waypoint)`)) return;
  toast(`Re-scanning '${name}'...`);
  try {
    const st = await api(`/api/jobs/${encodeURIComponent(currentJobId)}/waypoints/${batchIdx}/rescan`, {
      method: "POST",
      body: JSON.stringify({}),
    });
    renderJobState(st);
    toast(`Re-scanned '${name}'!`);
  } catch (e) { toast("Re-scan error: " + e.message); }
}

async function runAction(action) {
  if (!currentJobId) { toast("Select a job first."); return; }
  toast(`Running ${action}... please wait.`);
  try {
    const res = await api(`/api/jobs/${encodeURIComponent(currentJobId)}/actions/${action}`, {
      method: "POST",
      body: JSON.stringify({}),
    });
    if (res.state) renderJobState(res.state);
    if (res.report_url) window.open(res.report_url, "_blank");
    toast(res.message || `${action} complete!`);
  } catch (e) { toast(`${action} failed: ` + e.message); }
}

async function runComparison() {
  const bId = document.getElementById("cmpBefore").value;
  const aId = document.getElementById("cmpAfter").value;
  if (!bId || !aId) { toast("Select both Before and After jobs."); return; }
  const btn = document.getElementById("btnCompare");
  btn.disabled = true; btn.textContent = "Comparing...";
  try {
    const res = await api("/api/compare", {
      method: "POST",
      body: JSON.stringify({ before_id: bId, after_id: aId }),
    });
    document.getElementById("cmpResultsCard").classList.remove("hidden");
    document.getElementById("cmpReportLink").href = res.report_url;
    const fmtD = (v, u="dB") => {
      if (v === null || v === undefined) return `<span class="sub">—</span>`;
      const cls = v > 0 ? "b-good" : (v < 0 ? "b-bad" : "");
      return `<span class="badge ${cls}">${v > 0 ? '+' : ''}${v} ${u}</span>`;
    };
    document.getElementById("cmpSummaryBar").innerHTML = `
      <div><span class="kv-label">Avg 5/6 GHz Delta</span>${fmtD(res.avg_delta_5_db)}</div>
      <div><span class="kv-label">Avg 2.4 GHz Delta</span>${fmtD(res.avg_delta_24_db)}</div>
      <div><span class="kv-label">High-CU Radios</span><strong>${res.before_high_cu} &rarr; ${res.after_high_cu}</strong></div>
      <div><span class="kv-label">Peak Channel Util</span><strong>${res.before_peak_cu}% &rarr; ${res.after_peak_cu}%</strong></div>
    `;
    document.getElementById("cmpTableBody").innerHTML = res.room_rows.map(r => `
      <tr>
        <td><strong>${esc(r.room)}</strong></td>
        <td>${r.before_5 !== null ? r.before_5 + ' dBm' : '—'}</td>
        <td>${r.after_5 !== null ? r.after_5 + ' dBm' : '—'}</td>
        <td>${fmtD(r.delta_5)}</td>
        <td>${r.before_24 !== null ? r.before_24 + ' dBm' : '—'}</td>
        <td>${r.after_24 !== null ? r.after_24 + ' dBm' : '—'}</td>
        <td>${fmtD(r.delta_24)}</td>
      </tr>
    `).join("");
    toast("Comparison report generated!");
  } catch (e) {
    toast("Compare error: " + e.message);
  } finally {
    btn.disabled = false; btn.textContent = "Compare Jobs";
  }
}

document.getElementById("wpInput").addEventListener("keydown", e => {
  if (e.key === "Enter") captureWaypoint();
});

renderChips();
refreshJobsList();
pollLive(false);
setInterval(() => pollLive(false), 3500);
</script>
</body>
</html>
"""


def create_server(jobs_root: str = DEFAULT_JOBS_DIR, host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    """Create a configured ThreadingHTTPServer bound to `host:port` serving `jobs_root`."""
    os.makedirs(jobs_root, exist_ok=True)

    class SurveyHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def _send_json(self, status: int, payload: dict):
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _send_html(self, status: int, html_text: str):
            body = html_text.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _send_bytes(self, status: int, data: bytes, content_type: str):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _read_json_body(self) -> dict:
            length = int(self.headers.get("Content-Length", "0") or 0)
            if length <= 0:
                return {}
            raw = self.rfile.read(length)
            return json.loads(raw.decode("utf-8"))

        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            qs = urllib.parse.parse_qs(parsed.query)

            try:
                if path == "/" or path == "/index.html":
                    self._send_html(200, UI_HTML)
                    return

                if path == "/api/live":
                    refresh = qs.get("refresh", ["0"])[0] == "1"
                    wifi = nd.get_active_wifi_interface()
                    nets = sc.run_native_wlan_scan(live_refresh=refresh)
                    nets_5 = [n for n in nets if "5" in n.get("band", "") or "6" in n.get("band", "")]
                    best_5g = max(nets_5, key=lambda x: x.get("signal_dbm", -100)) if nets_5 else None
                    self._send_json(200, {"wifi": wifi, "best_5g": best_5g, "bssid_count": len(nets)})
                    return

                if path == "/api/walk/status":
                    with _WALK_LOCK:
                        sess = _ACTIVE_WALK.get("session")
                    if sess is None:
                        self._send_json(200, {"running": False, "summary": None})
                    else:
                        snap = sess.snapshot()
                        self._send_json(200, {"running": sess.is_running, "summary": snap})
                    return

                if path == "/api/jobs":
                    self._send_json(200, {"jobs": list_jobs(jobs_root)})
                    return

                m_job = re.match(r"^/api/jobs/([^/]+)$", path)
                if m_job:
                    job_id = urllib.parse.unquote(m_job.group(1))
                    self._send_json(200, get_job_state(jobs_root, job_id))
                    return

                m_fp = re.match(r"^/jobs/([^/]+)/floorplans/([^/]+)$", path)
                if m_fp:
                    job_id = urllib.parse.unquote(m_fp.group(1))
                    fname = urllib.parse.unquote(m_fp.group(2))
                    job_folder = _safe_job_path(jobs_root, job_id)
                    fpath = _safe_floorplan_file(job_folder, fname)
                    if not os.path.isfile(fpath):
                        self._send_json(404, {"error": "Floorplan image not found"})
                        return
                    ext = os.path.splitext(fname)[1].lower().lstrip(".")
                    mime = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "webp": "image/webp"}.get(ext, "application/octet-stream")
                    with open(fpath, "rb") as f:
                        self._send_bytes(200, f.read(), mime)
                    return

                m_rep = re.match(r"^/jobs/([^/]+)/(PM_SITE_SURVEY_REPORT\.html|COMPARISON_REPORT\.html)$", path)
                if m_rep:
                    job_id = urllib.parse.unquote(m_rep.group(1))
                    fname = m_rep.group(2)
                    job_folder = _safe_job_path(jobs_root, job_id)
                    fpath = os.path.join(job_folder, fname)
                    if not os.path.isfile(fpath):
                        self._send_json(404, {"error": "Report not generated yet"})
                        return
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        self._send_html(200, f.read())
                    return

                self._send_json(404, {"error": "Not found"})
            except ValueError as e:
                self._send_json(400, {"error": str(e)})
            except FileNotFoundError as e:
                self._send_json(404, {"error": str(e)})
            except Exception as e:
                self._send_json(500, {"error": str(e)})

        def do_POST(self):
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path

            try:
                body = self._read_json_body()

                if path == "/api/jobs":
                    with _SURVEY_LOCK:
                        st = create_new_job(
                            jobs_root,
                            body.get("job_name", ""),
                            body.get("tech_name", "Field_Tech"),
                            body.get("target_ssid", ""),
                            body.get("notes", ""),
                        )
                    self._send_json(201, st)
                    return

                m_fp_up = re.match(r"^/api/jobs/([^/]+)/floorplans$", path)
                if m_fp_up:
                    job_id = urllib.parse.unquote(m_fp_up.group(1))
                    with _SURVEY_LOCK:
                        st = upload_floorplan(
                            jobs_root, job_id,
                            body.get("label", ""),
                            body.get("filename", "floorplan.png"),
                            body.get("data_url", ""),
                        )
                    self._send_json(201, st)
                    return

                m_fp_pin = re.match(r"^/api/jobs/([^/]+)/floorplans/pin$", path)
                if m_fp_pin:
                    job_id = urllib.parse.unquote(m_fp_pin.group(1))
                    job_folder = _safe_job_path(jobs_root, job_id)
                    with _SURVEY_LOCK:
                        wid = str(body.get("waypoint_id", "") or "").strip()
                        wp_name = (body.get("waypoint") or "").strip()
                        if body.get("capture_new"):
                            if not wp_name:
                                raise ValueError("Waypoint name is required for click-to-capture")
                            sc.record_waypoint(
                                wp_name,
                                target_ssid=None,
                                log_file=os.path.join(job_folder, "survey_waypoints.csv"),
                                run_speedtest=False,
                            )
                            cur = get_job_state(jobs_root, job_id)
                            if cur["waypoints"]:
                                wid = str(cur["waypoints"][-1].get("waypoint_id", ""))
                        st = upsert_floorplan_pin(
                            jobs_root, job_id,
                            body.get("floor_id", ""),
                            wp_name,
                            body.get("x", 0.5),
                            body.get("y", 0.5),
                            waypoint_id=wid,
                        )
                    self._send_json(200, st)
                    return

                m_walk_start = re.match(r"^/api/jobs/([^/]+)/walk/start$", path)
                if m_walk_start:
                    job_id = urllib.parse.unquote(m_walk_start.group(1))
                    job_folder = _safe_job_path(jobs_root, job_id)
                    with _WALK_LOCK:
                        prev = _ACTIVE_WALK.get("session")
                        if prev is not None and prev.is_running:
                            prev.stop_and_save()
                        sess = rwt.RoamingWalkSession(
                            job_folder=job_folder,
                            walk_label=body.get("walk_label", "Roaming Walk"),
                            interval_sec=float(body.get("interval_sec", 0.5)),
                        )
                        sess.start()
                        _ACTIVE_WALK["session"] = sess
                        _ACTIVE_WALK["job_id"] = job_id
                    self._send_json(200, {"running": True, "job_id": job_id})
                    return

                if path == "/api/walk/stop":
                    with _WALK_LOCK:
                        sess = _ACTIVE_WALK.get("session")
                        jid = _ACTIVE_WALK.get("job_id", "")
                    if sess is None:
                        self._send_json(200, {"running": False, "summary": None})
                        return
                    summary = sess.stop_and_save()
                    st = get_job_state(jobs_root, jid) if jid else None
                    self._send_json(200, {"running": False, "summary": summary, "state": st})
                    return

                m_wp = re.match(r"^/api/jobs/([^/]+)/waypoints$", path)
                if m_wp:
                    job_id = urllib.parse.unquote(m_wp.group(1))
                    job_folder = _safe_job_path(jobs_root, job_id)
                    wp_name = (body.get("waypoint") or "").strip()
                    if not wp_name:
                        raise ValueError("Waypoint name is required")
                    run_st = bool(body.get("run_speedtest", False))
                    with _SURVEY_LOCK:
                        sc.record_waypoint(
                            wp_name,
                            target_ssid=None,
                            log_file=os.path.join(job_folder, "survey_waypoints.csv"),
                            run_speedtest=run_st,
                        )
                        st = get_job_state(jobs_root, job_id)
                    self._send_json(201, st)
                    return

                m_rescan = re.match(r"^/api/jobs/([^/]+)/waypoints/(\d+)/rescan$", path)
                if m_rescan:
                    job_id = urllib.parse.unquote(m_rescan.group(1))
                    b_idx = int(m_rescan.group(2))
                    job_folder = _safe_job_path(jobs_root, job_id)
                    with _SURVEY_LOCK:
                        cur = get_job_state(jobs_root, job_id)
                        if b_idx < 0 or b_idx >= len(cur["waypoints"]):
                            raise IndexError("Invalid waypoint index")
                        wp_name = cur["waypoints"][b_idx]["waypoint"]
                        modify_waypoint_batch(jobs_root, job_id, b_idx, delete=True)
                        sc.record_waypoint(
                            wp_name,
                            target_ssid=None,
                            log_file=os.path.join(job_folder, "survey_waypoints.csv"),
                            run_speedtest=False,
                        )
                        st = get_job_state(jobs_root, job_id)
                    self._send_json(200, st)
                    return

                m_act = re.match(r"^/api/jobs/([^/]+)/actions/([^/]+)$", path)
                if m_act:
                    job_id = urllib.parse.unquote(m_act.group(1))
                    action = m_act.group(2)
                    job_folder = _safe_job_path(jobs_root, job_id)
                    with _SURVEY_LOCK:
                        if action == "speedtest":
                            wifi = nd.get_active_wifi_interface()
                            hop = nd.run_split_hop_diagnostics(wifi.get("gateway"))
                            st_res = nd.run_cloudflare_speedtest()
                            st_path = os.path.join(job_folder, "speedtest_results.json")
                            existing = gjs.load_json_safe(st_path)
                            existing.append({
                                "waypoint": "Baseline",
                                "timestamp": datetime.now().isoformat(),
                                "wifi_interface": wifi,
                                "split_hop_ping": hop,
                                "speedtest": st_res,
                            })
                            with open(st_path, "w", encoding="utf-8") as sf:
                                json.dump(existing, sf, indent=2)
                            msg = f"Speedtest: {st_res.get('download_mbps')} / {st_res.get('upload_mbps')} Mbps ({st_res.get('bufferbloat_grade')})"
                            self._send_json(200, {"message": msg, "state": get_job_state(jobs_root, job_id)})
                            return
                        if action == "lan-sweep":
                            devs = nd.run_lan_discovery(job_folder)
                            self._send_json(200, {"message": f"Discovered {len(devs)} active LAN hosts.", "state": get_job_state(jobs_root, job_id)})
                            return
                        if action == "export-roaming":
                            proc = subprocess.run(
                                ["wevtutil", "qe", "Microsoft-Windows-WLAN-AutoConfig/Operational", "/c:60", "/rd:true", "/f:text"],
                                capture_output=True, text=True, errors="replace", timeout=15
                            )
                            with open(os.path.join(job_folder, "wlan_roaming_events.txt"), "w", encoding="utf-8") as rf:
                                rf.write(proc.stdout)
                            self._send_json(200, {"message": "Exported Windows WLAN roaming log.", "state": get_job_state(jobs_root, job_id)})
                            return
                        if action == "generate-report":
                            gjs.generate_summary(job_folder)
                            url = f"/jobs/{urllib.parse.quote(job_id)}/PM_SITE_SURVEY_REPORT.html"
                            self._send_json(200, {"message": "Generated Engineering & PM reports.", "report_url": url, "state": get_job_state(jobs_root, job_id)})
                            return
                    self._send_json(400, {"error": f"Unknown action: {action}"})
                    return

                if path == "/api/compare":
                    b_id = body.get("before_id", "")
                    a_id = body.get("after_id", "")
                    b_dir = _safe_job_path(jobs_root, b_id)
                    a_dir = _safe_job_path(jobs_root, a_id)
                    res = compare_jobs.compare_job_folders(b_dir, a_dir, out_dir=a_dir)
                    self._send_json(200, {
                        "avg_delta_5_db": res["avg_delta_5_db"],
                        "avg_delta_24_db": res["avg_delta_24_db"],
                        "before_high_cu": res["before"]["high_cu_count"],
                        "after_high_cu": res["after"]["high_cu_count"],
                        "before_peak_cu": res["before"]["peak_cu_pct"],
                        "after_peak_cu": res["after"]["peak_cu_pct"],
                        "room_rows": res["room_rows"],
                        "report_url": f"/jobs/{urllib.parse.quote(a_id)}/COMPARISON_REPORT.html",
                    })
                    return

                self._send_json(404, {"error": "Not found"})
            except (ValueError, IndexError) as e:
                self._send_json(400, {"error": str(e)})
            except FileNotFoundError as e:
                self._send_json(404, {"error": str(e)})
            except Exception as e:
                self._send_json(500, {"error": str(e)})

        def do_PATCH(self):
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            try:
                body = self._read_json_body()
                m_meta = re.match(r"^/api/jobs/([^/]+)/meta$", path)
                if m_meta:
                    job_id = urllib.parse.unquote(m_meta.group(1))
                    with _SURVEY_LOCK:
                        st = update_job_meta(jobs_root, job_id, body)
                    self._send_json(200, st)
                    return

                m_wp = re.match(r"^/api/jobs/([^/]+)/waypoints/(\d+)$", path)
                if m_wp:
                    job_id = urllib.parse.unquote(m_wp.group(1))
                    b_idx = int(m_wp.group(2))
                    new_name = (body.get("waypoint") or "").strip()
                    if not new_name:
                        raise ValueError("New waypoint name is required")
                    with _SURVEY_LOCK:
                        st = modify_waypoint_batch(jobs_root, job_id, b_idx, new_name=new_name, delete=False)
                    self._send_json(200, st)
                    return

                self._send_json(404, {"error": "Not found"})
            except (ValueError, IndexError) as e:
                self._send_json(400, {"error": str(e)})
            except Exception as e:
                self._send_json(500, {"error": str(e)})

        def do_DELETE(self):
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            try:
                m_fp_pin = re.match(r"^/api/jobs/([^/]+)/floorplans/pin$", path)
                if m_fp_pin:
                    job_id = urllib.parse.unquote(m_fp_pin.group(1))
                    body = self._read_json_body()
                    with _SURVEY_LOCK:
                        st = delete_floorplan_pin(
                            jobs_root, job_id,
                            body.get("floor_id", ""),
                            waypoint=body.get("waypoint", ""),
                            waypoint_id=body.get("waypoint_id", ""),
                        )
                    self._send_json(200, st)
                    return

                m_wp = re.match(r"^/api/jobs/([^/]+)/waypoints/(\d+)$", path)
                if m_wp:
                    job_id = urllib.parse.unquote(m_wp.group(1))
                    b_idx = int(m_wp.group(2))
                    with _SURVEY_LOCK:
                        st = modify_waypoint_batch(jobs_root, job_id, b_idx, delete=True)
                    self._send_json(200, st)
                    return
                self._send_json(404, {"error": "Not found"})
            except (ValueError, IndexError) as e:
                self._send_json(400, {"error": str(e)})
            except Exception as e:
                self._send_json(500, {"error": str(e)})

    return ThreadingHTTPServer((host, port), SurveyHandler)


def _find_open_port(host: str, preferred: int) -> int:
    for p in range(preferred, preferred + 20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((host, p))
                return p
            except OSError:
                continue
    return 0


def main():
    parser = argparse.ArgumentParser(description="Wi-Fi Site Survey — Local Web Field Console")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="Bind port (default: 8765)")
    parser.add_argument("--jobs-dir", default=DEFAULT_JOBS_DIR, help="Path to Jobs directory")
    parser.add_argument("--no-browser", action="store_true", help="Do not auto-open the web browser")
    args = parser.parse_args()

    port = _find_open_port(args.host, args.port)
    srv = create_server(jobs_root=args.jobs_dir, host=args.host, port=port)
    actual_port = srv.server_address[1]
    url = f"http://{args.host}:{actual_port}"

    print("=" * 75)
    print(f"  Wi-Fi Site Survey Field Console running at: {url}")
    print(f"  Jobs Directory: {os.path.abspath(args.jobs_dir)}")
    print("  Press Ctrl+C in this window to stop the server.")
    print("=" * 75)

    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()

    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping Field Console...")
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
