"""
Engineering Hand-Off & Executive PM Report Generator
Summarizes all survey waypoints (separating 5/6 GHz vs 2.4 GHz with primary & secondary APs),
active link telemetry, sticky-client detection, CCI/ACI/DFS/peak-CU RF health audits,
controller AP List.csv mapping, survey NIC capability checks, Windows 802.11 roaming events,
Cloudflare speedtest & bufferbloat metrics, split-hop latency, and LAN device discovery
into both:
  1. ENGINEERING_HANDOFF_SUMMARY.txt
  2. PM_SITE_SURVEY_REPORT.html (Print-to-PDF ready)
"""

import os
import sys
import re
import json
import csv
import html
import base64
from collections import defaultdict
from datetime import datetime

from network_diagnostics import lookup_oui

CSV_STANDARD_HEADERS = [
    "timestamp", "waypoint", "ssid", "bssid", "band", "channel",
    "radio_type", "signal_dbm", "signal_pct", "cu_pct", "stations", "auth", "enc"
]

NON_OVERLAPPING_24GHZ = {1, 6, 11}
DFS_5GHZ_CHANNELS = set(range(52, 145))

# Standard 5 GHz channel bonding blocks (20 MHz sub-channels)
_BLOCKS_5GHZ_40 = [
    {36, 40}, {44, 48}, {52, 56}, {60, 64},
    {100, 104}, {108, 112}, {116, 120}, {124, 128},
    {132, 136}, {140, 144}, {149, 153}, {157, 161}, {165, 169}, {173, 177},
]
_BLOCKS_5GHZ_80 = [
    {36, 40, 44, 48}, {52, 56, 60, 64},
    {100, 104, 108, 112}, {116, 120, 124, 128},
    {132, 136, 140, 144}, {149, 153, 157, 161}, {165, 169, 173, 177},
]
_BLOCKS_5GHZ_160 = [
    {36, 40, 44, 48, 52, 56, 60, 64},
    {100, 104, 108, 112, 116, 120, 124, 128},
    {149, 153, 157, 161, 165, 169, 173, 177},
]


def _occupied_subchannels(band: str, ch: int, width_mhz: int) -> frozenset:
    """Return the set of 20 MHz sub-channels occupied by a radio so bonded overlaps are caught."""
    if not ch:
        return frozenset()
    w = width_mhz if width_mhz in (20, 40, 80, 160, 320) else 20
    if "5" in band:
        if w == 160:
            for blk in _BLOCKS_5GHZ_160:
                if ch in blk:
                    return frozenset(blk)
        elif w == 80:
            for blk in _BLOCKS_5GHZ_80:
                if ch in blk:
                    return frozenset(blk)
        elif w == 40:
            for blk in _BLOCKS_5GHZ_40:
                if ch in blk:
                    return frozenset(blk)
        return frozenset({ch})
    if "6" in band and ch >= 1:
        # 6 GHz channels are spaced by 4 starting at Ch 1: 1, 5, 9, 13, ...
        if w == 20:
            return frozenset({ch})
        per_block = w // 20
        idx = (ch - 1) // 4
        start_idx = (idx // per_block) * per_block
        return frozenset(1 + 4 * (start_idx + i) for i in range(per_block))
    return frozenset({ch})


def _read_text_auto(path: str) -> str:
    """Read a text file handling UTF-8, UTF-8-BOM, and UTF-16LE/BE (e.g. wevtutil output)."""
    if not os.path.exists(path):
        return ""
    try:
        with open(path, "rb") as f:
            raw = f.read()
        if not raw:
            return ""
        if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
            return raw.decode("utf-16", errors="replace")
        # Heuristic for BOM-less UTF-16LE/BE (common on Windows redirected output)
        sample = raw[:200]
        if b"\x00" in sample:
            null_even = sum(1 for i in range(0, len(sample), 2) if sample[i] == 0)
            null_odd = sum(1 for i in range(1, len(sample), 2) if sample[i] == 0)
            if null_odd > len(sample) // 6:
                return raw.decode("utf-16-le", errors="replace")
            if null_even > len(sample) // 6:
                return raw.decode("utf-16-be", errors="replace")
            return raw.replace(b"\x00", b"").decode("utf-8", errors="replace")
        return raw.decode("utf-8-sig", errors="replace")
    except Exception:
        return ""


def _safe_int(val, default: int = -100) -> int:
    try:
        return int(float(str(val).strip()))
    except Exception:
        return default


def _parse_iso_ts(ts_str: str):
    """Best-effort parse of ISO-8601 timestamps (with optional Z or fractional seconds)."""
    if not ts_str:
        return None
    s = ts_str.strip()
    if s.endswith("Z"):
        s = s[:-1]
    # Trim >6 fractional digits (Windows event logs use 7 digits)
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None


def _normalize_ap_prefix(bssid: str) -> str:
    """
    Normalize a BSSID to its 5-octet physical AP prefix (xx:xx:xx:xx:xx),
    mapping Ruckus / Access Networks 4th-octet band offsets (+0x40 / +0x80) back to base MAC.
    """
    clean = (bssid or "").strip().lower().replace("-", ":")
    if len(clean) >= 14:
        if "ruckus" in lookup_oui(clean).lower():
            try:
                base_oct4 = int(clean[9:11], 16) & 0x3F
                return f"{clean[:8]}:{base_oct4:02x}:{clean[12:14]}"
            except ValueError:
                pass
        return clean[:14]
    return clean


def detect_connected_ssid(job_folder: str) -> str:
    """Fallback: detect connected SSID from wlan_interfaces.txt if target_ssid is blank."""
    iface_path = os.path.join(job_folder, "wlan_interfaces.txt")
    text = _read_text_auto(iface_path)
    if text:
        for line in text.splitlines():
            l = line.strip()
            if re.match(r"^SSID\s*:", l, re.IGNORECASE):
                val = l.split(":", 1)[1].strip()
                if val:
                    return val
    return ""


def parse_wlan_drivers(job_folder: str) -> dict:
    """
    Parse `wlan_drivers.txt` (`netsh wlan show drivers`) to identify survey adapter
    hardware capabilities and flag potential Wi-Fi 6/6E/7 or 6 GHz blind spots.
    """
    path = os.path.join(job_folder, "wlan_drivers.txt")
    text = _read_text_auto(path)
    info = {
        "present": False,
        "driver": "",
        "vendor": "",
        "version": "",
        "date": "",
        "radio_types": [],
        "bands": [],
        "supports_wifi6": False,
        "supports_wifi7": False,
        "supports_6ghz": False,
        "supports_wpa3": False,
        "warnings": [],
    }
    if not text:
        return info

    info["present"] = True
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if re.match(r"^Driver\s*:", line, re.IGNORECASE):
            info["driver"] = line.split(":", 1)[1].strip()
        elif re.match(r"^Vendor\s*:", line, re.IGNORECASE):
            info["vendor"] = line.split(":", 1)[1].strip()
        elif re.match(r"^Version\s*:", line, re.IGNORECASE):
            info["version"] = line.split(":", 1)[1].strip()
        elif re.match(r"^Date\s*:", line, re.IGNORECASE):
            info["date"] = line.split(":", 1)[1].strip()
        elif re.match(r"^Radio types supported\s*:", line, re.IGNORECASE):
            radios = line.split(":", 1)[1].strip().split()
            info["radio_types"] = radios
        elif re.search(r"\b(2\.4|5|6)\s*GHz\b", line, re.IGNORECASE):
            m = re.search(r"\b(2\.4|5|6)\s*GHz\b", line, re.IGNORECASE)
            if m:
                band_label = f"{m.group(1)} GHz"
                if band_label not in info["bands"]:
                    info["bands"].append(band_label)
        if "wpa3" in line.lower():
            info["supports_wpa3"] = True

    radios_lower = {r.lower() for r in info["radio_types"]}
    info["supports_wifi6"] = "802.11ax" in radios_lower or "802.11be" in radios_lower
    info["supports_wifi7"] = "802.11be" in radios_lower
    info["supports_6ghz"] = "6 GHz" in info["bands"]

    if info["driver"]:
        if not info["supports_wifi6"]:
            info["warnings"].append(
                f"Survey NIC ({info['driver']}) maxes out at Wi-Fi 5 (802.11ac) — "
                "6 GHz band is invisible and Wi-Fi 6/6E/7 client speeds will be under-reported."
            )
        elif not info["supports_6ghz"]:
            info["warnings"].append(
                f"Survey NIC ({info['driver']}) does not support 6 GHz — "
                "Wi-Fi 6E / Wi-Fi 7 6 GHz radios will not appear in scans."
            )
        if not info["supports_wpa3"]:
            info["warnings"].append(
                "Survey NIC driver does not advertise WPA3 support — cannot associate to WPA3-only SSIDs."
            )

    return info


def load_ap_list_csv(job_folder: str) -> dict:
    """
    Auto-detect and parse a controller AP export CSV (e.g. Ruckus Unleashed `AP List.csv`,
    Access Networks, or generic `ap_list.csv` / `ap_names.csv`) in the job folder.
    Returns a dict keyed by normalized 5-octet AP prefix.
    """
    if not os.path.isdir(job_folder):
        return {}

    candidates = []
    for fn in os.listdir(job_folder):
        low = fn.lower()
        if low in ("ap list.csv", "ap_list.csv", "ap_names.csv", "ap_inventory.csv"):
            candidates.append(os.path.join(job_folder, fn))
    if not candidates:
        return {}

    ap_map = {}
    for path in candidates:
        try:
            with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    norm_row = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
                    mac = (
                        norm_row.get("mac address")
                        or norm_row.get("mac")
                        or norm_row.get("bssid")
                        or ""
                    )
                    if not mac:
                        continue
                    pref = _normalize_ap_prefix(mac)
                    if len(pref) < 14:
                        continue
                    ap_map[pref] = {
                        "name": norm_row.get("ap name") or norm_row.get("name") or norm_row.get("device name") or "",
                        "model": norm_row.get("model") or "",
                        "ip": norm_row.get("ip address") or norm_row.get("ip") or "",
                        "mac": mac.lower().replace("-", ":"),
                        "poe": norm_row.get("poe operating mode") or norm_row.get("poe") or "",
                        "uptime": norm_row.get("uptime") or "",
                        "firmware": norm_row.get("firmware version") or norm_row.get("firmware") or "",
                        "role": norm_row.get("role") or "",
                        "channel": norm_row.get("channel") or "",
                    }
        except Exception:
            continue
    return ap_map


def load_waypoints_csv(csv_file: str) -> list:
    if not os.path.exists(csv_file):
        return []
    records = []
    try:
        with open(csv_file, "r", encoding="utf-8-sig", errors="replace") as f:
            first_line = f.readline()
            if not first_line:
                return []
            f.seek(0)
            # Recover gracefully if header row was accidentally deleted
            if first_line.lower().startswith("timestamp,"):
                reader = csv.DictReader(f)
            else:
                reader = csv.DictReader(f, fieldnames=CSV_STANDARD_HEADERS)
            for row in reader:
                records.append({k: (v if v is not None else "") for k, v in row.items() if k is not None})
    except Exception as e:
        print(f"Error reading CSV: {e}")
    return records


def load_baseline_fallback(job_folder: str) -> list:
    """
    Fallback for baseline-only jobs (when survey_waypoints.csv is missing or empty):
    loads `baseline_rf_scan.json` if present, otherwise parses `baseline_rf_scan.txt`.
    """
    json_path = os.path.join(job_folder, "baseline_rf_scan.json")
    if os.path.exists(json_path):
        data = load_json_safe(json_path)
        records = []
        for item in data:
            if isinstance(item, dict) and item.get("bssid"):
                rec = dict(item)
                rec.setdefault("waypoint", "Baseline Scan")
                rec.setdefault("waypoint_id", "0")
                records.append(rec)
        if records:
            return records

    txt_path = os.path.join(job_folder, "baseline_rf_scan.txt")
    text = _read_text_auto(txt_path)
    if not text:
        return []

    records = []
    ts_str = ""
    m_ts = re.search(r"Timestamp:\s*([0-9\-:\s]+)", text)
    if m_ts:
        ts_str = m_ts.group(1).strip().replace(" ", "T")

    for line in text.splitlines():
        if "|" not in line or line.strip().startswith("SSID"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 9:
            continue
        if len(parts) >= 11:
            ssid, bssid, band, ch, width_col, radio, rssi_col, util_col, sta_col, roam_col, sec_col = parts[:11]
            cw_mhz = width_col.rstrip("Mm") if width_col.rstrip("Mm").isdigit() else ""
            roam_flags = "" if roam_col == "-" else roam_col
        else:
            ssid, bssid, band, ch, radio, rssi_col, util_col, sta_col, sec_col = parts[:9]
            cw_mhz = ""
            roam_flags = ""
        if not re.match(r"^[0-9a-fA-F:]{17}$", bssid):
            continue
        m_rssi = re.search(r"(-?\d+)\s*dBm\s*\((\d+)%\)", rssi_col)
        sig_dbm = int(m_rssi.group(1)) if m_rssi else -100
        sig_pct = int(m_rssi.group(2)) if m_rssi else 0
        cu_pct = util_col.replace("%", "").strip() if util_col.endswith("%") else ""
        stations = sta_col if sta_col.isdigit() else ""
        auth, enc = (sec_col.split("/", 1) + [""])[:2]
        records.append({
            "timestamp": ts_str,
            "waypoint": "Baseline Scan",
            "waypoint_id": "0",
            "ssid": ssid,
            "bssid": bssid.lower(),
            "band": band,
            "channel": ch,
            "channel_width_mhz": cw_mhz,
            "roaming_flags": roam_flags,
            "radio_type": radio,
            "signal_dbm": str(sig_dbm),
            "signal_pct": str(sig_pct),
            "cu_pct": cu_pct,
            "stations": stations,
            "auth": auth.strip(),
            "enc": enc.strip(),
        })
    return records


def parse_roaming_events(job_folder: str) -> dict:
    """
    Parse Windows `wlan_roaming_events.txt` (from Microsoft-Windows-WLAN-AutoConfig/Operational)
    handling UTF-8 and UTF-16 encodings, and summarize connects, disconnects, failures,
    security re-keys/roams, and handoff latency.
    """
    path = os.path.join(job_folder, "wlan_roaming_events.txt")
    text = _read_text_auto(path)
    summary = {
        "present": False,
        "total_events": 0,
        "connects": 0,
        "disconnects": 0,
        "connect_failures": 0,
        "assoc_failures": 0,
        "security_rekeys": 0,
        "security_failures": 0,
        "avg_rekey_ms": None,
        "max_rekey_ms": None,
        "ssids": [],
        "time_range": "",
        "failure_reasons": [],
    }
    if not text:
        return summary

    blocks = re.split(r"(?m)^Event\[\d+\]\s*$", text)
    parsed_events = []
    for blk in blocks[1:]:
        m_id = re.search(r"Event ID:\s*(\d+)", blk)
        if not m_id:
            continue
        eid = int(m_id.group(1))
        m_date = re.search(r"Date:\s*(\S+)", blk)
        dt = _parse_iso_ts(m_date.group(1)) if m_date else None
        m_ssid = re.search(r"Network SSID:\s*(.+)", blk)
        ssid = m_ssid.group(1).strip() if m_ssid else ""
        m_reason = re.search(r"Reason:\s*(.+)", blk)
        reason = m_reason.group(1).strip() if m_reason else ""
        parsed_events.append({
            "id": eid,
            "dt": dt,
            "ssid": ssid,
            "reason": reason,
        })

    if not parsed_events:
        return summary

    summary["present"] = True
    summary["total_events"] = len(parsed_events)

    # Sort chronologically (wevtutil /rd:true outputs newest first)
    parsed_events.sort(key=lambda e: e["dt"] or datetime.min)

    valid_dts = [e["dt"] for e in parsed_events if e["dt"] is not None]
    if valid_dts:
        summary["time_range"] = f"{valid_dts[0].strftime('%Y-%m-%d %H:%M:%S')} to {valid_dts[-1].strftime('%H:%M:%S')} UTC"

    ssids_seen = []
    rekey_durations = []
    last_sec_start = {}

    for ev in parsed_events:
        eid = ev["id"]
        ssid = ev["ssid"]
        if ssid and ssid not in ssids_seen:
            ssids_seen.append(ssid)

        if eid == 8001:
            summary["connects"] += 1
        elif eid == 8002:
            summary["connect_failures"] += 1
            if ev["reason"] and ev["reason"] not in summary["failure_reasons"]:
                summary["failure_reasons"].append(ev["reason"])
        elif eid == 8003:
            summary["disconnects"] += 1
        elif eid == 11002:
            summary["assoc_failures"] += 1
            if ev["reason"] and ev["reason"] not in summary["failure_reasons"]:
                summary["failure_reasons"].append(ev["reason"])
        elif eid == 11010:
            if ev["dt"] is not None:
                last_sec_start[ssid] = ev["dt"]
        elif eid == 11005:
            summary["security_rekeys"] += 1
            if ev["dt"] is not None and ssid in last_sec_start:
                delta_ms = (ev["dt"] - last_sec_start[ssid]).total_seconds() * 1000.0
                if 0.0 <= delta_ms <= 15000.0:
                    rekey_durations.append(round(delta_ms, 1))
                last_sec_start.pop(ssid, None)
        elif eid == 11006:
            summary["security_failures"] += 1
            if ev["reason"] and ev["reason"] not in summary["failure_reasons"]:
                summary["failure_reasons"].append(ev["reason"])

    summary["ssids"] = ssids_seen
    if rekey_durations:
        summary["avg_rekey_ms"] = round(sum(rekey_durations) / len(rekey_durations), 1)
        summary["max_rekey_ms"] = round(max(rekey_durations), 1)

    return summary


def load_floorplan_data(job_folder: str) -> dict:
    """Load `floorplan_pins.json` if present in the job folder."""
    path = os.path.join(job_folder, "floorplan_pins.json")
    if not os.path.exists(path):
        return {"floorplans": [], "pins": []}
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return {
                    "floorplans": data.get("floorplans", []),
                    "pins": data.get("pins", []),
                }
    except Exception:
        pass
    return {"floorplans": [], "pins": []}


def _render_walk_svg(walk: dict) -> str:
    """Build a crisp inline SVG timeline of True RSSI (dBm) + Roam markers for PM_SITE_SURVEY_REPORT.html."""
    samples = walk.get("samples", [])
    if len(samples) < 2:
        return ""
    w, h = 880, 175
    pad_l, pad_r, pad_t, pad_b = 46, 18, 18, 28
    plot_w = w - pad_l - pad_r
    plot_h = h - pad_t - pad_b
    max_t = max(float(s.get("elapsed_sec", 0.0) or 0.0) for s in samples) or 1.0

    def x_pos(t_val):
        return round(pad_l + (float(t_val) / max_t) * plot_w, 1)

    def y_rssi(dbm):
        clamped = max(-95.0, min(-30.0, float(dbm)))
        return round(pad_t + ((-30.0 - clamped) / 65.0) * plot_h, 1)

    pts = []
    drop_marks = []
    for s in samples:
        t = float(s.get("elapsed_sec", 0.0) or 0.0)
        rssi = s.get("rssi_dbm")
        if rssi is not None:
            pts.append(f"{x_pos(t)},{y_rssi(rssi)}")
        if s.get("packet_lost"):
            drop_marks.append(f"<circle cx='{x_pos(t)}' cy='{pad_t + plot_h - 4}' r='3.5' fill='#dc2626'/>")

    roam_lines = []
    for r in walk.get("roam_events", []):
        rx = x_pos(r.get("elapsed_sec", 0.0))
        roam_lines.append(
            f"<line x1='{rx}' y1='{pad_t}' x2='{rx}' y2='{pad_t + plot_h}' stroke='#7c3aed' stroke-width='2' stroke-dasharray='4,3'/>"
            f"<text x='{rx + 3}' y='{pad_t + 11}' font-size='10' fill='#7c3aed' font-weight='700'>ROAM Ch{html.escape(str(r.get('to_channel', '')))}</text>"
        )

    y67 = y_rssi(-67)
    grid = ""
    for db in (-40, -55, -67, -80, -90):
        yy = y_rssi(db)
        col = "#f59e0b" if db == -67 else "#e2e8f0"
        dash = " stroke-dasharray='5,4'" if db == -67 else ""
        grid += f"<line x1='{pad_l}' y1='{yy}' x2='{w - pad_r}' y2='{yy}' stroke='{col}'{dash}/>"
        grid += f"<text x='4' y='{yy + 3}' font-size='10' fill='#64748b'>{db} dBm</text>"

    poly = f"<polyline fill='none' stroke='#2563eb' stroke-width='2.2' points='{' '.join(pts)}'/>" if pts else ""
    return (
        f"<svg viewBox='0 0 {w} {h}' style='width:100%;max-width:{w}px;height:auto;border:1px solid #e2e8f0;border-radius:8px;background:#fff;margin:8px 0 12px 0;'>"
        f"{grid}{poly}{''.join(roam_lines)}{''.join(drop_marks)}"
        f"<text x='{pad_l}' y='{h - 6}' font-size='10' fill='#64748b'>0s</text>"
        f"<text x='{w - pad_r - 36}' y='{h - 6}' font-size='10' fill='#64748b'>{round(max_t, 1)}s</text>"
        f"<text x='{pad_l + 100}' y='{h - 6}' font-size='10' fill='#64748b'>Blue = True RSSI | Dashed Orange = -67 dBm | Purple = Roam | Red Dots = Dropped GW Ping</text>"
        f"</svg>"
    )


def _build_floorplans_html(job_folder: str, floorplan_data: dict, wp_summaries: list, format_ap_tag) -> str:
    """Embed uploaded floorplans + pinned waypoints with interactive/print-ready IDW RF heatmap canvas."""
    fps = floorplan_data.get("floorplans", [])
    pins = floorplan_data.get("pins", [])
    if not fps:
        return ""

    # Map waypoint_id & waypoint name -> signal summary
    wp_by_id = {}
    wp_by_name = {}
    for ws in wp_summaries:
        wid = str(ws.get("waypoint_id", "") or "").strip()
        if wid:
            wp_by_id[wid] = ws
        wp_by_name[(ws.get("raw_waypoint") or ws.get("waypoint", "")).strip().lower()] = ws

    cards = []
    for idx, fp in enumerate(fps):
        fname = fp.get("filename", "")
        fpath = os.path.join(job_folder, "floorplans", fname)
        if not os.path.isfile(fpath):
            continue
        ext = os.path.splitext(fname)[1].lower().lstrip(".")
        mime = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "webp": "image/webp"}.get(ext, "image/png")
        try:
            with open(fpath, "rb") as imgf:
                b64 = base64.b64encode(imgf.read()).decode("ascii")
        except Exception:
            continue

        fp_pins = []
        for p in pins:
            if p.get("floor_id") != fp.get("id"):
                continue
            ws = wp_by_id.get(str(p.get("waypoint_id", "")).strip()) or wp_by_name.get((p.get("waypoint") or "").strip().lower())
            b5 = ws["best_5"] if ws else None
            b24 = ws["best_24"] if ws else None
            fp_pins.append({
                "x": float(p.get("x", 0.5)),
                "y": float(p.get("y", 0.5)),
                "label": p.get("waypoint") or (ws["waypoint"] if ws else "Pin"),
                "dbm5": _safe_int(b5.get("signal_dbm")) if b5 else None,
                "ap5": format_ap_tag(b5.get("bssid")) if b5 else "",
                "dbm24": _safe_int(b24.get("signal_dbm")) if b24 else None,
            })

        pins_json = json.dumps(fp_pins).replace("</", "<\\/")
        label = html.escape(str(fp.get("label") or fname))
        cards.append(f"""
        <div class="fp-block" style="margin-bottom:20px;">
          <h3 style="margin:8px 0;font-size:14px;color:#334155;">{label} ({len(fp_pins)} pinned waypoints &mdash; 5/6 GHz RF Heatmap)</h3>
          <div style="position:relative;display:inline-block;max-width:100%;border:1px solid #cbd5e1;border-radius:8px;overflow:hidden;">
            <img id="fpImg_{idx}" src="data:{mime};base64,{b64}" style="display:block;max-width:100%;height:auto;" onload="if(window.renderReportHeatmap)renderReportHeatmap({idx})">
            <canvas id="fpCanvas_{idx}" style="position:absolute;top:0;left:0;width:100%;height:100%;pointer-events:none;"></canvas>
          </div>
          <script>window._fpPins = window._fpPins || {{}}; window._fpPins[{idx}] = {pins_json};</script>
        </div>""")

    if not cards:
        return ""

    heatmap_script = """
    <script>
    function _rssiColor(dbm) {
      if (dbm >= -55) return [22, 163, 74];
      if (dbm >= -65) return [132, 204, 22];
      if (dbm >= -70) return [245, 158, 11];
      if (dbm >= -76) return [249, 115, 22];
      return [220, 38, 38];
    }
    window.renderReportHeatmap = function(idx) {
      const img = document.getElementById("fpImg_" + idx);
      const canvas = document.getElementById("fpCanvas_" + idx);
      const pins = (window._fpPins && window._fpPins[idx]) || [];
      if (!img || !canvas || !img.naturalWidth) return;
      const w = img.naturalWidth, h = img.naturalHeight;
      canvas.width = w; canvas.height = h;
      const ctx = canvas.getContext("2d");
      ctx.clearRect(0, 0, w, h);

      const valid = pins.filter(p => p.dbm5 !== null && p.dbm5 !== undefined);
      if (valid.length > 0) {
        const gridW = 140, gridH = Math.max(60, Math.round(gridW * (h / w)));
        const off = document.createElement("canvas");
        off.width = gridW; off.height = gridH;
        const octx = off.getContext("2d");
        const idata = octx.createImageData(gridW, gridH);
        const maxRadius = 0.32;
        for (let gy = 0; gy < gridH; gy++) {
          const ny = (gy + 0.5) / gridH;
          for (let gx = 0; gx < gridW; gx++) {
            const nx = (gx + 0.5) / gridW;
            let num = 0, den = 0, minD = 99;
            for (const p of valid) {
              const dx = nx - p.x, dy = ny - p.y;
              const d = Math.hypot(dx, dy);
              if (d < minD) minD = d;
              const wt = 1 / (d * d + 0.0008);
              num += p.dbm5 * wt;
              den += wt;
            }
            if (minD <= maxRadius && den > 0) {
              const val = num / den;
              const rgb = _rssiColor(val);
              const fade = Math.max(0, Math.min(1, 1 - (minD / maxRadius) * 0.75));
              const pos = (gy * gridW + gx) * 4;
              idata.data[pos] = rgb[0];
              idata.data[pos + 1] = rgb[1];
              idata.data[pos + 2] = rgb[2];
              idata.data[pos + 3] = Math.round(135 * fade);
            }
          }
        }
        octx.putImageData(idata, 0, 0);
        ctx.drawImage(off, 0, 0, w, h);
      }

      const scale = Math.max(1, w / 900);
      for (const p of pins) {
        const px = p.x * w, py = p.y * h;
        const rgb = p.dbm5 !== null ? _rssiColor(p.dbm5) : [100, 116, 139];
        ctx.beginPath();
        ctx.arc(px, py, 9 * scale, 0, Math.PI * 2);
        ctx.fillStyle = `rgb(${rgb[0]},${rgb[1]},${rgb[2]})`;
        ctx.fill();
        ctx.lineWidth = 2.5 * scale;
        ctx.strokeStyle = "#ffffff";
        ctx.stroke();

        const tag = p.dbm5 !== null ? `${p.label} (${p.dbm5} dBm)` : p.label;
        ctx.font = `bold ${Math.round(12 * scale)}px sans-serif`;
        const tw = ctx.measureText(tag).width;
        const bx = Math.min(w - tw - 12 * scale, Math.max(4, px + 11 * scale));
        const by = Math.max(18 * scale, py - 8 * scale);
        ctx.fillStyle = "rgba(15, 23, 42, 0.85)";
        ctx.fillRect(bx - 4 * scale, by - 13 * scale, tw + 8 * scale, 18 * scale);
        ctx.fillStyle = "#ffffff";
        ctx.fillText(tag, bx, by);
      }
    };
    window.addEventListener("load", function() {
      if (!window._fpPins) return;
      Object.keys(window._fpPins).forEach(function(k) { window.renderReportHeatmap(Number(k)); });
    });
    </script>"""

    return f"""
    <h2>Floorplan RF Coverage Heatmaps</h2>
    <div class="sub" style="margin-bottom:8px;">Legend: <span class="badge badge-good">&ge; -65 dBm Strong</span> <span class="badge badge-warn">-66 to -75 dBm Fair</span> <span class="badge badge-bad">&le; -76 dBm Weak</span></div>
    {heatmap_script}
    {''.join(cards)}"""


def load_csv_generic(path: str) -> list:
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
            return [
                {k: (v if v is not None else "") for k, v in row.items() if k is not None}
                for row in csv.DictReader(f)
            ]
    except Exception:
        return []


def load_json_safe(path: str):
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
            data = json.load(f)
            return data if isinstance(data, list) else [data]
    except Exception:
        return []


def _group_waypoint_batches(records: list, telemetry_rows: list) -> list:
    """
    Preserve chronological waypoint batches WITHOUT merging or overwriting repeated room names.
    Groups by `waypoint_id` when present, otherwise splits whenever the waypoint name changes
    or the scan timestamp jumps by > 15 seconds on the same name. Pairs each batch 1-to-1 with
    its corresponding row in `waypoint_telemetry.csv`.
    """
    batches = []
    cur_batch = None

    for r in records:
        wp = (r.get("waypoint") or "").strip()
        if not wp:
            continue
        wid = str(r.get("waypoint_id", "") or "").strip()
        dt = _parse_iso_ts(r.get("timestamp", ""))

        start_new = False
        if cur_batch is None:
            start_new = True
        elif wid and cur_batch["waypoint_id"]:
            if wid != cur_batch["waypoint_id"] or wp != cur_batch["waypoint"]:
                start_new = True
        elif wp != cur_batch["waypoint"]:
            start_new = True
        elif dt is not None and cur_batch["last_dt"] is not None:
            if abs((dt - cur_batch["last_dt"]).total_seconds()) > 15.0:
                start_new = True

        if start_new:
            cur_batch = {
                "waypoint": wp,
                "waypoint_id": wid,
                "first_ts": r.get("timestamp", ""),
                "first_dt": dt,
                "last_dt": dt,
                "records": [r],
            }
            batches.append(cur_batch)
        else:
            cur_batch["records"].append(r)
            if dt is not None:
                cur_batch["last_dt"] = dt

    # Label repeated room names cleanly (e.g., "Office (#1)", "Office (#2)")
    name_counts = defaultdict(int)
    for b in batches:
        name_counts[b["waypoint"]] += 1
    seen_counts = defaultdict(int)
    for b in batches:
        name = b["waypoint"]
        seen_counts[name] += 1
        if name_counts[name] > 1:
            b["display_name"] = f"{name} (#{seen_counts[name]})"
        else:
            b["display_name"] = name

    # Match each batch 1-to-1 with telemetry rows
    used_tel = set()
    for b in batches:
        matched_idx = None
        b_wid = b["waypoint_id"]
        b_wp = b["waypoint"]
        b_dt = b["first_dt"]

        # 1. Exact waypoint_id match
        if b_wid:
            for idx, t in enumerate(telemetry_rows):
                if idx in used_tel:
                    continue
                if str(t.get("waypoint_id", "") or "").strip() == b_wid:
                    matched_idx = idx
                    break

        # 2. Same waypoint name with closest timestamp (within 90s)
        if matched_idx is None:
            best_diff = None
            for idx, t in enumerate(telemetry_rows):
                if idx in used_tel:
                    continue
                if (t.get("waypoint") or "").strip() != b_wp:
                    continue
                t_dt = _parse_iso_ts(t.get("timestamp", ""))
                if b_dt is not None and t_dt is not None:
                    diff = abs((t_dt - b_dt).total_seconds())
                    if diff <= 90.0 and (best_diff is None or diff < best_diff):
                        best_diff = diff
                        matched_idx = idx
                elif matched_idx is None:
                    matched_idx = idx

        if matched_idx is not None:
            used_tel.add(matched_idx)
            b["telemetry"] = telemetry_rows[matched_idx]
        else:
            b["telemetry"] = {}

    return batches


def generate_summary(job_folder: str):
    meta_file = os.path.join(job_folder, "job_meta.json")
    meta = {}
    if os.path.exists(meta_file):
        try:
            with open(meta_file, "r", encoding="utf-8-sig", errors="replace") as f:
                meta = json.load(f)
        except Exception as e:
            print(f"[!] Warning reading job_meta.json: {e}")

    records = load_waypoints_csv(os.path.join(job_folder, "survey_waypoints.csv"))
    used_baseline_fallback = False
    if not records:
        records = load_baseline_fallback(job_folder)
        if records:
            used_baseline_fallback = True

    telemetry_rows = load_csv_generic(os.path.join(job_folder, "waypoint_telemetry.csv"))
    lan_devices = load_csv_generic(os.path.join(job_folder, "lan_devices.csv"))
    speedtest_runs = load_json_safe(os.path.join(job_folder, "speedtest_results.json"))
    controller_aps = load_ap_list_csv(job_folder)
    nic_info = parse_wlan_drivers(job_folder)
    roaming_summary = parse_roaming_events(job_folder)
    walk_tests = load_json_safe(os.path.join(job_folder, "roaming_walk_summary.json"))
    floorplan_data = load_floorplan_data(job_folder)

    target_ssid = meta.get("target_ssid", "").strip()
    if not target_ssid:
        target_ssid = detect_connected_ssid(job_folder)

    def matches_target(ssid_val: str) -> bool:
        if not target_ssid:
            return ssid_val not in ("<Hidden / Broadcast>", "<Dead Zone>", "")
        s_clean = (ssid_val or "").strip().lower()
        t_clean = target_ssid.strip().lower()
        return s_clean == t_clean

    # Determine whether the target SSID has exact matches in the dataset.
    # Only use substring fallback if the user typed a partial SSID with zero exact matches across the entire survey.
    use_substring_fallback = False
    if records and target_ssid:
        exact_matches = [r for r in records if matches_target(r.get("ssid", "")) and r.get("bssid")]
        if not exact_matches:
            use_substring_fallback = True

    def record_matches_target(r: dict) -> bool:
        ssid_val = r.get("ssid", "")
        if matches_target(ssid_val):
            return True
        if use_substring_fallback and target_ssid:
            return target_ssid.lower() in (ssid_val or "").lower()
        return False

    # Group target BSSIDs into physical APs by normalized 5-octet MAC prefix
    ap_prefix_map = {}
    ap_short_name = {}
    ap_details = defaultdict(lambda: {
        "prefix": "", "vendor": "", "radios": {},
        "controller_name": "", "model": "", "ip": "", "poe": "", "firmware": "", "uptime": "",
        "roaming_flags": set(), "pmf_modes": set(), "min_basic_24": None,
    })
    ap_channels_by_band = defaultdict(set)       # (ap_label, band) -> set of primary channels
    ap_radio_spans = defaultdict(list)           # band -> list of {"ap": label, "ch": int, "width": int, "subchannels": frozenset}
    seen_radio_span_keys = set()
    has_phase2_ie_data = False

    if records:
        target_recs_all = [r for r in records if record_matches_target(r) and len(r.get("bssid", "")) >= 14]
        # Collect broadcast AP names from beacons as secondary fallback when AP List.csv is absent
        beacon_ap_names = {}
        for r in target_recs_all:
            b_ap_name = (r.get("ap_name") or "").strip()
            if b_ap_name:
                beacon_ap_names.setdefault(_normalize_ap_prefix(r.get("bssid", "")), b_ap_name)
            if str(r.get("channel_width_mhz", "")).strip() or (r.get("roaming_flags") or "").strip() or (r.get("pmf") or "").strip():
                has_phase2_ie_data = True

        prefixes = sorted(list(set(_normalize_ap_prefix(r.get("bssid", "")) for r in target_recs_all)))
        for idx, pref in enumerate(prefixes, start=1):
            ctrl = controller_aps.get(pref, {})
            ctrl_name = ctrl.get("name", "") or beacon_ap_names.get(pref, "")
            ap_label = f"AP {idx} - {ctrl_name}" if ctrl_name else f"AP {idx}"
            ap_prefix_map[pref] = ap_label
            ap_short_name[pref] = ctrl_name if ctrl_name else f"AP {idx}"
            ap_details[ap_label]["prefix"] = pref
            ap_details[ap_label]["vendor"] = lookup_oui(pref)
            if ctrl_name:
                ap_details[ap_label]["controller_name"] = ctrl_name
            if ctrl:
                ap_details[ap_label]["model"] = ctrl.get("model", "")
                ap_details[ap_label]["ip"] = ctrl.get("ip", "")
                ap_details[ap_label]["poe"] = ctrl.get("poe", "")
                ap_details[ap_label]["firmware"] = ctrl.get("firmware", "")
                ap_details[ap_label]["uptime"] = ctrl.get("uptime", "")

        radio_lists = defaultdict(lambda: defaultdict(list))
        for r in target_recs_all:
            bssid = r.get("bssid", "")
            pref = _normalize_ap_prefix(bssid)
            if pref in ap_prefix_map:
                ap_label = ap_prefix_map[pref]
                band = r.get("band", "Unknown")
                ch = str(r.get("channel", "?")).strip()
                cw_s = str(r.get("channel_width_mhz", "") or "").strip()
                cw_int = int(cw_s) if cw_s.isdigit() else 0
                radio = r.get("radio_type", "")
                cw_tag = f" @{cw_int}MHz" if cw_int else ""
                entry = f"{bssid} (Ch {ch}{cw_tag}, {radio})"
                if entry not in radio_lists[ap_label][band]:
                    radio_lists[ap_label][band].append(entry)

                roam_f = (r.get("roaming_flags") or "").strip()
                if roam_f:
                    for tok in roam_f.split("/"):
                        if tok.strip():
                            ap_details[ap_label]["roaming_flags"].add(tok.strip())
                pmf_v = (r.get("pmf") or "").strip()
                if pmf_v and pmf_v != "None":
                    ap_details[ap_label]["pmf_modes"].add(pmf_v)
                mbr_s = str(r.get("min_basic_rate_mbps", "") or "").strip()
                if "2.4" in band and mbr_s:
                    try:
                        mbr_f = float(mbr_s)
                        cur_mbr = ap_details[ap_label]["min_basic_24"]
                        if cur_mbr is None or mbr_f < cur_mbr:
                            ap_details[ap_label]["min_basic_24"] = mbr_f
                    except ValueError:
                        pass

                if ch.isdigit():
                    ch_int = int(ch)
                    ap_channels_by_band[(ap_label, band)].add(ch_int)
                    span_key = (ap_label, band, ch_int, cw_int or 20)
                    if span_key not in seen_radio_span_keys:
                        seen_radio_span_keys.add(span_key)
                        ap_radio_spans[band].append({
                            "ap": ap_label,
                            "ch": ch_int,
                            "width": cw_int or 20,
                            "subchannels": _occupied_subchannels(band, ch_int, cw_int or 20),
                        })

        for ap_label, bands_dict in radio_lists.items():
            for band, entries in bands_dict.items():
                ap_details[ap_label]["radios"][band] = ", ".join(entries)

    def format_ap_tag(bssid: str) -> str:
        if not bssid:
            return "N/A"
        pref = _normalize_ap_prefix(bssid)
        if pref in ap_short_name:
            return f"{ap_short_name[pref]} ({bssid[-5:]})"
        return bssid

    # Group chronological waypoint batches (preserving duplicates cleanly)
    batches = _group_waypoint_batches(records, telemetry_rows)

    # Detect Connected SSID vs Target SSID mismatch
    connected_ssids_mismatched = []
    if target_ssid:
        for t in telemetry_rows:
            c_ssid = (t.get("connected_ssid") or "").strip()
            if c_ssid and c_ssid.lower() != target_ssid.lower():
                if c_ssid not in connected_ssids_mismatched:
                    connected_ssids_mismatched.append(c_ssid)

    # Build per-waypoint summary objects + detect Sticky Clients + Co-Channel overlap
    wp_summaries = []
    sticky_alerts = []
    cci_room_hits = defaultdict(set)  # (band, ch_int) -> set of waypoint display names

    for batch in batches:
        wp_disp = batch["display_name"]
        wp_recs = batch["records"]
        tel = batch["telemetry"]

        if target_ssid:
            t_recs = [r for r in wp_recs if record_matches_target(r) and r.get("bssid")]
        else:
            t_recs = [r for r in wp_recs if r.get("bssid")]

        recs_5_6 = [r for r in t_recs if "5" in r.get("band", "") or "6" in r.get("band", "")]
        recs_24 = [r for r in t_recs if "2.4" in r.get("band", "")]

        # Sort 5/6 GHz records strongest-first to find Primary and Secondary DISTINCT physical APs
        recs_5_6_sorted = sorted(recs_5_6, key=lambda x: _safe_int(x.get("signal_dbm", -100)), reverse=True)
        best_5 = recs_5_6_sorted[0] if recs_5_6_sorted else None
        second_5 = None
        if best_5:
            best_pref = _normalize_ap_prefix(best_5.get("bssid", ""))
            for cand in recs_5_6_sorted[1:]:
                if _normalize_ap_prefix(cand.get("bssid", "")) != best_pref:
                    second_5 = cand
                    break

        best_24 = max(recs_24, key=lambda x: _safe_int(x.get("signal_dbm", -100))) if recs_24 else None

        # Track rooms where >= 2 distinct target APs are heard simultaneously >= -75 dBm on the same channel
        per_ch_aps = defaultdict(set)
        for r in t_recs:
            ch_s = str(r.get("channel", "")).strip()
            if ch_s.isdigit() and _safe_int(r.get("signal_dbm", -100)) >= -75:
                per_ch_aps[(r.get("band", ""), int(ch_s))].add(_normalize_ap_prefix(r.get("bssid", "")))
        for (band_k, ch_k), pref_set in per_ch_aps.items():
            if len(pref_set) >= 2:
                cci_room_hits[(band_k, ch_k)].add(wp_disp)

        # Sticky Client detection (only when connected to an AP in our target hardware fleet)
        sticky_note = ""
        conn_bssid = (tel.get("connected_bssid") or "").strip().lower()
        if conn_bssid and best_5:
            conn_pref = _normalize_ap_prefix(conn_bssid)
            best_pref = _normalize_ap_prefix(best_5.get("bssid", ""))
            if conn_pref in ap_prefix_map and best_pref in ap_prefix_map and conn_pref != best_pref:
                # Compare apples-to-apples using scan RSSI of connected AP in same room if available
                conn_scan_recs = [
                    r for r in wp_recs
                    if _normalize_ap_prefix(r.get("bssid", "")) == conn_pref
                    and ("5" in r.get("band", "") or "6" in r.get("band", ""))
                ]
                if conn_scan_recs:
                    conn_dbm = max(_safe_int(r.get("signal_dbm", -100)) for r in conn_scan_recs)
                else:
                    conn_dbm = _safe_int(tel.get("true_rssi_dbm", ""), -100)
                best_dbm = _safe_int(best_5.get("signal_dbm", -100))
                delta_db = best_dbm - conn_dbm
                if delta_db >= 8 and conn_dbm <= -62:
                    sticky_note = (
                        f"Stuck on {format_ap_tag(conn_bssid)} ({conn_dbm} dBm) "
                        f"while {format_ap_tag(best_5.get('bssid'))} is {best_dbm} dBm (+{delta_db} dB)"
                    )
                    sticky_alerts.append({
                        "waypoint": wp_disp,
                        "connected_ap": format_ap_tag(conn_bssid),
                        "connected_dbm": conn_dbm,
                        "better_ap": format_ap_tag(best_5.get("bssid")),
                        "better_dbm": best_dbm,
                        "delta_db": delta_db,
                    })

        ts_raw = batch["first_ts"] or ""
        ts_short = ts_raw[11:19] if len(ts_raw) >= 19 else ts_raw

        wp_summaries.append({
            "waypoint": wp_disp,
            "raw_waypoint": batch["waypoint"],
            "waypoint_id": batch["waypoint_id"],
            "time": ts_short,
            "best_5": best_5,
            "second_5": second_5,
            "best_24": best_24,
            "telemetry": tel,
            "sticky_note": sticky_note,
        })

    # RF Health Audit 1: Target AP Co-Channel Interference (CCI - exact & bonded width overlap) & DFS
    ch_to_target_aps = defaultdict(list)
    dfs_target_aps = []
    for (ap_label, band), ch_set in sorted(ap_channels_by_band.items()):
        for ch_int in sorted(ch_set):
            if ap_label not in ch_to_target_aps[(band, ch_int)]:
                ch_to_target_aps[(band, ch_int)].append(ap_label)
            if "5" in band and ch_int in DFS_5GHZ_CHANNELS:
                dfs_target_aps.append({"ap": ap_label, "channel": ch_int})

    cci_alerts = []
    cci_covered_pairs = set()
    for (band, ch_int), aps in sorted(ch_to_target_aps.items()):
        if len(aps) >= 2:
            cci_alerts.append({
                "band": band,
                "channel": str(ch_int),
                "aps": aps,
                "overlap_rooms": sorted(list(cci_room_hits.get((band, ch_int), set()))),
                "detail": "",
            })
            for i in range(len(aps)):
                for j in range(i + 1, len(aps)):
                    cci_covered_pairs.add((band, tuple(sorted((aps[i], aps[j])))))

    # Also detect bonded 40/80/160/320 MHz overlaps where primary channels differ (e.g. Ch 36@80M + Ch 44@80M)
    for band, span_list in sorted(ap_radio_spans.items()):
        if "5" not in band and "6" not in band:
            continue
        for i in range(len(span_list)):
            for j in range(i + 1, len(span_list)):
                a, b = span_list[i], span_list[j]
                if a["ap"] == b["ap"] or a["ch"] == b["ch"]:
                    continue
                shared = a["subchannels"] & b["subchannels"]
                if shared:
                    pair_key = (band, tuple(sorted((a["ap"], b["ap"]))))
                    if pair_key not in cci_covered_pairs:
                        cci_covered_pairs.add(pair_key)
                        cci_alerts.append({
                            "band": band,
                            "channel": f"{a['ch']}/{b['ch']}",
                            "aps": [
                                f"{a['ap']} (Ch {a['ch']} @{a['width']}MHz)",
                                f"{b['ap']} (Ch {b['ch']} @{b['width']}MHz)",
                            ],
                            "overlap_rooms": [],
                            "detail": f"bonded spectrum overlap on sub-channels {sorted(shared)}",
                        })

    # RF Health Audit 1b: 40 MHz on 2.4 GHz (major interference red flag), 802.11k/v, Legacy 1/2 Mbps Basic Rates
    wide_24_alerts = []
    seen_wide24 = set()
    for r in records:
        if "2.4" not in (r.get("band") or ""):
            continue
        cw_s = str(r.get("channel_width_mhz", "") or "").strip()
        if cw_s.isdigit() and int(cw_s) >= 40:
            dbm = _safe_int(r.get("signal_dbm", -100))
            is_target = record_matches_target(r)
            if not is_target and dbm < -75:
                continue
            bssid = (r.get("bssid") or "").strip().lower()
            wkey = (_normalize_ap_prefix(bssid), str(r.get("channel", "")))
            if wkey not in seen_wide24:
                seen_wide24.add(wkey)
                wide_24_alerts.append({
                    "ssid": r.get("ssid", ""),
                    "bssid": bssid,
                    "channel": str(r.get("channel", "")),
                    "width_mhz": int(cw_s),
                    "is_target": is_target,
                    "dbm": dbm,
                    "vendor": lookup_oui(bssid),
                })

    roaming_cap_warnings = []
    legacy_rate_warnings = []
    if has_phase2_ie_data and ap_details:
        if len(ap_details) >= 2:
            missing_kv = [
                ap_lbl for ap_lbl, info in ap_details.items()
                if not ({"11k", "11v"} <= info["roaming_flags"])
            ]
            if missing_kv:
                roaming_cap_warnings.append(
                    f"{len(missing_kv)}/{len(ap_details)} target AP(s) missing full 802.11k/v assisted roaming "
                    f"({', '.join(missing_kv[:6])})"
                )
        legacy_aps = [
            f"{ap_lbl} ({info['min_basic_24']:g} Mbps)"
            for ap_lbl, info in ap_details.items()
            if info["min_basic_24"] is not None and info["min_basic_24"] <= 2.0
        ]
        if legacy_aps:
            legacy_rate_warnings.append(
                f"2.4 GHz legacy 802.11b basic rates enabled on {', '.join(legacy_aps)} "
                "(disable 1/2/5.5 Mbps rates to reduce beacon airtime overhead)"
            )

    # RF Health Audit 2: 2.4 GHz Non-Standard Channel (ACI) Alerts (deduped by physical radio)
    aci_map = {}
    for r in records:
        if "2.4" not in (r.get("band") or ""):
            continue
        ch_s = str(r.get("channel", "")).strip()
        if not ch_s.isdigit():
            continue
        ch_int = int(ch_s)
        if ch_int in NON_OVERLAPPING_24GHZ:
            continue
        dbm = _safe_int(r.get("signal_dbm", -100))
        cu_s = str(r.get("cu_pct", "")).strip()
        cu_val = int(cu_s) if cu_s.isdigit() else None
        if dbm < -80 and (cu_val is None or cu_val < 25):
            continue
        bssid = (r.get("bssid") or "").strip().lower()
        rkey = (_normalize_ap_prefix(bssid), ch_int)
        entry = aci_map.get(rkey)
        ssid = (r.get("ssid") or "").strip()
        if entry is None:
            aci_map[rkey] = {
                "ssids": [ssid] if ssid else [],
                "bssid": bssid,
                "vendor": lookup_oui(bssid),
                "channel": ch_int,
                "peak_dbm": dbm,
                "peak_cu": cu_val,
            }
        else:
            if ssid and ssid not in entry["ssids"]:
                entry["ssids"].append(ssid)
            if dbm > entry["peak_dbm"]:
                entry["peak_dbm"] = dbm
            if cu_val is not None and (entry["peak_cu"] is None or cu_val > entry["peak_cu"]):
                entry["peak_cu"] = cu_val
    aci_alerts = sorted(aci_map.values(), key=lambda x: x["peak_dbm"], reverse=True)

    # RF Health Audit 3: Peak Channel Utilization (>= 35%), deduplicated per physical radio
    cu_by_radio = {}
    for r in records:
        cu_val_s = str(r.get("cu_pct", "")).strip()
        if not cu_val_s.isdigit():
            continue
        cu_val = int(cu_val_s)
        if cu_val < 35:
            continue
        bssid = (r.get("bssid") or "").strip().lower()
        band = (r.get("band") or "").strip()
        ch = str(r.get("channel", "")).strip()
        ssid = (r.get("ssid") or "").strip()
        wp = (r.get("waypoint") or "").strip()
        rkey = (_normalize_ap_prefix(bssid), band, ch)
        existing = cu_by_radio.get(rkey)
        if existing is None:
            cu_by_radio[rkey] = {
                "ssids": [ssid] if ssid else [],
                "bssid": bssid,
                "vendor": lookup_oui(bssid),
                "channel": ch,
                "band": band,
                "cu_pct": cu_val,
                "peak_waypoint": wp,
                "ap_tag": ap_short_name.get(_normalize_ap_prefix(bssid), ""),
            }
        else:
            if ssid and ssid not in existing["ssids"]:
                existing["ssids"].append(ssid)
            if cu_val > existing["cu_pct"]:
                existing["cu_pct"] = cu_val
                existing["peak_waypoint"] = wp
                existing["bssid"] = bssid

    high_cu_alerts = []
    for item in cu_by_radio.values():
        non_hidden = [s for s in item["ssids"] if s and s != "<Hidden / Broadcast>"]
        ssid_label = ", ".join(non_hidden) if non_hidden else "<Hidden / Broadcast>"
        item["ssid"] = ssid_label
        high_cu_alerts.append(item)
    high_cu_alerts.sort(key=lambda x: (-x["cu_pct"], x["band"], _safe_int(x["channel"], 0)))

    # 1. Generate Executive HTML Report first so its file size is captured in the artifact inventory
    html_path = os.path.join(job_folder, "PM_SITE_SURVEY_REPORT.html")
    generate_html_report(
        html_path, meta, target_ssid, ap_details, wp_summaries,
        speedtest_runs, lan_devices, high_cu_alerts, format_ap_tag,
        nic_info=nic_info,
        cci_alerts=cci_alerts,
        aci_alerts=aci_alerts,
        dfs_target_aps=dfs_target_aps,
        sticky_alerts=sticky_alerts,
        wide_24_alerts=wide_24_alerts,
        roaming_cap_warnings=roaming_cap_warnings,
        legacy_rate_warnings=legacy_rate_warnings,
        roaming_summary=roaming_summary,
        walk_tests=walk_tests,
        floorplan_data=floorplan_data,
        job_folder=job_folder,
        connected_ssids_mismatched=connected_ssids_mismatched,
        used_baseline_fallback=used_baseline_fallback,
    )

    # 2. Build and Write ENGINEERING_HANDOFF_SUMMARY.txt
    summary_path = os.path.join(job_folder, "ENGINEERING_HANDOFF_SUMMARY.txt")
    body_lines = []

    if nic_info.get("present") and nic_info.get("driver"):
        body_lines.append("[SURVEY ADAPTER CAPABILITIES]")
        radios_txt = " ".join(nic_info["radio_types"]) or "Unknown"
        bands_txt = ", ".join(nic_info["bands"]) or "Unknown"
        body_lines.append(
            f"  Adapter : {nic_info['driver']} (Driver v{nic_info['version'] or 'N/A'}, {nic_info['date'] or 'N/A'})"
        )
        body_lines.append(f"  Radios  : {radios_txt} | Bands: {bands_txt} | WPA3: {'Yes' if nic_info['supports_wpa3'] else 'No'}")
        for w in nic_info["warnings"]:
            body_lines.append(f"  [!] NOTE: {w}")
        body_lines.append("")

    if connected_ssids_mismatched:
        body_lines.append("[!] SSID CONTEXT NOTICE")
        body_lines.append(
            f"  Survey laptop was connected to {', '.join(connected_ssids_mismatched)} "
            f"while auditing target SSID '{target_ssid}'."
        )
        body_lines.append("  Active link rate & ping telemetry reflect the connected management/test SSID.")
        body_lines.append("")

    if ap_details:
        src_note = " (from Baseline RF Scan)" if used_baseline_fallback else ""
        body_lines.append(f"[DETECTED ACCESS POINTS FOR '{target_ssid or 'SITE'}'{src_note}]")
        for ap_label, info in ap_details.items():
            radios_str = " | ".join(f"{b}: {v}" for b, v in sorted(info["radios"].items()))
            extra = []
            if info["model"]:
                extra.append(info["model"])
            if info["ip"]:
                extra.append(info["ip"])
            if info["poe"]:
                extra.append(info["poe"])
            if info["firmware"]:
                extra.append(f"FW {info['firmware']}")
            if info["roaming_flags"]:
                extra.append("/".join(sorted(info["roaming_flags"])))
            if info["pmf_modes"]:
                extra.append(f"PMF:{'/'.join(sorted(info['pmf_modes']))}")
            extra_str = f" [{', '.join(extra)}]" if extra else ""
            body_lines.append(f"  * {ap_label:22} [{info['prefix']}:xx] ({info['vendor']}){extra_str} -> {radios_str}")
        body_lines.append("")

    if speedtest_runs:
        body_lines.append("[CLOUDFLARE SPEEDTEST & BUFFERBLOAT AUDIT]")
        for sr in speedtest_runs:
            loc = sr.get("waypoint", "Baseline")
            st = sr.get("speedtest", {})
            hop = sr.get("split_hop_ping", {})
            gw = hop.get("gateway", {})
            wan = hop.get("wan", {})
            if st.get("status") == "success":
                body_lines.append(
                    f"  * [{loc}] Down: {st.get('download_mbps')} Mbps | Up: {st.get('upload_mbps')} Mbps | "
                    f"Unloaded Ping: {st.get('unloaded_ping_ms')} ms (Jitter {st.get('unloaded_jitter_ms')} ms) | "
                    f"Bufferbloat: +{st.get('bufferbloat_delta_ms')} ms ({st.get('bufferbloat_grade')})"
                )
            if gw or wan:
                body_lines.append(
                    f"    Split-Hop Ping -> Gateway ({gw.get('host', 'N/A')}): {gw.get('avg_ms')} ms "
                    f"(Loss {gw.get('loss_pct')}%) | WAN (1.1.1.1): {wan.get('avg_ms')} ms "
                    f"(Loss {wan.get('loss_pct')}%) | {hop.get('diagnosis', '')}"
                )
        body_lines.append("")

    if wp_summaries:
        body_lines.append("[SURVEY COVERAGE & WAYPOINT SUMMARY (5/6 GHz vs. 2.4 GHz)]")
        body_lines.append(f"  Total Waypoints Logged : {len(wp_summaries)}")
        body_lines.append(f"  Total BSSID Records    : {len(records)}")
        body_lines.append("")
        body_lines.append("  " + "-" * 112)
        body_lines.append(
            f"  {'Waypoint / Room':24} | {'Primary 5/6 GHz':26} | {'2nd 5/6 GHz':20} | "
            f"{'Best 2.4 GHz':22} | {'Ping GW/WAN'}"
        )
        body_lines.append("  " + "-" * 112)

        for ws in wp_summaries:
            wp = ws["waypoint"][:24]
            b5 = ws["best_5"]
            sec5 = ws["second_5"]
            b24 = ws["best_24"]
            tel = ws["telemetry"]

            if b5:
                s5 = f"{b5.get('signal_dbm')} dBm {format_ap_tag(b5.get('bssid'))} c{b5.get('channel')}"[:26]
            else:
                s5 = "NO 5/6G SIGNAL"

            if sec5:
                s5_2 = f"{sec5.get('signal_dbm')} dBm {format_ap_tag(sec5.get('bssid'))}"[:20]
            else:
                s5_2 = "None (1 AP only)"

            if b24:
                s24 = f"{b24.get('signal_dbm')} dBm {format_ap_tag(b24.get('bssid'))} c{b24.get('channel')}"[:22]
            else:
                s24 = "NO 2.4G SIGNAL"

            if tel and tel.get("gw_avg_ms"):
                ping_str = f"{tel.get('gw_avg_ms')}/{tel.get('wan_avg_ms')} ms"
            else:
                ping_str = "-"

            body_lines.append(f"  {wp:24} | {s5:26} | {s5_2:20} | {s24:22} | {ping_str}")
            if ws["sticky_note"]:
                body_lines.append(f"    -> [!] STICKY CLIENT: {ws['sticky_note']}")
        body_lines.append("  " + "-" * 112)
        body_lines.append("")

    # Automated RF Health Alerts (CCI, 2.4G 40MHz, Roaming 11k/v, Legacy Rates, ACI, DFS, Sticky Client)
    if cci_alerts or aci_alerts or dfs_target_aps or sticky_alerts or wide_24_alerts or roaming_cap_warnings or legacy_rate_warnings:
        body_lines.append("[!] RF DESIGN & ROAMING HEALTH ALERTS")
        for c in cci_alerts:
            rooms_txt = f" | Heard together >= -75 dBm in {len(c['overlap_rooms'])} room(s)" if c["overlap_rooms"] else ""
            detail_txt = f" ({c['detail']})" if c.get("detail") else ""
            body_lines.append(
                f"  * [CCI] {c['band']} Ch {c['channel']}: {len(c['aps'])} target APs overlapping "
                f"({', '.join(c['aps'])}){detail_txt}{rooms_txt}"
            )
        for w24 in wide_24_alerts:
            scope = "TARGET AP" if w24["is_target"] else "Neighbor"
            body_lines.append(
                f"  * [2.4G 40MHz] {scope} '{w24['ssid']}' ({w24['bssid']}, {w24['vendor']}) on Ch {w24['channel']} "
                f"using {w24['width_mhz']} MHz width ({w24['dbm']} dBm) — use 20 MHz on 2.4 GHz"
            )
        for rw in roaming_cap_warnings:
            body_lines.append(f"  * [ROAMING 11k/v] {rw}")
        for lw in legacy_rate_warnings:
            body_lines.append(f"  * [LEGACY RATES] {lw}")
        for s in sticky_alerts:
            body_lines.append(
                f"  * [STICKY] {s['waypoint']}: Connected to {s['connected_ap']} ({s['connected_dbm']} dBm) "
                f"while {s['better_ap']} was {s['better_dbm']} dBm (+{s['delta_db']} dB stronger)"
            )
        if dfs_target_aps:
            dfs_list = ", ".join(f"{d['ap']} (Ch {d['channel']})" for d in dfs_target_aps)
            body_lines.append(f"  * [DFS] Target APs on 5 GHz DFS channels (52-144): {dfs_list}")
        for a in aci_alerts[:10]:
            ssids_txt = ", ".join(a["ssids"]) if a["ssids"] else "<Hidden>"
            cu_txt = f", Peak CU {a['peak_cu']}%" if a["peak_cu"] is not None else ""
            body_lines.append(
                f"  * [ACI 2.4G] Non-standard Ch {a['channel']}: {ssids_txt} ({a['bssid']}, {a['vendor']}) "
                f"Peak {a['peak_dbm']} dBm{cu_txt}"
            )
        body_lines.append("")

    if high_cu_alerts:
        body_lines.append("[!] ENGINEERING ALERTS: PEAK CHANNEL CONGESTION (>= 35% Utilization, Deduplicated by Radio)")
        for h in high_cu_alerts:
            ap_tag = f" [{h['ap_tag']}]" if h["ap_tag"] else ""
            wp_tag = f" @ {h['peak_waypoint']}" if h["peak_waypoint"] else ""
            body_lines.append(
                f"  * Peak {h['cu_pct']:3}% | Ch {str(h['channel']):3} ({h['band']:7}) | "
                f"SSIDs: {h['ssid'][:28]:28} | {h['bssid']} ({h['vendor']}){ap_tag}{wp_tag}"
            )
        body_lines.append("")

    if roaming_summary.get("present"):
        body_lines.append("[WINDOWS 802.11 ROAMING & HANDOFF LOG SUMMARY]")
        body_lines.append(
            f"  Events Analyzed : {roaming_summary['total_events']} | Window: {roaming_summary['time_range'] or 'N/A'}"
        )
        body_lines.append(
            f"  Connects: {roaming_summary['connects']} | Disconnects: {roaming_summary['disconnects']} | "
            f"Security Re-keys/Roams: {roaming_summary['security_rekeys']} | "
            f"Failures (Conn/Assoc/Sec): {roaming_summary['connect_failures']}/"
            f"{roaming_summary['assoc_failures']}/{roaming_summary['security_failures']}"
        )
        if roaming_summary["avg_rekey_ms"] is not None:
            body_lines.append(
                f"  Security Handoff Latency: Avg {roaming_summary['avg_rekey_ms']} ms | Max {roaming_summary['max_rekey_ms']} ms"
            )
        if roaming_summary["failure_reasons"]:
            body_lines.append(f"  Failure Reasons : {'; '.join(roaming_summary['failure_reasons'][:5])}")
        body_lines.append("")

    if walk_tests:
        body_lines.append(f"[CONTINUOUS ROAMING WALK-TEST RESULTS ({len(walk_tests)} Walk(s))]")
        for wt in walk_tests:
            body_lines.append(
                f"  * [{wt.get('walk_label', 'Walk')}] Duration: {wt.get('duration_sec')}s | "
                f"Samples: {wt.get('sample_count')} | Roams: {wt.get('roam_count')} | "
                f"Disconnects: {wt.get('disconnect_count')} | GW Loss: {wt.get('packet_loss_pct')}% | "
                f"Min RSSI: {wt.get('min_rssi_dbm')} dBm | Max GW Ping: {wt.get('max_gw_ms')} ms"
            )
            for re_ev in wt.get("roam_events", []):
                body_lines.append(
                    f"      -> [{re_ev.get('elapsed_sec')}s] {format_ap_tag(re_ev.get('from_bssid'))} "
                    f"(Ch {re_ev.get('from_channel')}, {re_ev.get('rssi_before_dbm')} dBm) "
                    f"==> {format_ap_tag(re_ev.get('to_bssid'))} "
                    f"(Ch {re_ev.get('to_channel')}, {re_ev.get('rssi_after_dbm')} dBm) | "
                    f"Dropped Pings: {re_ev.get('dropped_pings')} (~{re_ev.get('est_outage_ms')} ms) | {re_ev.get('grade')}"
                )
        body_lines.append("")

    if floorplan_data.get("floorplans"):
        body_lines.append(
            f"[FLOORPLAN HEATMAPS] {len(floorplan_data['floorplans'])} floorplan(s) with "
            f"{len(floorplan_data.get('pins', []))} pinned waypoint(s) embedded in PM_SITE_SURVEY_REPORT.html."
        )
        body_lines.append("")

    if lan_devices:
        body_lines.append(f"[DISCOVERED LAN DEVICES ({len(lan_devices)} Active Hosts)]")
        for d in lan_devices:
            host_str = f" ({d.get('hostname')})" if d.get("hostname") else ""
            body_lines.append(
                f"  * {d.get('ip', ''):15} | {d.get('mac', ''):17} | "
                f"{(d.get('vendor', '') + host_str):38} | {d.get('role', '')}"
            )
        body_lines.append("")

    body_lines.append("=" * 95)
    body_lines.append("                     END OF ENGINEERING HAND-OFF SUMMARY")
    body_lines.append("=" * 95)

    header_lines = [
        "=" * 95,
        "                  FIELD SITE SURVEY - ENGINEERING HAND-OFF PACKAGE",
        "=" * 95,
        "",
        "[JOB METADATA]",
        f"  Project / Job Name : {meta.get('job_name', 'N/A')}",
        f"  Field Technician   : {meta.get('tech_name', 'N/A')}",
        f"  Audit Date & Time  : {meta.get('date', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}",
        f"  Target SSID        : {target_ssid or 'All Visible Networks'}",
        f"  Site Notes         : {meta.get('notes', 'None')}",
        f"  Output Directory   : {job_folder}",
        "",
        "[COLLECTED ARTIFACTS]",
    ]

    existing_files = [fn for fn in sorted(os.listdir(job_folder)) if fn != "ENGINEERING_HANDOFF_SUMMARY.txt"]
    for fn in existing_files:
        fp = os.path.join(job_folder, fn)
        sz = os.path.getsize(fp) if os.path.isfile(fp) else 0
        header_lines.append(f"  - {fn:35} ({sz:,} bytes)")
    header_lines.append("")

    full_text = "\n".join(header_lines + body_lines) + "\n"
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write(full_text)

    print(f"[+] Engineering hand-off summary created: {summary_path}")
    print(f"[+] Executive PM HTML Report created   : {html_path}")


def generate_html_report(
    html_path, meta, target_ssid, ap_details, wp_summaries,
    speedtest_runs, lan_devices, high_cu_alerts, format_ap_tag,
    nic_info=None, cci_alerts=None, aci_alerts=None, dfs_target_aps=None,
    sticky_alerts=None, wide_24_alerts=None, roaming_cap_warnings=None,
    legacy_rate_warnings=None, roaming_summary=None, walk_tests=None,
    floorplan_data=None, job_folder="", connected_ssids_mismatched=None,
    used_baseline_fallback=False,
):
    nic_info = nic_info or {}
    cci_alerts = cci_alerts or []
    aci_alerts = aci_alerts or []
    dfs_target_aps = dfs_target_aps or []
    sticky_alerts = sticky_alerts or []
    wide_24_alerts = wide_24_alerts or []
    roaming_cap_warnings = roaming_cap_warnings or []
    legacy_rate_warnings = legacy_rate_warnings or []
    roaming_summary = roaming_summary or {}
    walk_tests = walk_tests or []
    floorplan_data = floorplan_data or {"floorplans": [], "pins": []}
    connected_ssids_mismatched = connected_ssids_mismatched or []

    job_name = html.escape(str(meta.get("job_name", "Site Survey")))
    tech_name = html.escape(str(meta.get("tech_name", "Field Tech")))
    date_str = html.escape(str(meta.get("date", datetime.now().strftime("%Y-%m-%d %H:%M"))))
    ssid_str = html.escape(str(target_ssid or "All Visible Networks"))
    notes_str = html.escape(str(meta.get("notes", "") or "Standard site walkthrough & RF verification."))

    # Advisory banners (Survey NIC warnings + Connected SSID mismatch)
    banners_html = ""
    if nic_info.get("warnings"):
        warn_items = "".join(f"<li>{html.escape(w)}</li>" for w in nic_info["warnings"])
        banners_html += f"""
        <div class="alert-box alert-info">
          <strong>Survey Adapter Hardware Notice ({html.escape(nic_info.get('driver', 'Wi-Fi NIC'))}):</strong>
          <ul>{warn_items}</ul>
        </div>"""
    if connected_ssids_mismatched:
        mism_str = html.escape(", ".join(connected_ssids_mismatched))
        banners_html += f"""
        <div class="alert-box alert-warn">
          <strong>SSID Context Notice:</strong> Survey laptop was connected to <code>{mism_str}</code>
          while auditing target SSID <code>{ssid_str}</code>. Active link rates &amp; ping latency reflect the connected network.
        </div>"""

    # Build Waypoint Rows HTML
    wp_rows_html = ""
    for ws in wp_summaries:
        wp_name = html.escape(str(ws["waypoint"]))
        t_str = html.escape(str(ws["time"] or "-"))
        b5 = ws["best_5"]
        sec5 = ws.get("second_5")
        b24 = ws["best_24"]
        tel = ws["telemetry"]
        sticky_note = ws.get("sticky_note", "")

        if b5:
            dbm5 = _safe_int(b5.get("signal_dbm", -100))
            pct5 = html.escape(str(b5.get("signal_pct", "")))
            ch5 = html.escape(str(b5.get("channel", "")))
            s5_html = f"<strong>{dbm5} dBm</strong> ({pct5}%)<br><span class='sub'>{html.escape(format_ap_tag(b5.get('bssid')))} &bull; Ch {ch5}</span>"
            if sec5:
                dbm5_2 = _safe_int(sec5.get("signal_dbm", -100))
                s5_html += f"<br><span class='sub'>2nd: {dbm5_2} dBm ({html.escape(format_ap_tag(sec5.get('bssid')))})</span>"
            else:
                s5_html += "<br><span class='sub'>2nd: None (no overlap)</span>"
        else:
            dbm5 = -100
            s5_html = "<span class='badge badge-bad'>No 5G Signal</span>"

        if b24:
            dbm24 = _safe_int(b24.get("signal_dbm", -100))
            pct24 = html.escape(str(b24.get("signal_pct", "")))
            ch24 = html.escape(str(b24.get("channel", "")))
            s24_html = f"<strong>{dbm24} dBm</strong> ({pct24}%)<br><span class='sub'>{html.escape(format_ap_tag(b24.get('bssid')))} &bull; Ch {ch24}</span>"
        else:
            dbm24 = -100
            s24_html = "<span class='sub'>N/A</span>"

        # Active link + ping
        link_str = "-"
        if tel and tel.get("tx_rate_mbps"):
            tx = html.escape(str(tel.get("tx_rate_mbps", "")))
            rx = html.escape(str(tel.get("rx_rate_mbps", "")))
            gw_ms = html.escape(str(tel.get("gw_avg_ms", "")))
            wan_ms = html.escape(str(tel.get("wan_avg_ms", "")))
            c_ssid = html.escape(str(tel.get("connected_ssid", "")))
            ssid_tag = f" <span class='sub'>[{c_ssid}]</span>" if c_ssid and target_ssid and c_ssid.lower() != target_ssid.lower() else ""
            link_str = f"{tx}/{rx} Mbps{ssid_tag}<br><span class='sub'>GW: {gw_ms}ms | WAN: {wan_ms}ms</span>"
            if tel.get("download_mbps"):
                dl_m = html.escape(str(tel.get("download_mbps", "")))
                link_str += f"<br><strong>DL: {dl_m} Mbps</strong>"

        if dbm5 >= -62:
            badge = "<span class='badge badge-good'>Excellent</span>"
        elif dbm5 >= -68:
            badge = "<span class='badge badge-good'>Good</span>"
        elif dbm5 >= -75:
            badge = "<span class='badge badge-warn'>Fair 5G</span>"
        else:
            badge = "<span class='badge badge-bad'>Weak 5G</span>"

        if sticky_note:
            badge += f"<br><span class='badge badge-warn' style='margin-top:4px;'>Sticky Client</span><br><span class='sub'>{html.escape(sticky_note)}</span>"

        wp_rows_html += f"""
        <tr>
          <td>{t_str}</td>
          <td><strong>{wp_name}</strong></td>
          <td>{s5_html}</td>
          <td>{s24_html}</td>
          <td>{link_str}</td>
          <td>{badge}</td>
        </tr>"""

    # Build RF Health Alerts HTML (CCI / 2.4G 40MHz / 11k/v / Legacy Rates / ACI / DFS / Sticky Client)
    rf_alerts_html = ""
    rf_items = []
    for c in cci_alerts:
        ov = f" (heard together &ge; -75 dBm in {len(c['overlap_rooms'])} room(s))" if c["overlap_rooms"] else ""
        det = f" &mdash; {html.escape(c['detail'])}" if c.get("detail") else ""
        rf_items.append(
            f"<li><span class='badge badge-bad'>CCI</span> <strong>{html.escape(c['band'])} Ch {html.escape(str(c['channel']))}:</strong> "
            f"{len(c['aps'])} target APs overlapping ({html.escape(', '.join(c['aps']))}){det}{ov}</li>"
        )
    for w24 in wide_24_alerts:
        scope = "TARGET AP" if w24["is_target"] else "Neighbor"
        rf_items.append(
            f"<li><span class='badge badge-bad'>2.4G 40MHz</span> <strong>{scope} {html.escape(str(w24['ssid']))}</strong> "
            f"(<code>{html.escape(w24['bssid'])}</code>, Ch {html.escape(w24['channel'])}, {w24['width_mhz']} MHz, {w24['dbm']} dBm) "
            f"&mdash; switch 2.4 GHz to 20 MHz width</li>"
        )
    for rw in roaming_cap_warnings:
        rf_items.append(f"<li><span class='badge badge-warn'>11k/v Roaming</span> {html.escape(rw)}</li>")
    for lw in legacy_rate_warnings:
        rf_items.append(f"<li><span class='badge badge-warn'>Legacy Rates</span> {html.escape(lw)}</li>")
    for s in sticky_alerts:
        rf_items.append(
            f"<li><span class='badge badge-warn'>Sticky Client</span> <strong>{html.escape(s['waypoint'])}:</strong> "
            f"Connected to {html.escape(s['connected_ap'])} ({s['connected_dbm']} dBm) while "
            f"{html.escape(s['better_ap'])} was {s['better_dbm']} dBm (+{s['delta_db']} dB stronger)</li>"
        )
    if dfs_target_aps:
        dfs_txt = ", ".join(f"{d['ap']} (Ch {d['channel']})" for d in dfs_target_aps)
        rf_items.append(
            f"<li><span class='badge badge-info'>DFS</span> <strong>5 GHz DFS Channels Active:</strong> {html.escape(dfs_txt)}</li>"
        )
    for a in aci_alerts[:8]:
        ssids_txt = ", ".join(a["ssids"]) if a["ssids"] else "<Hidden>"
        cu_txt = f", Peak CU {a['peak_cu']}%" if a["peak_cu"] is not None else ""
        rf_items.append(
            f"<li><span class='badge badge-warn'>2.4G ACI</span> <strong>Non-standard Ch {a['channel']}:</strong> "
            f"{html.escape(ssids_txt)} (<code>{html.escape(a['bssid'])}</code>, {html.escape(a['vendor'])}) &mdash; Peak {a['peak_dbm']} dBm{cu_txt}</li>"
        )
    if rf_items:
        rf_alerts_html = f"""
        <h2>RF Design, Interference &amp; Roaming Alerts</h2>
        <ul class="rf-alert-list">{''.join(rf_items)}</ul>"""

    # Build Speedtest HTML section
    st_html = ""
    if speedtest_runs:
        st_rows = ""
        for sr in speedtest_runs:
            loc = html.escape(str(sr.get("waypoint", "Baseline")))
            st = sr.get("speedtest", {})
            hop = sr.get("split_hop_ping", {})
            gw = hop.get("gateway", {})
            wan = hop.get("wan", {})
            dl_val = html.escape(str(st.get("download_mbps", "N/A")))
            ul_val = html.escape(str(st.get("upload_mbps", "N/A")))
            gw_avg = html.escape(str(gw.get("avg_ms", "N/A")))
            gw_jit = html.escape(str(gw.get("jitter_ms", 0)))
            wan_avg = html.escape(str(wan.get("avg_ms", "N/A")))
            dns_val = html.escape(str(hop.get("dns_lookup_ms", "N/A")))
            bb_delta = html.escape(str(st.get("bufferbloat_delta_ms", 0)))
            bb_grade = html.escape(str(st.get("bufferbloat_grade", "N/A")))
            st_rows += f"""
            <tr>
              <td><strong>{loc}</strong></td>
              <td><strong>{dl_val} Mbps</strong></td>
              <td><strong>{ul_val} Mbps</strong></td>
              <td>{gw_avg} ms (Jitter {gw_jit} ms)</td>
              <td>{wan_avg} ms (DNS {dns_val} ms)</td>
              <td>+{bb_delta} ms ({bb_grade})</td>
            </tr>"""
        st_html = f"""
        <h2>Cloudflare Speedtest, Split-Hop Ping &amp; Bufferbloat</h2>
        <table>
          <thead>
            <tr>
              <th>Location</th>
              <th>Download</th>
              <th>Upload</th>
              <th>Wi-Fi Gateway Ping</th>
              <th>WAN Ping (1.1.1.1)</th>
              <th>Bufferbloat Under Load</th>
            </tr>
          </thead>
          <tbody>{st_rows}</tbody>
        </table>"""

    # Build AP Inventory HTML
    has_ctrl_meta = any(info.get("model") or info.get("ip") for info in ap_details.values())
    ap_rows = ""
    for ap_label, info in ap_details.items():
        r24 = html.escape(info["radios"].get("2.4 GHz", "—"))
        r5 = html.escape(info["radios"].get("5 GHz", "—"))
        r6 = html.escape(info["radios"].get("6 GHz", "—"))
        meta_bits = [b for b in (info.get("model"), info.get("ip"), info.get("poe"), info.get("uptime")) if b]
        if info.get("roaming_flags"):
            meta_bits.append("/".join(sorted(info["roaming_flags"])))
        if info.get("pmf_modes"):
            meta_bits.append(f"PMF: {'/'.join(sorted(info['pmf_modes']))}")
        meta_sub = f"<br><span class='sub'>{html.escape(' • '.join(meta_bits))}</span>" if meta_bits else ""
        ap_rows += f"""
        <tr>
          <td><strong>{html.escape(ap_label)}</strong><br><code>{html.escape(info['prefix'])}:xx</code>{meta_sub}</td>
          <td>{html.escape(info['vendor'])}</td>
          <td><code>{r24}</code></td>
          <td><code>{r5}</code></td>
          <td><code>{r6}</code></td>
        </tr>"""

    # Build High Congestion HTML section (Peak CU deduplicated per physical radio)
    cu_html = ""
    if high_cu_alerts:
        cu_rows = ""
        for h in high_cu_alerts:
            ap_sub = f"<br><span class='sub'>{html.escape(h['ap_tag'])}</span>" if h.get("ap_tag") else ""
            wp_str = html.escape(str(h.get("peak_waypoint") or "—"))
            cu_rows += f"""
            <tr>
              <td><strong>{html.escape(str(h['ssid']))}</strong>{ap_sub}</td>
              <td><code>{html.escape(str(h['bssid']))}</code></td>
              <td>{html.escape(str(h['vendor']))}</td>
              <td>{html.escape(str(h['band']))} &bull; Ch {html.escape(str(h['channel']))}</td>
              <td>{wp_str}</td>
              <td><span class='badge badge-warn'>{int(h['cu_pct'])}%</span></td>
            </tr>"""
        cu_html = f"""
        <h2>Peak RF Channel Congestion (&ge; 35% Utilization, Deduplicated by Radio)</h2>
        <table>
          <thead>
            <tr>
              <th>SSID(s) on Radio</th>
              <th>BSSID</th>
              <th>Hardware Vendor (OUI)</th>
              <th>Band &amp; Channel</th>
              <th>Peak Location</th>
              <th>Peak Utilization</th>
            </tr>
          </thead>
          <tbody>{cu_rows}</tbody>
        </table>"""

    # Build Roaming Summary HTML section
    roam_html = ""
    if roaming_summary.get("present"):
        avg_rk = f"{roaming_summary['avg_rekey_ms']} ms" if roaming_summary.get("avg_rekey_ms") is not None else "N/A"
        max_rk = f"{roaming_summary['max_rekey_ms']} ms" if roaming_summary.get("max_rekey_ms") is not None else "N/A"
        fail_total = (
            roaming_summary.get("connect_failures", 0)
            + roaming_summary.get("assoc_failures", 0)
            + roaming_summary.get("security_failures", 0)
        )
        fail_badge = "badge-bad" if fail_total > 0 else "badge-good"
        roam_html = f"""
        <h2>Windows 802.11 Roaming &amp; Handoff Health</h2>
        <div class="meta" style="grid-template-columns: repeat(4, 1fr);">
          <div><strong>Security Re-keys / Roams</strong><span>{roaming_summary.get('security_rekeys', 0)}</span></div>
          <div><strong>Connects / Disconnects</strong><span>{roaming_summary.get('connects', 0)} / {roaming_summary.get('disconnects', 0)}</span></div>
          <div><strong>Handoff Latency (Avg / Max)</strong><span>{html.escape(avg_rk)} / {html.escape(max_rk)}</span></div>
          <div><strong>Auth / Assoc Failures</strong><span class="badge {fail_badge}">{fail_total}</span></div>
        </div>"""

    # Build Continuous Roaming Walk-Test HTML section
    walk_html = ""
    if walk_tests:
        walk_blocks = []
        for wt in walk_tests:
            lbl = html.escape(str(wt.get("walk_label", "Roaming Walk")))
            svg_chart = _render_walk_svg(wt)
            ev_rows = ""
            for ev in wt.get("roam_events", []):
                g = ev.get("grade", "")
                g_cls = "badge-good" if g == "Seamless" else ("badge-warn" if "Minor" in g else "badge-bad")
                ev_rows += f"""
                <tr>
                  <td>{ev.get('elapsed_sec')}s</td>
                  <td>{html.escape(format_ap_tag(ev.get('from_bssid')))}<br><span class='sub'>{html.escape(str(ev.get('from_band')))} Ch {html.escape(str(ev.get('from_channel')))} ({ev.get('rssi_before_dbm')} dBm)</span></td>
                  <td>{html.escape(format_ap_tag(ev.get('to_bssid')))}<br><span class='sub'>{html.escape(str(ev.get('to_band')))} Ch {html.escape(str(ev.get('to_channel')))} ({ev.get('rssi_after_dbm')} dBm)</span></td>
                  <td>{ev.get('dropped_pings')} (~{ev.get('est_outage_ms')} ms)</td>
                  <td>{ev.get('peak_ping_ms') if ev.get('peak_ping_ms') is not None else '—'} ms</td>
                  <td><span class='badge {g_cls}'>{html.escape(g)}</span></td>
                </tr>"""
            ev_table = (
                f"<table><thead><tr><th>Time</th><th>From AP</th><th>To AP</th><th>Dropped Pings</th><th>Peak GW Ping</th><th>Handoff Grade</th></tr></thead><tbody>{ev_rows}</tbody></table>"
                if ev_rows else "<div class='sub' style='margin-bottom:10px;'>No BSSID roam transitions occurred during this walk.</div>"
            )
            walk_blocks.append(f"""
            <div style="margin-bottom:16px;">
              <h3 style="margin:8px 0 4px 0;font-size:14px;color:#334155;">{lbl} &mdash; {wt.get('duration_sec')}s ({wt.get('roam_count')} roam(s), {wt.get('packet_loss_pct')}% GW loss, Min RSSI {wt.get('min_rssi_dbm')} dBm)</h3>
              {svg_chart}
              {ev_table}
            </div>""")
        walk_html = f"<h2>Continuous Roaming Walk-Test Results</h2>{''.join(walk_blocks)}"

    # Build Floorplan Heatmaps HTML section
    floorplans_html = _build_floorplans_html(job_folder, floorplan_data, wp_summaries, format_ap_tag) if job_folder else ""

    # Build LAN Devices HTML section if any
    lan_html = ""
    if lan_devices:
        has_hostnames = any(d.get("hostname") for d in lan_devices)
        lan_rows = ""
        for d in lan_devices:
            host_td = f"<td>{html.escape(str(d.get('hostname', '') or '—'))}</td>" if has_hostnames else ""
            lan_rows += f"""
            <tr>
              <td><code>{html.escape(str(d.get('ip', '')))}</code></td>
              <td><code>{html.escape(str(d.get('mac', '')))}</code></td>
              {host_td}
              <td>{html.escape(str(d.get('vendor', '')))}</td>
              <td>{html.escape(str(d.get('role', '')))}</td>
            </tr>"""
        host_th = "<th>Hostname</th>" if has_hostnames else ""
        lan_html = f"""
        <h2>Discovered LAN Devices ({len(lan_devices)} Active Hosts)</h2>
        <table>
          <thead>
            <tr>
              <th>IPv4 Address</th>
              <th>MAC Address</th>
              {host_th}
              <th>Hardware Vendor (OUI)</th>
              <th>Role</th>
            </tr>
          </thead>
          <tbody>{lan_rows}</tbody>
        </table>"""

    wp_title_suffix = " (Baseline RF Scan)" if used_baseline_fallback else ""
    ap_title_suffix = " + Controller Inventory" if has_ctrl_meta else ""

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Site Survey Report — {job_name}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f8fafc; color: #0f172a; margin: 0; padding: 28px; }}
    .container {{ max-width: 1060px; margin: 0 auto; background: #fff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 32px 36px; box-shadow: 0 4px 14px rgba(0,0,0,0.04); }}
    .header {{ display: flex; justify-content: space-between; border-bottom: 2px solid #1e40af; padding-bottom: 16px; margin-bottom: 20px; }}
    .header h1 {{ margin: 0 0 4px 0; font-size: 22px; color: #1e40af; }}
    .meta {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 8px; padding: 12px 16px; margin-bottom: 20px; font-size: 13px; }}
    .meta strong {{ display: block; font-size: 11px; color: #475569; text-transform: uppercase; }}
    .alert-box {{ border-radius: 8px; padding: 11px 15px; margin-bottom: 14px; font-size: 13px; }}
    .alert-box ul {{ margin: 6px 0 0 18px; padding: 0; }}
    .alert-info {{ background: #eff6ff; border: 1px solid #93c5fd; color: #1e3a8a; }}
    .alert-warn {{ background: #fff7ed; border: 1px solid #fdba74; color: #9a3412; }}
    .rf-alert-list {{ margin: 8px 0 16px 0; padding-left: 18px; font-size: 13px; line-height: 1.7; }}
    h2 {{ font-size: 16px; color: #1e40af; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; margin-top: 24px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 16px; }}
    th, td {{ text-align: left; padding: 9px 10px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }}
    th {{ background: #f1f5f9; font-size: 11.5px; text-transform: uppercase; color: #334155; }}
    .sub {{ font-size: 11.5px; color: #64748b; }}
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 99px; font-weight: 600; font-size: 11.5px; }}
    .badge-good {{ background: #dcfce7; color: #166534; }}
    .badge-warn {{ background: #ffedd5; color: #9a3412; }}
    .badge-bad {{ background: #fee2e2; color: #991b1b; }}
    .badge-info {{ background: #dbeafe; color: #1e40af; }}
    @media print {{ body {{ background: #fff; padding: 0; }} .container {{ border: none; box-shadow: none; padding: 0; }} }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <h1>Wi-Fi Field Survey &amp; Engineering Report</h1>
        <div class="sub">Notes: {notes_str}</div>
      </div>
      <div style="text-align:right;font-size:12.5px;color:#475569;">
        <strong>Date:</strong> {date_str}<br>
        <strong>Tech:</strong> {tech_name}
      </div>
    </div>
    <div class="meta">
      <div><strong>Client / Site</strong><span>{job_name}</span></div>
      <div><strong>Target SSID</strong><span>{ssid_str}</span></div>
      <div><strong>Waypoints Logged</strong><span>{len(wp_summaries)} Rooms</span></div>
      <div><strong>Detected APs</strong><span>{len(ap_details)} Target APs</span></div>
    </div>

    {banners_html}
    {rf_alerts_html}
    {floorplans_html}
    {st_html}

    <h2>Room-by-Room Coverage &amp; Link Performance ({ssid_str}){wp_title_suffix}</h2>
    <table>
      <thead>
        <tr>
          <th>Time</th>
          <th>Room / Waypoint</th>
          <th>Primary &amp; 2nd 5/6 GHz</th>
          <th>Best 2.4 GHz Signal</th>
          <th>Active Link &amp; Ping</th>
          <th>Assessment</th>
        </tr>
      </thead>
      <tbody>{wp_rows_html}</tbody>
    </table>

    <h2>Target Access Point Hardware Inventory{ap_title_suffix}</h2>
    <table>
      <thead>
        <tr>
          <th>Access Point</th>
          <th>Vendor (OUI)</th>
          <th>2.4 GHz Radio</th>
          <th>5 GHz Radio</th>
          <th>6 GHz Radio</th>
        </tr>
      </thead>
      <tbody>{ap_rows}</tbody>
    </table>

    {cu_html}
    {walk_html}
    {roam_html}
    {lan_html}
  </div>
</body>
</html>"""

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(doc)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        generate_summary(sys.argv[1])
    else:
        print("Usage: python generate_job_summary.py <job_folder>")
