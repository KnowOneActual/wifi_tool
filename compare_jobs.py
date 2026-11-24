"""
Before vs. After Wi-Fi Site Survey Job Comparison Engine
Compares two job folders (e.g., Pre-Remediation vs. Post-Remediation) and generates:
  1. COMPARISON_REPORT.html (Print-to-PDF ready executive delta report)
  2. COMPARISON_REPORT.txt  (Plain-text engineering diff summary)

100% Python standard library — zero external dependencies.
"""

import argparse
import difflib
import html
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime

import generate_job_summary as gjs


def _normalize_room_key(name: str) -> str:
    """Normalize room names for resilient fuzzy matching across visits."""
    s = (name or "").lower().strip()
    s = re.sub(r"\(#\d+\)", "", s)
    s = re.sub(r"\b(pre[- ]?fix|post[- ]?fix|before|after|flr|fl|floor)\b", "", s)
    s = re.sub(r"[^a-z0-9]+", " ", s).strip()
    tokens = sorted(s.split())
    return " ".join(tokens)


def _extract_job_snapshot(job_folder: str) -> dict:
    """Load structured metrics for a single job folder."""
    meta = {}
    meta_path = os.path.join(job_folder, "job_meta.json")
    if os.path.exists(meta_path):
        try:
            with open(meta_path, "r", encoding="utf-8-sig", errors="replace") as f:
                meta = json.load(f)
        except Exception:
            meta = {}

    records = gjs.load_waypoints_csv(os.path.join(job_folder, "survey_waypoints.csv"))
    if not records:
        records = gjs.load_baseline_fallback(job_folder)
    telemetry_rows = gjs.load_csv_generic(os.path.join(job_folder, "waypoint_telemetry.csv"))
    speedtests = gjs.load_json_safe(os.path.join(job_folder, "speedtest_results.json"))
    controller_aps = gjs.load_ap_list_csv(job_folder)

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

    # AP inventory & channels
    ap_channels = defaultdict(lambda: defaultdict(set))  # prefix -> band -> set(ch)
    ap_names = {}
    for r in records:
        if rec_matches(r) and len(r.get("bssid", "")) >= 14:
            pref = gjs._normalize_ap_prefix(r.get("bssid", ""))
            band = r.get("band", "")
            ch = str(r.get("channel", "")).strip()
            if ch:
                ap_channels[pref][band].add(ch)
            if pref not in ap_names:
                ctrl = controller_aps.get(pref, {})
                ap_names[pref] = ctrl.get("name") or (r.get("ap_name") or "").strip() or pref

    # Per-waypoint summaries
    batches = gjs._group_waypoint_batches(records, telemetry_rows)
    waypoints = []
    for b in batches:
        wp_recs = b["records"]
        t_recs = [r for r in wp_recs if (rec_matches(r) if target_ssid else True) and r.get("bssid")]
        r5 = [r for r in t_recs if "5" in r.get("band", "") or "6" in r.get("band", "")]
        r24 = [r for r in t_recs if "2.4" in r.get("band", "")]
        best_5 = max(r5, key=lambda x: gjs._safe_int(x.get("signal_dbm", -100))) if r5 else None
        best_24 = max(r24, key=lambda x: gjs._safe_int(x.get("signal_dbm", -100))) if r24 else None
        tel = b["telemetry"]

        def _ap_disp(rec):
            if not rec:
                return ""
            pref = gjs._normalize_ap_prefix(rec.get("bssid", ""))
            return ap_names.get(pref, pref[-5:])

        waypoints.append({
            "name": b["display_name"],
            "raw_name": b["waypoint"],
            "norm_key": _normalize_room_key(b["waypoint"]),
            "dbm_5": gjs._safe_int(best_5.get("signal_dbm")) if best_5 else None,
            "ap_5": _ap_disp(best_5),
            "ch_5": best_5.get("channel", "") if best_5 else "",
            "dbm_24": gjs._safe_int(best_24.get("signal_dbm")) if best_24 else None,
            "ap_24": _ap_disp(best_24),
            "gw_ms": tel.get("gw_avg_ms", ""),
            "wan_ms": tel.get("wan_avg_ms", ""),
        })

    # Peak CU & high-CU radio count
    cu_radios = {}
    for r in records:
        cu_s = str(r.get("cu_pct", "")).strip()
        if cu_s.isdigit():
            val = int(cu_s)
            if val >= 35:
                k = (gjs._normalize_ap_prefix(r.get("bssid", "")), r.get("band", ""), str(r.get("channel", "")))
                cu_radios[k] = max(cu_radios.get(k, 0), val)

    # Speedtest summary (baseline / first successful run)
    st_ok = [s for s in speedtests if isinstance(s, dict) and s.get("speedtest", {}).get("status") == "success"]
    baseline_st = st_ok[0]["speedtest"] if st_ok else None

    return {
        "folder": job_folder,
        "folder_name": os.path.basename(os.path.normpath(job_folder)),
        "job_name": meta.get("job_name") or os.path.basename(os.path.normpath(job_folder)),
        "date": meta.get("date", ""),
        "tech": meta.get("tech_name", ""),
        "notes": meta.get("notes", ""),
        "target_ssid": target_ssid,
        "ap_count": len(ap_channels),
        "ap_channels": {p: {b: sorted(list(chs)) for b, chs in bands.items()} for p, bands in ap_channels.items()},
        "ap_names": ap_names,
        "waypoints": waypoints,
        "high_cu_count": len(cu_radios),
        "peak_cu_pct": max(cu_radios.values()) if cu_radios else 0,
        "speedtest": baseline_st,
    }


def _match_waypoints(before_wps: list, after_wps: list) -> list:
    """Pair Before and After waypoints using exact normalized keys first, then fuzzy matching."""
    matched_pairs = []
    used_after = set()

    # Pass 1: exact normalized match
    for bw in before_wps:
        hit_idx = None
        for idx, aw in enumerate(after_wps):
            if idx in used_after:
                continue
            if bw["raw_name"].strip().lower() == aw["raw_name"].strip().lower() or (
                bw["norm_key"] and bw["norm_key"] == aw["norm_key"]
            ):
                hit_idx = idx
                break
        if hit_idx is not None:
            used_after.add(hit_idx)
            matched_pairs.append((bw, after_wps[hit_idx]))
        else:
            matched_pairs.append((bw, None))

    # Pass 2: fuzzy match remaining unmatched Before waypoints against remaining After waypoints
    for i, (bw, aw) in enumerate(matched_pairs):
        if aw is not None:
            continue
        best_score = 0.0
        best_idx = None
        for idx, cand in enumerate(after_wps):
            if idx in used_after:
                continue
            score = difflib.SequenceMatcher(None, bw["norm_key"], cand["norm_key"]).ratio()
            raw_score = difflib.SequenceMatcher(None, bw["raw_name"].lower(), cand["raw_name"].lower()).ratio()
            sc = max(score, raw_score)
            if sc > best_score:
                best_score = sc
                best_idx = idx
        if best_idx is not None and best_score >= 0.70:
            used_after.add(best_idx)
            matched_pairs[i] = (bw, after_wps[best_idx])

    # Append unmatched After-only rooms
    for idx, aw in enumerate(after_wps):
        if idx not in used_after:
            matched_pairs.append((None, aw))

    return matched_pairs


def compare_job_folders(before_dir: str, after_dir: str, out_dir: str = None) -> dict:
    """
    Compare two Wi-Fi site survey job folders and write `COMPARISON_REPORT.txt` and
    `COMPARISON_REPORT.html` into `out_dir` (defaults to `after_dir`).
    Returns a structured dict containing all deltas and output file paths.
    """
    before = _extract_job_snapshot(before_dir)
    after = _extract_job_snapshot(after_dir)
    dest_dir = out_dir or after_dir
    os.makedirs(dest_dir, exist_ok=True)

    pairs = _match_waypoints(before["waypoints"], after["waypoints"])
    room_rows = []
    deltas_5 = []
    deltas_24 = []

    for bw, aw in pairs:
        b5 = bw["dbm_5"] if bw else None
        a5 = aw["dbm_5"] if aw else None
        d5 = (a5 - b5) if (b5 is not None and a5 is not None) else None
        if d5 is not None:
            deltas_5.append(d5)

        b24 = bw["dbm_24"] if bw else None
        a24 = aw["dbm_24"] if aw else None
        d24 = (a24 - b24) if (b24 is not None and a24 is not None) else None
        if d24 is not None:
            deltas_24.append(d24)

        room_label = (aw["name"] if aw else bw["name"])
        if bw and aw and bw["raw_name"].lower() != aw["raw_name"].lower():
            room_label = f"{aw['name']} (was: {bw['name']})"

        room_rows.append({
            "room": room_label,
            "before_5": b5,
            "after_5": a5,
            "delta_5": d5,
            "before_ap5": bw["ap_5"] if bw else "",
            "after_ap5": aw["ap_5"] if aw else "",
            "before_24": b24,
            "after_24": a24,
            "delta_24": d24,
        })

    # AP Channel Changes
    all_prefixes = sorted(set(before["ap_channels"].keys()) | set(after["ap_channels"].keys()))
    ap_changes = []
    for pref in all_prefixes:
        b_bands = before["ap_channels"].get(pref, {})
        a_bands = after["ap_channels"].get(pref, {})
        label = after["ap_names"].get(pref) or before["ap_names"].get(pref) or pref
        if not b_bands and a_bands:
            ap_changes.append({"ap": label, "prefix": pref, "status": "Added", "before": "—", "after": _fmt_bands(a_bands)})
        elif b_bands and not a_bands:
            ap_changes.append({"ap": label, "prefix": pref, "status": "Removed", "before": _fmt_bands(b_bands), "after": "—"})
        elif b_bands != a_bands:
            ap_changes.append({"ap": label, "prefix": pref, "status": "Channel Changed", "before": _fmt_bands(b_bands), "after": _fmt_bands(a_bands)})

    avg_delta_5 = round(sum(deltas_5) / len(deltas_5), 1) if deltas_5 else None
    avg_delta_24 = round(sum(deltas_24) / len(deltas_24), 1) if deltas_24 else None

    # Speedtest delta
    st_delta = None
    if before["speedtest"] and after["speedtest"]:
        bs, as_ = before["speedtest"], after["speedtest"]
        st_delta = {
            "dl_before": bs.get("download_mbps", 0),
            "dl_after": as_.get("download_mbps", 0),
            "dl_diff": round(as_.get("download_mbps", 0) - bs.get("download_mbps", 0), 1),
            "ul_before": bs.get("upload_mbps", 0),
            "ul_after": as_.get("upload_mbps", 0),
            "ul_diff": round(as_.get("upload_mbps", 0) - bs.get("upload_mbps", 0), 1),
            "bb_before": bs.get("bufferbloat_delta_ms", 0),
            "bb_after": as_.get("bufferbloat_delta_ms", 0),
            "bb_diff": round(as_.get("bufferbloat_delta_ms", 0) - bs.get("bufferbloat_delta_ms", 0), 1),
        }

    result = {
        "before": before,
        "after": after,
        "room_rows": room_rows,
        "avg_delta_5_db": avg_delta_5,
        "avg_delta_24_db": avg_delta_24,
        "ap_changes": ap_changes,
        "speedtest_delta": st_delta,
        "high_cu_delta": after["high_cu_count"] - before["high_cu_count"],
        "peak_cu_delta": after["peak_cu_pct"] - before["peak_cu_pct"],
    }

    txt_path = os.path.join(dest_dir, "COMPARISON_REPORT.txt")
    html_path = os.path.join(dest_dir, "COMPARISON_REPORT.html")
    _write_comparison_txt(txt_path, result)
    _write_comparison_html(html_path, result)
    result["txt_path"] = txt_path
    result["html_path"] = html_path
    return result


def _fmt_bands(bands_dict: dict) -> str:
    return ", ".join(f"{b}: Ch {'/'.join(chs)}" for b, chs in sorted(bands_dict.items()))


def _fmt_delta(val, unit="dB") -> str:
    if val is None:
        return "—"
    sign = "+" if val > 0 else ""
    return f"{sign}{val} {unit}"


def _write_comparison_txt(path: str, data: dict):
    b, a = data["before"], data["after"]
    lines = [
        "=" * 96,
        "                 WI-FI SITE SURVEY — BEFORE vs. AFTER COMPARISON REPORT",
        "=" * 96,
        "",
        f"  BEFORE Job : {b['job_name']} ({b['folder_name']}) | SSID: {b['target_ssid'] or 'N/A'} | APs: {b['ap_count']}",
        f"  AFTER  Job : {a['job_name']} ({a['folder_name']}) | SSID: {a['target_ssid'] or 'N/A'} | APs: {a['ap_count']}",
        f"  Generated  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "[EXECUTIVE DELTA SUMMARY]",
        f"  Avg 5/6 GHz RSSI Change : {_fmt_delta(data['avg_delta_5_db'])}",
        f"  Avg 2.4 GHz RSSI Change : {_fmt_delta(data['avg_delta_24_db'])}",
        f"  High-Congestion Radios  : {b['high_cu_count']} -> {a['high_cu_count']} ({_fmt_delta(data['high_cu_delta'], 'radios')}) | Peak CU: {b['peak_cu_pct']}% -> {a['peak_cu_pct']}%",
    ]
    if data["speedtest_delta"]:
        sd = data["speedtest_delta"]
        lines.append(
            f"  Speedtest Download      : {sd['dl_before']} -> {sd['dl_after']} Mbps ({_fmt_delta(sd['dl_diff'], 'Mbps')})"
        )
        lines.append(
            f"  Speedtest Upload        : {sd['ul_before']} -> {sd['ul_after']} Mbps ({_fmt_delta(sd['ul_diff'], 'Mbps')})"
        )
        lines.append(
            f"  Bufferbloat Delta       : +{sd['bb_before']} -> +{sd['bb_after']} ms ({_fmt_delta(sd['bb_diff'], 'ms')})"
        )
    lines.append("")

    lines.append("[ROOM-BY-ROOM RF COVERAGE DELTA]")
    lines.append("  " + "-" * 92)
    lines.append(f"  {'Room / Waypoint':32} | {'Before 5G':10} | {'After 5G':10} | {'5G Delta':9} | {'Before 2.4G':11} | {'After 2.4G'}")
    lines.append("  " + "-" * 92)
    for r in data["room_rows"]:
        b5 = f"{r['before_5']} dBm" if r["before_5"] is not None else "—"
        a5 = f"{r['after_5']} dBm" if r["after_5"] is not None else "—"
        d5 = _fmt_delta(r["delta_5"])
        b24 = f"{r['before_24']} dBm" if r["before_24"] is not None else "—"
        a24 = f"{r['after_24']} dBm" if r["after_24"] is not None else "—"
        lines.append(f"  {r['room'][:32]:32} | {b5:10} | {a5:10} | {d5:9} | {b24:11} | {a24}")
    lines.append("  " + "-" * 92)
    lines.append("")

    if data["ap_changes"]:
        lines.append("[ACCESS POINT & CHANNEL PLAN CHANGES]")
        for c in data["ap_changes"]:
            lines.append(f"  * [{c['status']}] {c['ap']} ({c['prefix']}:xx): {c['before']}  ==>  {c['after']}")
        lines.append("")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def _write_comparison_html(path: str, data: dict):
    b, a = data["before"], data["after"]

    def delta_badge(val, unit="dB", invert=False):
        if val is None:
            return "<span class='sub'>—</span>"
        good = (val < 0) if invert else (val > 0)
        bad = (val > 0) if invert else (val < 0)
        cls = "badge-good" if good else ("badge-bad" if bad else "badge-neutral")
        return f"<span class='badge {cls}'>{html.escape(_fmt_delta(val, unit))}</span>"

    rows_html = ""
    for r in data["room_rows"]:
        b5 = f"{r['before_5']} dBm<br><span class='sub'>{html.escape(r['before_ap5'])}</span>" if r["before_5"] is not None else "<span class='sub'>—</span>"
        a5 = f"{r['after_5']} dBm<br><span class='sub'>{html.escape(r['after_ap5'])}</span>" if r["after_5"] is not None else "<span class='sub'>—</span>"
        b24 = f"{r['before_24']} dBm" if r["before_24"] is not None else "—"
        a24 = f"{r['after_24']} dBm" if r["after_24"] is not None else "—"
        rows_html += f"""
        <tr>
          <td><strong>{html.escape(r['room'])}</strong></td>
          <td>{b5}</td>
          <td>{a5}</td>
          <td>{delta_badge(r['delta_5'])}</td>
          <td>{b24} &rarr; {a24}</td>
          <td>{delta_badge(r['delta_24'])}</td>
        </tr>"""

    st_html = ""
    if data["speedtest_delta"]:
        sd = data["speedtest_delta"]
        st_html = f"""
        <h2>Throughput &amp; Bufferbloat Delta</h2>
        <table>
          <thead><tr><th>Metric</th><th>Before</th><th>After</th><th>Change</th></tr></thead>
          <tbody>
            <tr><td><strong>Download</strong></td><td>{sd['dl_before']} Mbps</td><td>{sd['dl_after']} Mbps</td><td>{delta_badge(sd['dl_diff'], 'Mbps')}</td></tr>
            <tr><td><strong>Upload</strong></td><td>{sd['ul_before']} Mbps</td><td>{sd['ul_after']} Mbps</td><td>{delta_badge(sd['ul_diff'], 'Mbps')}</td></tr>
            <tr><td><strong>Bufferbloat Added Latency</strong></td><td>+{sd['bb_before']} ms</td><td>+{sd['bb_after']} ms</td><td>{delta_badge(sd['bb_diff'], 'ms', invert=True)}</td></tr>
          </tbody>
        </table>"""

    ap_html = ""
    if data["ap_changes"]:
        ap_rows = "".join(
            f"<tr><td><span class='badge badge-info'>{html.escape(c['status'])}</span></td>"
            f"<td><strong>{html.escape(c['ap'])}</strong> (<code>{html.escape(c['prefix'])}:xx</code>)</td>"
            f"<td><code>{html.escape(c['before'])}</code></td><td><code>{html.escape(c['after'])}</code></td></tr>"
            for c in data["ap_changes"]
        )
        ap_html = f"""
        <h2>Access Point &amp; Channel Plan Changes</h2>
        <table>
          <thead><tr><th>Change</th><th>Access Point</th><th>Before</th><th>After</th></tr></thead>
          <tbody>{ap_rows}</tbody>
        </table>"""

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Before vs. After Comparison — {html.escape(a['job_name'])}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f8fafc; color: #0f172a; margin: 0; padding: 28px; }}
    .container {{ max-width: 1020px; margin: 0 auto; background: #fff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 32px 36px; }}
    .header {{ border-bottom: 2px solid #1e40af; padding-bottom: 14px; margin-bottom: 20px; }}
    .header h1 {{ margin: 0 0 4px 0; font-size: 22px; color: #1e40af; }}
    .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 8px; padding: 12px 16px; margin-bottom: 20px; font-size: 13px; }}
    .grid strong {{ display: block; font-size: 11px; color: #475569; text-transform: uppercase; }}
    h2 {{ font-size: 16px; color: #1e40af; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; margin-top: 24px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 16px; }}
    th, td {{ text-align: left; padding: 9px 10px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }}
    th {{ background: #f1f5f9; font-size: 11.5px; text-transform: uppercase; color: #334155; }}
    .sub {{ font-size: 11.5px; color: #64748b; }}
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 99px; font-weight: 600; font-size: 11.5px; }}
    .badge-good {{ background: #dcfce7; color: #166534; }}
    .badge-bad {{ background: #fee2e2; color: #991b1b; }}
    .badge-neutral {{ background: #e2e8f0; color: #334155; }}
    .badge-info {{ background: #dbeafe; color: #1e40af; }}
    @media print {{ body {{ background: #fff; padding: 0; }} .container {{ border: none; padding: 0; }} }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Wi-Fi Site Survey — Before vs. After Comparison</h1>
      <div class="sub">Before: <strong>{html.escape(b['folder_name'])}</strong> &rarr; After: <strong>{html.escape(a['folder_name'])}</strong></div>
    </div>
    <div class="grid">
      <div><strong>Avg 5/6 GHz Delta</strong>{delta_badge(data['avg_delta_5_db'])}</div>
      <div><strong>Avg 2.4 GHz Delta</strong>{delta_badge(data['avg_delta_24_db'])}</div>
      <div><strong>High-CU Radios (&ge;35%)</strong><span>{b['high_cu_count']} &rarr; {a['high_cu_count']}</span></div>
      <div><strong>Peak Channel Util</strong><span>{b['peak_cu_pct']}% &rarr; {a['peak_cu_pct']}%</span></div>
    </div>
    {st_html}
    <h2>Room-by-Room Signal Improvement</h2>
    <table>
      <thead>
        <tr>
          <th>Room / Waypoint</th>
          <th>Before 5/6 GHz</th>
          <th>After 5/6 GHz</th>
          <th>5/6 GHz Delta</th>
          <th>2.4 GHz (Before &rarr; After)</th>
          <th>2.4 GHz Delta</th>
        </tr>
      </thead>
      <tbody>{rows_html}</tbody>
    </table>
    {ap_html}
  </div>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)


def main():
    parser = argparse.ArgumentParser(description="Compare two Wi-Fi Site Survey Job Folders (Before vs. After)")
    parser.add_argument("before_folder", help="Path to the Before (baseline) job folder")
    parser.add_argument("after_folder", help="Path to the After (post-remediation) job folder")
    parser.add_argument("--out-dir", help="Output directory for COMPARISON_REPORT.{html,txt} (defaults to after_folder)")
    args = parser.parse_args()

    res = compare_job_folders(args.before_folder, args.after_folder, out_dir=args.out_dir)
    print(f"[+] Comparison TXT created : {res['txt_path']}")
    print(f"[+] Comparison HTML created: {res['html_path']}")


if __name__ == "__main__":
    main()
