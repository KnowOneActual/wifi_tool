"""
Engineering Hand-Off & Executive PM Report Generator
Summarizes all survey waypoints (separating 5/6 GHz vs 2.4 GHz), active link telemetry,
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
from collections import defaultdict
from datetime import datetime

from network_diagnostics import lookup_oui

CSV_STANDARD_HEADERS = [
    "timestamp", "waypoint", "ssid", "bssid", "band", "channel",
    "radio_type", "signal_dbm", "signal_pct", "cu_pct", "stations", "auth", "enc"
]


def detect_connected_ssid(job_folder: str) -> str:
    """Fallback: detect connected SSID from wlan_interfaces.txt if target_ssid is blank."""
    iface_path = os.path.join(job_folder, "wlan_interfaces.txt")
    if os.path.exists(iface_path):
        try:
            with open(iface_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    l = line.strip()
                    if re.match(r"^SSID\s*:", l, re.IGNORECASE):
                        val = l.split(":", 1)[1].strip()
                        if val:
                            return val
        except Exception:
            pass
    return ""


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
                records.append(row)
    except Exception as e:
        print(f"Error reading CSV: {e}")
    return records


def load_csv_generic(path: str) -> list:
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
            return list(csv.DictReader(f))
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
    telemetry_rows = load_csv_generic(os.path.join(job_folder, "waypoint_telemetry.csv"))
    lan_devices = load_csv_generic(os.path.join(job_folder, "lan_devices.csv"))
    speedtest_runs = load_json_safe(os.path.join(job_folder, "speedtest_results.json"))

    target_ssid = meta.get("target_ssid", "").strip()
    if not target_ssid:
        target_ssid = detect_connected_ssid(job_folder)

    def matches_target(ssid_val: str) -> bool:
        if not target_ssid:
            return ssid_val != "<Hidden / Broadcast>"
        s_clean = (ssid_val or "").strip().lower()
        t_clean = target_ssid.strip().lower()
        return s_clean == t_clean

    # Group target BSSIDs into physical APs by 5-octet MAC prefix (xx:xx:xx:xx:xx)
    ap_prefix_map = {}
    ap_details = defaultdict(lambda: {"prefix": "", "vendor": "", "radios": {}})
    if records:
        target_recs_all = [r for r in records if matches_target(r.get("ssid", ""))]
        if not target_recs_all and target_ssid:
            target_recs_all = [r for r in records if target_ssid.lower() in r.get("ssid", "").lower()]
        prefixes = sorted(list(set(r.get("bssid", "")[:14] for r in target_recs_all if len(r.get("bssid", "")) >= 14)))
        for idx, pref in enumerate(prefixes, start=1):
            ap_label = f"AP {idx}"
            ap_prefix_map[pref] = ap_label
            ap_details[ap_label]["prefix"] = pref
            ap_details[ap_label]["vendor"] = lookup_oui(pref)

        for r in target_recs_all:
            bssid = r.get("bssid", "")
            pref = bssid[:14]
            if pref in ap_prefix_map:
                ap_label = ap_prefix_map[pref]
                band = r.get("band", "Unknown")
                ch = r.get("channel", "?")
                radio = r.get("radio_type", "")
                ap_details[ap_label]["radios"][band] = f"{bssid} (Ch {ch}, {radio})"

    def format_ap_tag(bssid: str) -> str:
        if not bssid:
            return "N/A"
        pref = bssid[:14]
        if pref in ap_prefix_map:
            return f"{ap_prefix_map[pref]} ({bssid[-5:]})"
        return bssid

    # Map telemetry by waypoint name
    tel_by_wp = {}
    for t in telemetry_rows:
        wp_name = t.get("waypoint", "")
        if wp_name:
            tel_by_wp[wp_name] = t

    # Preserve chronological order of waypoints
    waypoints = []
    seen_wp = set()
    for r in records:
        wp = r.get("waypoint", "")
        if wp and wp not in seen_wp:
            seen_wp.add(wp)
            waypoints.append(wp)

    # Build per-waypoint summary objects
    wp_summaries = []
    for wp in waypoints:
        wp_recs = [r for r in records if r.get("waypoint") == wp]
        if target_ssid:
            t_recs = [r for r in wp_recs if matches_target(r.get("ssid", ""))]
            if not t_recs:
                t_recs = [r for r in wp_recs if target_ssid.lower() in r.get("ssid", "").lower()]
        else:
            t_recs = wp_recs

        recs_5_6 = [r for r in t_recs if "5" in r.get("band", "") or "6" in r.get("band", "")]
        recs_24 = [r for r in t_recs if "2.4" in r.get("band", "")]

        best_5 = max(recs_5_6, key=lambda x: int(x.get("signal_dbm", -100))) if recs_5_6 else None
        best_24 = max(recs_24, key=lambda x: int(x.get("signal_dbm", -100))) if recs_24 else None

        ts_raw = wp_recs[0].get("timestamp", "") if wp_recs else ""
        ts_short = ts_raw[11:19] if len(ts_raw) >= 19 else ts_raw

        wp_summaries.append({
            "waypoint": wp,
            "time": ts_short,
            "best_5": best_5,
            "best_24": best_24,
            "telemetry": tel_by_wp.get(wp, {})
        })

    # 1. Write ENGINEERING_HANDOFF_SUMMARY.txt
    summary_path = os.path.join(job_folder, "ENGINEERING_HANDOFF_SUMMARY.txt")
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("=" * 95 + "\n")
        f.write("                  FIELD SITE SURVEY - ENGINEERING HAND-OFF PACKAGE\n")
        f.write("=" * 95 + "\n\n")

        f.write("[JOB METADATA]\n")
        f.write(f"  Project / Job Name : {meta.get('job_name', 'N/A')}\n")
        f.write(f"  Field Technician   : {meta.get('tech_name', 'N/A')}\n")
        f.write(f"  Audit Date & Time  : {meta.get('date', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}\n")
        f.write(f"  Target SSID        : {target_ssid or 'All Visible Networks'}\n")
        f.write(f"  Site Notes         : {meta.get('notes', 'None')}\n")
        f.write(f"  Output Directory   : {job_folder}\n\n")

        files = os.listdir(job_folder)
        f.write("[COLLECTED ARTIFACTS]\n")
        for fn in sorted(files):
            fp = os.path.join(job_folder, fn)
            sz = os.path.getsize(fp) if os.path.isfile(fp) else 0
            f.write(f"  - {fn:35} ({sz:,} bytes)\n")
        f.write("\n")

        if ap_details:
            f.write(f"[DETECTED ACCESS POINTS FOR '{target_ssid or 'SITE'}']\n")
            for ap_label, info in ap_details.items():
                radios_str = " | ".join(f"{b}: {v}" for b, v in sorted(info["radios"].items()))
                f.write(f"  * {ap_label:5} [{info['prefix']}:xx] ({info['vendor']}) -> {radios_str}\n")
            f.write("\n")

        if speedtest_runs:
            f.write("[CLOUDFLARE SPEEDTEST & BUFFERBLOAT AUDIT]\n")
            for sr in speedtest_runs:
                loc = sr.get("waypoint", "Baseline")
                st = sr.get("speedtest", {})
                hop = sr.get("split_hop_ping", {})
                gw = hop.get("gateway", {})
                wan = hop.get("wan", {})
                if st.get("status") == "success":
                    f.write(
                        f"  * [{loc}] Down: {st.get('download_mbps')} Mbps | Up: {st.get('upload_mbps')} Mbps | "
                        f"Unloaded Ping: {st.get('unloaded_ping_ms')} ms (Jitter {st.get('unloaded_jitter_ms')} ms) | "
                        f"Bufferbloat: +{st.get('bufferbloat_delta_ms')} ms ({st.get('bufferbloat_grade')})\n"
                    )
                if gw or wan:
                    f.write(
                        f"    Split-Hop Ping -> Gateway ({gw.get('host', 'N/A')}): {gw.get('avg_ms')} ms "
                        f"(Loss {gw.get('loss_pct')}%) | WAN (1.1.1.1): {wan.get('avg_ms')} ms "
                        f"(Loss {wan.get('loss_pct')}%) | {hop.get('diagnosis', '')}\n"
                    )
            f.write("\n")

        if wp_summaries:
            f.write("[SURVEY COVERAGE & WAYPOINT SUMMARY (5/6 GHz vs. 2.4 GHz)]\n")
            f.write(f"  Total Waypoints Logged : {len(wp_summaries)}\n")
            f.write(f"  Total BSSID Records    : {len(records)}\n\n")
            f.write("  " + "-" * 91 + "\n")
            f.write(f"  {'Waypoint / Room':24} | {'Best 5/6 GHz (AP / Ch)':28} | {'Best 2.4 GHz (AP / Ch)':28} | {'Ping GW/WAN'}\n")
            f.write("  " + "-" * 91 + "\n")

            for ws in wp_summaries:
                wp = ws["waypoint"][:24]
                b5 = ws["best_5"]
                b24 = ws["best_24"]
                tel = ws["telemetry"]

                if b5:
                    s5 = f"{b5.get('signal_dbm')} dBm {format_ap_tag(b5.get('bssid'))} c{b5.get('channel')}"
                else:
                    s5 = "NO 5/6G SIGNAL"

                if b24:
                    s24 = f"{b24.get('signal_dbm')} dBm {format_ap_tag(b24.get('bssid'))} c{b24.get('channel')}"
                else:
                    s24 = "NO 2.4G SIGNAL"

                if tel and tel.get("gw_avg_ms"):
                    ping_str = f"{tel.get('gw_avg_ms')}/{tel.get('wan_avg_ms')} ms"
                else:
                    ping_str = "-"

                f.write(f"  {wp:24} | {s5:28} | {s24:28} | {ping_str}\n")
            f.write("  " + "-" * 91 + "\n\n")

            # High utilization alerts
            high_cu = [
                r for r in records
                if r.get("cu_pct") and str(r.get("cu_pct")).isdigit() and int(r.get("cu_pct")) >= 35
            ]
            if high_cu:
                f.write("[!] ENGINEERING ALERTS: HIGH CHANNEL CONGESTION (>= 35% Utilization)\n")
                seen_cu = set()
                for h in high_cu:
                    k = (h.get("ssid"), h.get("bssid"), h.get("channel"))
                    if k not in seen_cu:
                        seen_cu.add(k)
                        vendor = lookup_oui(h.get("bssid", ""))
                        f.write(
                            f"  * SSID: {h.get('ssid', ''):20} | BSSID: {h.get('bssid')} ({vendor}) | "
                            f"Ch {h.get('channel', ''):3} ({h.get('band')}) | Utilization: {h.get('cu_pct')}%\n"
                        )
                f.write("\n")

        if lan_devices:
            f.write(f"[DISCOVERED LAN DEVICES ({len(lan_devices)} Active Hosts)]\n")
            for d in lan_devices:
                f.write(f"  * {d.get('ip', ''):15} | {d.get('mac', ''):17} | {d.get('vendor', ''):32} | {d.get('role', '')}\n")
            f.write("\n")

        f.write("=" * 95 + "\n")
        f.write("                     END OF ENGINEERING HAND-OFF SUMMARY\n")
        f.write("=" * 95 + "\n")

    print(f"[+] Engineering hand-off summary created: {summary_path}")

    # 2. Generate Executive HTML Report (PM_SITE_SURVEY_REPORT.html)
    html_path = os.path.join(job_folder, "PM_SITE_SURVEY_REPORT.html")
    generate_html_report(
        html_path, meta, target_ssid, ap_details, wp_summaries,
        speedtest_runs, lan_devices, records, format_ap_tag
    )
    print(f"[+] Executive PM HTML Report created   : {html_path}")


def generate_html_report(
    html_path, meta, target_ssid, ap_details, wp_summaries,
    speedtest_runs, lan_devices, records, format_ap_tag
):
    job_name = html.escape(meta.get("job_name", "Site Survey"))
    tech_name = html.escape(meta.get("tech_name", "Field Tech"))
    date_str = html.escape(meta.get("date", datetime.now().strftime("%Y-%m-%d %H:%M")))
    ssid_str = html.escape(target_ssid or "All Visible Networks")
    notes_str = html.escape(meta.get("notes", "") or "Standard site walkthrough & RF verification.")

    # Build Waypoint Rows HTML
    wp_rows_html = ""
    for ws in wp_summaries:
        wp_name = html.escape(ws["waypoint"])
        t_str = html.escape(ws["time"] or "-")
        b5 = ws["best_5"]
        b24 = ws["best_24"]
        tel = ws["telemetry"]

        if b5:
            dbm5 = int(b5.get("signal_dbm", -100))
            s5_html = f"<strong>{dbm5} dBm</strong> ({b5.get('signal_pct')}%)<br><span class='sub'>{html.escape(format_ap_tag(b5.get('bssid')))} &bull; Ch {b5.get('channel')}</span>"
        else:
            dbm5 = -100
            s5_html = "<span class='badge badge-bad'>No 5G Signal</span>"

        if b24:
            dbm24 = int(b24.get("signal_dbm", -100))
            s24_html = f"<strong>{dbm24} dBm</strong> ({b24.get('signal_pct')}%)<br><span class='sub'>{html.escape(format_ap_tag(b24.get('bssid')))} &bull; Ch {b24.get('channel')}</span>"
        else:
            dbm24 = -100
            s24_html = "<span class='sub'>N/A</span>"

        # Active link + ping
        link_str = "-"
        if tel and tel.get("tx_rate_mbps"):
            link_str = f"{tel.get('tx_rate_mbps')}/{tel.get('rx_rate_mbps')} Mbps<br><span class='sub'>GW: {tel.get('gw_avg_ms')}ms | WAN: {tel.get('wan_avg_ms')}ms</span>"
            if tel.get("download_mbps"):
                link_str += f"<br><strong>DL: {tel.get('download_mbps')} Mbps</strong>"

        if dbm5 >= -62:
            badge = "<span class='badge badge-good'>Excellent</span>"
        elif dbm5 >= -68:
            badge = "<span class='badge badge-good'>Good</span>"
        elif dbm5 >= -75:
            badge = "<span class='badge badge-warn'>Fair 5G</span>"
        else:
            badge = "<span class='badge badge-bad'>Weak 5G</span>"

        wp_rows_html += f"""
        <tr>
          <td>{t_str}</td>
          <td><strong>{wp_name}</strong></td>
          <td>{s5_html}</td>
          <td>{s24_html}</td>
          <td>{link_str}</td>
          <td>{badge}</td>
        </tr>"""

    # Build Speedtest HTML section
    st_html = ""
    if speedtest_runs:
        st_rows = ""
        for sr in speedtest_runs:
            loc = html.escape(sr.get("waypoint", "Baseline"))
            st = sr.get("speedtest", {})
            hop = sr.get("split_hop_ping", {})
            gw = hop.get("gateway", {})
            wan = hop.get("wan", {})
            st_rows += f"""
            <tr>
              <td><strong>{loc}</strong></td>
              <td><strong>{st.get('download_mbps', 'N/A')} Mbps</strong></td>
              <td><strong>{st.get('upload_mbps', 'N/A')} Mbps</strong></td>
              <td>{gw.get('avg_ms', 'N/A')} ms (Jitter {gw.get('jitter_ms', 0)} ms)</td>
              <td>{wan.get('avg_ms', 'N/A')} ms (DNS {hop.get('dns_lookup_ms', 'N/A')} ms)</td>
              <td>+{st.get('bufferbloat_delta_ms', 0)} ms ({html.escape(str(st.get('bufferbloat_grade', 'N/A')))})</td>
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
    ap_rows = ""
    for ap_label, info in ap_details.items():
        r24 = html.escape(info["radios"].get("2.4 GHz", "—"))
        r5 = html.escape(info["radios"].get("5 GHz", "—"))
        r6 = html.escape(info["radios"].get("6 GHz", "—"))
        ap_rows += f"""
        <tr>
          <td><strong>{html.escape(ap_label)}</strong> (<code>{html.escape(info['prefix'])}:xx</code>)</td>
          <td>{html.escape(info['vendor'])}</td>
          <td><code>{r24}</code></td>
          <td><code>{r5}</code></td>
          <td><code>{r6}</code></td>
        </tr>"""

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Site Survey Report — {job_name}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f8fafc; color: #0f172a; margin: 0; padding: 28px; }}
    .container {{ max-width: 1020px; margin: 0 auto; background: #fff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 32px 36px; box-shadow: 0 4px 14px rgba(0,0,0,0.04); }}
    .header {{ display: flex; justify-content: space-between; border-bottom: 2px solid #1e40af; padding-bottom: 16px; margin-bottom: 20px; }}
    .header h1 {{ margin: 0 0 4px 0; font-size: 22px; color: #1e40af; }}
    .meta {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 8px; padding: 12px 16px; margin-bottom: 24px; font-size: 13px; }}
    .meta strong {{ display: block; font-size: 11px; color: #475569; text-transform: uppercase; }}
    h2 {{ font-size: 16px; color: #1e40af; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; margin-top: 24px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 16px; }}
    th, td {{ text-align: left; padding: 9px 10px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }}
    th {{ background: #f1f5f9; font-size: 11.5px; text-transform: uppercase; color: #334155; }}
    .sub {{ font-size: 11.5px; color: #64748b; }}
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 99px; font-weight: 600; font-size: 11.5px; }}
    .badge-good {{ background: #dcfce7; color: #166534; }}
    .badge-warn {{ background: #ffedd5; color: #9a3412; }}
    .badge-bad {{ background: #fee2e2; color: #991b1b; }}
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

    {st_html}

    <h2>Room-by-Room Coverage &amp; Link Performance ({ssid_str})</h2>
    <table>
      <thead>
        <tr>
          <th>Time</th>
          <th>Room / Waypoint</th>
          <th>Best 5 / 6 GHz Signal</th>
          <th>Best 2.4 GHz Signal</th>
          <th>Active Link &amp; Ping</th>
          <th>Assessment</th>
        </tr>
      </thead>
      <tbody>{wp_rows_html}</tbody>
    </table>

    <h2>Target Access Point Hardware Inventory</h2>
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
