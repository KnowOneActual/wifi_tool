"""
Open-Source Wi-Fi Site Survey Scanner for Windows 11
Extracts native 2.4 GHz, 5 GHz, and 6 GHz (Wi-Fi 6E / Wi-Fi 7) telemetry:
- Forces a live hardware scan via Windows Native Wi-Fi API (wlanapi.dll WlanScan)
- SSID, BSSID, Hardware Vendor (OUI), Radio Standard (802.11be/ax/ac/n)
- Band & Channel (including 6 GHz UNII-5 to UNII-8)
- Signal Quality (% and estimated dBm)
- BSS Load: Connected Clients & Channel Utilization (%)
- Per-Waypoint Active Link Telemetry (True RSSI dBm, PHY Tx/Rx Mbps, Roaming BSSID)
- Per-Waypoint Split-Hop Ping & Jitter (Local Gateway vs. Cloudflare 1.1.1.1)
"""

import subprocess
import ctypes
from ctypes import wintypes
import time
import re
import os
import sys
import json
import csv
import argparse
from datetime import datetime

from network_diagnostics import (
    lookup_oui,
    get_active_wifi_interface,
    run_split_hop_diagnostics,
    run_cloudflare_speedtest,
)


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class WLAN_INTERFACE_INFO(ctypes.Structure):
    _fields_ = [
        ("InterfaceGuid", GUID),
        ("strInterfaceDescription", ctypes.c_wchar * 256),
        ("isState", ctypes.c_uint),
    ]


class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
    _fields_ = [
        ("dwNumberOfItems", wintypes.DWORD),
        ("dwIndex", wintypes.DWORD),
        ("InterfaceInfo", WLAN_INTERFACE_INFO * 1),
    ]


def force_wlan_scan(wait_seconds: float = 3.0) -> bool:
    """
    Trigger a live hardware RF scan across all bands using Windows wlanapi.dll (WlanScan)
    so `netsh wlan show networks mode=bssid` returns fresh beacon data instead of cached data.
    """
    try:
        wlanapi = ctypes.windll.LoadLibrary("wlanapi.dll")
        negotiated_version = wintypes.DWORD()
        client_handle = wintypes.HANDLE()

        res = wlanapi.WlanOpenHandle(
            wintypes.DWORD(2), None, ctypes.byref(negotiated_version), ctypes.byref(client_handle)
        )
        if res != 0:
            return False

        p_iface_list = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)()
        res = wlanapi.WlanEnumInterfaces(client_handle, None, ctypes.byref(p_iface_list))
        if res != 0:
            wlanapi.WlanCloseHandle(client_handle, None)
            return False

        num_items = p_iface_list.contents.dwNumberOfItems
        iface_array_type = WLAN_INTERFACE_INFO * num_items
        iface_array = ctypes.cast(
            ctypes.byref(p_iface_list.contents.InterfaceInfo),
            ctypes.POINTER(iface_array_type)
        ).contents

        triggered = False
        for i in range(num_items):
            guid = iface_array[i].InterfaceGuid
            scan_res = wlanapi.WlanScan(client_handle, ctypes.byref(guid), None, None, None)
            if scan_res == 0:
                triggered = True

        wlanapi.WlanFreeMemory(p_iface_list)
        wlanapi.WlanCloseHandle(client_handle, None)

        if triggered and wait_seconds > 0:
            time.sleep(wait_seconds)
        return triggered
    except Exception:
        return False


def run_netsh_scan(live_refresh: bool = True):
    if live_refresh:
        force_wlan_scan(wait_seconds=2.8)

    cmd = ["netsh", "wlan", "show", "networks", "mode=bssid"]
    proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    if proc.returncode != 0:
        print(f"Error running netsh: {proc.stderr}")
        return []

    lines = proc.stdout.splitlines()
    networks = []

    current_ssid = None
    current_bssid = None
    current_auth = None
    current_enc = None
    bssid_data = {}

    for line in lines:
        l = line.strip()
        if not l:
            continue

        if l.startswith("SSID"):
            m = re.match(r"SSID\s+\d+\s+:\s*(.*)", l)
            if m:
                current_ssid = m.group(1).strip()
                if not current_ssid:
                    current_ssid = "<Hidden / Broadcast>"
        elif l.startswith("Authentication"):
            current_auth = l.split(":", 1)[1].strip()
        elif l.startswith("Encryption"):
            current_enc = l.split(":", 1)[1].strip()
        elif l.startswith("BSSID"):
            if current_bssid and bssid_data:
                networks.append(bssid_data)
            m = re.match(r"BSSID\s+\d+\s+:\s*([0-9a-fA-F:]{17})", l)
            if m:
                current_bssid = m.group(1).lower()
                bssid_data = {
                    "ssid": current_ssid,
                    "bssid": current_bssid,
                    "vendor": lookup_oui(current_bssid),
                    "auth": current_auth,
                    "enc": current_enc,
                    "timestamp": datetime.now().isoformat()
                }
        elif current_bssid:
            if l.startswith("Signal"):
                m = re.search(r"(\d+)%", l)
                if m:
                    pct = int(m.group(1))
                    bssid_data["signal_pct"] = pct
                    # Standard Windows dBm approximation: dBm = (pct / 2) - 100
                    bssid_data["signal_dbm"] = int((pct / 2) - 100)
            elif l.startswith("Radio type"):
                bssid_data["radio_type"] = l.split(":", 1)[1].strip()
            elif l.startswith("Band"):
                bssid_data["band"] = l.split(":", 1)[1].strip()
            elif l.startswith("Channel Utilization"):
                m = re.search(r"(\d+)\s*\(\s*(\d+)\s*%\s*\)", l)
                if m:
                    bssid_data["cu_raw"] = int(m.group(1))
                    bssid_data["cu_pct"] = int(m.group(2))
            elif re.match(r"^Channel\s*:", l):
                bssid_data["channel"] = l.split(":", 1)[1].strip()
            elif l.startswith("Connected Stations"):
                m = re.search(r"(\d+)", l)
                if m:
                    bssid_data["stations"] = int(m.group(1))

    if current_bssid and bssid_data:
        networks.append(bssid_data)

    return networks


def print_scan_table(networks, filter_ssid=None):
    if filter_ssid:
        networks = [n for n in networks if filter_ssid.lower() in n.get("ssid", "").lower()]

    # Sort by Signal dBm descending
    networks.sort(key=lambda x: x.get("signal_dbm", -100), reverse=True)

    print("\n" + "=" * 115)
    print(f"{'SSID':25} | {'BSSID':17} | {'Band':7} | {'Ch':4} | {'Radio':8} | {'RSSI':15} | {'Util':6} | {'STAs':4} | {'Security'}")
    print("=" * 115)

    for n in networks:
        ssid = n.get("ssid", "")[:25]
        bssid = n.get("bssid", "")
        band = n.get("band", "")[:7]
        ch = str(n.get("channel", ""))[:4]
        radio = n.get("radio_type", "")[:8]
        sig_pct = n.get("signal_pct", 0)
        sig_dbm = n.get("signal_dbm", -100)
        rssi_str = f"{sig_dbm} dBm ({sig_pct}%)"
        cu = f"{n.get('cu_pct')}%" if "cu_pct" in n else "N/A"
        stas = str(n.get("stations", "-"))
        sec = f"{n.get('auth', '')}/{n.get('enc', '')}"

        print(f"{ssid:25} | {bssid:17} | {band:7} | {ch:>4} | {radio:8} | {rssi_str:15} | {cu:>6} | {stas:>4} | {sec}")
    print("=" * 115)
    print(f"Total Detected BSSIDs: {len(networks)} | Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")


def record_waypoint(waypoint_name, target_ssid=None, log_file="survey_log.csv", run_speedtest=False):
    # Support trailing '*' on waypoint name as a shortcut to trigger a room speedtest
    clean_waypoint = waypoint_name.strip()
    if clean_waypoint.endswith("*"):
        run_speedtest = True
        clean_waypoint = clean_waypoint[:-1].strip()

    print(f"    [*] Triggering live hardware Wi-Fi scan at '{clean_waypoint}'...")
    networks = run_netsh_scan(live_refresh=True)
    if target_ssid:
        networks = [n for n in networks if target_ssid.lower() in n.get("ssid", "").lower()]

    if not networks:
        print(f"No networks found matching '{target_ssid or ''}' at waypoint '{clean_waypoint}'.")
        return

    file_exists = os.path.exists(log_file) and os.path.getsize(log_file) > 0
    with open(log_file, "a", newline="", encoding="utf-8") as f:
        fieldnames = [
            "timestamp", "waypoint", "ssid", "bssid", "band", "channel",
            "radio_type", "signal_dbm", "signal_pct", "cu_pct", "stations", "auth", "enc"
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()

        for n in networks:
            writer.writerow({
                "timestamp": n.get("timestamp"),
                "waypoint": clean_waypoint,
                "ssid": n.get("ssid"),
                "bssid": n.get("bssid"),
                "band": n.get("band"),
                "channel": n.get("channel"),
                "radio_type": n.get("radio_type"),
                "signal_dbm": n.get("signal_dbm"),
                "signal_pct": n.get("signal_pct"),
                "cu_pct": n.get("cu_pct", ""),
                "stations": n.get("stations", ""),
                "auth": n.get("auth", ""),
                "enc": n.get("enc", "")
            })

    print(f"    [+] Recorded {len(networks)} BSSID records for '{clean_waypoint}' -> {os.path.basename(log_file)}")

    # Capture active connection link telemetry + split-hop Gateway vs. WAN latency
    job_dir = os.path.dirname(os.path.abspath(log_file))
    telemetry_file = os.path.join(job_dir, "waypoint_telemetry.csv")
    wifi_link = get_active_wifi_interface()
    print(f"    [*] Active Link: {wifi_link.get('ssid') or 'Disconnected'} | BSSID={wifi_link.get('bssid')} "
          f"({wifi_link.get('band')} Ch {wifi_link.get('channel')}) | True RSSI={wifi_link.get('true_rssi_dbm')} dBm | "
          f"Link={wifi_link.get('tx_rate_mbps')}/{wifi_link.get('rx_rate_mbps')} Mbps")

    print(f"    [*] Measuring Gateway vs. WAN (1.1.1.1) latency & jitter...")
    hop = run_split_hop_diagnostics(wifi_link.get("gateway"), "1.1.1.1", count=4)
    gw = hop["gateway"]
    wan = hop["wan"]
    print(f"    [+] Ping: Gateway={gw['avg_ms']} ms (Jitter {gw['jitter_ms']} ms, Loss {gw['loss_pct']}%) | "
          f"WAN={wan['avg_ms']} ms (Jitter {wan['jitter_ms']} ms, Loss {wan['loss_pct']}%) | DNS={hop['dns_lookup_ms']} ms")

    dl_mbps = ""
    ul_mbps = ""
    bb_grade = ""
    if run_speedtest:
        print(f"    [*] Running Cloudflare Speedtest + Bufferbloat at '{clean_waypoint}'...")
        st = run_cloudflare_speedtest(duration_target_sec=5.0)
        if st.get("status") == "success":
            dl_mbps = st["download_mbps"]
            ul_mbps = st["upload_mbps"]
            bb_grade = st["bufferbloat_grade"]
            print(f"    [+] Speedtest: Down={dl_mbps} Mbps | Up={ul_mbps} Mbps | Bufferbloat={bb_grade}")
            # Also save to speedtest_results.json in job folder
            st_json_path = os.path.join(job_dir, "speedtest_results.json")
            existing = []
            if os.path.exists(st_json_path):
                try:
                    with open(st_json_path, "r", encoding="utf-8") as sf:
                        d = json.load(sf)
                        existing = d if isinstance(d, list) else [d]
                except Exception:
                    existing = []
            existing.append({
                "waypoint": clean_waypoint,
                "timestamp": datetime.now().isoformat(),
                "wifi_interface": wifi_link,
                "split_hop_ping": hop,
                "speedtest": st
            })
            with open(st_json_path, "w", encoding="utf-8") as sf:
                json.dump(existing, sf, indent=2)

    tel_exists = os.path.exists(telemetry_file) and os.path.getsize(telemetry_file) > 0
    tel_fields = [
        "timestamp", "waypoint", "connected_ssid", "connected_bssid", "connected_band",
        "connected_channel", "radio_type", "true_rssi_dbm", "signal_pct",
        "tx_rate_mbps", "rx_rate_mbps", "gateway_ip", "gw_avg_ms", "gw_jitter_ms", "gw_loss_pct",
        "wan_avg_ms", "wan_jitter_ms", "wan_loss_pct", "dns_ms", "diagnosis",
        "download_mbps", "upload_mbps", "bufferbloat_grade"
    ]
    with open(telemetry_file, "a", newline="", encoding="utf-8") as tf:
        tw = csv.DictWriter(tf, fieldnames=tel_fields)
        if not tel_exists:
            tw.writeheader()
        tw.writerow({
            "timestamp": datetime.now().isoformat(),
            "waypoint": clean_waypoint,
            "connected_ssid": wifi_link.get("ssid", ""),
            "connected_bssid": wifi_link.get("bssid", ""),
            "connected_band": wifi_link.get("band", ""),
            "connected_channel": wifi_link.get("channel", ""),
            "radio_type": wifi_link.get("radio_type", ""),
            "true_rssi_dbm": wifi_link.get("true_rssi_dbm", ""),
            "signal_pct": wifi_link.get("signal_pct", ""),
            "tx_rate_mbps": wifi_link.get("tx_rate_mbps", ""),
            "rx_rate_mbps": wifi_link.get("rx_rate_mbps", ""),
            "gateway_ip": gw.get("host", ""),
            "gw_avg_ms": gw.get("avg_ms", ""),
            "gw_jitter_ms": gw.get("jitter_ms", ""),
            "gw_loss_pct": gw.get("loss_pct", ""),
            "wan_avg_ms": wan.get("avg_ms", ""),
            "wan_jitter_ms": wan.get("jitter_ms", ""),
            "wan_loss_pct": wan.get("loss_pct", ""),
            "dns_ms": hop.get("dns_lookup_ms", ""),
            "diagnosis": hop.get("diagnosis", ""),
            "download_mbps": dl_mbps,
            "upload_mbps": ul_mbps,
            "bufferbloat_grade": bb_grade
        })


def main():
    parser = argparse.ArgumentParser(description="Open-Source Wi-Fi Site Surveyor for Windows 11")
    parser.add_argument("--scan", action="store_true", help="Perform a one-time live RF survey scan")
    parser.add_argument("--ssid", type=str, help="Filter results by SSID (e.g. 51AB)")
    parser.add_argument("--waypoint", type=str, help="Record scan data for a specific site location (append * to also run speedtest)")
    parser.add_argument("--speedtest", action="store_true", help="Also run a Cloudflare speedtest at this waypoint")
    parser.add_argument("--out", type=str, default="survey_log.csv", help="CSV log filename (default: survey_log.csv)")
    parser.add_argument("--json", action="store_true", help="Output raw scan data as JSON")

    args = parser.parse_args()

    if args.waypoint:
        record_waypoint(args.waypoint, target_ssid=args.ssid, log_file=args.out, run_speedtest=args.speedtest)
    elif args.json:
        nets = run_netsh_scan(live_refresh=True)
        if args.ssid:
            nets = [n for n in nets if args.ssid.lower() in n.get("ssid", "").lower()]
        print(json.dumps(nets, indent=2))
    else:
        nets = run_netsh_scan(live_refresh=True)
        print_scan_table(nets, filter_ssid=args.ssid)


if __name__ == "__main__":
    main()
