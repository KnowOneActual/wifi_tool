"""
Network Diagnostics, Cloudflare Speedtest (with Bufferbloat), Split-Hop Ping,
Active Wi-Fi Link Telemetry, and Fast LAN ARP/OUI Discovery for Windows 11.
100% Standard Library Python — Zero external pip dependencies required.
"""

import subprocess
import urllib.request
import ssl
import socket
import time
import json
import csv
import os
import re
import sys
import statistics
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Built-in MAC OUI Vendor Lookup Table (Common Wi-Fi APs, Mesh, Gateways, Smart Home, Client NICs)
OUI_VENDORS = {
    "50:61:3f": "eero / Amazon (Wi-Fi 7)",
    "64:c2:69": "ISP / Router Gateway",
    "4e:d7:4a": "Xfinity / Comcast Gateway (Virtual)",
    "4c:d5:46": "Comcast / Arris / Technicolor",
    "28:94:01": "Netgear (Orbi / Nighthawk)",
    "2e:94:01": "Netgear (Orbi Backhaul/Guest)",
    "36:94:01": "Netgear (Orbi IoT/Virtual)",
    "48:62:64": "Arlo Technologies (Camera Hub)",
    "00:24:d6": "Intel Corporate (Wireless NIC)",
    "10:65:30": "Intel Corporate (Ethernet NIC)",
    "74:ca:60": "Router / Mesh AP",
    "94:ff:06": "Router / Mesh AP",
    "18:a5:ff": "T-Mobile / Arcadyan Gateway",
    "bc:af:6e": "T-Mobile / Sagemcom 5G Gateway",
    "be:af:6e": "T-Mobile / Sagemcom (Virtual)",
    "a0:2d:13": "AT&T / Pace / Arris Gateway",
    "6a:2d:13": "AT&T Gateway (Virtual)",
    "7a:2d:13": "AT&T Gateway (Virtual)",
    "a8:40:f8": "AT&T / Nokia / Humax Gateway",
    "28:70:4e": "Router / AP",
    "32:70:4e": "Router / AP (Virtual)",
    "c8:52:61": "Consumer AP / Router",
    "d6:52:61": "Consumer AP (Virtual)",
    "da:52:61": "Consumer AP (Virtual)",
    "ba:16:5f": "LG Electronics (Smart Appliance)",
    "78:8a:20": "Ubiquiti Inc. (UniFi)",
    "e0:63:da": "Ubiquiti Inc. (UniFi)",
    "f0:9f:c2": "Ubiquiti Inc. (UniFi)",
    "24:5a:4c": "Ubiquiti Inc. (UniFi)",
    "74:83:c2": "Ubiquiti Inc. (UniFi)",
    "60:22:32": "Ubiquiti Inc. (UniFi)",
    "d0:21:f9": "Ubiquiti Inc. (UniFi)",
    "ac:8b:a9": "Ubiquiti Inc. (UniFi)",
    "b4:fb:e4": "Ubiquiti Inc. (UniFi)",
    "70:a7:41": "Ubiquiti Inc. (UniFi)",
    "88:dc:96": "Senao / EnGenius",
    "00:18:0a": "Cisco Meraki",
    "88:15:44": "Cisco Meraki",
    "e0:55:3d": "Cisco Meraki",
    "34:56:fe": "Aruba / HPE",
    "ec:b5:fa": "Philips Hue",
    "00:0e:58": "Sonos",
    "5c:aa:fd": "Sonos",
    "78:28:ca": "Sonos",
    "34:7e:5c": "Sonos",
    "48:a6:b8": "Sonos",
    "f0:f6:c1": "Sonos",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "d8:3a:dd": "Raspberry Pi",
    "50:14:79": "TP-Link / Deco",
    "b0:95:75": "TP-Link",
    "98:da:c4": "TP-Link",
    "04:d9:f5": "ASUSTek",
    "f0:2f:74": "ASUSTek",
}


def lookup_oui(mac: str) -> str:
    """Return hardware vendor or LAA classification from MAC address."""
    if not mac:
        return "Unknown"
    clean = mac.strip().lower().replace("-", ":")
    prefix = clean[:8]
    if prefix in OUI_VENDORS:
        return OUI_VENDORS[prefix]
    # Check Locally Administered Address bit (second hex char in first octet: 2, 6, a, e)
    if len(clean) >= 2 and clean[1] in ("2", "6", "a", "e"):
        return "Virtual BSSID / Private MAC (LAA)"
    return "Standard OUI"


def get_active_wifi_interface() -> dict:
    """
    Parse `netsh wlan show interfaces` and `ipconfig` to extract active Wi-Fi connection
    details including True RSSI (dBm), PHY Tx/Rx Link Rate (Mbps), connected BSSID, Band, Channel,
    and Default Gateway IP.
    """
    info = {
        "interface_name": "Wi-Fi",
        "adapter_description": "",
        "state": "disconnected",
        "ssid": "",
        "bssid": "",
        "band": "",
        "channel": "",
        "radio_type": "",
        "auth": "",
        "cipher": "",
        "rx_rate_mbps": 0.0,
        "tx_rate_mbps": 0.0,
        "signal_pct": 0,
        "true_rssi_dbm": None,
        "ipv4": "",
        "subnet_mask": "",
        "gateway": "",
        "timestamp": datetime.now().isoformat()
    }

    proc = subprocess.run(
        ["netsh", "wlan", "show", "interfaces"],
        capture_output=True, text=True, errors="replace"
    )
    if proc.returncode == 0:
        for line in proc.stdout.splitlines():
            l = line.strip()
            if not l or ":" not in l:
                continue
            key, val = [x.strip() for x in l.split(":", 1)]
            kl = key.lower()
            if kl == "name":
                info["interface_name"] = val
            elif kl == "description":
                info["adapter_description"] = val
            elif kl == "state":
                info["state"] = val.lower()
            elif kl == "ssid":
                info["ssid"] = val
            elif kl in ("ap bssid", "bssid"):
                info["bssid"] = val.lower()
            elif kl == "band":
                info["band"] = val
            elif kl == "channel":
                info["channel"] = val
            elif kl == "radio type":
                info["radio_type"] = val
            elif kl == "authentication":
                info["auth"] = val
            elif kl == "cipher":
                info["cipher"] = val
            elif "receive rate" in kl:
                try:
                    info["rx_rate_mbps"] = float(re.findall(r"[\d\.]+", val)[0])
                except Exception:
                    pass
            elif "transmit rate" in kl:
                try:
                    info["tx_rate_mbps"] = float(re.findall(r"[\d\.]+", val)[0])
                except Exception:
                    pass
            elif kl == "signal":
                m = re.search(r"(\d+)%", val)
                if m:
                    info["signal_pct"] = int(m.group(1))
            elif kl == "rssi":
                m = re.search(r"(-?\d+)", val)
                if m:
                    info["true_rssi_dbm"] = int(m.group(1))

    if info["true_rssi_dbm"] is None and info["signal_pct"] > 0:
        info["true_rssi_dbm"] = int((info["signal_pct"] / 2) - 100)

    # Extract IPv4 and Default Gateway from ipconfig
    ip_proc = subprocess.run(["ipconfig"], capture_output=True, text=True, errors="replace")
    if ip_proc.returncode == 0:
        in_wifi = False
        for line in ip_proc.stdout.splitlines():
            if "adapter" in line.lower() and ":" in line:
                in_wifi = ("wi-fi" in line.lower() or "wireless" in line.lower())
                continue
            if in_wifi or not info["gateway"]:
                if "IPv4 Address" in line and ":" in line:
                    ip_val = line.split(":", 1)[1].strip()
                    ip_val = re.sub(r"\(.*\)", "", ip_val).strip()
                    if not ip_val.startswith("169.254."):
                        info["ipv4"] = ip_val
                elif "Subnet Mask" in line and ":" in line and info["ipv4"]:
                    info["subnet_mask"] = line.split(":", 1)[1].strip()
                elif "Default Gateway" in line and ":" in line:
                    gw_val = line.split(":", 1)[1].strip()
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", gw_val):
                        info["gateway"] = gw_val

    return info


def ping_target(host: str, count: int = 4, timeout_ms: int = 1000) -> dict:
    """Ping a host multiple times and compute min, avg, max, jitter (ms), and packet loss (%)."""
    result = {
        "host": host,
        "sent": count,
        "received": 0,
        "loss_pct": 100.0,
        "min_ms": None,
        "avg_ms": None,
        "max_ms": None,
        "jitter_ms": None,
        "samples_ms": []
    }
    if not host:
        return result

    samples = []
    for _ in range(count):
        proc = subprocess.run(
            ["ping", "-n", "1", "-w", str(timeout_ms), host],
            capture_output=True, text=True, errors="replace"
        )
        out = proc.stdout
        m = re.search(r"time[=<](\d+)\s*ms", out, re.IGNORECASE)
        if m:
            samples.append(float(m.group(1)))
        elif "time<1ms" in out.lower():
            samples.append(0.5)
        time.sleep(0.05)

    result["received"] = len(samples)
    result["loss_pct"] = round(((count - len(samples)) / count) * 100.0, 1)
    result["samples_ms"] = samples

    if samples:
        result["min_ms"] = round(min(samples), 1)
        result["avg_ms"] = round(sum(samples) / len(samples), 1)
        result["max_ms"] = round(max(samples), 1)
        if len(samples) > 1:
            diffs = [abs(samples[i] - samples[i - 1]) for i in range(1, len(samples))]
            result["jitter_ms"] = round(sum(diffs) / len(diffs), 1)
        else:
            result["jitter_ms"] = 0.0

    return result


def measure_dns_resolution(domain: str = "speed.cloudflare.com") -> float:
    """Measure DNS lookup time in milliseconds."""
    t0 = time.perf_counter()
    try:
        socket.getaddrinfo(domain, 443)
        return round((time.perf_counter() - t0) * 1000.0, 1)
    except Exception:
        return -1.0


def run_split_hop_diagnostics(gateway_ip: str = None, wan_ip: str = "1.1.1.1", count: int = 4) -> dict:
    """
    Simultaneously test the Local Gateway (Wi-Fi Hop) and Cloudflare 1.1.1.1 (WAN Hop)
    to isolate Wi-Fi RF issues from ISP/Modem issues.
    """
    if not gateway_ip:
        wifi_info = get_active_wifi_interface()
        gateway_ip = wifi_info.get("gateway", "")

    with ThreadPoolExecutor(max_workers=3) as ex:
        fut_gw = ex.submit(ping_target, gateway_ip, count, 800) if gateway_ip else None
        fut_wan = ex.submit(ping_target, wan_ip, count, 1000)
        fut_dns = ex.submit(measure_dns_resolution, "cloudflare.com")

        gw_res = fut_gw.result() if fut_gw else ping_target("", count)
        wan_res = fut_wan.result()
        dns_ms = fut_dns.result()

    # Automated root-cause diagnosis
    diagnosis = "Healthy Wi-Fi & WAN"
    gw_avg = gw_res.get("avg_ms")
    wan_avg = wan_res.get("avg_ms")
    if gw_res["loss_pct"] > 0 or (gw_avg is not None and gw_avg > 15):
        diagnosis = "Wi-Fi RF Hop Degradation (High Gateway Latency/Loss)"
    elif wan_res["loss_pct"] > 0 or (wan_avg is not None and wan_avg > 75):
        diagnosis = "ISP / WAN Circuit Degradation (Gateway Healthy, WAN Slow/Lossy)"

    return {
        "gateway": gw_res,
        "wan": wan_res,
        "dns_lookup_ms": dns_ms,
        "diagnosis": diagnosis,
        "timestamp": datetime.now().isoformat()
    }


def run_cloudflare_speedtest(duration_target_sec: float = 6.0) -> dict:
    """
    Perform an HTTP/HTTPS Speedtest + Bufferbloat check against Cloudflare's edge network
    (speed.cloudflare.com) using Python standard library.
    Measures:
      - ISP / Public IP / Cloudflare Edge Colo (via /cdn-cgi/trace)
      - Unloaded HTTP/ICMP Latency & Jitter
      - Download Mbps + Loaded Download Latency (Bufferbloat)
      - Upload Mbps + Loaded Upload Latency (Bufferbloat)
      - Bufferbloat Grade (A+ to F)
    """
    ctx = ssl.create_default_context()
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WiFiSurveyTool/2.0"
    }

    result = {
        "timestamp": datetime.now().isoformat(),
        "public_ip": "Unknown",
        "colo": "Unknown",
        "http_protocol": "Unknown",
        "unloaded_ping_ms": None,
        "unloaded_jitter_ms": None,
        "download_mbps": 0.0,
        "loaded_dl_ping_ms": None,
        "upload_mbps": 0.0,
        "loaded_ul_ping_ms": None,
        "bufferbloat_delta_ms": 0.0,
        "bufferbloat_grade": "N/A",
        "status": "failed",
        "error": ""
    }

    try:
        # 1. Fetch Cloudflare Edge Trace Info
        req = urllib.request.Request("https://speed.cloudflare.com/cdn-cgi/trace", headers=headers)
        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            trace_text = resp.read().decode("utf-8", errors="replace")
            for line in trace_text.splitlines():
                if line.startswith("ip="):
                    result["public_ip"] = line.split("=", 1)[1].strip()
                elif line.startswith("colo="):
                    result["colo"] = line.split("=", 1)[1].strip()
                elif line.startswith("http="):
                    result["http_protocol"] = line.split("=", 1)[1].strip()

        # 2. Measure Unloaded Latency (5 lightweight HTTP RTT probes + ICMP 1.1.1.1)
        unloaded_ping = ping_target("1.1.1.1", count=5, timeout_ms=800)
        if unloaded_ping["avg_ms"] is not None:
            result["unloaded_ping_ms"] = unloaded_ping["avg_ms"]
            result["unloaded_jitter_ms"] = unloaded_ping["jitter_ms"]
        else:
            http_rtts = []
            for _ in range(4):
                t0 = time.perf_counter()
                r = urllib.request.Request("https://speed.cloudflare.com/__down?bytes=0", headers=headers)
                with urllib.request.urlopen(r, timeout=3, context=ctx) as resp:
                    resp.read()
                http_rtts.append((time.perf_counter() - t0) * 1000.0)
            result["unloaded_ping_ms"] = round(min(http_rtts), 1)
            result["unloaded_jitter_ms"] = round(statistics.pstdev(http_rtts), 1)

        # 3. Download Throughput Test + Simultaneous Loaded Ping (Bufferbloat)
        dl_bytes_total = 0
        dl_stop = False

        def loaded_ping_worker(target_list):
            while not dl_stop:
                p = ping_target("1.1.1.1", count=1, timeout_ms=800)
                if p["avg_ms"] is not None:
                    target_list.append(p["avg_ms"])
                time.sleep(0.15)

        loaded_dl_samples = []
        ping_thread = ThreadPoolExecutor(max_workers=1)
        ping_fut = ping_thread.submit(loaded_ping_worker, loaded_dl_samples)

        def download_worker(chunk_size_bytes):
            nonlocal dl_bytes_total
            t_end = time.perf_counter() + (duration_target_sec * 0.65)
            while time.perf_counter() < t_end:
                url = f"https://speed.cloudflare.com/__down?bytes={chunk_size_bytes}"
                req_dl = urllib.request.Request(url, headers=headers)
                try:
                    with urllib.request.urlopen(req_dl, timeout=6, context=ctx) as resp:
                        while True:
                            buf = resp.read(65536)
                            if not buf:
                                break
                            dl_bytes_total += len(buf)
                            if time.perf_counter() >= t_end:
                                break
                except Exception:
                    break

        t_dl_start = time.perf_counter()
        # Run 3 parallel download streams for accurate Wi-Fi throughput saturation
        with ThreadPoolExecutor(max_workers=3) as dl_ex:
            futs = [dl_ex.submit(download_worker, 15_000_000) for _ in range(3)]
            for f in as_completed(futs):
                pass
        t_dl_elapsed = max(0.1, time.perf_counter() - t_dl_start)
        dl_stop = True
        ping_fut.result(timeout=2)
        ping_thread.shutdown(wait=False)

        result["download_mbps"] = round((dl_bytes_total * 8) / (t_dl_elapsed * 1_000_000), 1)
        if loaded_dl_samples:
            result["loaded_dl_ping_ms"] = round(sum(loaded_dl_samples) / len(loaded_dl_samples), 1)

        # 4. Upload Throughput Test + Simultaneous Loaded Ping
        ul_bytes_total = 0
        dl_stop = False
        loaded_ul_samples = []
        ping_thread_ul = ThreadPoolExecutor(max_workers=1)
        ping_fut_ul = ping_thread_ul.submit(loaded_ping_worker, loaded_ul_samples)

        payload = b"0" * 1_000_000  # 1 MB upload block

        def upload_worker():
            nonlocal ul_bytes_total
            t_end = time.perf_counter() + (duration_target_sec * 0.45)
            while time.perf_counter() < t_end:
                req_ul = urllib.request.Request(
                    "https://speed.cloudflare.com/__up",
                    data=payload,
                    headers={**headers, "Content-Type": "application/octet-stream"},
                    method="POST"
                )
                try:
                    with urllib.request.urlopen(req_ul, timeout=5, context=ctx) as resp:
                        resp.read()
                    ul_bytes_total += len(payload)
                except Exception:
                    break

        t_ul_start = time.perf_counter()
        with ThreadPoolExecutor(max_workers=2) as ul_ex:
            futs = [ul_ex.submit(upload_worker) for _ in range(2)]
            for f in as_completed(futs):
                pass
        t_ul_elapsed = max(0.1, time.perf_counter() - t_ul_start)
        dl_stop = True
        ping_fut_ul.result(timeout=2)
        ping_thread_ul.shutdown(wait=False)

        result["upload_mbps"] = round((ul_bytes_total * 8) / (t_ul_elapsed * 1_000_000), 1)
        if loaded_ul_samples:
            result["loaded_ul_ping_ms"] = round(sum(loaded_ul_samples) / len(loaded_ul_samples), 1)

        # 5. Calculate Bufferbloat Grade
        base_ping = result["unloaded_ping_ms"] or 20.0
        loaded_pings = [p for p in (result["loaded_dl_ping_ms"], result["loaded_ul_ping_ms"]) if p is not None]
        max_loaded = max(loaded_pings) if loaded_pings else base_ping
        delta = max(0.0, round(max_loaded - base_ping, 1))
        result["bufferbloat_delta_ms"] = delta

        if delta < 5:
            result["bufferbloat_grade"] = "A+ (Zero Bufferbloat)"
        elif delta < 30:
            result["bufferbloat_grade"] = "A (Minimal Bufferbloat)"
        elif delta < 60:
            result["bufferbloat_grade"] = "B (Moderate Bufferbloat)"
        elif delta < 150:
            result["bufferbloat_grade"] = "C (Elevated Bufferbloat)"
        else:
            result["bufferbloat_grade"] = "D/F (Severe Bufferbloat - Video Calls May Drop)"

        result["status"] = "success"

    except Exception as e:
        result["error"] = str(e)

    return result


def run_lan_discovery(job_folder: str) -> list:
    """
    Perform a fast 2.5-second parallel ping sweep of the local /24 subnet to populate the Windows
    ARP cache, then capture `ipconfig /all` and `arp -a`, and write an enriched `lan_devices.csv`
    with IP, MAC, Vendor (OUI), and Hostname.
    """
    os.makedirs(job_folder, exist_ok=True)
    wifi = get_active_wifi_interface()
    ipv4 = wifi.get("ipv4", "")
    gw = wifi.get("gateway", "")

    # Save ipconfig /all
    ip_proc = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, errors="replace")
    with open(os.path.join(job_folder, "lan_ipconfig.txt"), "w", encoding="utf-8") as f:
        f.write(ip_proc.stdout)

    # Fast parallel ping sweep of /24 subnet if connected
    subnet_prefix = ""
    if ipv4 and re.match(r"^\d+\.\d+\.\d+\.\d+$", ipv4):
        parts = ipv4.split(".")
        subnet_prefix = f"{parts[0]}.{parts[1]}.{parts[2]}"
        print(f"[*] Running fast parallel LAN discovery sweep on {subnet_prefix}.1-254...")

        def quick_ping(ip):
            subprocess.run(
                ["ping", "-n", "1", "-w", "220", ip],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )

        with ThreadPoolExecutor(max_workers=64) as ex:
            list(ex.map(quick_ping, [f"{subnet_prefix}.{i}" for i in range(1, 255)]))

    # Capture arp -a
    arp_proc = subprocess.run(["arp", "-a"], capture_output=True, text=True, errors="replace")
    with open(os.path.join(job_folder, "lan_arp_table.txt"), "w", encoding="utf-8") as f:
        f.write(arp_proc.stdout)

    # Parse dynamic and relevant static unicast entries from ARP table
    devices = []
    seen_ips = set()
    for line in arp_proc.stdout.splitlines():
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\w+)", line)
        if m:
            ip_addr, mac_raw, arp_type = m.group(1), m.group(2).lower().replace("-", ":"), m.group(3).lower()
            # Skip multicast/broadcast (224.x, 239.x, 255.x, ff:ff:ff:ff:ff:ff)
            first_octet = int(ip_addr.split(".")[0])
            if first_octet >= 224 or ip_addr.endswith(".255") or mac_raw == "ff:ff:ff:ff:ff:ff":
                continue
            if ip_addr in seen_ips:
                continue
            seen_ips.add(ip_addr)

            role = "LAN Host"
            if ip_addr == gw:
                role = "Default Gateway / Router"
            elif ip_addr == ipv4:
                role = "Survey Laptop"

            devices.append({
                "ip": ip_addr,
                "mac": mac_raw,
                "vendor": lookup_oui(mac_raw),
                "type": arp_type,
                "role": role
            })

    # Sort by IP last octet
    devices.sort(key=lambda d: [int(x) for x in d["ip"].split(".")])

    csv_path = os.path.join(job_folder, "lan_devices.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["ip", "mac", "vendor", "role", "type"])
        writer.writeheader()
        writer.writerows(devices)

    print(f"[+] Discovered {len(devices)} active LAN devices -> {csv_path}")
    return devices


def main():
    parser = argparse.ArgumentParser(description="Wi-Fi & WAN Network Diagnostics (Cloudflare Speedtest, Split-Hop Ping, LAN Sweep)")
    parser.add_argument("--speedtest", action="store_true", help="Run Cloudflare Speedtest + Bufferbloat check")
    parser.add_argument("--ping", action="store_true", help="Run Gateway vs. WAN split-hop ping & jitter test")
    parser.add_argument("--lan-sweep", type=str, metavar="JOB_FOLDER", help="Run fast /24 LAN ping sweep and save enriched ARP table")
    parser.add_argument("--out-json", type=str, help="Save speedtest & ping diagnostics to JSON file")
    parser.add_argument("--waypoint", type=str, default="Baseline", help="Location label for the speedtest record")

    args = parser.parse_args()

    combined = {
        "waypoint": args.waypoint,
        "timestamp": datetime.now().isoformat(),
        "wifi_interface": get_active_wifi_interface()
    }

    w = combined["wifi_interface"]
    print(f"[*] Active Wi-Fi Link: SSID='{w['ssid']}' | BSSID={w['bssid']} ({w['band']} Ch {w['channel']}) | "
          f"RSSI={w['true_rssi_dbm']} dBm ({w['signal_pct']}%) | Tx/Rx={w['tx_rate_mbps']}/{w['rx_rate_mbps']} Mbps")

    if args.ping or args.speedtest:
        print("[*] Testing Split-Hop Latency (Local Gateway vs. Cloudflare 1.1.1.1)...")
        hop = run_split_hop_diagnostics(w.get("gateway"))
        combined["split_hop_ping"] = hop
        gw = hop["gateway"]
        wan = hop["wan"]
        print(f"    -> Local Gateway ({gw['host'] or 'N/A'}): Avg={gw['avg_ms']} ms | Jitter={gw['jitter_ms']} ms | Loss={gw['loss_pct']}%")
        print(f"    -> WAN (1.1.1.1)          : Avg={wan['avg_ms']} ms | Jitter={wan['jitter_ms']} ms | Loss={wan['loss_pct']}% | DNS={hop['dns_lookup_ms']} ms")
        print(f"    -> Diagnosis              : {hop['diagnosis']}")

    if args.speedtest:
        print("[*] Running Cloudflare Speedtest + Loaded Latency (Bufferbloat) check...")
        st = run_cloudflare_speedtest()
        combined["speedtest"] = st
        if st["status"] == "success":
            print(f"    -> Download : {st['download_mbps']} Mbps (Loaded Ping: {st['loaded_dl_ping_ms']} ms)")
            print(f"    -> Upload   : {st['upload_mbps']} Mbps (Loaded Ping: {st['loaded_ul_ping_ms']} ms)")
            print(f"    -> Unloaded : {st['unloaded_ping_ms']} ms (Jitter: {st['unloaded_jitter_ms']} ms) | Edge Colo: {st['colo']} | Public IP: {st['public_ip']}")
            print(f"    -> Bufferbloat: +{st['bufferbloat_delta_ms']} ms ({st['bufferbloat_grade']})")
        else:
            print(f"    [!] Speedtest could not reach Cloudflare: {st['error']}")

    if args.lan_sweep:
        devices = run_lan_discovery(args.lan_sweep)
        combined["lan_devices_count"] = len(devices)

    if args.out_json:
        # If file exists and is a list of speedtests, append to it
        existing = []
        if os.path.exists(args.out_json):
            try:
                with open(args.out_json, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    existing = data if isinstance(data, list) else [data]
            except Exception:
                existing = []
        existing.append(combined)
        with open(args.out_json, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)
        print(f"[+] Saved diagnostics telemetry -> {args.out_json}")


if __name__ == "__main__":
    main()
