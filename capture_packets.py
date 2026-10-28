"""
Open-Source Wi-Fi RF & Network Packet Capture Tool (TShark Wrapper)
Automatically detects the active Windows Wi-Fi interface (instead of hardcoded interface indices)
and captures traffic into a standardized .pcapng capture file.
"""

import subprocess
import os
import re
import sys
import shutil
import argparse
from datetime import datetime

TSHARK_DEFAULT = r"C:\Program Files\Wireshark\tshark.exe"


def resolve_tshark_path(tshark_path=TSHARK_DEFAULT) -> str:
    """Locate tshark.exe across standard install paths or system PATH."""
    if tshark_path and os.path.exists(tshark_path):
        return tshark_path
    which_path = shutil.which("tshark")
    if which_path:
        return which_path
    alt_path = r"C:\Program Files (x86)\Wireshark\tshark.exe"
    if os.path.exists(alt_path):
        return alt_path
    return tshark_path


def list_interfaces(tshark_path=TSHARK_DEFAULT):
    tshark_bin = resolve_tshark_path(tshark_path)
    if not os.path.exists(tshark_bin):
        print(f"Error: TShark not found at '{tshark_bin}'.")
        return ""
    cmd = [tshark_bin, "-D"]
    res = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    print("Available Capture Interfaces:")
    print(res.stdout)
    return res.stdout


def detect_wifi_interface(tshark_path=TSHARK_DEFAULT, fallback="Wi-Fi"):
    """Auto-detect the TShark interface index or name corresponding to 'Wi-Fi'."""
    tshark_bin = resolve_tshark_path(tshark_path)
    if not os.path.exists(tshark_bin):
        return fallback
    res = subprocess.run([tshark_bin, "-D"], capture_output=True, text=True, errors="replace")
    if res.returncode == 0:
        candidates = []
        for line in res.stdout.splitlines():
            # Example line: 5. \Device\NPF_{GUID} (Wi-Fi)
            m = re.match(r"^(\d+)\.\s+.*\((.*)\)", line.strip())
            if m:
                idx, friendly = m.group(1), m.group(2).strip()
                fl = friendly.lower()
                if fl == "wi-fi":
                    return idx
                if ("wi-fi" in fl or "wireless" in fl or "wlan" in fl) and "local area connection*" not in fl:
                    candidates.append(idx)
        if candidates:
            return candidates[0]
    return fallback


def capture_wifi_traffic(interface_num, duration_sec, output_pcap, tshark_path=TSHARK_DEFAULT):
    tshark_bin = resolve_tshark_path(tshark_path)
    if not os.path.exists(tshark_bin):
        print(f"Error: TShark not found at '{tshark_bin}'. Please install Wireshark.")
        return

    if str(interface_num).lower() in ("auto", "wi-fi", "2"):
        detected = detect_wifi_interface(tshark_bin, fallback=str(interface_num))
        interface_num = detected

    print(f"[*] Starting {duration_sec}s Wi-Fi packet capture on interface '{interface_num}'...")
    print(f"[*] Saving capture into '{output_pcap}'...")

    cmd = [
        tshark_bin,
        "-i", str(interface_num),
        "-a", f"duration:{duration_sec}",
        "-w", output_pcap
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
        if proc.returncode == 0:
            file_size = os.path.getsize(output_pcap) if os.path.exists(output_pcap) else 0
            print(f"[+] Capture completed successfully!")
            print(f"[+] Output: {output_pcap} ({file_size:,} bytes)")
        else:
            print(f"[-] Capture failed: {proc.stderr}")
    except KeyboardInterrupt:
        print("\n[!] Capture stopped by user.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Open-Source Wi-Fi Packet Capturer")
    parser.add_argument("-D", "--list-interfaces", action="store_true", help="List available capture interfaces")
    parser.add_argument("-i", "--interface", type=str, default="auto", help="Interface index or 'auto' (default: auto-detect Wi-Fi)")
    parser.add_argument("-d", "--duration", type=int, default=30, help="Capture duration in seconds (default: 30)")
    parser.add_argument("-o", "--output", type=str, default=None, help="Output .pcapng file path")

    args = parser.parse_args()

    if args.list_interfaces:
        list_interfaces()
    else:
        out = args.output or f"wifi_survey_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcapng"
        capture_wifi_traffic(args.interface, args.duration, out)
