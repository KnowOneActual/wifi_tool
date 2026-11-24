"""
Open-Source Wi-Fi Site Survey Scanner for Windows 10/11
Extracts native 2.4 GHz, 5 GHz, and 6 GHz (Wi-Fi 6E / Wi-Fi 7) telemetry via Windows
Native Wi-Fi API (`wlanapi.dll` `WlanScan` + `WlanGetNetworkBssList`) with automatic
`netsh` fallback:
- True uncapped RSSI (dBm) for every visible BSSID (no Windows -50 dBm ceiling)
- Exact frequency (MHz), Band & Primary Channel (including 6 GHz UNII-5 to UNII-8)
- Channel Width (20 / 40 / 80 / 160 / 320 MHz) from HT / VHT / HE / EHT Operation IEs
- Roaming & Security Capabilities: 802.11k / 802.11v / 802.11r / 802.11w (PMF)
- Minimum Basic Rate (Mbps) to detect legacy 802.11b (1/2 Mbps) airtime overhead
- BSS Load: Connected Stations & Channel Utilization (%)
- Hardware Vendor (OUI) & Broadcast AP Name (Cisco CCX / Aruba beacon IEs)
- Per-Waypoint Active Link Telemetry & Split-Hop Gateway vs. WAN Ping
"""

import subprocess
import ctypes
from ctypes import wintypes
import struct
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


class DOT11_SSID(ctypes.Structure):
    _fields_ = [
        ("uSSIDLength", wintypes.ULONG),
        ("ucSSID", ctypes.c_ubyte * 32),
    ]


class WLAN_RATE_SET(ctypes.Structure):
    _fields_ = [
        ("uRateSetLength", wintypes.ULONG),
        ("usRateSet", ctypes.c_ushort * 126),
    ]


class WLAN_BSS_ENTRY(ctypes.Structure):
    _fields_ = [
        ("dot11Ssid", DOT11_SSID),
        ("uPhyId", wintypes.ULONG),
        ("dot11Bssid", ctypes.c_ubyte * 6),
        ("dot11BssType", ctypes.c_uint),
        ("dot11BssPhyType", ctypes.c_uint),
        ("lRssi", ctypes.c_long),
        ("uLinkQuality", wintypes.ULONG),
        ("bInRegDomain", ctypes.c_ubyte),
        ("usBeaconPeriod", ctypes.c_ushort),
        ("ullTimestamp", ctypes.c_ulonglong),
        ("ullHostTimestamp", ctypes.c_ulonglong),
        ("usCapabilityInformation", ctypes.c_ushort),
        ("ulChCenterFrequency", wintypes.ULONG),
        ("wlanRateSet", WLAN_RATE_SET),
        ("ulIeOffset", wintypes.ULONG),
        ("ulIeSize", wintypes.ULONG),
    ]


class WLAN_BSS_LIST(ctypes.Structure):
    _fields_ = [
        ("dwTotalSize", wintypes.DWORD),
        ("dwNumberOfItems", wintypes.DWORD),
        ("wlanBssEntries", WLAN_BSS_ENTRY * 1),
    ]


PHY_TYPE_MAP = {
    1: "802.11fhss",
    2: "802.11dsss",
    3: "802.11ir",
    4: "802.11a",
    5: "802.11b",
    6: "802.11g",
    7: "802.11n",
    8: "802.11ac",
    9: "802.11ad",
    10: "802.11ax",
    11: "802.11be",
}

RADIO_RANK = {
    "802.11b": 1,
    "802.11g": 2,
    "802.11a": 2,
    "802.11n": 3,
    "802.11ac": 4,
    "802.11ax": 5,
    "802.11be": 6,
}


def freq_khz_to_band_channel(freq_khz: int) -> tuple:
    """
    Convert Windows `ulChCenterFrequency` (in kHz) to `(band_str, channel_str, freq_mhz)`.
    Supports 2.4 GHz, 5 GHz, and 6 GHz (UNII-5 through UNII-8).
    """
    if not freq_khz or freq_khz <= 0:
        return ("Unknown", "", 0)
    freq_mhz = int(round(freq_khz / 1000.0))
    if 2412 <= freq_mhz <= 2472:
        return ("2.4 GHz", str((freq_mhz - 2407) // 5), freq_mhz)
    if freq_mhz == 2484:
        return ("2.4 GHz", "14", freq_mhz)
    if 5000 < freq_mhz < 5900:
        return ("5 GHz", str((freq_mhz - 5000) // 5), freq_mhz)
    if freq_mhz == 5935:
        return ("6 GHz", "2", freq_mhz)
    if 5955 <= freq_mhz <= 7115:
        return ("6 GHz", str((freq_mhz - 5950) // 5), freq_mhz)
    return ("Unknown", "", freq_mhz)


def _clean_ascii_name(raw_bytes: bytes) -> str:
    """Decode printable ASCII AP names safely, returning empty string if binary/garbage."""
    try:
        s = raw_bytes.split(b"\x00", 1)[0].decode("ascii", errors="strict").strip()
    except Exception:
        return ""
    if 2 <= len(s) <= 32 and all(32 <= ord(ch) <= 126 for ch in s):
        return s
    return ""


def _parse_rsn_ie(payload: bytes) -> dict:
    """Parse IEEE 802.11 RSN Information Element (IE 48) for AKM, cipher, 11r, and 11w PMF."""
    out = {"akms": set(), "ciphers": set(), "pmf": "None", "has_11r": False}
    if len(payload) < 8:
        return out
    pos = 2  # skip RSN version (2 bytes)
    pos += 4  # skip group data cipher suite (4 bytes)
    if pos + 2 > len(payload):
        return out

    pairwise_cnt = struct.unpack_from("<H", payload, pos)[0]
    pos += 2
    for _ in range(pairwise_cnt):
        if pos + 4 > len(payload):
            return out
        oui = payload[pos : pos + 3]
        ctype = payload[pos + 3]
        if oui == b"\x00\x0f\xac":
            out["ciphers"].add(ctype)
        pos += 4

    if pos + 2 > len(payload):
        return out
    akm_cnt = struct.unpack_from("<H", payload, pos)[0]
    pos += 2
    for _ in range(akm_cnt):
        if pos + 4 > len(payload):
            return out
        oui = payload[pos : pos + 3]
        atype = payload[pos + 3]
        if oui == b"\x00\x0f\xac":
            out["akms"].add(atype)
            if atype in (3, 4, 9, 13):  # FT-802.1X, FT-PSK, FT-SAE, FT-802.1X-SHA384
                out["has_11r"] = True
        pos += 4

    if pos + 2 <= len(payload):
        rsn_caps = struct.unpack_from("<H", payload, pos)[0]
        mfpr = bool(rsn_caps & 0x0040)
        mfpc = bool(rsn_caps & 0x0080)
        if mfpr:
            out["pmf"] = "Required"
        elif mfpc:
            out["pmf"] = "Capable"
    return out


def parse_ie_bytes(ie_bytes: bytes, band: str = "", capability_info: int = 0) -> dict:
    """
    Parse raw 802.11 beacon/probe-response Information Elements (IEs) from `WLAN_BSS_ENTRY`.
    Extracts channel width (20/40/80/160/320 MHz), 802.11k/v/r flags, 802.11w PMF,
    security auth/cipher, BSS Load (stations & channel utilization), minimum basic rate,
    radio generation hint, and broadcast AP name (Cisco CCX / Aruba).
    """
    info = {
        "channel_width_mhz": 20,
        "ht_secondary_offset": 0,
        "has_11k": False,
        "has_11v": False,
        "has_11r": False,
        "roaming_flags": "",
        "pmf": "None",
        "min_basic_rate_mbps": None,
        "radio_hint": "",
        "ap_name": "",
        "auth": "",
        "enc": "",
    }
    if not ie_bytes:
        privacy = bool(capability_info & 0x0010)
        info["auth"] = "WEP/Private" if privacy else "Open"
        info["enc"] = "WEP" if privacy else "None"
        return info

    basic_rates = []
    rsn_info = None
    has_wpa1 = False
    wpa1_is_enterprise = False
    wpa1_ciphers = set()
    radio_hint = ""

    def bump_radio(candidate: str):
        nonlocal radio_hint
        if RADIO_RANK.get(candidate, 0) > RADIO_RANK.get(radio_hint, 0):
            radio_hint = candidate

    pos = 0
    total = len(ie_bytes)
    while pos + 2 <= total:
        eid = ie_bytes[pos]
        ln = ie_bytes[pos + 1]
        if pos + 2 + ln > total:
            break
        payload = ie_bytes[pos + 2 : pos + 2 + ln]
        pos += 2 + ln

        if eid in (1, 50):  # Supported Rates / Extended Supported Rates
            for b in payload:
                val = b & 0x7F
                # Skip BSS Membership Selectors (HT=127, VHT=126, SAE=123, HE=122, EHT=121)
                if val == 0 or val >= 120:
                    continue
                if b & 0x80:
                    basic_rates.append(val * 0.5)

        elif eid == 11 and ln >= 5:  # BSS Load
            info["stations"] = struct.unpack_from("<H", payload, 0)[0]
            cu_raw = payload[2]
            info["cu_raw"] = cu_raw
            info["cu_pct"] = int(round((cu_raw / 255.0) * 100.0))

        elif eid == 45:  # HT Capabilities
            bump_radio("802.11n")

        elif eid == 48:  # RSN (WPA2 / WPA3 / OWE / 802.11w PMF)
            rsn_info = _parse_rsn_ie(payload)
            if rsn_info["has_11r"]:
                info["has_11r"] = True
            info["pmf"] = rsn_info["pmf"]

        elif eid == 54 and ln >= 3:  # Mobility Domain (802.11r Fast BSS Transition)
            info["has_11r"] = True

        elif eid == 61 and ln >= 2:  # HT Operation
            bump_radio("802.11n")
            ht_info1 = payload[1]
            sec_offset = ht_info1 & 0x03
            sta_width = (ht_info1 >> 2) & 0x01
            if sec_offset in (1, 3) and sta_width == 1:
                info["channel_width_mhz"] = max(info["channel_width_mhz"], 40)
                info["ht_secondary_offset"] = 1 if sec_offset == 1 else -1

        elif eid == 70 and ln >= 5:  # RM Enabled Capabilities (802.11k)
            info["has_11k"] = True

        elif eid == 127 and ln >= 3:  # Extended Capabilities (802.11v BSS Transition = bit 19)
            if payload[2] & 0x08:
                info["has_11v"] = True

        elif eid == 133 and ln >= 26:  # Cisco CCX1 CKIP / AP Name
            if not info["ap_name"]:
                ap_n = _clean_ascii_name(payload[10:26])
                if ap_n:
                    info["ap_name"] = ap_n

        elif eid == 191:  # VHT Capabilities
            bump_radio("802.11ac")

        elif eid == 192 and ln >= 3:  # VHT Operation
            bump_radio("802.11ac")
            vht_cw = payload[0]
            ccfs0 = payload[1]
            ccfs1 = payload[2]
            if vht_cw == 1:
                if ccfs1 != 0 and (abs(ccfs1 - ccfs0) == 8 or abs(ccfs1 - ccfs0) > 16):
                    info["channel_width_mhz"] = max(info["channel_width_mhz"], 160)
                else:
                    info["channel_width_mhz"] = max(info["channel_width_mhz"], 80)
            elif vht_cw in (2, 3):
                info["channel_width_mhz"] = max(info["channel_width_mhz"], 160)

        elif eid == 221 and ln >= 4:  # Vendor Specific
            oui = payload[:3]
            vtype = payload[3]
            # WPA1 IE (00:50:f2, type 01)
            if oui == b"\x00\x50\xf2" and vtype == 1 and ln >= 12:
                has_wpa1 = True
                # Parse pairwise ciphers & AKM loosely
                p_pos = 10
                if p_pos + 2 <= ln:
                    pc = struct.unpack_from("<H", payload, p_pos)[0]
                    p_pos += 2
                    for _ in range(pc):
                        if p_pos + 4 <= ln:
                            wpa1_ciphers.add(payload[p_pos + 3])
                        p_pos += 4
                if p_pos + 2 <= ln:
                    ac = struct.unpack_from("<H", payload, p_pos)[0]
                    p_pos += 2
                    for _ in range(ac):
                        if p_pos + 4 <= ln and payload[p_pos + 3] == 1:
                            wpa1_is_enterprise = True
                        p_pos += 4
            # Aruba AP Name Vendor IE (00:0b:86, type 01, subtype 03)
            elif oui == b"\x00\x0b\x86" and vtype == 1 and ln >= 7 and payload[4] == 3:
                if not info["ap_name"]:
                    ap_n = _clean_ascii_name(payload[6:])
                    if ap_n:
                        info["ap_name"] = ap_n

        elif eid == 255 and ln >= 1:  # Element ID Extension (HE / EHT)
            ext_id = payload[0]
            ext_payload = payload[1:]
            if ext_id == 35:  # HE Capabilities
                bump_radio("802.11ax")
            elif ext_id == 36 and len(ext_payload) >= 6:  # HE Operation
                bump_radio("802.11ax")
                he_op_params = ext_payload[0] | (ext_payload[1] << 8) | (ext_payload[2] << 16)
                vht_op_present = bool(he_op_params & (1 << 14))
                co_hosted = bool(he_op_params & (1 << 15))
                six_ghz_present = bool(he_op_params & (1 << 17))
                if six_ghz_present:
                    off = 6 + (3 if vht_op_present else 0) + (1 if co_hosted else 0)
                    if off + 2 <= len(ext_payload):
                        ctrl_6g = ext_payload[off + 1]
                        cw_6g = {0: 20, 1: 40, 2: 80, 3: 160}.get(ctrl_6g & 0x03, 20)
                        info["channel_width_mhz"] = max(info["channel_width_mhz"], cw_6g)
            elif ext_id == 108:  # EHT Capabilities (Wi-Fi 7)
                bump_radio("802.11be")
            elif ext_id == 106 and len(ext_payload) >= 1:  # EHT Operation (Wi-Fi 7)
                bump_radio("802.11be")
                eht_op_params = ext_payload[0]
                eht_op_info_present = bool(eht_op_params & 0x01)
                if eht_op_info_present and len(ext_payload) >= 6:
                    eht_ctrl = ext_payload[5]
                    cw_eht = {0: 20, 1: 40, 2: 80, 3: 160, 4: 320}.get(eht_ctrl & 0x07, 20)
                    info["channel_width_mhz"] = max(info["channel_width_mhz"], cw_eht)

    if basic_rates:
        info["min_basic_rate_mbps"] = min(basic_rates)

    info["radio_hint"] = radio_hint

    flags = []
    if info["has_11k"]:
        flags.append("11k")
    if info["has_11v"]:
        flags.append("11v")
    if info["has_11r"]:
        flags.append("11r")
    info["roaming_flags"] = "/".join(flags)

    # Determine Authentication & Encryption labels
    if rsn_info:
        akms = rsn_info["akms"]
        ciphers = rsn_info["ciphers"]
        has_sae = bool(akms & {8, 9, 24})
        has_psk = bool(akms & {2, 4, 6})
        has_ent = bool(akms & {1, 3, 5, 11, 12, 13})
        has_owe = 18 in akms
        if has_sae and has_psk:
            info["auth"] = "WPA2/WPA3-Personal"
        elif has_sae:
            info["auth"] = "WPA3-Personal"
        elif has_owe:
            info["auth"] = "OWE"
        elif has_ent:
            info["auth"] = "WPA3-Enterprise" if bool(akms & {12, 13}) else "WPA2-Enterprise"
        elif has_psk:
            info["auth"] = "WPA2-Personal"
        else:
            info["auth"] = "WPA2/RSN"

        if 9 in ciphers:
            info["enc"] = "GCMP-256"
        elif 8 in ciphers:
            info["enc"] = "GCMP-128"
        elif 4 in ciphers:
            info["enc"] = "CCMP"
        elif 2 in ciphers:
            info["enc"] = "TKIP"
        else:
            info["enc"] = "CCMP"
    elif has_wpa1:
        info["auth"] = "WPA-Enterprise" if wpa1_is_enterprise else "WPA-Personal"
        info["enc"] = "CCMP" if 4 in wpa1_ciphers else "TKIP"
    elif capability_info & 0x0010:
        info["auth"] = "WEP"
        info["enc"] = "WEP"
    else:
        info["auth"] = "Open"
        info["enc"] = "None"

    return info


def _configure_wlanapi(wlanapi):
    """Set explicit 64-bit safe ctypes signatures on wlanapi.dll functions."""
    wlanapi.WlanOpenHandle.argtypes = [
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.HANDLE),
    ]
    wlanapi.WlanOpenHandle.restype = wintypes.DWORD

    wlanapi.WlanEnumInterfaces.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)),
    ]
    wlanapi.WlanEnumInterfaces.restype = wintypes.DWORD

    wlanapi.WlanScan.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(GUID),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    wlanapi.WlanScan.restype = wintypes.DWORD

    wlanapi.WlanGetNetworkBssList.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(GUID),
        ctypes.c_void_p,
        ctypes.c_uint,
        wintypes.BOOL,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.POINTER(WLAN_BSS_LIST)),
    ]
    wlanapi.WlanGetNetworkBssList.restype = wintypes.DWORD

    wlanapi.WlanFreeMemory.argtypes = [ctypes.c_void_p]
    wlanapi.WlanFreeMemory.restype = None

    wlanapi.WlanCloseHandle.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    wlanapi.WlanCloseHandle.restype = wintypes.DWORD


def force_wlan_scan(wait_seconds: float = 3.0) -> bool:
    """
    Trigger a live hardware RF scan across all bands using Windows wlanapi.dll (WlanScan)
    so subsequent BSS reads return fresh beacon data instead of stale cached entries.
    """
    client_handle = wintypes.HANDLE()
    p_iface_list = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)()
    wlanapi = None
    try:
        wlanapi = ctypes.windll.LoadLibrary("wlanapi.dll")
        _configure_wlanapi(wlanapi)

        negotiated_version = wintypes.DWORD()
        res = wlanapi.WlanOpenHandle(
            wintypes.DWORD(2), None, ctypes.byref(negotiated_version), ctypes.byref(client_handle)
        )
        if res != 0:
            return False

        res = wlanapi.WlanEnumInterfaces(client_handle, None, ctypes.byref(p_iface_list))
        if res != 0 or not p_iface_list:
            return False

        num_items = p_iface_list.contents.dwNumberOfItems
        if num_items == 0:
            return False
        iface_array_type = WLAN_INTERFACE_INFO * num_items
        iface_array = ctypes.cast(
            ctypes.byref(p_iface_list.contents.InterfaceInfo),
            ctypes.POINTER(iface_array_type),
        ).contents

        triggered = False
        for i in range(num_items):
            guid = iface_array[i].InterfaceGuid
            scan_res = wlanapi.WlanScan(client_handle, ctypes.byref(guid), None, None, None)
            if scan_res == 0:
                triggered = True

        if triggered and wait_seconds > 0:
            time.sleep(wait_seconds)
        return triggered
    except Exception:
        return False
    finally:
        if wlanapi is not None:
            if p_iface_list:
                try:
                    wlanapi.WlanFreeMemory(p_iface_list)
                except Exception:
                    pass
            if client_handle and client_handle.value:
                try:
                    wlanapi.WlanCloseHandle(client_handle, None)
                except Exception:
                    pass


def run_native_wlan_scan(live_refresh: bool = True, wait_seconds: float = 2.8) -> list:
    """
    Scan all visible BSSIDs via Windows Native Wi-Fi API (`WlanScan` + `WlanGetNetworkBssList`).
    Returns uncapped true `lRssi` (dBm), exact center frequency, channel width (20/40/80/160/320 MHz),
    802.11k/v/r roaming flags, 802.11w PMF, minimum basic rate, BSS Load, and vendor AP names.
    """
    client_handle = wintypes.HANDLE()
    p_iface_list = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)()
    wlanapi = None
    networks = []
    seen = {}

    try:
        wlanapi = ctypes.windll.LoadLibrary("wlanapi.dll")
        _configure_wlanapi(wlanapi)

        negotiated_version = wintypes.DWORD()
        if wlanapi.WlanOpenHandle(wintypes.DWORD(2), None, ctypes.byref(negotiated_version), ctypes.byref(client_handle)) != 0:
            return []

        if wlanapi.WlanEnumInterfaces(client_handle, None, ctypes.byref(p_iface_list)) != 0 or not p_iface_list:
            return []

        num_ifaces = p_iface_list.contents.dwNumberOfItems
        if num_ifaces == 0:
            return []

        iface_array = ctypes.cast(
            ctypes.byref(p_iface_list.contents.InterfaceInfo),
            ctypes.POINTER(WLAN_INTERFACE_INFO * num_ifaces),
        ).contents

        if live_refresh:
            triggered = False
            for i in range(num_ifaces):
                guid = iface_array[i].InterfaceGuid
                if wlanapi.WlanScan(client_handle, ctypes.byref(guid), None, None, None) == 0:
                    triggered = True
            if triggered and wait_seconds > 0:
                time.sleep(wait_seconds)

        scan_ts = datetime.now().isoformat()
        for i in range(num_ifaces):
            guid = iface_array[i].InterfaceGuid
            p_bss_list = ctypes.POINTER(WLAN_BSS_LIST)()
            try:
                # dot11_BSS_type_any = 3
                res = wlanapi.WlanGetNetworkBssList(
                    client_handle, ctypes.byref(guid), None, 3, False, None, ctypes.byref(p_bss_list)
                )
                if res != 0 or not p_bss_list:
                    continue

                n_items = p_bss_list.contents.dwNumberOfItems
                if n_items == 0:
                    continue

                entries = ctypes.cast(
                    ctypes.byref(p_bss_list.contents.wlanBssEntries),
                    ctypes.POINTER(WLAN_BSS_ENTRY * n_items),
                ).contents

                for idx in range(n_items):
                    e = entries[idx]
                    ssid_len = min(int(e.dot11Ssid.uSSIDLength), 32)
                    raw_ssid = bytes(e.dot11Ssid.ucSSID[:ssid_len])
                    ssid = raw_ssid.decode("utf-8", errors="replace").strip("\x00").strip()
                    if not ssid:
                        ssid = "<Hidden / Broadcast>"

                    bssid = ":".join(f"{b:02x}" for b in e.dot11Bssid)
                    band, ch_str, freq_mhz = freq_khz_to_band_channel(int(e.ulChCenterFrequency))

                    ie_bytes = b""
                    if e.ulIeSize > 0 and e.ulIeOffset >= ctypes.sizeof(WLAN_BSS_ENTRY):
                        ie_addr = ctypes.addressof(e) + int(e.ulIeOffset)
                        ie_bytes = ctypes.string_at(ie_addr, int(e.ulIeSize))

                    ie_info = parse_ie_bytes(ie_bytes, band=band, capability_info=int(e.usCapabilityInformation))

                    phy_radio = PHY_TYPE_MAP.get(int(e.dot11BssPhyType), "")
                    hint_radio = ie_info.get("radio_hint", "")
                    if RADIO_RANK.get(hint_radio, 0) >= RADIO_RANK.get(phy_radio, 0) and hint_radio:
                        radio_type = hint_radio
                    else:
                        radio_type = phy_radio or ("802.11a" if band == "5 GHz" else "802.11g")

                    rec = {
                        "ssid": ssid,
                        "bssid": bssid,
                        "vendor": lookup_oui(bssid),
                        "auth": ie_info["auth"],
                        "enc": ie_info["enc"],
                        "band": band,
                        "channel": ch_str,
                        "freq_mhz": freq_mhz,
                        "channel_width_mhz": ie_info["channel_width_mhz"],
                        "radio_type": radio_type,
                        "signal_dbm": int(e.lRssi),
                        "signal_pct": int(e.uLinkQuality),
                        "roaming_flags": ie_info["roaming_flags"],
                        "pmf": ie_info["pmf"],
                        "min_basic_rate_mbps": ie_info["min_basic_rate_mbps"],
                        "ap_name": ie_info["ap_name"],
                        "timestamp": scan_ts,
                    }
                    if "cu_pct" in ie_info:
                        rec["cu_raw"] = ie_info["cu_raw"]
                        rec["cu_pct"] = ie_info["cu_pct"]
                    if "stations" in ie_info:
                        rec["stations"] = ie_info["stations"]

                    dedupe_key = (bssid, ssid)
                    prev = seen.get(dedupe_key)
                    if prev is None or rec["signal_dbm"] > prev["signal_dbm"]:
                        seen[dedupe_key] = rec
            finally:
                if p_bss_list:
                    try:
                        wlanapi.WlanFreeMemory(p_bss_list)
                    except Exception:
                        pass

        networks = list(seen.values())
        return networks
    except Exception:
        return []
    finally:
        if wlanapi is not None:
            if p_iface_list:
                try:
                    wlanapi.WlanFreeMemory(p_iface_list)
                except Exception:
                    pass
            if client_handle and client_handle.value:
                try:
                    wlanapi.WlanCloseHandle(client_handle, None)
                except Exception:
                    pass


def _run_netsh_fallback(live_refresh: bool = True) -> list:
    """Fallback RF scan via `netsh wlan show networks mode=bssid` if native API is unavailable."""
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
                    "channel_width_mhz": "",
                    "roaming_flags": "",
                    "pmf": "",
                    "min_basic_rate_mbps": "",
                    "ap_name": "",
                    "freq_mhz": "",
                    "timestamp": datetime.now().isoformat(),
                }
        elif current_bssid:
            if l.startswith("Signal"):
                m = re.search(r"(\d+)%", l)
                if m:
                    pct = int(m.group(1))
                    bssid_data["signal_pct"] = pct
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


def run_netsh_scan(live_refresh: bool = True):
    """
    Perform a live RF scan across all bands.
    Uses Windows Native Wi-Fi API (`WlanGetNetworkBssList`) for true uncapped dBm,
    channel width, and 802.11k/v/r/w IEs, falling back to `netsh` if unavailable.
    """
    native_nets = run_native_wlan_scan(live_refresh=live_refresh)
    if native_nets:
        return native_nets
    return _run_netsh_fallback(live_refresh=False)


run_rf_scan = run_netsh_scan


def print_scan_table(networks, filter_ssid=None):
    if filter_ssid:
        networks = [n for n in networks if filter_ssid.lower() in n.get("ssid", "").lower()]

    # Sort by Signal dBm descending
    networks.sort(key=lambda x: x.get("signal_dbm", -100), reverse=True)

    print("\n" + "=" * 134)
    print(
        f"{'SSID':24} | {'BSSID':17} | {'Band':7} | {'Ch':4} | {'Width':5} | {'Radio':8} | "
        f"{'RSSI':15} | {'Util':5} | {'STAs':4} | {'11k/v/r':11} | {'Security'}"
    )
    print("=" * 134)

    for n in networks:
        ssid = n.get("ssid", "")[:24]
        bssid = n.get("bssid", "")
        band = n.get("band", "")[:7]
        ch = str(n.get("channel", ""))[:4]
        cw_val = n.get("channel_width_mhz", "")
        cw = f"{cw_val}M" if cw_val else "-"
        radio = n.get("radio_type", "")[:8]
        sig_pct = n.get("signal_pct", 0)
        sig_dbm = n.get("signal_dbm", -100)
        rssi_str = f"{sig_dbm} dBm ({sig_pct}%)"
        cu = f"{n.get('cu_pct')}%" if "cu_pct" in n else "N/A"
        stas = str(n.get("stations", "-"))
        roam = (n.get("roaming_flags", "") or "-")[:11]
        sec = f"{n.get('auth', '')}/{n.get('enc', '')}"

        print(
            f"{ssid:24} | {bssid:17} | {band:7} | {ch:>4} | {cw:>5} | {radio:8} | "
            f"{rssi_str:15} | {cu:>5} | {stas:>4} | {roam:11} | {sec}"
        )
    print("=" * 134)
    print(f"Total Detected BSSIDs: {len(networks)} | Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")


def _get_existing_csv_headers(path: str):
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return None
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
            reader = csv.reader(f)
            row = next(reader, None)
            if row and row[0].strip().lower() == "timestamp":
                return [c.strip() for c in row]
    except Exception:
        pass
    return None


def _next_waypoint_id(telemetry_file: str, log_file: str) -> int:
    """Compute the next sequential waypoint_id so duplicate room names stay distinct."""
    max_id = 0
    for path in (telemetry_file, log_file):
        if os.path.exists(path) and os.path.getsize(path) > 0:
            try:
                with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
                    rows = list(csv.DictReader(f))
                for r in rows:
                    wid = str(r.get("waypoint_id", "")).strip()
                    if wid.isdigit():
                        max_id = max(max_id, int(wid))
                if max_id == 0 and path == telemetry_file:
                    max_id = len(rows)
            except Exception:
                pass
    return max_id + 1


def record_waypoint(waypoint_name, target_ssid=None, log_file="survey_log.csv", run_speedtest=False):
    # Support trailing '*' on waypoint name as a shortcut to trigger a room speedtest
    clean_waypoint = waypoint_name.strip()
    if clean_waypoint.endswith("*"):
        run_speedtest = True
        clean_waypoint = clean_waypoint[:-1].strip()

    job_dir = os.path.dirname(os.path.abspath(log_file))
    telemetry_file = os.path.join(job_dir, "waypoint_telemetry.csv")
    waypoint_id = _next_waypoint_id(telemetry_file, log_file)

    print(f"    [*] Triggering live hardware Wi-Fi scan at '{clean_waypoint}' (Waypoint #{waypoint_id})...")
    networks = run_netsh_scan(live_refresh=True)
    if target_ssid:
        networks = [n for n in networks if target_ssid.lower() in n.get("ssid", "").lower()]

    if not networks:
        print(f"    [!] No networks detected matching '{target_ssid or 'any'}' at '{clean_waypoint}' (Logging as Dead Zone).")
        networks = [{
            "timestamp": datetime.now().isoformat(),
            "ssid": target_ssid or "<Dead Zone>",
            "bssid": "",
            "band": "None",
            "channel": "",
            "radio_type": "",
            "signal_dbm": -100,
            "signal_pct": 0,
            "cu_pct": "",
            "stations": "",
            "auth": "",
            "enc": "",
            "channel_width_mhz": "",
            "roaming_flags": "",
            "pmf": "",
            "min_basic_rate_mbps": "",
            "ap_name": "",
            "freq_mhz": "",
        }]

    existing_headers = _get_existing_csv_headers(log_file)
    default_fieldnames = [
        "timestamp", "waypoint", "ssid", "bssid", "band", "channel",
        "radio_type", "signal_dbm", "signal_pct", "cu_pct", "stations", "auth", "enc",
        "waypoint_id", "channel_width_mhz", "roaming_flags", "pmf",
        "min_basic_rate_mbps", "ap_name", "freq_mhz"
    ]
    fieldnames = existing_headers if existing_headers else default_fieldnames
    file_exists = os.path.exists(log_file) and os.path.getsize(log_file) > 0
    with open(log_file, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        if not file_exists:
            writer.writeheader()

        for n in networks:
            mbr = n.get("min_basic_rate_mbps")
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
                "enc": n.get("enc", ""),
                "waypoint_id": waypoint_id,
                "channel_width_mhz": n.get("channel_width_mhz", ""),
                "roaming_flags": n.get("roaming_flags", ""),
                "pmf": n.get("pmf", ""),
                "min_basic_rate_mbps": "" if mbr is None else mbr,
                "ap_name": n.get("ap_name", ""),
                "freq_mhz": n.get("freq_mhz", ""),
            })

    print(f"    [+] Recorded {len(networks)} BSSID records for '{clean_waypoint}' -> {os.path.basename(log_file)}")

    # Capture active connection link telemetry + split-hop Gateway vs. WAN latency
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
                "waypoint_id": waypoint_id,
                "timestamp": datetime.now().isoformat(),
                "wifi_interface": wifi_link,
                "split_hop_ping": hop,
                "speedtest": st
            })
            with open(st_json_path, "w", encoding="utf-8") as sf:
                json.dump(existing, sf, indent=2)

    tel_existing_headers = _get_existing_csv_headers(telemetry_file)
    default_tel_fields = [
        "timestamp", "waypoint", "connected_ssid", "connected_bssid", "connected_band",
        "connected_channel", "radio_type", "true_rssi_dbm", "signal_pct",
        "tx_rate_mbps", "rx_rate_mbps", "gateway_ip", "gw_avg_ms", "gw_jitter_ms", "gw_loss_pct",
        "wan_avg_ms", "wan_jitter_ms", "wan_loss_pct", "dns_ms", "diagnosis",
        "download_mbps", "upload_mbps", "bufferbloat_grade", "waypoint_id"
    ]
    tel_fields = tel_existing_headers if tel_existing_headers else default_tel_fields
    tel_exists = os.path.exists(telemetry_file) and os.path.getsize(telemetry_file) > 0
    with open(telemetry_file, "a", newline="", encoding="utf-8") as tf:
        tw = csv.DictWriter(tf, fieldnames=tel_fields, extrasaction="ignore")
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
            "bufferbloat_grade": bb_grade,
            "waypoint_id": waypoint_id
        })


def main():
    parser = argparse.ArgumentParser(description="Open-Source Wi-Fi Site Surveyor for Windows 10/11")
    parser.add_argument("--scan", action="store_true", help="Perform a one-time live RF survey scan")
    parser.add_argument("--ssid", type=str, help="Filter results by SSID (e.g. OfficeWiFi)")
    parser.add_argument("--waypoint", type=str, help="Record scan data for a specific site location (append * to also run speedtest)")
    parser.add_argument("--speedtest", action="store_true", help="Also run a Cloudflare speedtest at this waypoint")
    parser.add_argument("--out", type=str, default="survey_log.csv", help="CSV log filename (default: survey_log.csv)")
    parser.add_argument("--json", action="store_true", help="Output raw scan data as JSON")
    parser.add_argument("--save-json", type=str, help="Also save structured JSON scan data to this file path")

    args = parser.parse_args()

    if args.waypoint:
        record_waypoint(args.waypoint, target_ssid=args.ssid, log_file=args.out, run_speedtest=args.speedtest)
    elif args.json:
        nets = run_netsh_scan(live_refresh=True)
        if args.ssid:
            nets = [n for n in nets if args.ssid.lower() in n.get("ssid", "").lower()]
        if args.save_json:
            with open(args.save_json, "w", encoding="utf-8") as jf:
                json.dump(nets, jf, indent=2)
        print(json.dumps(nets, indent=2))
    else:
        nets = run_netsh_scan(live_refresh=True)
        if args.save_json:
            filtered = [n for n in nets if args.ssid.lower() in n.get("ssid", "").lower()] if args.ssid else nets
            with open(args.save_json, "w", encoding="utf-8") as jf:
                json.dump(filtered, jf, indent=2)
        print_scan_table(nets, filter_ssid=args.ssid)


if __name__ == "__main__":
    main()
