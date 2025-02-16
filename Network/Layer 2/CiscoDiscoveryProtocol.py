#!/usr/bin/env python3
import sys
import glob
import re
from scapy.all import rdpcap, load_contrib, LLC, SNAP, bind_layers

# Load the CDP contrib module; this registers the "CDP" layer.
load_contrib("cdp")

from scapy.contrib import cdp
CDP = cdp.CDPv2_HDR

# Bind CDP to LLC/SNAP frames using standard values:
# LLC: DSAP = 0xAA, SSAP = 0xAA, ctrl = 0x03
# SNAP: OUI = 00:00:0C, code = 0x2000
bind_layers(LLC, CDP, dsap=0xaa, ssap=0xaa, ctrl=0x03)
bind_layers(SNAP, CDP, OUI=b'\x00\x00\x0c', code=0x2000)

def manual_parse_tlvs(raw_bytes):
    """
    Manually parse TLVs from raw_bytes.
    Cisco CDP TLVs are formatted as:
      - Type: 2 bytes (big-endian)
      - Length: 2 bytes (big-endian, including the 4-byte header)
      - Value: (Length - 4) bytes
    Returns a dictionary mapping TLV type (as an integer) to a decoded ASCII string.
    """
    tlvs = {}
    offset = 0
    while offset + 4 <= len(raw_bytes):
        tlv_type = int.from_bytes(raw_bytes[offset:offset+2], byteorder="big")
        tlv_len = int.from_bytes(raw_bytes[offset+2:offset+4], byteorder="big")
        if tlv_len < 4 or offset + tlv_len > len(raw_bytes):
            break
        value_bytes = raw_bytes[offset+4:offset+tlv_len]
        try:
            value = value_bytes.decode("ascii", errors="ignore").strip()
        except Exception:
            value = value_bytes.hex()
        tlvs[tlv_type] = value
        offset += tlv_len
    return tlvs

def extract_cdp_info(pkt):
    """
    Extract relevant CDP information from a packet.
    Also parse the software version string to extract:
      - Cisco IOS version (e.g., "12.1(22)EA14")
      - Copyright years (e.g., "1986", "2010")
    This function always manually parses TLVs from the raw bytes.
    Returns a dictionary with the extracted fields.
    """
    cdp_layer = pkt.getlayer(CDP)
    if cdp_layer is None:
        return None

    info = {}
    raw = bytes(cdp_layer)
    if len(raw) < 4:
        return None

    # Extract basic header: first byte is version, second is ttl.
    info["version"] = raw[0]
    info["ttl"] = raw[1]

    # Manually parse TLVs from the raw payload after the 4-byte header.
    raw_payload = raw[4:]
    tlvs = manual_parse_tlvs(raw_payload)

    # Cisco CDP TLV types:
    #   1: Device-ID, 3: Port-ID, 4: Capabilities,
    #   5: Software Version, 6: Platform
    if 1 in tlvs:
        info["device_id"] = tlvs[1]
    if 3 in tlvs:
        info["port_id"] = tlvs[3]
    if 4 in tlvs:
        info["capabilities"] = tlvs[4]
    if 5 in tlvs:
        info["software_version"] = tlvs[5]
    if 6 in tlvs:
        info["platform"] = tlvs[6]

    # If a software version string is present, extract IOS version and copyright years.
    if "software_version" in info:
        sw_text = info["software_version"]
        version_match = re.search(r"Version\s+([\d\.\(\)A-Za-z]+)", sw_text)
        info["ios_version"] = version_match.group(1) if version_match else "Not found"
        years = re.findall(r"\b(?:19|20)\d{2}\b", sw_text)
        info["copyright_years"] = years if years else "Not found"

    return info

def process_file(pcap_file):
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error reading {pcap_file}: {e}")
        return

    print(f"\n[+] Processing file: {pcap_file}")
    print(f"[+] Loaded {len(packets)} packets from {pcap_file}")

    found = False
    for pkt in packets:
        if pkt.haslayer(CDP):
            found = True
            info = extract_cdp_info(pkt)
            if info is None:
                continue
            print("=== CDP Packet ===")
            for key, value in info.items():
                print(f"{key:20s}: {value}")
            print("-" * 40)
    if not found:
        print("[-] No CDP packets found in this file.")

def main():
    if len(sys.argv) != 2:
        sys.exit(f"Usage: {sys.argv[0]} <pcap_file_pattern>")
    
    pattern = sys.argv[1]
    files = glob.glob(pattern)
    if not files:
        sys.exit(f"No files found matching pattern: {pattern}")
    
    for pcap_file in files:
        process_file(pcap_file)

if __name__ == "__main__":
    main()

