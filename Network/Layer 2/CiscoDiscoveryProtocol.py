#!/usr/bin/env python3
import sys
from scapy.all import rdpcap
# Import the CDP layer and its TLV classes from Scapy
from scapy.layers.cdp import (
    CDP,
    CDPMsgDeviceID,
    CDPMsgAddress,
    CDPMsgPortID,
    CDPMsgCapabilities,
    CDPMsgSoftwareVersion,
    CDPMsgPlatform
)

def extract_cdp_info(pkt):
    """
    Given a packet with a CDP layer, extract relevant TLV information.
    Returns a dictionary of discovered fields.
    """
    cdp_info = {}
    cdp_layer = pkt[CDP]

    # Basic CDP header fields
    cdp_info["version"] = cdp_layer.version
    cdp_info["ttl"] = cdp_layer.ttl

    # Iterate over the TLVs in the CDP packet (if available)
    # Each TLV is an instance of a CDPMsg* class.
    if hasattr(cdp_layer, "tlvlist") and cdp_layer.tlvlist:
        for tlv in cdp_layer.tlvlist:
            # Device-ID TLV
            if tlv.__class__.__name__ == "CDPMsgDeviceID":
                cdp_info["device_id"] = tlv.val
            # Address TLV (may include one or more addresses)
            elif tlv.__class__.__name__ == "CDPMsgAddress":
                # Depending on Scapy version, addresses may be in 'addr' or 'addrs'
                addresses = None
                if hasattr(tlv, "addrs") and tlv.addrs:
                    addresses = tlv.addrs
                elif hasattr(tlv, "addr") and tlv.addr:
                    addresses = tlv.addr
                cdp_info["addresses"] = addresses
            # Port-ID TLV
            elif tlv.__class__.__name__ == "CDPMsgPortID":
                cdp_info["port_id"] = tlv.val
            # Capabilities TLV (bitmask value)
            elif tlv.__class__.__name__ == "CDPMsgCapabilities":
                cdp_info["capabilities"] = tlv.val
            # Software Version TLV
            elif tlv.__class__.__name__ == "CDPMsgSoftwareVersion":
                cdp_info["software_version"] = tlv.val
            # Platform TLV
            elif tlv.__class__.__name__ == "CDPMsgPlatform":
                cdp_info["platform"] = tlv.val
            # Additional TLVs can be added here if needed.
    return cdp_info

def main():
    if len(sys.argv) != 2:
        sys.exit(f"Usage: {sys.argv[0]} <pcap_file>")
    
    pcap_file = sys.argv[1]
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        sys.exit(f"Error reading pcap file: {e}")

    print(f"[+] Loaded {len(packets)} packets from {pcap_file}\n")

    found = False
    for pkt in packets:
        # Check if the packet has a CDP layer. CDP packets are usually sent to the
        # multicast MAC address 01:00:0c:cc:cc:cc and are sent at the data-link layer.
        if pkt.haslayer(CDP):
            found = True
            cdp_info = extract_cdp_info(pkt)
            print("=== CDP Packet ===")
            for key, value in cdp_info.items():
                print(f"{key:20s}: {value}")
            print("-" * 40)
    
    if not found:
        print("[-] No CDP packets found in the provided pcap.")

if __name__ == "__main__":
    main()
