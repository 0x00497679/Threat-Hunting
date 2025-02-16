#!/usr/bin/env python3
import sys
from scapy.all import rdpcap, Packet, Ether, LLC
from scapy.fields import ByteEnumField, ByteField, ShortField

########################################
# Custom MOP RC Layer Definition
########################################

class MOP_RC(Packet):
    """
    A minimal custom Scapy layer for MOP RC.
    
    The first 4 bytes are:
      - 1 byte: code (1 = Request, 2 = Response)
      - 1 byte: function
      - 2 bytes: reserved
    Any additional bytes after these 4 are considered payload.
    """
    name = "MOP RC"
    fields_desc = [
        ByteEnumField("code", 0, {1: "Request", 2: "Response"}),
        ByteField("function", 0),
        ShortField("reserved", 0)
    ]

########################################
# Utility Functions
########################################

def get_src_dst_mac(pkt):
    """
    Retrieve the source and destination MAC addresses from an Ethernet packet.
    """
    if pkt.haslayer(Ether):
        return pkt[Ether].src, pkt[Ether].dst
    return "N/A", "N/A"

def is_mop_rc(pkt):
    """
    Determine if a packet is likely a MOP RC packet.
    
    Heuristic:
      - The packet must have an LLC layer.
      - LLC DSAP and SSAP are typically 0x42 for DEC MOP.
      - The LLC control field is expected to be 0x03 (UI frame).
      - The LLC payload must be at least 4 bytes (for the MOP RC header).
    """
    if pkt.haslayer(LLC):
        llc = pkt[LLC]
        # Check DSAP and SSAP values; adjust these values if your environment differs.
        if llc.dsap == 0x42 and llc.ssap == 0x42 and llc.ctrl == 0x03:
            # Ensure there is enough payload for the MOP RC header.
            if llc.payload and hasattr(llc.payload, "original") and len(llc.payload.original) >= 4:
                return True
    return False

########################################
# Main Detection Logic
########################################

def main():
    if len(sys.argv) != 2:
        sys.exit("Usage: {} <pcap_file>".format(sys.argv[0]))
    
    pcap_file = sys.argv[1]
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        sys.exit("Error reading pcap file: " + str(e))
    
    print("[+] Loaded {} packets from {}".format(len(packets), pcap_file))
    mop_rc_count = 0
    
    for pkt in packets:
        if is_mop_rc(pkt):
            mop_rc_count += 1
            llc = pkt[LLC]
            # The LLC payload contains the MOP RC header (and potentially additional data)
            mop_payload = llc.payload.original
            mop_pkt = MOP_RC(mop_payload)
            src_mac, dst_mac = get_src_dst_mac(pkt)
            print("=== MOP RC Packet ===")
            print("Source MAC:      {}".format(src_mac))
            print("Destination MAC: {}".format(dst_mac))
            print("Code:            {} ({})".format(
                mop_pkt.code,
                MOP_RC.fields_desc[0].i2s.get(mop_pkt.code, "Unknown")
            ))
            print("Function:        {}".format(mop_pkt.function))
            print("Reserved:        0x{:04x}".format(mop_pkt.reserved))
            
            # Check for any additional data beyond the 4-byte header.
            if mop_pkt.payload and hasattr(mop_pkt.payload, "original") and len(mop_pkt.payload.original) > 0:
                additional_data = mop_pkt.payload.original
                print("Additional Data (hex): {}".format(additional_data.hex()))
            print("-" * 40)
    
    if mop_rc_count == 0:
        print("[-] No MOP RC packets found in the pcap file.")
    else:
        print("[+] Found {} MOP RC packet(s).".format(mop_rc_count))

if __name__ == "__main__":
    main()
