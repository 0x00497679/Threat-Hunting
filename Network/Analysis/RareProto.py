#!/usr/bin/env python3
import sys
from scapy.all import rdpcap, Ether

def main(pcap_file):
    # Known EtherTypes (hex -> human-readable string)
    # Reference: https://en.wikipedia.org/wiki/EtherType
    known_ether_types = {
        0x0800: "IPv4",
        0x0806: "ARP",
        0x8100: "802.1Q VLAN",
        0x86DD: "IPv6",
        0x88A8: "802.1ad (Q-in-Q)",
        0x8847: "MPLS unicast",
        0x8848: "MPLS multicast",
        0x88E1: "HomePlug AV MME",
        0x88E7: "Provider Backbone Bridges (PBB)",
    }
    
    # Read the packets
    packets = rdpcap(pcap_file)

    total_eth_packets = 0
    nonstandard_count = 0

    for pkt in packets:
        # Only consider packets that actually have an Ethernet layer
        if Ether in pkt:
            total_eth_packets += 1
            ether_type = pkt[Ether].type
            
            # If not in known EtherTypes, flag it
            if ether_type not in known_ether_types:
                nonstandard_count += 1
                print(f"[!] Non-standard EtherType detected: "
                      f"0x{ether_type:04X} | "
                      f"Source MAC={pkt[Ether].src} | "
                      f"Destination MAC={pkt[Ether].dst}")
    
    # Summary
    print("\n--- Analysis Summary ---")
    print(f"Total Ethernet frames examined: {total_eth_packets}")
    print(f"Non-standard EtherTypes found: {nonstandard_count}")
    if total_eth_packets > 0:
        pct_nonstandard = (nonstandard_count / total_eth_packets) * 100
        print(f"Percentage of non-standard EtherTypes: {pct_nonstandard:.2f}%")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    main(pcap_file)
