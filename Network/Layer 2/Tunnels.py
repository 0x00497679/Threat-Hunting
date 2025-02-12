#!/usr/bin/env python3
import sys
from scapy.all import rdpcap, Ether, IP, UDP, TCP

def identify_l2_tunnels(pcap_file):
    """
    Scans the given PCAP file for indications of common L2 tunneling protocols:
    - GRE (IP proto 47)
    - L2TP (UDP port 1701 or IP proto 115)
    - PPPoE (EtherType 0x8863 or 0x8864)
    - VLAN stacking (EtherType 0x88A8)
    - EtherIP (IP proto 97)
    """

    packets = rdpcap(pcap_file)
    
    # Counters for each type of potential L2 tunnel
    gre_count       = 0
    l2tp_count      = 0
    pppoe_count     = 0
    qinq_count      = 0
    etherip_count   = 0
    
    total_packets   = 0

    for pkt in packets:
        total_packets += 1
        
        # 1) Look at EtherType for PPPoE, VLAN stacking (Q-in-Q), etc.
        if Ether in pkt:
            ether_type = pkt[Ether].type
            
            # PPPoE Discovery (0x8863) or PPPoE Session (0x8864)
            if ether_type in (0x8863, 0x8864):
                pppoe_count += 1
                print(f"[PPPoE] EtherType=0x{ether_type:04X}, "
                      f"Source MAC={pkt[Ether].src}, Dest MAC={pkt[Ether].dst}")
            
            # 802.1ad Q-in-Q VLAN stacking
            if ether_type == 0x88A8:
                qinq_count += 1
                print(f"[Q-in-Q VLAN Stacking] EtherType=0x{ether_type:04X}, "
                      f"Source MAC={pkt[Ether].src}, Dest MAC={pkt[Ether].dst}")

        # 2) Look at the IP layer for GRE, L2TP, EtherIP, etc.
        if IP in pkt:
            ip_proto = pkt[IP].proto
            
            # GRE is IP protocol 47
            if ip_proto == 47:
                gre_count += 1
                print(f"[GRE] IP Proto=47, "
                      f"Source IP={pkt[IP].src}, Dest IP={pkt[IP].dst}")

            # EtherIP is IP protocol 97
            if ip_proto == 97:
                etherip_count += 1
                print(f"[EtherIP] IP Proto=97, "
                      f"Source IP={pkt[IP].src}, Dest IP={pkt[IP].dst}")

            # L2TP can be indicated by:
            # - IP protocol 115
            # - or by UDP port 1701 (though strictly speaking that’s the common port)
            if ip_proto == 115:
                l2tp_count += 1
                print(f"[L2TP] IP Proto=115, "
                      f"Source IP={pkt[IP].src}, Dest IP={pkt[IP].dst}")
            
            # Check UDP or TCP ports (commonly L2TP uses UDP/1701)
            if (UDP in pkt or TCP in pkt):
                layer_4 = pkt[UDP] if (UDP in pkt) else pkt[TCP]
                sport = layer_4.sport
                dport = layer_4.dport
                if 1701 in (sport, dport):
                    l2tp_count += 1
                    print(f"[L2TP] Detected by port 1701, "
                          f"Source IP={pkt[IP].src}:{sport}, "
                          f"Dest IP={pkt[IP].dst}:{dport}")
    
    # Summary
    print("\n--- L2 Tunneling Analysis Summary ---")
    print(f"Total packets: {total_packets}")
    print(f"GRE detections: {gre_count}")
    print(f"L2TP detections: {l2tp_count}")
    print(f"PPPoE detections: {pppoe_count}")
    print(f"Q-in-Q VLAN detections: {qinq_count}")
    print(f"EtherIP detections: {etherip_count}")

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    identify_l2_tunnels(pcap_file)

if __name__ == "__main__":
    main()
