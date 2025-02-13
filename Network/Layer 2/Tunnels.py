#!/usr/bin/env python3
import sys
import json
import csv
import argparse
from scapy.all import sniff, Ether, IP, UDP, TCP, Raw
from scapy.layers.inet import GRE
# Some advanced protocols might be in scapy.contrib.*
# For deeper L2TP, NVGRE, GENEVE, you might need to:
#   from scapy.contrib.l2tp import L2TP
#   from scapy.contrib.nvgree import NVGRE
# etc.

def parse_args():
    parser = argparse.ArgumentParser(
        description="Detect common Layer 2 tunneling protocols in a PCAP file."
    )
    parser.add_argument("-i", "--input", required=True,
                        help="Path to the PCAP file.")
    parser.add_argument("--filter", default=None,
                        help="Optional BPF filter to limit packets (e.g. 'udp port 4789').")
    parser.add_argument("--output", action="append", choices=["csv", "json"],
                        help="Choose output format(s). Can be specified multiple times.")
    parser.add_argument("--outfile", default=None,
                        help="Output filename (if not specified, uses 'detections.csv' or 'detections.json').")
    
    return parser.parse_args()


def detect_gre_details(pkt):
    """
    Attempt to distinguish GRE bridging vs routing:
      - If next layer is Ether, it might be bridging GRE (layer 2).
      - If next layer is IP, it might be routed GRE (layer 3).
    """
    # Look for Ether or IP after GRE
    if pkt.haslayer(Ether):
        return "GRE (Ethernet over GRE - bridging)"
    elif pkt.haslayer(IP):
        return "GRE (IP over GRE - routing)"
    else:
        return "GRE (undetermined payload)"


def detect_l2tp_details(pkt):
    """
    Attempt to see if the L2TP tunnel is carrying PPP/Ether or IP.
    Since scapy may not dissect L2TP automatically, this is a best-effort approach.
    """
    # If the payload after UDP or L2TP is Ethernet => bridging
    # If it's IP => likely routing
    # This is heuristic; actual L2TP dissection might need scapy.contrib.l2tp
    if pkt.haslayer(Ether):
        return "L2TP (Ethernet bridging)"
    elif pkt.haslayer(IP):
        return "L2TP (IP routing)"
    else:
        return "L2TP (undetermined payload)"


def detect_nvgre(pkt):
    """
    NVGRE is a variant of GRE with a specific GRE key indicating a VSID (virtual subnet ID).
    This often requires scapy.contrib.nvgree for full parse.
    Here, we just label it if we see GRE with certain flags or key field set.
    """
    # Minimal stub — real NVGRE detection would parse the GRE flags and key.
    return "NVGRE (GRE variant with potential virtualization)"


def identify_l2_tunnels(packets):
    """
    Scans packets for a variety of L2 tunneling protocols.
    Returns a list of detections with relevant info.
    """
    detections = []

    for pkt in packets:
        # Simplify references
        ether = pkt[Ether] if Ether in pkt else None
        ip    = pkt[IP] if IP in pkt else None

        # 1) Ether-based checks
        if ether:
            ether_type = ether.type
            # PPPoE Discovery (0x8863) or PPPoE Session (0x8864)
            if ether_type in (0x8863, 0x8864):
                detections.append({
                    "protocol" : "PPPoE",
                    "detail"   : f"EtherType=0x{ether_type:04X}",
                    "src_mac"  : ether.src,
                    "dst_mac"  : ether.dst
                })
            # 802.1ad Q-in-Q VLAN stacking (EtherType=0x88A8)
            if ether_type == 0x88A8:
                detections.append({
                    "protocol" : "Q-in-Q VLAN",
                    "detail"   : "EtherType=0x88A8",
                    "src_mac"  : ether.src,
                    "dst_mac"  : ether.dst
                })
            # EoMPLS: EtherType 0x8847 (MPLS unicast) or 0x8848 (MPLS multicast)
            if ether_type in (0x8847, 0x8848):
                detections.append({
                    "protocol" : "EoMPLS (possible MPLS-based L2 tunnel)",
                    "detail"   : f"EtherType=0x{ether_type:04X}",
                    "src_mac"  : ether.src,
                    "dst_mac"  : ether.dst
                })

        # 2) IP-based checks
        if ip:
            ip_proto = ip.proto

            # GRE is IP protocol 47
            if ip_proto == 47 and pkt.haslayer(GRE):
                gre_info = detect_gre_details(pkt)
                # Check if it might be NVGRE by analyzing flags/keys, etc.
                # For demonstration, let's do a naive check:
                # (A real NVGRE detection would parse GRE fields carefully.)
                if "NVGRE" in detect_nvgre(pkt):
                    # This is a naive approach: just label if we suspect NVGRE
                    detections.append({
                        "protocol" : "NVGRE",
                        "detail"   : detect_nvgre(pkt),
                        "src_ip"   : ip.src,
                        "dst_ip"   : ip.dst
                    })
                else:
                    detections.append({
                        "protocol" : "GRE",
                        "detail"   : gre_info,
                        "src_ip"   : ip.src,
                        "dst_ip"   : ip.dst
                    })

            # EtherIP is IP protocol 97
            if ip_proto == 97:
                detections.append({
                    "protocol" : "EtherIP",
                    "detail"   : "IP proto=97 (EtherIP)",
                    "src_ip"   : ip.src,
                    "dst_ip"   : ip.dst
                })

            # L2TP can be indicated by IP proto 115 or UDP port 1701
            if ip_proto == 115:
                l2tp_info = detect_l2tp_details(pkt)
                detections.append({
                    "protocol" : "L2TP",
                    "detail"   : l2tp_info + " (IP proto=115)",
                    "src_ip"   : ip.src,
                    "dst_ip"   : ip.dst
                })

            if UDP in pkt or TCP in pkt:
                layer_4 = pkt[UDP] if (UDP in pkt) else pkt[TCP]
                sport = layer_4.sport
                dport = layer_4.dport

                # L2TP (UDP/1701)
                if 1701 in (sport, dport):
                    l2tp_info = detect_l2tp_details(pkt)
                    detections.append({
                        "protocol" : "L2TP",
                        "detail"   : l2tp_info + " (UDP port 1701)",
                        "src_ip"   : ip.src,
                        "dst_ip"   : ip.dst,
                        "src_port" : sport,
                        "dst_port" : dport
                    })

                # VXLAN: UDP/4789
                if 4789 in (sport, dport):
                    detections.append({
                        "protocol" : "VXLAN",
                        "detail"   : "UDP port 4789",
                        "src_ip"   : ip.src,
                        "dst_ip"   : ip.dst,
                        "src_port" : sport,
                        "dst_port" : dport
                    })

                # GENEVE: UDP/6081
                if 6081 in (sport, dport):
                    detections.append({
                        "protocol" : "GENEVE",
                        "detail"   : "UDP port 6081",
                        "src_ip"   : ip.src,
                        "dst_ip"   : ip.dst,
                        "src_port" : sport,
                        "dst_port" : dport
                    })

    return detections


def write_csv(detections, outfile):
    """
    Write detections to CSV.
    """
    # Collect all field names from the union of detection keys
    fieldnames = set()
    for det in detections:
        fieldnames.update(det.keys())
    fieldnames = list(fieldnames)

    with open(outfile, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(detections)


def write_json(detections, outfile):
    """
    Write detections to JSON.
    """
    with open(outfile, 'w', encoding='utf-8') as f:
        json.dump(detections, f, indent=4)


def main():
    args = parse_args()

    # Read the PCAP with optional BPF filter
    if args.filter:
        packets = sniff(offline=args.input, filter=args.filter)
    else:
        packets = sniff(offline=args.input)

    print(f"Loaded {len(packets)} packets from {args.input} (BPF filter: {args.filter or 'none'})")

    # Detect L2 tunneling
    detections = identify_l2_tunnels(packets)
    
    # Print summary
    print("\n--- L2 Tunneling Analysis Summary ---")
    print(f"Total packets processed: {len(packets)}")
    print(f"Number of potential L2 tunnel detections: {len(detections)}")

    # Print a short preview of detections to screen
    if detections:
        print("\nSample of detections:")
        for det in detections[:10]:  # show only first 10 for brevity
            print(det)
    else:
        print("No L2 tunneling detected based on known signatures.")

    # Output to CSV or JSON if requested
    if args.output:
        for fmt in args.output:
            if fmt == "csv":
                csv_outfile = args.outfile or "detections.csv"
                write_csv(detections, csv_outfile)
                print(f"[+] Wrote CSV output to: {csv_outfile}")
            elif fmt == "json":
                json_outfile = args.outfile or "detections.json"
                write_json(detections, json_outfile)
                print(f"[+] Wrote JSON output to: {json_outfile}")


if __name__ == "__main__":
    main()
