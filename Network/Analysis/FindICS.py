#!/usr/bin/env python3
import sys
import glob
from scapy.all import rdpcap, TCP, UDP, IP, IPv6

# Dictionary mapping protocol names to lists of common port numbers.
SCADA_PORTS = {
    "Modbus/TCP": [502],
    "DNP3": [20000, 20001],
    "IEC 60870-5-104": [2404],
    "Siemens S7comm": [102],
    "EtherNet/IP": [44818],
    "OPC UA": [4840],
    "BACnet/IP": [47808],       # Typically UDP
    "SNMP": [161, 162],         # UDP ports 161 (queries) and 162 (traps)
    "Profinet": [34962, 34963, 34964],  # Commonly UDP ports
}

def detect_scada_protocols(pkt):
    """
    Check if a packet (TCP or UDP) uses one of the known SCADA/OT/ICS ports.
    Returns a list of protocol names if detected, or an empty list.
    """
    detected = []
    if pkt.haslayer(TCP):
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        for proto, ports in SCADA_PORTS.items():
            if sport in ports or dport in ports:
                detected.append(proto)
    elif pkt.haslayer(UDP):
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        for proto, ports in SCADA_PORTS.items():
            if sport in ports or dport in ports:
                detected.append(proto)
    return detected

def generate_packet_bpf(pkt, protocols_detected):
    """
    Generate a BPF filter string specific to the packet and the protocols detected.
    It includes the source and destination IP (or IPv6) addresses and port conditions.
    """
    # Get source/destination addresses.
    ip_filter = ""
    if pkt.haslayer(IP):
        src = pkt[IP].src
        dst = pkt[IP].dst
        ip_filter = f"ip src {src} and ip dst {dst}"
    elif pkt.haslayer(IPv6):
        src = pkt[IPv6].src
        dst = pkt[IPv6].dst
        ip_filter = f"ip6 src {src} and ip6 dst {dst}"
    
    # Collect all ports for the detected protocols.
    port_conditions = []
    for proto in protocols_detected:
        ports = SCADA_PORTS.get(proto, [])
        for port in ports:
            port_conditions.append(f"port {port}")
    # Remove duplicates and sort numerically.
    if port_conditions:
        unique_ports = sorted(set(port_conditions), key=lambda x: int(x.split()[1]))
        ports_filter = " or ".join(unique_ports)
    else:
        ports_filter = ""

    # Combine the IP filter and ports filter.
    if ip_filter and ports_filter:
        bpf = f"({ip_filter}) and ({ports_filter})"
    elif ip_filter:
        bpf = ip_filter
    elif ports_filter:
        bpf = ports_filter
    else:
        bpf = ""
    return bpf

def process_file(pcap_file):
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error reading {pcap_file}: {e}")
        return

    print(f"\n[+] Processing file: {pcap_file}")
    print(f"[+] Loaded {len(packets)} packets from {pcap_file}\n")

    scada_pkt_count = 0
    for idx, pkt in enumerate(packets, start=1):
        protocols = detect_scada_protocols(pkt)
        if protocols:
            scada_pkt_count += 1
            bpf = generate_packet_bpf(pkt, protocols)
            print(f"Packet {idx:5d}: Detected {', '.join(protocols)}")
            print(f"            BPF Filter: {bpf}")
    print(f"\nTotal SCADA/OT/ICS packets detected: {scada_pkt_count} out of {len(packets)}\n")

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

