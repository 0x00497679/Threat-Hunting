#!/usr/bin/env python3
import sys
import base64
import re
import math
from collections import defaultdict
from scapy.all import rdpcap, DNS, DNSQR, UDP, TCP, IP, IPv6

############################
# CONFIGURATION & CONSTANTS
############################

# 1. HTTP-like keywords that might appear in the data
HTTP_KEYWORDS = [
    "GET", "POST", "HEAD", "HTTP/1.", "Host:", "User-Agent:", "Accept:",
    "Content-Type:", "PUT", "DELETE"
]

# 2. Regex for base64-like strings
BASE64_REGEX = re.compile(r"^[A-Za-z0-9+/=]+$")

# 3. Various detection thresholds
MAX_QNAME_LENGTH       = 200       # If a QNAME exceeds this length, suspect
MAX_LABEL_LENGTH       = 63        # Standard DNS label max is 63, but >60 might be suspicious
ENTROPY_THRESHOLD      = 4.5       # If Shannon entropy of a label > 4.5, consider suspicious
FREQUENCY_THRESHOLD    = 50        # If a domain is queried more than this, suspect
PARTIAL_KEYWORD_WINDOW = 5         # How many QNAMEs to keep in a rolling buffer per IP

# 4. Known CDN base domains to exclude from checks
#    (Customize this list for your environment.)
KNOWN_CDN_DOMAINS = {
    "cloudfront.net",
    "fastly.net",
    "akamai.net",
    "akamaiedge.net",
    "edgecastcdn.net",
    "cdn77.net",
    "cdn77.org",
    "cachefly.net",
    "incapdns.net",
    "edgesuite.net",
    "llnwd.net",
    # Add or remove domains as appropriate
}

############################
# UTILITY FUNCTIONS
############################

def calc_shannon_entropy(data: str) -> float:
    """
    Calculate the Shannon entropy of a string.
    """
    if not data:
        return 0.0
    freq_map = {}
    for char in data:
        freq_map[char] = freq_map.get(char, 0) + 1

    entropy = 0.0
    length = len(data)
    for count in freq_map.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def looks_like_http(payload: str) -> bool:
    """
    Check if a string contains any typical HTTP signatures.
    """
    for keyword in HTTP_KEYWORDS:
        if keyword in payload:
            return True
    return False

def decode_base64_and_check(payload: str) -> bool:
    """
    Attempt to decode base64 and see if it contains HTTP keywords.
    """
    try:
        decoded = base64.b64decode(payload, validate=False).decode('utf-8', errors='ignore')
        if looks_like_http(decoded):
            return True
    except Exception:
        pass
    return False

def get_base_domain(qname: str) -> str:
    """
    Extract a 'base domain' from a QNAME (e.g. 'sub.example.com' -> 'example.com').
    This is simplistic; real-world TLD parsing can be more complex.
    """
    labels = qname.strip('.').split('.')
    if len(labels) > 1:
        return '.'.join(labels[-2:])
    else:
        return qname.strip('.')

def get_src_dst_ip(pkt) -> (str, str):
    """
    Retrieve source and destination IP addresses from a packet.
    Checks for IPv4 first; if not present, then IPv6.
    """
    if pkt.haslayer(IP):
        return pkt[IP].src, pkt[IP].dst
    elif pkt.haslayer(IPv6):
        return pkt[IPv6].src, pkt[IPv6].dst
    else:
        return "N/A", "N/A"

def inspect_dns_qname(qname: str, src_ip: str, partial_cache: dict):
    """
    Check a single DNS query name for suspicious indicators:
      - Unusually long QNAME.
      - Suspicious subdomain lengths.
      - High entropy labels.
      - Possible embedded HTTP keywords (plain or base64).
      - Partial-chaining detection for split HTTP keywords.
    
    partial_cache is a dict that stores rolling QNAME pieces for each src_ip
    to detect if keywords are split across multiple queries.
    
    Returns (is_suspicious, reasons_list).
    """
    reasons = []
    is_suspicious = False

    # Strip trailing dots
    stripped_qname = qname.rstrip('.')
    qname_len = len(stripped_qname)

    # 1) Check overall length
    if qname_len > MAX_QNAME_LENGTH:
        is_suspicious = True
        reasons.append(f"QNAME length {qname_len} > {MAX_QNAME_LENGTH}")

    # 2) Break into labels
    labels = stripped_qname.split('.')

    # 3) Evaluate each label
    for label in labels:
        # If label is unusually long (beyond DNS standard or threshold)
        if len(label) > MAX_LABEL_LENGTH:
            is_suspicious = True
            reasons.append(f"Label '{label}' length {len(label)} > {MAX_LABEL_LENGTH}")

        # Entropy check
        ent = calc_shannon_entropy(label)
        if ent > ENTROPY_THRESHOLD:
            is_suspicious = True
            reasons.append(f"High entropy label '{label}' (entropy={ent:.2f} > {ENTROPY_THRESHOLD})")

        # Direct HTTP check in label
        if looks_like_http(label):
            is_suspicious = True
            reasons.append(f"Label '{label}' contains HTTP keywords")

        # Base64 check
        if len(label) > 4 and BASE64_REGEX.match(label):
            if decode_base64_and_check(label):
                is_suspicious = True
                reasons.append(f"Label '{label}' decodes to HTTP content")

    # 4) Check partial chaining: combine this entire QNAME with a rolling buffer
    if src_ip not in partial_cache:
        partial_cache[src_ip] = []
    partial_cache[src_ip].append(stripped_qname)

    # Limit memory usage in rolling buffer
    if len(partial_cache[src_ip]) > PARTIAL_KEYWORD_WINDOW:
        partial_cache[src_ip].pop(0)

    # Combine the recently seen QNAMEs for partial keyword detection
    combined_recent = ''.join(partial_cache[src_ip])
    if looks_like_http(combined_recent):
        is_suspicious = True
        reasons.append("Partial-chaining detected possible HTTP keyword across multiple queries")

    return is_suspicious, reasons

############################
# MAIN DETECTION LOGIC
############################

def detect_http_over_dns(pcap_file):
    """
    Reads a PCAP file, looks for DNS queries that might be carrying HTTP content.
    Excludes queries to known CDN domains from detection.
    Returns a list of suspicious queries with reasons.
    """
    suspicious_queries = []
    partial_cache = defaultdict(list)  # For partial-chaining per src_ip
    domain_frequency = defaultdict(int)

    packets = rdpcap(pcap_file)

    for pkt in packets:
        # Check for DNS over UDP or TCP
        if pkt.haslayer(DNS) and (pkt.haslayer(UDP) or pkt.haslayer(TCP)):
            dns_layer = pkt[DNS]
            # Focus on standard queries
            if dns_layer.qr == 0 and dns_layer.opcode == 0 and dns_layer.qdcount > 0:
                # Extract the QNAME
                try:
                    qname = dns_layer.qd.qname.decode('utf-8', errors='ignore')
                except AttributeError:
                    continue

                # Retrieve source/destination IP addresses (IPv4 or IPv6)
                src_ip, dst_ip = get_src_dst_ip(pkt)

                base_dom = get_base_domain(qname)

                # -- EXCLUSION: Skip known CDN domains entirely --
                if base_dom in KNOWN_CDN_DOMAINS:
                    continue

                # Increment frequency for domain
                domain_frequency[base_dom] += 1

                # Check suspicious indicators
                is_suspicious, reasons = inspect_dns_qname(qname, src_ip, partial_cache)

                # 5) Frequency-based detection for the domain
                if domain_frequency[base_dom] > FREQUENCY_THRESHOLD:
                    is_suspicious = True
                    reasons.append(f"Domain '{base_dom}' queried more than {FREQUENCY_THRESHOLD} times")

                if is_suspicious:
                    suspicious_queries.append({
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "qname": qname,
                        "reasons": reasons
                    })

    return suspicious_queries

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    print(f"[+] Analyzing PCAP: {pcap_file} for HTTP-over-DNS patterns (excluding known CDNs)...")
    
    results = detect_http_over_dns(pcap_file)
    
    print("[+] Analysis complete.")
    print(f"[*] Total suspicious DNS queries found: {len(results)}")
    
    # Print a summary of suspicious queries
    for idx, r in enumerate(results, 1):
        reasons_str = "; ".join(r["reasons"])
        print(f"{idx}. QNAME={r['qname']} | SRC={r['src_ip']} | DST={r['dst_ip']} | Reasons={reasons_str}")

if __name__ == "__main__":
    main()
