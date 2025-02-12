#!/usr/bin/env python3

import warnings

# 1) Ignore all warnings (including NotOpenSSLWarning)
warnings.filterwarnings("ignore")

import os
import requests
import zipfile
import io
import csv
import ipaddress
from datetime import datetime, timedelta
from urllib3.exceptions import NotOpenSSLWarning

LOCAL_ZIP_FILE = "GeoLite2-ASN-CSV-latest.zip"
MAX_AGE_HOURS = 24

def is_file_older_than(filepath, hours=24):
    """Return True if 'filepath' doesn't exist or is older than 'hours'."""
    if not os.path.exists(filepath):
        return True
    mtime = os.path.getmtime(filepath)
    file_age = datetime.now() - datetime.fromtimestamp(mtime)
    return file_age > timedelta(hours=hours)

def download_geolite_asn(license_key, out_file):
    """Download the GeoLite2-ASN-CSV ZIP from MaxMind using 'license_key' to 'out_file'."""
    url = (
        "https://download.maxmind.com/app/geoip_download?"
        f"edition_id=GeoLite2-ASN-CSV&license_key={license_key}&suffix=zip"
    )
    print("Downloading GeoLite2 ASN CSV database...")
    response = requests.get(url)
    response.raise_for_status()
    with open(out_file, "wb") as f:
        f.write(response.content)
    print(f"Saved new copy to {out_file}\n")

def main():
    # 1. Prompt for user inputs
    partial_org_input = input("Enter partial AS Organization name (match must start with this): ").strip().lower()
    license_key = input("Enter your MaxMind license key: ").strip()

    # 2. Download if necessary
    if is_file_older_than(LOCAL_ZIP_FILE, hours=MAX_AGE_HOURS):
        download_geolite_asn(license_key, LOCAL_ZIP_FILE)
    else:
        print(f"Using existing '{LOCAL_ZIP_FILE}' (not older than {MAX_AGE_HOURS} hours).")

    # 3. Read the CSV(s) and gather matching networks + org names
    matched_orgs = set()
    matched_networks = []

    with zipfile.ZipFile(LOCAL_ZIP_FILE, "r") as z:
        csv_files = [f for f in z.namelist() if f.endswith(".csv")]
        for csv_file in csv_files:
            with z.open(csv_file) as f:
                reader = csv.reader(io.TextIOWrapper(f, encoding="utf-8"))
                try:
                    header = next(reader)
                except StopIteration:
                    continue  # Empty file

                # Identify needed columns
                try:
                    net_idx = header.index("network")
                    org_idx = header.index("autonomous_system_organization")
                except ValueError:
                    # If we don't have those columns, skip
                    continue

                for row in reader:
                    if net_idx >= len(row) or org_idx >= len(row):
                        continue

                    cidr_str = row[net_idx].strip()
                    as_org_str = row[org_idx].strip()

                    # Match must START with partial_org_input (case-insensitive)
                    if as_org_str.lower().startswith(partial_org_input):
                        # Try parsing network
                        try:
                            net = ipaddress.ip_network(cidr_str)
                        except ValueError:
                            continue
                        matched_orgs.add(as_org_str)
                        matched_networks.append(net)

    # 4. If no matches, we're done
    if not matched_orgs:
        print("\nNo matching AS Organization networks found.")
        return

    # 5. List the matching AS Organization names
    print("\n=== Matching AS Organizations ===")
    for org in sorted(matched_orgs, key=str.lower):
        print(f" - {org}")

    # 6. Collapse the networks
    v4_nets = [n for n in matched_networks if n.version == 4]
    v6_nets = [n for n in matched_networks if n.version == 6]

    collapsed_v4 = list(ipaddress.collapse_addresses(v4_nets))
    collapsed_v6 = list(ipaddress.collapse_addresses(v6_nets))

    # If you want them truly sorted by IP, do:
    # final_collapsed = sorted(
    #     collapsed_v4 + collapsed_v6,
    #     key=lambda net: (net.version, net.network_address)
    # )
    # Otherwise, just do IPv4 then IPv6:
    final_collapsed = collapsed_v4 + collapsed_v6

    print("\n=== Collapsed CIDR Ranges (Combined) ===")
    for net in final_collapsed:
        print(f" - {net}")

    print("\nDone.")

if __name__ == "__main__":
    main()
