import struct
import socket
from collections import defaultdict


HOST_SCAN_THRESHOLD = 20


def detect_host_scan(file_path, threshold=HOST_SCAN_THRESHOLD):
    """
    Detect possible host scanning.

    A host scan is suspected when one source IP
    contacts many different destination IP addresses.
    """

    destinations_by_source = defaultdict(set)

    with open(file_path, "rb") as f:

        # -----------------------------------------
        # Read PCAP global header
        # -----------------------------------------

        global_header = f.read(24)

        if len(global_header) != 24:
            return []

        # -----------------------------------------
        # Read packets
        # -----------------------------------------

        while True:

            packet_header = f.read(16)

            if not packet_header:
                break

            if len(packet_header) != 16:
                break

            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                "<IIII",
                packet_header
            )

            packet = f.read(incl_len)

            if len(packet) < 34:
                continue

            # -----------------------------------------
            # Ethernet header
            # -----------------------------------------

            ether_type = struct.unpack(
                "!H",
                packet[12:14]
            )[0]

            # Only IPv4
            if ether_type != 0x0800:
                continue

            # -----------------------------------------
            # IPv4 header
            # -----------------------------------------

            ip_header_start = 14

            version_ihl = packet[ip_header_start]

            ihl = (version_ihl & 0x0F) * 4

            if len(packet) < 14 + ihl:
                continue

            src_ip = socket.inet_ntoa(
                packet[26:30]
            )

            dst_ip = socket.inet_ntoa(
                packet[30:34]
            )

            destinations_by_source[src_ip].add(dst_ip)

    # -----------------------------------------
    # Analyse results
    # -----------------------------------------

    alerts = []

    for src_ip, destinations in destinations_by_source.items():

        destination_count = len(destinations)

        if destination_count > threshold:

            alerts.append({
                "type": "Possible Host Scan",
                "severity": "Medium",
                "description": (
                    f"Source {src_ip} contacted "
                    f"{destination_count} different destination hosts. "
                    f"Threshold: {threshold}."
                ),
                "source_ip": src_ip,
                "destination_count": destination_count
            })

    return alerts