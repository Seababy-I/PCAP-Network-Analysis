from collections import defaultdict
import struct
import socket


PORT_SCAN_THRESHOLD = 20


def parse_packets(file_path):
    """
    Read a basic Ethernet + IPv4 + TCP/UDP PCAP
    and return source IP and destination port information.
    """

    packets = []

    with open(file_path, "rb") as file:
        # Read PCAP global header
        global_header = file.read(24)

        if len(global_header) != 24:
            raise ValueError("Invalid PCAP file.")

        while True:
            packet_header = file.read(16)

            if not packet_header:
                break

            if len(packet_header) != 16:
                break

            ts_sec, ts_usec, captured_length, original_length = struct.unpack(
                "<IIII",
                packet_header
            )

            packet_data = file.read(captured_length)

            if len(packet_data) != captured_length:
                break

            # Ethernet header = 14 bytes
            if len(packet_data) < 34:
                continue

            # Check EtherType
            ether_type = struct.unpack(
                "!H",
                packet_data[12:14]
            )[0]

            # Only process IPv4
            if ether_type != 0x0800:
                continue

            # IPv4 header
            ip_header = packet_data[14:34]

            version_ihl = ip_header[0]

            version = version_ihl >> 4
            ihl = (version_ihl & 0x0F) * 4

            if version != 4:
                continue

            protocol = ip_header[9]

            src_ip = socket.inet_ntoa(
                ip_header[12:16]
            )

            dst_ip = socket.inet_ntoa(
                ip_header[16:20]
            )

            transport_start = 14 + ihl

            # TCP or UDP
            if protocol not in (6, 17):
                continue

            if len(packet_data) < transport_start + 4:
                continue

            src_port, dst_port = struct.unpack(
                "!HH",
                packet_data[transport_start:transport_start + 4]
            )

            packets.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol
            })

    return packets


def detect_port_scan(file_path, threshold=PORT_SCAN_THRESHOLD):
    """
    Detect possible port scanning based on the number
    of distinct destination ports contacted by each source IP.
    """

    packets = parse_packets(file_path)

    ports_by_source = defaultdict(set)

    for packet in packets:
        ports_by_source[packet["src_ip"]].add(
            packet["dst_port"]
        )

    alerts = []

    for src_ip, destination_ports in ports_by_source.items():

        port_count = len(destination_ports)

        if port_count > threshold:
            alerts.append({
                "type": "Possible Port Scan",
                "source_ip": src_ip,
                "destination_port_count": port_count,
                "threshold": threshold,
                "severity": "Medium",
                "description": (
                    f"{src_ip} contacted "
                    f"{port_count} distinct destination ports."
                )
            })

    return alerts

if __name__ == "__main__":

    pcap_path = "data/detection_test.pcap"

    alerts = detect_port_scan(pcap_path)

    print("Forensic Detection Results")
    print("--------------------------")

    if not alerts:
        print("No suspicious activity detected.")

    else:
        for alert in alerts:
            print("\nALERT DETECTED")
            print("Type:", alert["type"])
            print("Source IP:", alert["source_ip"])
            print(
                "Destination Ports:",
                alert["destination_port_count"]
            )
            print("Threshold:", alert["threshold"])
            print("Severity:", alert["severity"])
            print("Description:", alert["description"])