import struct
import time
import socket


def checksum(data):
    if len(data) % 2:
        data += b"\x00"

    total = 0

    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


def create_udp_packet(src_ip, dst_ip, src_port, dst_port, payload):
    # Ethernet header
    dst_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
    src_mac = b"\x11\x22\x33\x44\x55\x66"

    ethernet_header = (
        dst_mac +
        src_mac +
        struct.pack("!H", 0x0800)  # IPv4
    )

    # IP addresses
    src_ip_bytes = socket.inet_aton(src_ip)
    dst_ip_bytes = socket.inet_aton(dst_ip)

    # UDP header
    udp_length = 8 + len(payload)

    udp_header = struct.pack(
        "!HHHH",
        src_port,
        dst_port,
        udp_length,
        0
    )

    # IPv4 header
    ip_header_without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,          # Version 4, IHL 5
        0,             # DSCP/ECN
        20 + udp_length,
        1,             # Identification
        0,             # Flags/fragment offset
        64,            # TTL
        17,            # UDP
        0,             # Checksum placeholder
        src_ip_bytes,
        dst_ip_bytes
    )

    ip_checksum = checksum(ip_header_without_checksum)

    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + udp_length,
        1,
        0,
        64,
        17,
        ip_checksum,
        src_ip_bytes,
        dst_ip_bytes
    )

    return ethernet_header + ip_header + udp_header + payload


def write_packet(file, packet, timestamp):
    seconds = int(timestamp)
    microseconds = int((timestamp - seconds) * 1_000_000)

    packet_length = len(packet)

    packet_header = struct.pack(
        "<IIII",
        seconds,
        microseconds,
        packet_length,
        packet_length
    )

    file.write(packet_header)
    file.write(packet)


# Create a PCAP file
output_file = "data/sample.pcap"

# PCAP global header
global_header = struct.pack(
    "<IHHIIII",
    0xA1B2C3D4,  # Magic number
    2,           # Major version
    4,           # Minor version
    0,           # Timezone
    0,           # Timestamp accuracy
    65535,       # Snapshot length
    1            # Ethernet
)

packets = [
    create_udp_packet(
        "192.168.1.10",
        "8.8.8.8",
        50000,
        53,
        b"DNS_QUERY_EXAMPLE"
    ),

    create_udp_packet(
        "192.168.1.10",
        "192.168.1.20",
        50001,
        8080,
        b"TEST_NETWORK_TRAFFIC"
    ),

    create_udp_packet(
        "192.168.1.20",
        "192.168.1.10",
        8080,
        50001,
        b"RESPONSE_DATA"
    )
]

with open(output_file, "wb") as file:
    file.write(global_header)

    timestamp = time.time()

    for packet in packets:
        write_packet(file, packet, timestamp)
        timestamp += 1

print("Valid sample PCAP created successfully!")
print(f"File: {output_file}")
print(f"Packets: {len(packets)}")