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


def create_tcp_packet(src_ip, dst_ip, src_port, dst_port):
    # Ethernet header
    dst_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
    src_mac = b"\x11\x22\x33\x44\x55\x66"

    ethernet_header = (
        dst_mac +
        src_mac +
        struct.pack("!H", 0x0800)
    )

    src_ip_bytes = socket.inet_aton(src_ip)
    dst_ip_bytes = socket.inet_aton(dst_ip)

    # TCP header
    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port,
        dst_port,
        0,          # Sequence number
        0,          # Acknowledgement number
        5 << 4,     # Header length = 5
        2,          # SYN flag
        65535,      # Window
        0,          # Checksum
        0           # Urgent pointer
    )

    tcp_checksum_data = (
        src_ip_bytes +
        dst_ip_bytes +
        struct.pack("!BBH", 0, 6, len(tcp_header)) +
        tcp_header
    )

    tcp_checksum = checksum(tcp_checksum_data)

    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port,
        dst_port,
        0,
        0,
        5 << 4,
        2,
        65535,
        tcp_checksum,
        0
    )

    # IPv4 header
    ip_header_without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp_header),
        1,
        0,
        64,
        6,
        0,
        src_ip_bytes,
        dst_ip_bytes
    )

    ip_checksum = checksum(ip_header_without_checksum)

    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp_header),
        1,
        0,
        64,
        6,
        ip_checksum,
        src_ip_bytes,
        dst_ip_bytes
    )

    return ethernet_header + ip_header + tcp_header


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


output_file = "data/detection_test.pcap"

# PCAP global header
global_header = struct.pack(
    "<IHHIIII",
    0xA1B2C3D4,
    2,
    4,
    0,
    0,
    65535,
    1
)

# One source IP contacting many destination ports
source_ip = "192.168.1.10"
destination_ip = "192.168.1.20"

packets = []

for destination_port in range(20, 61):
    packet = create_tcp_packet(
        source_ip,
        destination_ip,
        50000,
        destination_port
    )

    packets.append(packet)


with open(output_file, "wb") as file:
    file.write(global_header)

    timestamp = time.time()

    for packet in packets:
        write_packet(file, packet, timestamp)
        timestamp += 0.1


print("Detection test PCAP created successfully!")
print(f"File: {output_file}")
print(f"Packets: {len(packets)}")
print(f"Source IP: {source_ip}")
print(f"Destination IP: {destination_ip}")
print("Destination ports: 20-60")