import struct
import socket


output_file = "data/host_scan_test.pcap"


# -----------------------------------------
# PCAP Global Header
# -----------------------------------------

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


packets = []


# -----------------------------------------
# Create packets from one source IP
# to many destination IPs
# -----------------------------------------

source_ip = "192.168.1.10"


for i in range(1, 31):

    destination_ip = f"192.168.1.{i}"

    # Ethernet header
    ethernet = (
        b"\xaa\xbb\xcc\xdd\xee\xff"
        + b"\x11\x22\x33\x44\x55\x66"
        + struct.pack("!H", 0x0800)
    )

    # IPv4 header
    version_ihl = 0x45
    tos = 0
    total_length = 20 + 20
    identification = i
    flags_fragment = 0
    ttl = 64
    protocol = 6
    checksum = 0

    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_length,
        identification,
        flags_fragment,
        ttl,
        protocol,
        checksum,
        socket.inet_aton(source_ip),
        socket.inet_aton(destination_ip)
    )

    # TCP header
    src_port = 40000 + i
    dst_port = 22
    sequence = 0
    acknowledgement = 0
    data_offset = 5
    flags = 0x02  # SYN
    window = 8192
    checksum = 0
    urgent_pointer = 0

    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port,
        dst_port,
        sequence,
        acknowledgement,
        data_offset << 4,
        flags,
        window,
        checksum,
        urgent_pointer
    )

    packet = ethernet + ip_header + tcp_header

    # Packet header
    packet_header = struct.pack(
        "<IIII",
        i,
        0,
        len(packet),
        len(packet)
    )

    packets.append(packet_header + packet)


# -----------------------------------------
# Write PCAP
# -----------------------------------------

with open(output_file, "wb") as f:

    f.write(global_header)

    for packet in packets:
        f.write(packet)


print("Created:", output_file)
print("Packets:", len(packets))