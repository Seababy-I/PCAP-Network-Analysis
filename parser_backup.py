import pyshark


def parse_pcap(filename):

    capture = pyshark.FileCapture(
        filename,
        tshark_path=r"C:\Program Files\Wireshark\tshark.exe"
    )

    for packet in capture:

        # Packet number
        packet_number = packet.number

        # Timestamp
        timestamp = packet.sniff_time

        # Packet length
        packet_length = packet.length

        # Default values
        src_ip = "N/A"
        dst_ip = "N/A"
        src_port = "N/A"
        dst_port = "N/A"
        protocol = "OTHER"

        # IPv4 addresses
        if hasattr(packet, "ip"):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst

        # IPv6 addresses
        elif hasattr(packet, "ipv6"):
            src_ip = packet.ipv6.src
            dst_ip = packet.ipv6.dst

        # TCP
        if hasattr(packet, "tcp"):
            protocol = "TCP"
            src_port = packet.tcp.srcport
            dst_port = packet.tcp.dstport

        # UDP
        elif hasattr(packet, "udp"):
            protocol = "UDP"
            src_port = packet.udp.srcport
            dst_port = packet.udp.dstport

        # ICMP
        elif hasattr(packet, "icmp"):
            protocol = "ICMP"

        # ICMPv6
        elif hasattr(packet, "icmpv6"):
            protocol = "ICMPv6"

        # ARP
        elif hasattr(packet, "arp"):
            protocol = "ARP"

            if hasattr(packet.arp, "src_proto_ipv4"):
                src_ip = packet.arp.src_proto_ipv4

            if hasattr(packet.arp, "dst_proto_ipv4"):
                dst_ip = packet.arp.dst_proto_ipv4

        # Display basic packet information
        print(" ")
        print(f"Packet Number    : {packet_number}")
        print(f"Timestamp        : {timestamp}")
        print(f"Source IP        : {src_ip}")
        print(f"Destination IP   : {dst_ip}")
        print(f"Protocol         : {protocol}")
        print(f"Source Port      : {src_port}")
        print(f"Destination Port : {dst_port}")
        print(f"Packet Length    : {packet_length} bytes")

        # DNS extraction
        if hasattr(packet, "dns"):

            print("DNS Information:")

            if hasattr(packet.dns, "qry_name"):
                print(f"DNS Query Name   : {packet.dns.qry_name}")

            if hasattr(packet.dns, "qry_type"):
                print(f"DNS Query Type   : {packet.dns.qry_type}")

            print(f"DNS Source IP    : {src_ip}")
            print(f"DNS Destination IP : {dst_ip}")

        # HTTP extraction
        if hasattr(packet, "http"):

            print("HTTP Information:")

            if hasattr(packet.http, "request_method"):
                print(f"HTTP Method      : {packet.http.request_method}")

            if hasattr(packet.http, "host"):
                print(f"HTTP Host        : {packet.http.host}")

            if hasattr(packet.http, "request_uri"):
                print(f"HTTP URI         : {packet.http.request_uri}")

            if hasattr(packet.http, "response_code"):
                print(f"HTTP Status Code : {packet.http.response_code}")

    capture.close()


if __name__ == "__main__":
    parse_pcap("v6-http.cap")