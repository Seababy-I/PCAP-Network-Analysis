
import os
import shutil
import logging
from pathlib import Path
import pyshark

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)

logger = logging.getLogger(__name__)

def find_tshark(tshark_path=None):

    # 1. Explicit path supplied by caller
    if tshark_path:
        path = Path(tshark_path)

        if path.is_file():
            return str(path)

        raise FileNotFoundError(
            f"TShark was not found at the supplied path: {tshark_path}"
        )

    # 2. Environment variable
    env_path = os.environ.get("TSHARK_PATH")

    if env_path and Path(env_path).is_file():
        return env_path

    # 3. Search system PATH
    path_from_system = shutil.which("tshark")

    if path_from_system:
        return path_from_system

    # 4. Common installation locations
    common_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        "/usr/bin/tshark",
        "/usr/local/bin/tshark",
        "/opt/homebrew/bin/tshark"
    ]

    for path in common_paths:
        if Path(path).is_file():
            return path

    raise FileNotFoundError(
        "TShark was not found. Install Wireshark or provide "
        "the TShark executable path."
    )

def get_layer(packet, layer_name):
    try:
        for layer in packet.layers:
            if getattr(layer, "layer_name", "").lower() == layer_name.lower():
                return layer
    except Exception:
        return None
    return None


def get_field(layer, field_name):
    if layer is None:
        return None
    try:
        value = layer.get_field_value(field_name)
        if value is None:
            return None
        if isinstance(value, str):
            value = value.strip()
            if value == "":
                return None
        return value
    except (AttributeError, KeyError, TypeError, ValueError):
        return None


def to_integer(value):
    if value is None:
        return None
    try:
        if isinstance(value, int):
            return value
        value = str(value).strip()
        if not value:
            return None
        if value.lower().startswith("0x"):
            return int(value, 16)
        return int(value, 10)
    except (ValueError, TypeError):
        return None

def get_timestamp(packet):
    try:
        return float(packet.sniff_timestamp)
    except (AttributeError, TypeError, ValueError):
        return None

def get_packet_length(packet):
    try:
        return to_integer(packet.length)
    except (AttributeError, TypeError, ValueError):
        return None

def extract_ip_addresses(packet):
    src_ip = None
    dst_ip = None

    # IPv4
    ip_layer = get_layer(packet, "ip")
    if ip_layer is not None:
        src_ip = get_field(ip_layer, "src")
        dst_ip = get_field(ip_layer, "dst")
        return src_ip, dst_ip

    # IPv6
    ipv6_layer = get_layer(packet, "ipv6")
    if ipv6_layer is not None:
        src_ip = get_field(ipv6_layer, "src")
        dst_ip = get_field(ipv6_layer, "dst")
        return src_ip, dst_ip

    # ARP
    arp_layer = get_layer(packet, "arp")
    if arp_layer is not None:
        src_ip = get_field(arp_layer, "src_proto_ipv4")
        dst_ip = get_field(arp_layer, "dst_proto_ipv4")
        return src_ip, dst_ip
    return None, None


# ---------------------------------------------------------
# PROTOCOL EXTRACTION
# ---------------------------------------------------------

def extract_protocol(packet):
    if get_layer(packet, "tcp") is not None:
        return "TCP"
    if get_layer(packet, "udp") is not None:
        return "UDP"
    if get_layer(packet, "icmp") is not None:
        return "ICMP"
    if get_layer(packet, "icmpv6") is not None:
        return "ICMPv6"
    if get_layer(packet, "arp") is not None:
        return "ARP"
    return "OTHER"

def extract_ports(packet):
    tcp_layer = get_layer(packet, "tcp")
    if tcp_layer is not None:
        src_port = to_integer(get_field(tcp_layer, "srcport"))
        dst_port = to_integer(get_field(tcp_layer, "dstport"))
        return src_port, dst_port
    udp_layer = get_layer(packet, "udp")
    if udp_layer is not None:
        src_port = to_integer(get_field(udp_layer, "srcport"))
        dst_port = to_integer(get_field(udp_layer, "dstport"))
        return src_port, dst_port
    return None, None

def extract_tcp_flags(packet):
    tcp_layer = get_layer(packet, "tcp")
    if tcp_layer is None:
        return None
    flags = get_field(tcp_layer, "flags")
    return to_integer(flags)

def extract_dns_records(packet):
    dns_records = []
    try:
        dns_layers = [
            layer for layer in packet.layers
            if getattr(layer, "layer_name", "").lower() == "dns"
        ]
    except Exception:
        return dns_records
    for dns_layer in dns_layers:
        query_name = get_field(dns_layer, "qry_name")
        query_type = get_field(dns_layer, "qry_type")
        response_code = get_field(dns_layer, "flags_rcode")
        answers = []
        # DNS answer fields and their corresponding record types
        answer_fields = {
            "a": "A",
            "aaaa": "AAAA",
            "cname": "CNAME",
            "mx": "MX",
            "ns": "NS",
            "ptr": "PTR",
            "txt": "TXT"
        }
        answer_name = (
            get_field(dns_layer, "resp_name")
            or query_name
        )
        for field_name, record_type in answer_fields.items():
            answer_value = get_field(dns_layer, field_name)
            if answer_value is None:
                continue
            # Some PyShark fields may contain multiple values.
            if isinstance(answer_value, (list, tuple)):
                values = answer_value
            else:
                values = [answer_value]
            for value in values:
                if value is None:
                    continue
                answers.append({
                    "name": answer_name,
                    "type": record_type,
                    "value": str(value)
                })
        # Only store DNS records when meaningful DNS information
        # was successfully extracted.

        if any([
            query_name,
            query_type,
            response_code,
            answers
        ]):
            dns_records.append({
                "query_name": query_name,
                "query_type": query_type,
                "response_code": response_code,
                "answers": answers
            })
    return dns_records

def extract_http_records(packet):
    http_records = []
    http_layer = get_layer(packet, "http")
    if http_layer is None:
        return http_records
    method = get_field(http_layer, "request_method")
    host = get_field(http_layer, "host")
    uri = get_field(http_layer, "request_uri")
    status_code = to_integer(
        get_field(http_layer, "response_code")
    )
    http_records.append({
        "method": method,
        "host": host,
        "uri": uri,
        "status_code": status_code
    })
    return http_records

def extract_packet(packet):
    # Original PCAP frame number
    frame_number = to_integer(
        getattr(packet, "number", None)
    )

    # Timestamp
    timestamp = get_timestamp(packet)

    # Packet length
    length = get_packet_length(packet)

    # Required database fields
    if timestamp is None:
        raise ValueError("Packet timestamp is missing or invalid.")

    if length is None:
        raise ValueError("Packet length is missing or invalid.")

    if frame_number is None:
        raise ValueError("Packet frame number is missing or invalid.")

    # IP addresses
    src_ip, dst_ip = extract_ip_addresses(packet)

    # Protocol
    protocol = extract_protocol(packet)

    # Ports
    src_port, dst_port = extract_ports(packet)

    # TCP flags
    tcp_flags = extract_tcp_flags(packet)

    # DNS records
    dns_records = extract_dns_records(packet)

    # HTTP records
    http_records = extract_http_records(packet)

    # Final structured packet
    packet_data = {
        "timestamp": timestamp,

        "src_ip": src_ip,
        "dst_ip": dst_ip,

        "protocol": protocol,

        "src_port": src_port,
        "dst_port": dst_port,

        "length": length,

        "frame_number": frame_number,
        "tcp_flags": tcp_flags,

        "dns_records": dns_records,
        "http_records": http_records
    }
    return packet_data

def parse_pcap(path, tshark_path=None):
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(
            f"PCAP file not found: {path}"
        )
    executable = find_tshark(tshark_path)
    capture = None
    parsed_count = 0
    skipped_count = 0
    logger.info("Starting PCAP parsing.")
    logger.info("Input file: %s", file_path)
    logger.info("Using TShark: %s", executable)
    try:
        # keep_packets=False prevents PyShark from storing
        # all packets in memory.
        capture = pyshark.FileCapture(
            input_file=str(file_path),
            tshark_path=executable,
            keep_packets=False
        )
        try:
            for packet in capture:
                try:
                    packet_data = extract_packet(packet)
                    parsed_count += 1
                    yield packet_data
                except Exception as error:
                    skipped_count += 1
                    logger.warning(
                        "Skipping malformed packet: %s",
                        error
                    )
        except Exception as error:
            raise RuntimeError(
                f"Fatal error while reading capture. "
                f"Parsed packets: {parsed_count}, "
                f"skipped packets: {skipped_count}. "
                f"Original error: {error}"
            ) from error

    finally:
        # Always close the capture, even if parsing fails
        # or the caller closes the generator early.
        if capture is not None:
            try:
                capture.close()
            except Exception as error:
                logger.warning(
                    "Error while closing capture: %s",
                    error
                )
        logger.info("PCAP parsing finished.")
        logger.info("Successfully parsed: %d", parsed_count)
        logger.info("Skipped packets: %d", skipped_count)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="PCAP and PCAPNG structured packet parser"
    )
    parser.add_argument(
        "pcap_file",
        help="Path to the PCAP or PCAPNG file"
    )
    parser.add_argument(
        "--tshark",
        dest="tshark_path",
        default=None,
        help="Optional path to TShark executable"
    )
    args = parser.parse_args()
    total_packets = 0
    try:
        for packet in parse_pcap(
            args.pcap_file,
            tshark_path=args.tshark_path
        ):
            total_packets += 1
            print("\n------------------------------")
            print(f"Frame Number : {packet['frame_number']}")
            print(f"Timestamp    : {packet['timestamp']}")
            print(f"Source IP    : {packet['src_ip']}")
            print(f"Destination IP: {packet['dst_ip']}")
            print(f"Protocol     : {packet['protocol']}")
            print(f"Source Port  : {packet['src_port']}")
            print(f"Destination Port: {packet['dst_port']}")
            print(f"Length       : {packet['length']}")
            print(f"TCP Flags    : {packet['tcp_flags']}")
            if packet["dns_records"]:
                print("DNS Records  :", packet["dns_records"])
            if packet["http_records"]:
                print("HTTP Records :", packet["http_records"])
        print("\n==============================")
        print("Total parsed packets:", total_packets)
        print("==============================")
    except Exception as error:
        logger.error("Parsing failed: %s", error)