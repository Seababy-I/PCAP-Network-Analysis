

import os
import shutil
import logging
import struct
import math
import ipaddress
from pathlib import Path
import pyshark

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)

logger = logging.getLogger(__name__)


class ParserExtractionError(RuntimeError):
    """Fatal extraction failure with structured frame/progress information."""
    def __init__(self, frame_number, parsed_count, cause):
        self.frame_number = to_integer(frame_number)
        self.parsed_count = parsed_count
        self.failed_count = 1
        super().__init__(f"Extraction failed for frame {frame_number}: {cause}")

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
        if isinstance(value, bool):
            return None
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

def field_values(layer, name):
    """Read every PDML occurrence, rather than only PyShark's default field."""
    if layer is None:
        return []
    field = layer.get_field(name)
    if field is None:
        return []
    fields = getattr(field, "all_fields", None)
    if fields is None:
        fields = [field]
    values = []
    for item in fields:
        value = getattr(item, "show", None)
        if value is None:
            value = str(item)
        if value is not None and str(value).strip():
            values.append(str(value).strip())
    return values


def checked_number(raw, name, low, high):
    value = to_integer(raw)
    if value is None or not low <= value <= high:
        raise ValueError(f"Invalid {name}: {raw!r}")
    return value


def extract_dns_records(packet):
    records = []
    for layer in packet.layers:
        if getattr(layer, "layer_name", "").lower() != "dns":
            continue
        names = field_values(layer, "qry_name")
        types = field_values(layer, "qry_type")
        codes = field_values(layer, "flags_rcode")
        for raw in types:
            checked_number(raw, "DNS query type", 0, 65535)
        for raw in codes:
            checked_number(raw, "DNS response code", 0, 4095)
        # Resource-record name/type/length are parallel PDML fields. Retain
        # each answer's actual owner, including mixed CNAME/A responses.
        owners = field_values(layer, "resp_name")
        rrtypes = field_values(layer, "resp_type")
        values = {}
        mapping = {1:("a","A"),28:("aaaa","AAAA"),5:("cname","CNAME"),
                   15:("mx_mail_exchange","MX"),2:("ns","NS"),12:("ptr_domain_name","PTR"),16:("txt","TXT")}
        for number,(field,label) in mapping.items():
            values[number] = iter(field_values(layer, field))
        if len(field_values(layer, "txt")) > sum(to_integer(t)==16 for t in rrtypes):
            raise ValueError("Multi-string TXT resources are not supported; refusing incomplete extraction")
        answers = []
        if len(owners) != len(rrtypes):
            raise ValueError("DNS resource record names/types are inconsistent")
        for owner,raw_type in zip(owners,rrtypes):
            number = checked_number(raw_type, "DNS resource type", 0, 65535)
            if number not in mapping:
                continue  # Unsupported RR types are not claimed as extracted.
            value = next(values[number], None)
            if value is None:
                raise ValueError("DNS resource record value is missing")
            if number in (1,28):
                ipaddress.ip_address(value)
            answers.append(dict(name=owner,type=mapping[number][1],value=value))
        if len(names) != len(types):
            raise ValueError("DNS question names/types are inconsistent")
        # A DNS message can contain multiple questions. Its full resource list
        # belongs to the message; store it once, on the first question row.
        for index in range(max(1,len(names))):
            records.append(dict(query_name=names[index] if names else None,
                query_type=types[index] if types else None,
                response_code=codes[0] if codes else None,
                answers=answers if index==0 else []))
    return records


def extract_http_records(packet):
    records = []
    for layer in packet.layers:
        if getattr(layer, "layer_name", "").lower() != "http":
            continue
        methods = field_values(layer, "request_method")
        hosts = field_values(layer, "host")
        uris = field_values(layer, "request_uri")
        statuses = field_values(layer, "response_code")
        # TShark PDML normally provides one layer per HTTP message. Reject
        # ambiguous groupings rather than assigning one message's host to another.
        if any(len(values)>1 for values in (methods,hosts,uris,statuses)):
            raise ValueError("Ambiguous HTTP message grouping in TShark output")
        if not any((methods,hosts,uris,statuses)):
            continue
        records.append(dict(method=methods[0] if methods else None,
            host=hosts[0] if hosts else None,uri=uris[0] if uris else None,
            status_code=checked_number(statuses[0],"HTTP status",100,599) if statuses else None))
    return records


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
    if timestamp is None or not math.isfinite(timestamp):
        raise ValueError("Packet timestamp is missing or invalid.")

    if length is None or length < 0:
        raise ValueError("Packet length is missing or invalid.")

    if frame_number is None or frame_number < 1:
        raise ValueError("Packet frame number is missing or invalid.")

    # IP addresses
    src_ip, dst_ip = extract_ip_addresses(packet)

    # Protocol
    protocol = extract_protocol(packet)

    # Ports
    src_port, dst_port = extract_ports(packet)

    # TCP flags
    tcp_flags = extract_tcp_flags(packet)

    for address in (src_ip, dst_ip):
        if address is not None:
            ipaddress.ip_address(address)
    if protocol in ("TCP", "UDP"):
        if src_ip is None or dst_ip is None:
            raise ValueError("Transport packet has no valid IP addresses")
        checked_number(src_port, "source port", 0, 65535)
        checked_number(dst_port, "destination port", 0, 65535)
    if protocol == "TCP":
        checked_number(tcp_flags, "TCP flags", 0, 4095)

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

def validate_capture_format(path):
    """Reject invalid/truncated PCAP/PCAPNG before PyShark is started.

    This checks container structure, not the validity of every network packet.
    It avoids relying on version/platform-specific TShark error propagation.
    """
    size = path.stat().st_size

    def invalid(reason):
        raise RuntimeError(f"Invalid or truncated capture: {reason}: {path}")

    with path.open("rb") as handle:
        magic = handle.read(4)
        byte_orders = {
            b"\xd4\xc3\xb2\xa1": "<",  # PCAP, microsecond timestamps
            b"\xa1\xb2\xc3\xd4": ">",
            b"\x4d\x3c\xb2\xa1": "<",  # PCAP, nanosecond timestamps
            b"\xa1\xb2\x3c\x4d": ">",
        }
        if magic in byte_orders:
            order = byte_orders[magic]
            rest = handle.read(20)
            if len(rest) != 20:
                invalid("incomplete PCAP global header")
            major, minor, _, _, snaplen, _ = struct.unpack(order + "HHiIII", rest)
            if (major, minor) != (2, 4) or snaplen == 0:
                invalid("unsupported PCAP header")
            while handle.tell() < size:
                header = handle.read(16)
                if len(header) != 16:
                    invalid("incomplete packet header")
                _, _, captured_length, original_length = struct.unpack(order + "IIII", header)
                if captured_length > snaplen or captured_length > original_length:
                    invalid("inconsistent captured packet length")
                if handle.tell() + captured_length > size:
                    invalid("incomplete packet bytes")
                handle.seek(captured_length, 1)
            return

        if magic != b"\x0a\x0d\x0d\x0a":
            invalid("file is not PCAP or PCAPNG")
        handle.seek(0)
        order = None
        while handle.tell() < size:
            start = handle.tell()
            header = handle.read(12)
            if len(header) != 12:
                invalid("incomplete PCAPNG block header")
            section = header[:4] == b"\x0a\x0d\x0d\x0a"
            if section:
                order = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}.get(header[8:12])
                if order is None:
                    invalid("invalid PCAPNG byte-order marker")
            if order is None:
                invalid("missing PCAPNG section header")
            block_length = struct.unpack(order + "I", header[4:8])[0]
            if block_length < (28 if section else 12) or block_length % 4:
                invalid("invalid PCAPNG block length")
            if start + block_length > size:
                invalid("incomplete PCAPNG block")
            handle.seek(start + block_length - 4)
            trailer = handle.read(4)
            if struct.unpack(order + "I", trailer)[0] != block_length:
                invalid("PCAPNG block lengths disagree")


def parse_pcap(path, tshark_path=None):
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(
            f"PCAP file not found: {path}"
        )
    validate_capture_format(file_path)
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
                    raise ParserExtractionError(getattr(packet, 'number', '?'), parsed_count, error) from error
        except ParserExtractionError:
            raise
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
            process_handles = tuple(getattr(capture, "_running_processes", ()))
            try:
                capture.close()
            except Exception as error:
                # PyShark 0.6 can retain already-exited TShark processes after
                # malformed input. Remove only exited handles, then finish its
                # normal close so __del__ does not reuse a closed event loop.
                processes = getattr(capture, "_running_processes", None)
                if processes is not None:
                    for process in tuple(processes):
                        if process.returncode is not None:
                            processes.discard(process)
                try:
                    capture.close()
                except Exception as close_error:
                    logger.warning("Error while closing capture: %s", close_error)
                logger.debug("Initial capture close reported: %s", error)
            finally:
                # PyShark 0.6 can leave stdout pipes open after an early stop.
                # Close transports only for processes already confirmed exited.
                for process in process_handles:
                    transport = getattr(process, "_transport", None)
                    if process.returncode is not None and transport is not None:
                        transport.close()
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
        raise SystemExit(1)
