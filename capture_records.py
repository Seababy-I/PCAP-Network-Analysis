"""Temporary network-only reader. Does not replace the team's DNS/HTTP parser."""
import struct
import io
from pathlib import Path

from scapy.all import ARP, IP, IPv6, TCP, UDP, PcapReader

MAX_CAPTURE_BYTES = 20 * 1024 * 1024
MAX_PACKETS = 100000


def validate_container(path):
    """Reject damaged/truncated containers instead of silently treating them as clean."""
    if (len(path) if isinstance(path,bytes) else Path(path).stat().st_size) > MAX_CAPTURE_BYTES:
        raise ValueError('Capture exceeds the 20 MiB analysis limit')
    data = path if isinstance(path,bytes) else Path(path).read_bytes()
    magics = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>',
              b'\x4d\x3c\xb2\xa1': '<', b'\xa1\xb2\x3c\x4d': '>'}
    if data[:4] in magics:
        endian = magics[data[:4]]
        if len(data) < 24:
            raise ValueError('Truncated PCAP header')
        if struct.unpack(endian + 'HH', data[4:8]) != (2, 4):
            raise ValueError('Unsupported PCAP version')
        if struct.unpack(endian + 'I', data[20:24])[0] != 1:
            raise ValueError('Only Ethernet link-layer captures are supported currently')
        offset = 24
        while offset < len(data):
            if len(data) - offset < 16:
                raise ValueError('Truncated PCAP packet header')
            length = struct.unpack(endian + 'I', data[offset + 8:offset + 12])[0]
            original = struct.unpack(endian + 'I', data[offset + 12:offset + 16])[0]
            snaplen = struct.unpack(endian + 'I', data[16:20])[0]
            if length > original or length > snaplen:
                raise ValueError('Invalid PCAP captured/original length')
            offset += 16 + length
            if offset > len(data):
                raise ValueError('Truncated PCAP packet data')
    elif data[:4] == b'\x0a\x0d\x0d\x0a':
        offset, endian = 0, None
        while offset < len(data):
            if len(data) - offset < 12:
                raise ValueError('Truncated PCAPNG block')
            if data[offset:offset+4] == b'\x0a\x0d\x0d\x0a':
                bom = data[offset+8:offset+12]
                endian = {b'\x4d\x3c\x2b\x1a': '<', b'\x1a\x2b\x3c\x4d': '>'}.get(bom)
            if endian is None:
                raise ValueError('Invalid PCAPNG section')
            kind, length = struct.unpack(endian + 'II', data[offset:offset+8])
            if length < 12 or length % 4 or offset + length > len(data):
                raise ValueError('Invalid PCAPNG block length')
            if struct.unpack(endian + 'I', data[offset+length-4:offset+length])[0] != length:
                raise ValueError('PCAPNG block lengths disagree')
            if kind == 1 and (length < 20 or struct.unpack(endian+'H',data[offset+8:offset+10])[0] != 1):
                raise ValueError('Only Ethernet PCAPNG interfaces are supported currently')
            if kind == 6:
                if length < 32:
                    raise ValueError('Invalid enhanced packet block')
                captured = struct.unpack(endian+'I',data[offset+20:offset+24])[0]
                if 32 + ((captured + 3) // 4 * 4) > length:
                    raise ValueError('Truncated PCAPNG packet data')
            offset += length
    else:
        raise ValueError('Not a supported PCAP or PCAPNG capture')


def read_network_records(path):
    validate_container(path)
    records = []
    with PcapReader(io.BytesIO(path) if isinstance(path,bytes) else str(path)) as capture:
        for number, packet in enumerate(capture, 1):
            if number > MAX_PACKETS:
                raise ValueError('Capture exceeds the 100,000-packet analysis limit')
            record = dict(frame_number=number, timestamp=float(packet.time), length=len(packet),
                          src_ip=None, dst_ip=None, src_port=None, dst_port=None, protocol='OTHER', tcp_flags=0)
            network = packet[IP] if IP in packet else packet[IPv6] if IPv6 in packet else None
            if network is not None:
                record.update(src_ip=network.src, dst_ip=network.dst)
            if TCP in packet:
                record.update(protocol='TCP', src_port=int(packet[TCP].sport),
                              dst_port=int(packet[TCP].dport), tcp_flags=int(packet[TCP].flags))
            elif UDP in packet:
                record.update(protocol='UDP', src_port=int(packet[UDP].sport), dst_port=int(packet[UDP].dport))
            elif ARP in packet:
                record.update(protocol='ARP', src_ip=packet[ARP].psrc, dst_ip=packet[ARP].pdst)
            records.append(record)
    return records
