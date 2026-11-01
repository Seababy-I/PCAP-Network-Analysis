"""TCP SYN scan heuristics over normalized records or saved captures."""
from collections import defaultdict, deque
from os import PathLike

from capture_records import read_network_records

PORT_SCAN_THRESHOLD = 20


def parse_packets(file_path):
    return read_network_records(file_path)


def _scan(records, threshold, window_seconds, host_scan=False):
    if threshold < 1 or window_seconds <= 0:
        raise ValueError('Threshold and time window must be positive')
    groups = defaultdict(list)
    for packet in records:
        flags = int(packet.get('tcp_flags') or 0)
        if packet.get('protocol') != 'TCP' or not flags & 2 or flags & 16:
            continue
        if not packet.get('src_ip') or not packet.get('dst_ip') or packet.get('dst_port') is None:
            continue
        key = (packet['src_ip'], packet['dst_port'] if host_scan else packet['dst_ip'])
        groups[key].append(packet)
    alerts = []
    for (source, target), packets in sorted(groups.items(), key=lambda item: str(item[0])):
        queue, counts, best = deque(), defaultdict(int), None
        field = 'dst_ip' if host_scan else 'dst_port'
        for packet in sorted(packets, key=lambda p: p['timestamp']):
            now = packet['timestamp']
            while queue and queue[0]['timestamp'] < now - window_seconds:
                old = queue.popleft()[field]
                counts[old] -= 1
                if not counts[old]:
                    del counts[old]
            queue.append(packet)
            counts[packet[field]] += 1
            if len(counts) > threshold and (best is None or len(counts) > best['count']):
                best = dict(count=len(counts), first_seen=queue[0]['timestamp'], last_seen=now)
        if best:
            kind = 'Host' if host_scan else 'Port'
            detail = f'hosts on TCP/{target}' if host_scan else f'ports on {target}'
            alert = dict(type=f'Possible {kind} Scan', severity='Medium', source_ip=source,
                         threshold=threshold, window_seconds=window_seconds, rule_version=1, **best,
                         description=f'{source} contacted {best["count"]} distinct {detail} within {window_seconds:g} seconds (TCP SYN heuristic).')
            alert['destination_count' if host_scan else 'destination_port_count'] = best['count']
            alert['destination_port' if host_scan else 'destination_ip'] = target
            alerts.append(alert)
    return alerts


def detect_port_scan(source, threshold=PORT_SCAN_THRESHOLD, window_seconds=60):
    records = read_network_records(source) if isinstance(source, (str, PathLike)) else source
    return _scan(records, threshold, window_seconds)
