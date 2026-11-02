"""User-owned boundary checks for a teammate parser; contains no packet extraction."""
from datetime import datetime, timezone
import ipaddress
import json
import math
from numbers import Real

from capture_records import MAX_PACKETS, read_network_records
from security_detection import run_network_detection


class ParserContractError(ValueError):
    pass


def _integer(value, field, low, high=None, optional=False):
    if value is None and optional:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < low or (high is not None and value > high):
        raise ParserContractError(f'Invalid {field}: expected integer {low}..{high if high is not None else "unbounded"}')
    return value


def validate_record(record):
    if not isinstance(record, dict):
        raise ParserContractError('Parser must yield dictionaries')
    required = {'timestamp','frame_number','src_ip','dst_ip','protocol','src_port','dst_port',
                'length','tcp_flags','dns_records','http_records'}
    missing = required - record.keys()
    if missing:
        raise ParserContractError('Missing record fields: ' + ', '.join(sorted(missing)))
    value = {key:record[key] for key in required}
    timestamp = value['timestamp']
    if isinstance(timestamp, datetime):
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ParserContractError('Timestamp must be timezone-aware or numeric UTC epoch seconds')
        timestamp = timestamp.astimezone(timezone.utc).timestamp()
    if isinstance(timestamp, bool) or not isinstance(timestamp, Real) or not math.isfinite(timestamp):
        raise ParserContractError('Timestamp must be finite UTC epoch seconds')
    value['timestamp'] = float(timestamp)
    value['frame_number'] = _integer(value['frame_number'], 'frame_number', 1)
    value['length'] = _integer(value['length'], 'length', 0)
    protocol = value['protocol']
    if not isinstance(protocol, str) or not protocol.strip():
        raise ParserContractError('Protocol must be a nonempty string')
    value['protocol'] = protocol.upper()
    transport = value['protocol'] in ('TCP','UDP')
    for field in ('src_ip','dst_ip'):
        raw = value[field]
        if raw is None and not transport:
            continue
        if not isinstance(raw, str):
            raise ParserContractError(f'{field} must be a valid IP address')
        try:
            value[field] = str(ipaddress.ip_address(raw))
        except ValueError as error:
            raise ParserContractError(f'Invalid {field}: {raw}') from error
    for field in ('src_port','dst_port'):
        value[field] = _integer(value[field], field, 0, 65535, optional=not transport)
    value['tcp_flags'] = _integer(value['tcp_flags'], 'tcp_flags', 0, 4095, optional=value['protocol']!='TCP')
    for field, keys in [('dns_records', {'query_name','query_type','response_code','answers'}),
                        ('http_records', {'method','host','uri','status_code'})]:
        records = value[field]
        if not isinstance(records, list) or any(not isinstance(item, dict) or not keys <= item.keys() for item in records):
            raise ParserContractError(f'{field} must contain dictionaries with fields {sorted(keys)}')
        for item in records:
            if field == 'dns_records' and item['answers'] is not None and not isinstance(item['answers'], list):
                raise ParserContractError('DNS answers must be a list or None')
            if field == 'http_records':
                _integer(item['status_code'],'HTTP status_code',100,599,optional=True)
        try:
            value[field] = json.loads(json.dumps(records, allow_nan=False))
        except (TypeError, ValueError) as error:
            raise ParserContractError(f'{field} must contain finite JSON-compatible values') from error
    return value


def preview_capture(path, *, parser_fn, tshark_path=None):
    """Acceptance preview only. Does not sign, write evidence or alter a database.

    Compare frame coverage with the independent bounded reader so silent parser
    skips/duplicates cannot turn into a successful integration preview.
    """
    reference = read_network_records(path)
    records = []
    iterator = iter(parser_fn(path, tshark_path=tshark_path))
    try:
        for raw in iterator:
            if len(records) >= MAX_PACKETS:
                raise ParserContractError('Parser exceeded the preview packet limit')
            record = validate_record(raw)
            if record['frame_number'] != len(records) + 1:
                raise ParserContractError('Parser skipped, duplicated or reordered capture frame numbers')
            records.append(record)
    finally:
        close = getattr(iterator, 'close', None)
        if close is not None:
            close()
    if len(records) != len(reference):
        raise ParserContractError(f'Incomplete parser output: returned {len(records)} of {len(reference)} capture frames')
    return dict(status='PARSER_PREVIEW_ONLY', packet_count=len(records),
                dns_record_count=sum(len(record['dns_records']) for record in records),
                http_record_count=sum(len(record['http_records']) for record in records),
                alerts=run_network_detection(records), records=records,
                storage_status='Packet/DNS/HTTP/flow database integration pending')
