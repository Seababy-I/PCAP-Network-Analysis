from os import PathLike
from capture_records import read_network_records
from detection import _scan

HOST_SCAN_THRESHOLD = 20


def detect_host_scan(source, threshold=HOST_SCAN_THRESHOLD, window_seconds=60):
    records = read_network_records(source) if isinstance(source, (str, PathLike)) else source
    return _scan(records, threshold, window_seconds, host_scan=True)
