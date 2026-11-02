"""Network detection only; TLS analysis has been removed from the active workflow."""
from os import PathLike
from capture_records import read_network_records
from detection import detect_port_scan
from host_scan import detect_host_scan


def run_network_detection(source):
    records = read_network_records(source) if isinstance(source, (str, PathLike)) else list(source)
    return detect_port_scan(records) + detect_host_scan(records)


def run_all_detection(source):
    return run_network_detection(source)
