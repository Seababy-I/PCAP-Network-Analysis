from detection import detect_port_scan
from host_scan import detect_host_scan
from weak_crypto import detect_weak_tls


def run_network_detection(pcap_path):
    alerts = []

    # Port scan detection
    alerts.extend(detect_port_scan(pcap_path))

    # Host scan detection
    alerts.extend(detect_host_scan(pcap_path))

    return alerts


def run_tls_detection(tls_record):
    return detect_weak_tls(tls_record)


def run_all_detection(pcap_path, tls_records=None):
    alerts = []

    # Network detection
    alerts.extend(run_network_detection(pcap_path))

    # TLS detection
    if tls_records:
        for tls_record in tls_records:
            alerts.extend(run_tls_detection(tls_record))

    return alerts