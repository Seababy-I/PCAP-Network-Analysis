from detection import detect_port_scan
from weak_crypto import detect_weak_tls


def run_network_detection(pcap_path):
    """
    Run network-based security detection.
    """

    alerts = detect_port_scan(pcap_path)

    return alerts


def run_tls_detection(tls_record):
    """
    Run TLS and certificate security detection.
    """

    alerts = detect_weak_tls(tls_record)

    return alerts


def run_all_detection(pcap_path, tls_records=None):
    """
    Run all currently available security detection rules.
    """

    alerts = []

    # Port scan detection
    network_alerts = run_network_detection(pcap_path)
    alerts.extend(network_alerts)

    # TLS detection
    if tls_records:
        for tls_record in tls_records:
            tls_alerts = run_tls_detection(tls_record)
            alerts.extend(tls_alerts)

    return alerts