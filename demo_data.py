"""
Creates realistic sample packet records for demonstrating Aanya's
SQLite module before the real PyShark parser is integrated.

Run:
    python demo_data.py
"""

from database import (
    create_database,
    insert_evidence,
    insert_packets,
    insert_tls_record,
    insert_alert,
    count_packets_by_protocol,
)

DB_NAME = "forensic.db"


SAMPLE_PACKETS = [
    ("2026-10-06T08:30:01.100Z", "192.168.1.10", "192.168.1.1", "ARP", None, None, 42),
    ("2026-10-06T08:30:02.120Z", "192.168.1.10", "8.8.8.8", "UDP", 53001, 53, 74),
    ("2026-10-06T08:30:02.450Z", "8.8.8.8", "192.168.1.10", "UDP", 53, 53001, 118),
    ("2026-10-06T08:30:03.010Z", "192.168.1.10", "142.250.72.14", "TCP", 53002, 443, 66),
    ("2026-10-06T08:30:03.120Z", "142.250.72.14", "192.168.1.10", "TCP", 443, 53002, 66),
    ("2026-10-06T08:30:03.300Z", "192.168.1.10", "142.250.72.14", "TCP", 53002, 443, 517),
    ("2026-10-06T08:30:04.100Z", "142.250.72.14", "192.168.1.10", "TCP", 443, 53002, 1432),
    ("2026-10-06T08:30:05.000Z", "192.168.1.20", "192.168.1.10", "ICMP", None, None, 98),
    ("2026-10-06T08:30:06.000Z", "192.168.1.10", "192.168.1.50", "TCP", 54000, 22, 74),
    ("2026-10-06T08:30:06.100Z", "192.168.1.10", "192.168.1.51", "TCP", 54001, 22, 74),
]


def main():
    create_database(DB_NAME)

    evidence_id = insert_evidence(
        filename="sample.pcap",
        sha256="DEMO_SHA256_REPLACE_WITH_REAL_HASH",
        signature="DEMO_SIGNATURE_REPLACE_WITH_REAL_RSA_SIGNATURE",
        db_name=DB_NAME,
    )

    insert_packets(SAMPLE_PACKETS, db_name=DB_NAME)

    # Packet IDs are 1-based for a fresh demo database.
    # TLS record is attached to packet 4 (HTTPS/TCP).
    insert_tls_record(
        packet_id=4,
        tls_version="TLS 1.3",
        cipher_selected="TLS_AES_128_GCM_SHA256",
        sni="example.com",
        cert_issuer="Example CA",
        cert_not_before="2026-01-01",
        cert_not_after="2027-01-01",
        cert_sha256="DEMO_CERT_SHA256",
        is_self_signed=False,
        db_name=DB_NAME,
    )

    # Demonstration alert.
    insert_alert(
        packet_id=9,
        alert_type="Multiple Connection Attempts",
        severity="Medium",
        description="Several TCP connection attempts were observed to port 22.",
        timestamp="2026-10-06T08:30:06.100Z",
        db_name=DB_NAME,
    )

    print(f"Evidence inserted with ID: {evidence_id}")
    print("\nPacket counts:")
    for row in count_packets_by_protocol(DB_NAME):
        print(row)


if __name__ == "__main__":
    main()
