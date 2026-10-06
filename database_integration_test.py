from database import create_database, insert_alert
from detection import detect_port_scan
from database import insert_alert, query_alerts
from weak_crypto import detect_weak_tls

pcap_path = "data/detection_test.pcap"

# Make sure the database exists
create_database()

# Run our detection
alerts = detect_port_scan(pcap_path)

print("Detection alerts:", len(alerts))

# Insert each alert into SQLite
for alert in alerts:

    alert_id = insert_alert(
        packet_id=None,
        alert_type=alert["type"],
        severity=alert["severity"],
        description=alert["description"]
    )

    print(
        f"Inserted alert {alert_id}: "
        f"{alert['type']}"
    )

# ---------------------------------------
# Test weak TLS detection + database
# ---------------------------------------

tls_record = {
    "tls_version": "TLS 1.0",
    "cipher_selected": "RC4-SHA",
    "cert_not_after": "2020-01-01T00:00:00",
    "is_self_signed": True
}

alerts = detect_weak_tls(tls_record)

print(f"\nTLS Security Alerts: {len(alerts)}")

for alert in alerts:
    alert_id = insert_alert(
        packet_id=None,
        alert_type=alert["type"],
        severity=alert["severity"],
        description=alert["description"]
    )

    print(
        f"Inserted TLS alert {alert_id}: "
        f"{alert['type']} - {alert['severity']}"
    )