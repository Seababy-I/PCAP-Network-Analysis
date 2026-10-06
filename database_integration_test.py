from database import create_database, insert_alert
from detection import detect_port_scan


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