from security_detection import run_network_detection
from database import insert_alert, query_alerts


pcap_path = "data/host_scan_test.pcap"


# ==========================================
# Run network detection
# ==========================================

alerts = run_network_detection(pcap_path)

print("=" * 40)
print("HOST SCAN + DATABASE INTEGRATION")
print("=" * 40)


# ==========================================
# Store detected alerts
# ==========================================

for alert in alerts:

    alert_id = insert_alert(
        packet_id=None,
        alert_type=alert["type"],
        severity=alert["severity"],
        description=alert["description"]
    )

    print(
        f"Stored alert {alert_id}: "
        f"{alert['type']} - {alert['severity']}"
    )


# ==========================================
# Verify database
# ==========================================

print("\nDatabase Alerts:")

for alert in query_alerts():

    print(
        f"[{alert['alert_id']}] "
        f"{alert['alert_type']} - "
        f"{alert['severity']}"
    )