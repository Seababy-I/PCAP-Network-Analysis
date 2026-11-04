from security_detection import run_all_detection


pcap_path = "data/detection_test.pcap"


tls_records = [
    {
        "tls_version": "TLS 1.0",
        "cipher_selected": "RC4-SHA",
        "cert_not_after": "2020-01-01T00:00:00",
        "is_self_signed": True
    }
]


alerts = run_all_detection(
    pcap_path,
    tls_records
)


print("================================")
print("COMBINED SECURITY DETECTION")
print("================================")

print("Total Alerts:", len(alerts))

for alert in alerts:
    print("\nALERT")
    print("Type:", alert["type"])
    print("Severity:", alert["severity"])
    print("Description:", alert["description"])
    