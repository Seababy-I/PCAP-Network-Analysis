from security_detection import run_network_detection


pcap_path = "data/host_scan_test.pcap"

alerts = run_network_detection(pcap_path)


print("=" * 40)
print("UNIFIED NETWORK DETECTION")
print("=" * 40)

for alert in alerts:
    print(
        f"{alert['type']} | "
        f"{alert['severity']} | "
        f"{alert['description']}"
    )