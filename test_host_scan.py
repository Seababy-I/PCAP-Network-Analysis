from host_scan import detect_host_scan


pcap_path = "data/host_scan_test.pcap"

alerts = detect_host_scan(pcap_path)


print("=" * 40)
print("HOST SCAN DETECTION")
print("=" * 40)


if not alerts:
    print("No host scan detected.")

else:

    for alert in alerts:

        print("ALERT:", alert["type"])
        print("Severity:", alert["severity"])
        print("Source IP:", alert["source_ip"])
        print(
            "Destination Hosts:",
            alert["destination_count"]
        )
        print("Description:", alert["description"])