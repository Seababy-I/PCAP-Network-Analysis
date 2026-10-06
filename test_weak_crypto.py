from weak_crypto import detect_weak_tls


# Test case 1: Deprecated TLS
tls_test_1 = {
    "tls_version": "TLS 1.0",
    "cipher_selected": "AES128-SHA",
    "cert_not_after": "2030-01-01T00:00:00",
    "is_self_signed": False
}


# Test case 2: Weak cipher
tls_test_2 = {
    "tls_version": "TLS 1.2",
    "cipher_selected": "RC4-SHA",
    "cert_not_after": "2030-01-01T00:00:00",
    "is_self_signed": False
}


# Test case 3: Expired + self-signed certificate
tls_test_3 = {
    "tls_version": "TLS 1.2",
    "cipher_selected": "AES256-GCM-SHA384",
    "cert_not_after": "2020-01-01T00:00:00",
    "is_self_signed": True
}


tests = [
    ("Deprecated TLS", tls_test_1),
    ("Weak Cipher", tls_test_2),
    ("Expired/Self-Signed Certificate", tls_test_3)
]


for name, tls_record in tests:

    print("\n" + "=" * 50)
    print(name)
    print("=" * 50)

    alerts = detect_weak_tls(tls_record)

    if alerts:
        for alert in alerts:
            print("ALERT DETECTED")
            print("Type:", alert["type"])
            print("Severity:", alert["severity"])
            print("Description:", alert["description"])
    else:
        print("No weak cryptography detected.")