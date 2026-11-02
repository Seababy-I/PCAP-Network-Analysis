from tls_security import calculate_tls_security_score


# Strong TLS configuration
strong_tls = {
    "tls_version": "TLS 1.3",
    "cipher_selected": "AES256-GCM-SHA384",
    "cert_not_after": "2030-01-01T00:00:00",
    "is_self_signed": False
}


# Weak TLS configuration
weak_tls = {
    "tls_version": "TLS 1.0",
    "cipher_selected": "RC4-SHA",
    "cert_not_after": "2020-01-01T00:00:00",
    "is_self_signed": True
}


for name, record in [
    ("STRONG TLS", strong_tls),
    ("WEAK TLS", weak_tls)
]:

    result = calculate_tls_security_score(record)

    print("\n" + "=" * 40)
    print(name)
    print("=" * 40)

    print("Score:", result["score"], "/ 100")
    print("Risk Level:", result["risk_level"])

    print("Reasons:")

    for reason in result["reasons"]:
        print("-", reason)