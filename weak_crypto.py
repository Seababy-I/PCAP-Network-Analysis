from datetime import datetime


# Deprecated / insecure TLS versions
DEPRECATED_TLS = {
    "SSLv3",
    "TLS 1.0",
    "TLS 1.1"
}


# Examples of weak / deprecated cipher suites
WEAK_CIPHERS = {
    "RC4",
    "3DES",
    "DES",
    "NULL",
    "EXPORT",
    "MD5"
}


def detect_weak_tls(tls_record):
    """
    Analyze one TLS record and return security alerts.
    """

    alerts = []

    tls_version = tls_record.get("tls_version")
    cipher = tls_record.get("cipher_selected")
    cert_not_after = tls_record.get("cert_not_after")
    is_self_signed = tls_record.get("is_self_signed")

    # 1. Deprecated TLS version
    if tls_version in DEPRECATED_TLS:
        alerts.append({
            "type": "Deprecated TLS Version",
            "severity": "High",
            "description": f"{tls_version} is deprecated and insecure."
        })

    # 2. Weak cipher suite
    if cipher:
        cipher_upper = cipher.upper()

        for weak_cipher in WEAK_CIPHERS:
            if weak_cipher in cipher_upper:
                alerts.append({
                    "type": "Weak Cipher Suite",
                    "severity": "High",
                    "description": f"Weak/deprecated cipher detected: {cipher}"
                })
                break

    # 3. Expired certificate
    if cert_not_after:
        try:
            expiry = datetime.fromisoformat(cert_not_after)

            if expiry < datetime.now():
                alerts.append({
                    "type": "Expired Certificate",
                    "severity": "High",
                    "description": f"Certificate expired on {cert_not_after}."
                })

        except ValueError:
            pass

    # 4. Self-signed certificate
    if is_self_signed is True:
        alerts.append({
            "type": "Self-Signed Certificate",
            "severity": "Medium",
            "description": "Certificate is self-signed."
        })

    return alerts