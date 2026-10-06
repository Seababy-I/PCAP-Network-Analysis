def calculate_tls_security_score(tls_record):
    """
    Calculate a simple TLS security score out of 100.
    """

    score = 100
    reasons = []

    tls_version = tls_record.get("tls_version")
    cipher = tls_record.get("cipher_selected")
    cert_not_after = tls_record.get("cert_not_after")
    is_self_signed = tls_record.get("is_self_signed")

    # --------------------------------
    # TLS version
    # --------------------------------

    if tls_version in {"SSLv3", "TLS 1.0", "TLS 1.1"}:
        score -= 30
        reasons.append("Deprecated TLS version")

    elif tls_version == "TLS 1.2":
        score -= 5
        reasons.append("TLS 1.2")

    elif tls_version == "TLS 1.3":
        reasons.append("Modern TLS 1.3")

    # --------------------------------
    # Cipher
    # --------------------------------

    if cipher:
        cipher_upper = cipher.upper()

        weak_ciphers = {
            "RC4",
            "3DES",
            "DES",
            "NULL",
            "EXPORT",
            "MD5"
        }

        if any(
            weak_cipher in cipher_upper
            for weak_cipher in weak_ciphers
        ):
            score -= 30
            reasons.append("Weak/deprecated cipher")

        else:
            reasons.append("Strong cipher")

    # --------------------------------
    # Certificate expiry
    # --------------------------------

    if cert_not_after:
        from datetime import datetime

        try:
            expiry = datetime.fromisoformat(cert_not_after)

            if expiry < datetime.now():
                score -= 25
                reasons.append("Certificate expired")

        except ValueError:
            pass

    # --------------------------------
    # Self-signed certificate
    # --------------------------------

    if is_self_signed is True:
        score -= 15
        reasons.append("Self-signed certificate")

    # Keep score between 0 and 100
    score = max(0, min(100, score))

    # --------------------------------
    # Risk level
    # --------------------------------

    if score >= 80:
        risk_level = "LOW"

    elif score >= 50:
        risk_level = "MEDIUM"

    else:
        risk_level = "HIGH"

    return {
        "score": score,
        "risk_level": risk_level,
        "reasons": reasons
    }