from crypto_utils import (
    secure_evidence,
    verify_evidence_file
)
from risk_scoring import calculate_risk_score
from database import (
    insert_evidence,
    insert_alert,
    query_alerts
)
from weak_crypto import detect_weak_tls
from tls_security import calculate_tls_security_score


pcap_path = "data/sample.pcap"
signature_path = "signatures/sample.pcap.sig"


# ==========================================
# 1. Secure the evidence
# ==========================================

hash_value, saved_signature = secure_evidence(pcap_path)

print("Evidence secured successfully!")
print("SHA-256:", hash_value)
print("Signature:", saved_signature)


# ==========================================
# Store Evidence in Database
# ==========================================

evidence_id = insert_evidence(
    filename=pcap_path,
    sha256=hash_value,
    signature=saved_signature
)

print("Evidence stored in database.")
print("Evidence ID:", evidence_id)


# ==========================================
# 2. Verify the evidence
# ==========================================

is_valid = verify_evidence_file(
    pcap_path,
    signature_path
)

print("\nEvidence Verification:")

if is_valid:
    print("VALID - Evidence has not been modified.")
else:
    print("INVALID - Evidence may have been modified.")


# ==========================================
# 3. TLS Security Analysis
# ==========================================

tls_record = {
    "tls_version": "TLS 1.0",
    "cipher_selected": "RC4-SHA",
    "cert_not_after": "2020-01-01T00:00:00",
    "is_self_signed": True
}


# ------------------------------------------
# 3A. Weak TLS / Cryptography Detection
# ------------------------------------------

tls_alerts = detect_weak_tls(tls_record)

print("\nWeak Cryptography Detection:")

for alert in tls_alerts:

    print(
        f"ALERT: {alert['type']} | "
        f"Severity: {alert['severity']}"
    )

    alert_id = insert_alert(
        packet_id=None,
        alert_type=alert["type"],
        severity=alert["severity"],
        description=alert["description"]
    )

    print(f"Stored in database as alert ID: {alert_id}")


# ------------------------------------------
# 3B. TLS Security Score
# ------------------------------------------

tls_score = calculate_tls_security_score(tls_record)

print("\nTLS Security Score:")
print("-------------------")
print(f"Score: {tls_score['score']} / 100")
print(f"Risk Level: {tls_score['risk_level']}")

print("Reasons:")

for reason in tls_score["reasons"]:
    print("-", reason)

# ==========================================
# 4. Overall Risk Scoring
# ==========================================

overall_risk = calculate_risk_score(tls_alerts)

print("\nOverall Security Risk:")
print("----------------------")
print(f"Risk Score: {overall_risk['score']} / 100")
print(f"Risk Level: {overall_risk['risk_level']}")

# ==========================================
# 5. Display Stored Alerts
# ==========================================

print("\nDatabase Alerts:")

alerts = query_alerts()

for alert in alerts:
    print(
        f"[{alert['alert_id']}] "
        f"{alert['alert_type']} - "
        f"{alert['severity']}"
    )