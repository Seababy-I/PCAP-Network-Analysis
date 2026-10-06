from risk_scoring import calculate_risk_score


alerts = [
    {
        "alert_type": "Possible Port Scan",
        "severity": "Medium"
    },
    {
        "alert_type": "Weak Cipher Suite",
        "severity": "High"
    },
    {
        "alert_type": "Expired Certificate",
        "severity": "High"
    },
    {
        "alert_type": "Self-Signed Certificate",
        "severity": "Medium"
    }
]


result = calculate_risk_score(alerts)

print("=" * 40)
print("OVERALL SECURITY RISK")
print("=" * 40)

print("Risk Score:", result["score"], "/ 100")
print("Risk Level:", result["risk_level"])