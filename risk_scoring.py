def calculate_risk_score(alerts):
    """
    Calculate an overall security risk score from detected alerts.
    Higher score = higher risk.
    """

    severity_points = {
        "Low": 10,
        "Medium": 20,
        "High": 30,
        "Critical": 40
    }

    total_points = 0

    for alert in alerts:
        severity = alert.get("severity", "Low")
        total_points += severity_points.get(severity, 0)

    # Convert to a simple 0-100 scale.
    # More severe findings increase the score.
    score = min(total_points, 100)

    if score >= 75:
        risk_level = "CRITICAL"
    elif score >= 50:
        risk_level = "HIGH"
    elif score >= 25:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "score": score,
        "risk_level": risk_level
    }