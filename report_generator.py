import sqlite3
from pathlib import Path
from datetime import datetime


DB_NAME = "forensic.db"
REPORT_DIR = Path("reports")
REPORT_FILE = REPORT_DIR / "forensic_report.html"


def get_data():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row

    evidence = conn.execute("""
        SELECT
            evidence_id,
            filename,
            sha256,
            import_time,
            signature
        FROM evidence
        ORDER BY evidence_id DESC
        LIMIT 1
    """).fetchone()

    alerts = conn.execute("""
        SELECT
            alert_id,
            alert_type,
            severity,
            description,
            timestamp
        FROM alerts
        ORDER BY alert_id DESC
    """).fetchall()

    conn.close()

    return evidence, alerts


def generate_report():
    """
    Generate an HTML forensic investigation report
    from the current SQLite database.
    """

    evidence, alerts = get_data()

    REPORT_DIR.mkdir(exist_ok=True)

    if evidence:
        evidence_section = f"""
        <h2>Evidence Information</h2>

        <table>
            <tr><th>Evidence ID</th><td>{evidence['evidence_id']}</td></tr>
            <tr><th>Filename</th><td>{evidence['filename']}</td></tr>
            <tr><th>SHA-256</th><td><code>{evidence['sha256']}</code></td></tr>
            <tr><th>Import Time</th><td>{evidence['import_time']}</td></tr>
            <tr><th>RSA Signature</th><td>{evidence['signature']}</td></tr>
        </table>
        """
    else:
        evidence_section = """
        <h2>Evidence Information</h2>
        <p>No evidence record is currently available.</p>
        """

    total_alerts = len(alerts)

    high_count = sum(
        1 for alert in alerts
        if alert["severity"] == "High"
    )

    medium_count = sum(
        1 for alert in alerts
        if alert["severity"] == "Medium"
    )

    low_count = sum(
        1 for alert in alerts
        if alert["severity"] == "Low"
    )

    alert_rows = ""

    for alert in alerts:

        severity_class = alert["severity"].lower()

        alert_rows += f"""
        <tr>
            <td>{alert['alert_id']}</td>
            <td>{alert['alert_type']}</td>
            <td class="{severity_class}">
                {alert['severity']}
            </td>
            <td>{alert['description']}</td>
            <td>{alert['timestamp']}</td>
        </tr>
        """

    if not alert_rows:
        alert_rows = """
        <tr>
            <td colspan="5">No security alerts detected.</td>
        </tr>
        """

    generated_time = datetime.now().isoformat()

    html = f"""
<!DOCTYPE html>
<html>
<head>

<meta charset="UTF-8">

<title>PCAP Forensic Investigation Report</title>

<style>

body {{
    font-family: Arial, sans-serif;
    margin: 40px;
    background: #f5f7fa;
    color: #222;
}}

h1 {{
    color: #1f2937;
}}

h2 {{
    margin-top: 30px;
}}

.summary {{
    display: flex;
    gap: 20px;
    margin: 20px 0;
}}

.card {{
    background: white;
    padding: 20px;
    border-radius: 8px;
    min-width: 140px;
    box-shadow: 0 1px 4px rgba(0,0,0,0.1);
}}

.card strong {{
    display: block;
    font-size: 24px;
    margin-top: 8px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    background: white;
}}

th, td {{
    border: 1px solid #ddd;
    padding: 10px;
    text-align: left;
}}

th {{
    background: #e5e7eb;
}}

.high {{
    color: #b91c1c;
    font-weight: bold;
}}

.medium {{
    color: #b45309;
    font-weight: bold;
}}

.low {{
    color: #166534;
    font-weight: bold;
}}

code {{
    word-break: break-all;
}}

.footer {{
    margin-top: 40px;
    font-size: 13px;
    color: #666;
}}

</style>

</head>

<body>

<h1>PCAP Forensic Investigation Report</h1>

<p>
Generated: {generated_time}
</p>

{evidence_section}

<h2>Security Summary</h2>

<div class="summary">

<div class="card">
Total Alerts
<strong>{total_alerts}</strong>
</div>

<div class="card">
High Severity
<strong>{high_count}</strong>
</div>

<div class="card">
Medium Severity
<strong>{medium_count}</strong>
</div>

<div class="card">
Low Severity
<strong>{low_count}</strong>
</div>

</div>

<h2>Detected Security Alerts</h2>

<table>

<tr>
<th>ID</th>
<th>Alert Type</th>
<th>Severity</th>
<th>Description</th>
<th>Timestamp</th>
</tr>

{alert_rows}

</table>

<div class="footer">

<p>
This report is generated from the PCAP forensic analysis database.
Heuristic alerts are indicators requiring further investigation and
do not by themselves establish malicious activity.
</p>

</div>

</body>
</html>
"""

    REPORT_FILE.write_text(
        html,
        encoding="utf-8"
    )

    return str(REPORT_FILE)