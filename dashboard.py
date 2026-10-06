import sqlite3
import streamlit as st
from risk_scoring import calculate_risk_score
from crypto_utils import verify_evidence_file
from database import add_audit_log,verify_audit_chain

DB_NAME = "forensic.db"


def get_database_connection():
    return sqlite3.connect(DB_NAME)


def get_alerts():
    conn = get_database_connection()

    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            alert_id,
            alert_type,
            severity,
            description,
            timestamp
        FROM alerts
        ORDER BY alert_id DESC
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows


def get_evidence():
    conn = get_database_connection()

    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            evidence_id,
            filename,
            sha256,
            import_time,
            signature
        FROM evidence
        ORDER BY evidence_id DESC
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows
st.set_page_config(
    page_title="PCAP Forensic Security Dashboard",
    page_icon="🔐",
    layout="wide"
)

st.title("🔐 PCAP Forensic Security Dashboard")
st.write("Cryptographically secured network traffic forensic analysis")

st.success("Dashboard connected successfully.")

alerts = get_alerts()
evidence = get_evidence()

# ==========================================
# Security Overview
# ==========================================

total_alerts = len(alerts)

high_alerts = sum(
    1 for alert in alerts
    if alert[2] == "High"
)

medium_alerts = sum(
    1 for alert in alerts
    if alert[2] == "Medium"
)

low_alerts = sum(
    1 for alert in alerts
    if alert[2] == "Low"
)
risk_alerts = [
    {
        "severity": alert[2]
    }
    for alert in alerts
]

overall_risk = calculate_risk_score(risk_alerts)

st.subheader("Security Overview")

col1, col2, col3, col4, col5 = st.columns(5)

col1.metric(
    "Total Alerts",
    total_alerts
)

col2.metric(
    "High Alerts",
    high_alerts
)

col3.metric(
    "Medium Alerts",
    medium_alerts
)

col4.metric(
    "Evidence Records",
    len(evidence)
)

col5.metric(
    "Overall Risk",
    f"{overall_risk['score']}/100",
    overall_risk["risk_level"]
)
# ==========================================
# Evidence Security
# ==========================================

st.subheader("🔐 Evidence Security")

if evidence:

    latest_evidence = evidence[0]

    evidence_id = latest_evidence[0]
    filename = latest_evidence[1]
    sha256 = latest_evidence[2]
    import_time = latest_evidence[3]
    signature = latest_evidence[4]

    st.write(f"**Evidence ID:** {evidence_id}")
    st.write(f"**Filename:** {filename}")
    st.write(f"**Imported:** {import_time}")

    st.write("**SHA-256 Hash:**")
    st.code(sha256)

    st.write(f"**RSA Signature:** `{signature}`")

    if st.button("Verify Evidence", key="verify_evidence"):
        try:
            is_valid = verify_evidence_file(
                filename,
                signature
            )

            if is_valid:

                st.success(
                    "✅ VALID — Evidence has not been modified."
                )

                add_audit_log(
                    evidence_id=evidence_id,
                    operation="VERIFY",
                    status="SUCCESS"
                )

                st.success(
                    "✅ Verification recorded in audit log."
                )

            else:

                st.error(
                    "❌ INVALID — Evidence may have been modified."
                )

                add_audit_log(
                    evidence_id=evidence_id,
                    operation="VERIFY",
                    status="FAILED"
                )

                st.warning(
                    "⚠️ Failed verification recorded in audit log."
                )

        except Exception as e:

            st.error(
                f"Verification failed: {e}"
            )

else:

    st.info("No evidence records available.")

# ==========================================
# Audit Chain Verification
# ==========================================

st.subheader("🔗 Audit Log Integrity")

if st.button("Verify Audit Chain", key="verify_audit_chain"):

    try:
        result = verify_audit_chain()

        if result:
            st.success(
                "✅ VALID — Audit log hash chain is intact."
            )
        else:
            st.error(
                "❌ INVALID — Audit log may have been modified."
            )

    except Exception as e:

        st.error(
            f"Audit chain verification failed: {e}"
        )
# ==========================================
# Detected Alerts
# ==========================================

st.subheader("Detected Security Alerts")

if alerts:

    for alert in alerts:

        alert_id = alert[0]
        alert_type = alert[1]
        severity = alert[2]
        description = alert[3]
        timestamp = alert[4]

        if severity == "High":
            st.error(
                f"🔴 **{alert_type}**  \n"
                f"Severity: **{severity}**  \n"
                f"{description}"
            )

        elif severity == "Medium":
            st.warning(
                f"🟠 **{alert_type}**  \n"
                f"Severity: **{severity}**  \n"
                f"{description}"
            )

        else:
            st.info(
                f"🔵 **{alert_type}**  \n"
                f"Severity: **{severity}**  \n"
                f"{description}"
            )

else:

    st.success("No security alerts detected.")