"""

PCAP Forensic Security Dashboard

Polished dark-mode SOC / digital-forensics interface.

All original functionality preserved; only presentation changed.

"""

from html import escape
from textwrap import dedent

import sqlite3

import streamlit as st

from risk_scoring import calculate_risk_score

from crypto_utils import (

    verify_evidence_file,

    sign_report,

    verify_report,

)

from database import add_audit_log, verify_audit_chain

from report_generator import generate_report



# ──────────────────────────────────────────────────────────────────────────────

# Constants

# ──────────────────────────────────────────────────────────────────────────────

DB_NAME = "forensic.db"



SEVERITY_ICON = {

    "High":     "🔴",

    "Medium":   "🟡",

    "Low":      "🔵",

    "Critical": "🟣",

}



# ──────────────────────────────────────────────────────────────────────────────

# Page config  (must be first Streamlit call)

# ──────────────────────────────────────────────────────────────────────────────

st.set_page_config(

    page_title="PCAP Forensic Dashboard",

    page_icon="🛡️",

    layout="wide",

    initial_sidebar_state="expanded",

)



# ──────────────────────────────────────────────────────────────────────────────

# Custom CSS — dark navy/charcoal + cyan accents

# ──────────────────────────────────────────────────────────────────────────────

st.markdown("""

<style>

@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');



html, body, [class*="css"] { font-family: 'Inter', sans-serif !important; }



.stApp { background: #0d1117 !important; color: #c9d1d9 !important; }



[data-testid="stSidebar"] {

    background: #161b22 !important;

    border-right: 1px solid #21262d !important;

}

[data-testid="stSidebar"] * { color: #c9d1d9 !important; }



[data-testid="stMetric"] {

    background: #161b22 !important;

    border: 1px solid #21262d !important;

    border-radius: 10px !important;

    padding: 16px 20px !important;

}

[data-testid="stMetricLabel"] {

    font-size: 0.72rem !important; font-weight: 600 !important;

    letter-spacing: 0.08em !important; text-transform: uppercase !important;

    color: #8b949e !important;

}

[data-testid="stMetricValue"] {

    font-size: 2rem !important; font-weight: 700 !important;

    color: #e6edf3 !important; line-height: 1.1 !important;

}



.section-header {

    display: flex; align-items: center; gap: 10px;

    margin: 28px 0 14px 0; padding-bottom: 8px;

    border-bottom: 1px solid #21262d;

}

.section-header .icon { font-size: 1.05rem; color: #22d3ee; }

.section-header h3 {

    margin: 0; font-size: 0.88rem; font-weight: 600;

    letter-spacing: 0.06em; text-transform: uppercase; color: #8b949e;

}



.card {

    background: #161b22; border: 1px solid #21262d;

    border-radius: 10px; padding: 20px 22px; margin-bottom: 14px;

}

.card-title {

    font-size: 0.72rem; font-weight: 600; letter-spacing: 0.08em;

    text-transform: uppercase; color: #8b949e; margin-bottom: 4px;

}

.card-value { font-size: 1.35rem; font-weight: 700; color: #22d3ee; }



.risk-badge {

    display: inline-block; padding: 4px 12px; border-radius: 20px;

    font-size: 0.73rem; font-weight: 700; letter-spacing: 0.06em;

}

.risk-CRITICAL { background:rgba(168,85,247,.15); color:#a855f7; border:1px solid #a855f7; }

.risk-HIGH     { background:rgba(239,68,68,.15);  color:#ef4444; border:1px solid #ef4444; }

.risk-MEDIUM   { background:rgba(245,158,11,.15); color:#f59e0b; border:1px solid #f59e0b; }

.risk-LOW      { background:rgba(34,211,238,.15); color:#22d3ee; border:1px solid #22d3ee; }



.info-grid {

    display: grid; grid-template-columns: 160px 1fr;

    gap: 8px 16px; font-size: 0.84rem;

}

.info-label { color: #8b949e; font-weight: 500; }

.info-value { color: #e6edf3; word-break: break-all; }

.mono {

    font-family: 'JetBrains Mono', monospace; font-size: 0.76rem;

    color: #22d3ee; background: #0d1117; padding: 2px 6px;

    border-radius: 4px; word-break: break-all;

}



.sev-High     { color: #ef4444; font-weight: 700; }

.sev-Medium   { color: #f59e0b; font-weight: 700; }

.sev-Low      { color: #22d3ee; font-weight: 600; }

.sev-Critical { color: #a855f7; font-weight: 700; }



.alert-row {

    display: grid;

    grid-template-columns: 52px 1fr 90px 1fr 190px;

    gap: 0 12px; align-items: center;

    padding: 10px 14px; border-bottom: 1px solid #21262d;

    font-size: 0.81rem; transition: background 0.15s;

}

.alert-row:hover { background: #1c2128; }

.alert-row:last-child { border-bottom: none; }

.alert-header {

    display: grid;

    grid-template-columns: 52px 1fr 90px 1fr 190px;

    gap: 0 12px; padding: 8px 14px;

    font-size: 0.68rem; font-weight: 600;

    letter-spacing: 0.08em; text-transform: uppercase;

    color: #6e7681; background: #0d1117;

    border-bottom: 1px solid #21262d; border-radius: 8px 8px 0 0;

}

.alert-id   { color: #8b949e; font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; }

.alert-type { color: #e6edf3; font-weight: 600; }

.alert-desc { color: #8b949e; }

.alert-ts   { color: #6e7681; font-family: 'JetBrains Mono', monospace; font-size: 0.70rem; }



.stButton > button {

    background: transparent !important;

    border: 1px solid #30363d !important;

    color: #c9d1d9 !important; border-radius: 6px !important;

    font-size: 0.82rem !important; font-weight: 600 !important;

    padding: 8px 18px !important; letter-spacing: 0.02em !important;

    transition: all 0.18s !important; width: 100% !important;

}

.stButton > button:hover {

    border-color: #22d3ee !important; color: #22d3ee !important;

    background: rgba(34,211,238,0.06) !important;

    box-shadow: 0 0 10px rgba(34,211,238,0.12) !important;

}



.stTextInput input {

    background: #161b22 !important; border: 1px solid #30363d !important;

    color: #e6edf3 !important; border-radius: 6px !important; font-size: 0.83rem !important;

}

.stTextInput input:focus {

    border-color: #22d3ee !important;

    box-shadow: 0 0 0 3px rgba(34,211,238,0.12) !important;

}



.stAlert { border-radius: 8px !important; font-size: 0.83rem !important; }

hr { border-color: #21262d !important; }



::-webkit-scrollbar { width: 6px; height: 6px; }

::-webkit-scrollbar-track { background: #0d1117; }

::-webkit-scrollbar-thumb { background: #21262d; border-radius: 4px; }

::-webkit-scrollbar-thumb:hover { background: #30363d; }



.ledger-row {

    display: grid;

    grid-template-columns: 52px 1fr 100px 1fr 190px;

    gap: 0 10px; align-items: center;

    padding: 9px 14px; border-bottom: 1px solid #21262d;

    font-size: 0.79rem; transition: background 0.15s;

}

.ledger-row:hover { background: #1c2128; }

.ledger-row:last-child { border-bottom: none; }

.ledger-header {

    display: grid;

    grid-template-columns: 52px 1fr 100px 1fr 190px;

    gap: 0 10px; padding: 8px 14px;

    font-size: 0.67rem; font-weight: 600;

    letter-spacing: 0.08em; text-transform: uppercase;

    color: #6e7681; background: #0d1117;

    border-bottom: 1px solid #21262d; border-radius: 8px 8px 0 0;

}

</style>

""", unsafe_allow_html=True)





# ──────────────────────────────────────────────────────────────────────────────

# Database helpers  (identical logic to original)

# ──────────────────────────────────────────────────────────────────────────────



def get_database_connection():

    return sqlite3.connect(DB_NAME)





def get_alerts():

    conn = get_database_connection()

    cursor = conn.cursor()

    cursor.execute("""

        SELECT alert_id, alert_type, severity, description, timestamp

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

        SELECT evidence_id, filename, sha256, import_time, signature

        FROM evidence

        ORDER BY evidence_id DESC

    """)

    rows = cursor.fetchall()

    conn.close()

    return rows





def get_audit_log(limit=50):

    conn = get_database_connection()

    conn.row_factory = sqlite3.Row

    rows = conn.execute("""

        SELECT id, evidence_id, operation, status, timestamp,

               prev_hash, entry_hash

        FROM audit_log

        ORDER BY id DESC

        LIMIT ?

    """, (limit,)).fetchall()

    conn.close()

    return [dict(r) for r in rows]





# ──────────────────────────────────────────────────────────────────────────────

# Sidebar — navigation + branding

# ──────────────────────────────────────────────────────────────────────────────



with st.sidebar:

    st.markdown(dedent("""
        <div style="padding:16px 8px 24px 8px;border-bottom:1px solid #21262d;margin-bottom:20px;">
            <div style="display:flex;align-items:center;gap:10px;">
                <span style="font-size:1.6rem;">🛡️</span>
                <div>
                    <div style="font-size:0.95rem;font-weight:700;color:#e6edf3;">ForensicX</div>
                    <div style="font-size:0.7rem;color:#8b949e;letter-spacing:0.05em;">PCAP · NETWORK · FORENSICS</div>
                </div>
            </div>
        </div>
    """).strip(), unsafe_allow_html=True)



    PAGES = [

        ("📊", "Overview"),

        ("🚨", "Alerts"),

        ("🔐", "Evidence Security"),

        ("🔗", "Audit Log"),

        ("📄", "Reports"),

    ]



    if "page" not in st.session_state:

        st.session_state.page = "Overview"



    for icon, name in PAGES:

        if st.button(f"{icon}  {name}", key=f"nav_{name}", use_container_width=True):

            st.session_state.page = name

            st.rerun()



    st.markdown("<div style='height:24px'></div>", unsafe_allow_html=True)

    st.markdown(dedent("""
        <div style='font-size:0.68rem;color:#6e7681;padding:0 6px;'>
            <div style='margin-bottom:6px;font-weight:600;letter-spacing:0.06em;text-transform:uppercase;'>Database</div>
            <div>forensic.db · SQLite</div>
            <div style='margin-top:12px;font-weight:600;letter-spacing:0.06em;text-transform:uppercase;'>Crypto</div>
            <div>RSA-2048 · PSS · SHA-256</div>
            <div style='margin-top:12px;font-weight:600;letter-spacing:0.06em;text-transform:uppercase;'>Chain</div>
            <div>SHA-256 Hash Chain</div>
        </div>
    """).strip(), unsafe_allow_html=True)





# ──────────────────────────────────────────────────────────────────────────────

# Load data (once per run)

# ──────────────────────────────────────────────────────────────────────────────

alerts    = get_alerts()

evidence  = get_evidence()

audit_log = get_audit_log()



total_alerts  = len(alerts)

high_alerts   = sum(1 for a in alerts if a[2] == "High")

medium_alerts = sum(1 for a in alerts if a[2] == "Medium")

low_alerts    = sum(1 for a in alerts if a[2] == "Low")



risk_alerts  = [{"severity": a[2]} for a in alerts]

overall_risk = calculate_risk_score(risk_alerts)



# Latest evidence record (for Evidence Security & Report pages)

latest_evidence = evidence[0] if evidence else None

if latest_evidence:

    ev_id, ev_file, ev_sha, ev_time, ev_sig = latest_evidence





# ──────────────────────────────────────────────────────────────────────────────

# Helper — section header

# ──────────────────────────────────────────────────────────────────────────────

def section_header(icon: str, title: str):

    st.markdown(

        f'<div class="section-header">'

        f'<span class="icon">{escape(str(icon))}</span>'

        f'<h3>{escape(str(title))}</h3></div>',

        unsafe_allow_html=True,

    )



# ──────────────────────────────────────────────────────────────────────────────

# Helper — render alert table

# ──────────────────────────────────────────────────────────────────────────────

def _render_alert_table(alert_list):

    header = (

        '<div class="card" style="padding:0;overflow:hidden;">'

        '<div class="alert-header">'

        '<span>ID</span><span>Alert Type</span>'

        '<span>Severity</span><span>Description</span>'

        '<span>Timestamp</span>'

        '</div>'

    )



    rows_html = ""



    severity_classes = {

        "High": "sev-High",

        "Medium": "sev-Medium",

        "Low": "sev-Low",

        "Critical": "sev-Critical",

    }



    for alert in alert_list:

        aid, atype, sev, desc, ts = (

            alert[0], alert[1], alert[2], alert[3], alert[4]

        )



        icon = SEVERITY_ICON.get(sev, "⚪")

        sev_class = severity_classes.get(sev, "sev-Low")



        safe_type = escape(str(atype or "—"))

        safe_severity = escape(str(sev or "Unknown"))

        safe_description = escape(str(desc or ""))

        safe_timestamp = escape(

            str(ts[:19].replace("T", " ")) if ts else "—"

        )



        rows_html += (

            '<div class="alert-row">'

            f'<span class="alert-id">#{aid:04d}</span>'

            f'<span class="alert-type">{safe_type}</span>'

            f'<span class="{sev_class}">{icon} {safe_severity}</span>'

            f'<span class="alert-desc">{safe_description}</span>'

            f'<span class="alert-ts">{safe_timestamp}</span>'

            '</div>'

        )



    st.markdown(

        header + rows_html + "</div>",

        unsafe_allow_html=True,

    )

# ──────────────────────────────────────────────────────────────────────────────

# PAGE: Overview

# ──────────────────────────────────────────────────────────────────────────────

def page_overview():

    st.markdown(

        '<div style="margin-bottom:24px;">'

        '<div style="font-size:1.45rem;font-weight:700;color:#e6edf3;">Security Overview</div>'

        '<div style="font-size:0.82rem;color:#8b949e;margin-top:3px;">'

        'Cryptographically secured network traffic forensic analysis</div>'

        '</div>',

        unsafe_allow_html=True,

    )



    c1, c2, c3, c4, c5 = st.columns(5)

    c1.metric("Total Alerts",     total_alerts)

    c2.metric("High Severity",    high_alerts)

    c3.metric("Medium Severity",  medium_alerts)

    c4.metric("Low Severity",     low_alerts)

    c5.metric("Evidence Records", len(evidence))



    # Keep values used in HTML/CSS constrained to known-safe values.
    risk_score = max(0, min(100, int(overall_risk.get("score", 0))))
    risk_level = str(overall_risk.get("risk_level", "LOW") or "LOW")
    risk_classes = {
        "CRITICAL": "risk-CRITICAL",
        "HIGH": "risk-HIGH",
        "MEDIUM": "risk-MEDIUM",
        "LOW": "risk-LOW",
    }
    risk_cls = risk_classes.get(risk_level.upper(), "risk-LOW")
    safe_risk_level = escape(risk_level)

    st.markdown(

        f'<div class="card" style="margin-top:18px;display:flex;align-items:center;'

        f'justify-content:space-between;flex-wrap:wrap;gap:12px;">'

        f'<div><div class="card-title">Overall Risk Score</div>'

        f'<div style="display:flex;align-items:baseline;gap:10px;margin-top:4px;">'

        f'<span style="font-size:2.5rem;font-weight:700;color:#e6edf3;">{risk_score}</span>'

        f'<span style="font-size:1rem;color:#6e7681;">/&nbsp;100</span></div></div>'

        f'<div><span class="risk-badge {risk_cls}">{safe_risk_level}</span></div>'

        f'<div style="flex:1;min-width:180px;">'

        f'<div style="height:8px;background:#21262d;border-radius:4px;overflow:hidden;margin-top:6px;">'

        f'<div style="width:{risk_score}%;height:100%;'

        f'background:linear-gradient(90deg,#22d3ee,#ef4444);border-radius:4px;"></div></div>'

        f'<div style="display:flex;justify-content:space-between;font-size:0.68rem;'

        f'color:#6e7681;margin-top:4px;"><span>0</span><span>50</span><span>100</span></div>'

        f'</div></div>',

        unsafe_allow_html=True,

    )



    section_header("🚨", "Alert Distribution")

    col_h, col_m, col_l = st.columns(3)

    with col_h:

        pct = round(high_alerts / total_alerts * 100) if total_alerts else 0

        st.markdown(

            f'<div class="card" style="border-left:3px solid #ef4444;">'

            f'<div class="card-title" style="color:#ef4444;">High Severity</div>'

            f'<div style="font-size:2rem;font-weight:700;color:#ef4444;margin-top:4px;">{high_alerts}</div>'

            f'<div style="font-size:0.75rem;color:#6e7681;margin-top:2px;">{pct}% of total</div></div>',

            unsafe_allow_html=True,

        )

    with col_m:

        pct = round(medium_alerts / total_alerts * 100) if total_alerts else 0

        st.markdown(

            f'<div class="card" style="border-left:3px solid #f59e0b;">'

            f'<div class="card-title" style="color:#f59e0b;">Medium Severity</div>'

            f'<div style="font-size:2rem;font-weight:700;color:#f59e0b;margin-top:4px;">{medium_alerts}</div>'

            f'<div style="font-size:0.75rem;color:#6e7681;margin-top:2px;">{pct}% of total</div></div>',

            unsafe_allow_html=True,

        )

    with col_l:

        pct = round(low_alerts / total_alerts * 100) if total_alerts else 0

        st.markdown(

            f'<div class="card" style="border-left:3px solid #22d3ee;">'

            f'<div class="card-title" style="color:#22d3ee;">Low Severity</div>'

            f'<div style="font-size:2rem;font-weight:700;color:#22d3ee;margin-top:4px;">{low_alerts}</div>'

            f'<div style="font-size:0.75rem;color:#6e7681;margin-top:2px;">{pct}% of total</div></div>',

            unsafe_allow_html=True,

        )



    section_header("🕐", "Recent Alerts (Latest 5)")

    recent = alerts[:5]

    if recent:

        _render_alert_table(recent)

    else:

        st.info("No alerts in database.")





# ──────────────────────────────────────────────────────────────────────────────

# PAGE: Alerts  (searchable / filterable table)

# ──────────────────────────────────────────────────────────────────────────────

def page_alerts():

    st.markdown(

        '<div style="margin-bottom:24px;">'

        '<div style="font-size:1.45rem;font-weight:700;color:#e6edf3;">Security Alerts</div>'

        '<div style="font-size:0.82rem;color:#8b949e;margin-top:3px;">'

        'Searchable, filterable alert log from the forensic database</div>'

        '</div>',

        unsafe_allow_html=True,

    )



    fc1, fc2 = st.columns([3, 1.5])

    with fc1:

        search_text = st.text_input(

            "Search",

            placeholder="🔍  alert type or description…",

            label_visibility="collapsed",

            key="alert_search",

        )

    with fc2:

        severity_filter = st.selectbox(

            "Severity",

            ["All Severities", "High", "Medium", "Low"],

            label_visibility="collapsed",

            key="alert_sev_filter",

        )



    # Apply filters (identical logic to original)

    filtered = alerts



    if search_text:

        q = search_text.lower()

        filtered = [a for a in filtered if q in a[1].lower() or q in a[3].lower()]



    if severity_filter != "All Severities":

        filtered = [a for a in filtered if a[2] == severity_filter]



    total_shown = len(filtered)

    hi = sum(1 for a in filtered if a[2] == "High")

    me = sum(1 for a in filtered if a[2] == "Medium")

    lo = sum(1 for a in filtered if a[2] == "Low")

    st.markdown(

        f'<div style="display:flex;gap:20px;margin:14px 0 18px 0;'

        f'font-size:0.78rem;color:#8b949e;align-items:center;">'

        f'<span><b style="color:#e6edf3;">{total_shown}</b> alert(s) shown</span>'

        f'<span style="color:#ef4444;">● {hi} High</span>'

        f'<span style="color:#f59e0b;">● {me} Medium</span>'

        f'<span style="color:#22d3ee;">● {lo} Low</span>'

        f'</div>',

        unsafe_allow_html=True,

    )



    if filtered:

        _render_alert_table(filtered)

    else:

        if search_text or severity_filter != "All Severities":

            st.info("No alerts match the current filters.")

        else:

            st.success("✅ No security alerts detected.")





# ──────────────────────────────────────────────────────────────────────────────

# PAGE: Evidence Security

# ──────────────────────────────────────────────────────────────────────────────

def page_evidence():

    st.markdown(

        '<div style="margin-bottom:24px;">'

        '<div style="font-size:1.45rem;font-weight:700;color:#e6edf3;">Evidence Security</div>'

        '<div style="font-size:0.82rem;color:#8b949e;margin-top:3px;">'

        'Cryptographic integrity verification for PCAP evidence</div>'

        '</div>',

        unsafe_allow_html=True,

    )



    if not latest_evidence:

        st.info("No evidence records found in the database.")

        return



    section_header("📋", "Evidence Record")

    st.markdown(

        f'<div class="card">'

        f'<div class="info-grid">'

        f'<span class="info-label">Evidence ID</span><span class="info-value">#{ev_id}</span>'

        f'<span class="info-label">Filename</span><span class="info-value">{escape(str(ev_file or "—"))}</span>'

        f'<span class="info-label">Imported</span><span class="info-value">{escape(str(ev_time or "—"))}</span>'

        f'<span class="info-label">Signature Path</span><span class="mono">{escape(str(ev_sig or "—"))}</span>'

        f'</div></div>',

        unsafe_allow_html=True,

    )



    section_header("#", "SHA-256 Hash")

    st.code(ev_sha or "—", language=None)



    section_header("✅", "Integrity Verification")

    if st.button("🔍  Verify Evidence", key="verify_evidence"):

        try:

            is_valid = verify_evidence_file(ev_file, ev_sig)

            if is_valid:

                st.success("✅ VALID — Evidence has not been tampered with.")

                add_audit_log(evidence_id=ev_id, operation="VERIFY", status="SUCCESS")

                st.success("📋 Verification recorded in audit log.")

            else:

                st.error("❌ INVALID — Evidence may have been modified.")

                add_audit_log(evidence_id=ev_id, operation="VERIFY", status="FAILED")

                st.warning("⚠️ Failed verification recorded in audit log.")

        except Exception as e:

            st.error(f"Verification error: {e}")



    if len(evidence) > 1:

        section_header("📁", "All Evidence Records")

        header_html = (

            '<div class="card" style="padding:0;overflow:hidden;">'

            '<div style="display:grid;grid-template-columns:48px 2fr 3fr 2fr;gap:0 12px;'

            'padding:8px 14px;font-size:0.68rem;font-weight:600;letter-spacing:0.08em;'

            'text-transform:uppercase;color:#6e7681;background:#0d1117;'

            'border-bottom:1px solid #21262d;border-radius:8px 8px 0 0;">'

            '<span>ID</span><span>Filename</span><span>SHA-256</span><span>Imported</span>'

            '</div>'

        )

        rows_html = ""

        for rec in evidence:

            rid, rfile, rsha, rtime, _ = rec

            rsha_short = (rsha[:12] + "…") if rsha else "—"

            rtime_short = rtime[:19].replace("T", " ") if rtime else "—"

            safe_filename = escape(str(rfile or "—"))

            safe_hash = escape(str(rsha_short))

            safe_import_time = escape(str(rtime_short))

            rows_html += (

                f'<div style="display:grid;grid-template-columns:48px 2fr 3fr 2fr;gap:0 12px;'

                f'padding:10px 14px;border-bottom:1px solid #21262d;font-size:0.80rem;align-items:center;">'

                f'<span style="color:#8b949e;font-family:monospace;">#{rid}</span>'

                f'<span style="color:#e6edf3;">{safe_filename}</span>'

                f'<span class="mono">{safe_hash}</span>'

                f'<span style="color:#8b949e;font-family:monospace;font-size:0.72rem;">{safe_import_time}</span>'

                f'</div>'

            )

        st.markdown(header_html + rows_html + "</div>", unsafe_allow_html=True)





# ──────────────────────────────────────────────────────────────────────────────

# PAGE: Audit Log

# ──────────────────────────────────────────────────────────────────────────────

def page_audit():

    st.markdown(

        '<div style="margin-bottom:24px;">'

        '<div style="font-size:1.45rem;font-weight:700;color:#e6edf3;">Audit Log &amp; Chain Integrity</div>'

        '<div style="font-size:0.82rem;color:#8b949e;margin-top:3px;">'

        'SHA-256 hash-chained forensic audit trail</div>'

        '</div>',

        unsafe_allow_html=True,

    )



    section_header("🔗", "Hash Chain Verification")

    if st.button("🔗  Verify Audit Chain", key="verify_audit_chain"):

        try:

            result = verify_audit_chain()

            if isinstance(result, tuple):

                valid, msg = result

            else:

                valid, msg = bool(result), ""

            if valid:

                st.success(f"✅ VALID — Audit log hash chain is intact. {msg}".strip())

            else:

                st.error(f"❌ INVALID — {msg or 'Audit log may have been modified.'}")

        except Exception as e:

            st.error(f"Audit chain verification failed: {e}")



    section_header("📋", f"Recent Audit Entries (Latest {len(audit_log)})")



    if not audit_log:

        st.info("No audit log entries found.")

        return



    op_colors     = {"VERIFY": "#22d3ee", "REPORT_SIGN": "#a855f7", "IMPORT": "#3fb950"}

    status_colors = {"SUCCESS": "#3fb950", "FAILED": "#ef4444"}



    header = (

        '<div class="card" style="padding:0;overflow:hidden;">'

        '<div class="ledger-header">'

        '<span>ID</span><span>Operation</span><span>Status</span>'

        '<span>Entry Hash</span><span>Timestamp</span>'

        '</div>'

    )

    rows_html = ""

    for entry in audit_log:

        op    = entry["operation"]

        st_v  = entry["status"]

        ts    = (entry["timestamp"] or "")[:19].replace("T", " ")

        ehash = (entry["entry_hash"] or "")[:14] + "…"

        op_c  = op_colors.get(op, "#8b949e")

        st_c  = status_colors.get(st_v, "#8b949e")

        safe_operation = escape(str(op or ""))

        safe_hash = escape(str(ehash))

        safe_status = escape(str(st_v or ""))

        safe_timestamp = escape(str(ts))

        rows_html += (

            f'<div class="ledger-row">'

            f'<span style="color:#8b949e;font-family:monospace;font-size:0.72rem;">#{entry["id"]:04d}</span>'

            f'<span style="color:{op_c};font-weight:600;">{safe_operation}</span>'

            f'<span style="color:{st_c};font-size:0.75rem;font-weight:600;">{safe_status}</span>'

            f'<span style="font-family:\'JetBrains Mono\',monospace;font-size:0.70rem;color:#6e7681;">{safe_hash}</span>'

            f'<span style="font-family:\'JetBrains Mono\',monospace;font-size:0.70rem;color:#6e7681;">{safe_timestamp}</span>'

            f'</div>'

        )

    st.markdown(header + rows_html + "</div>", unsafe_allow_html=True)



    total_entries = len(audit_log)

    success_count = sum(1 for e in audit_log if e["status"] == "SUCCESS")

    failed_count  = total_entries - success_count

    st.markdown(

        f'<div style="display:flex;gap:20px;margin-top:16px;flex-wrap:wrap;">'

        f'<div class="card" style="flex:1;min-width:140px;padding:14px 18px;">'

        f'<div class="card-title">Total Entries</div><div class="card-value">{total_entries}</div></div>'

        f'<div class="card" style="flex:1;min-width:140px;padding:14px 18px;">'

        f'<div class="card-title" style="color:#3fb950;">Successful</div>'

        f'<div style="font-size:1.35rem;font-weight:700;color:#3fb950;">{success_count}</div></div>'

        f'<div class="card" style="flex:1;min-width:140px;padding:14px 18px;">'

        f'<div class="card-title" style="color:#ef4444;">Failed</div>'

        f'<div style="font-size:1.35rem;font-weight:700;color:#ef4444;">{failed_count}</div></div>'

        f'</div>',

        unsafe_allow_html=True,

    )





# ──────────────────────────────────────────────────────────────────────────────

# PAGE: Reports

# ──────────────────────────────────────────────────────────────────────────────

def page_reports():

    st.markdown(

        '<div style="margin-bottom:24px;">'

        '<div style="font-size:1.45rem;font-weight:700;color:#e6edf3;">Investigation Report</div>'

        '<div style="font-size:0.82rem;color:#8b949e;margin-top:3px;">'

        'Generate, sign, and verify the cryptographic forensic report</div>'

        '</div>',

        unsafe_allow_html=True,

    )



    if not latest_evidence:

        st.warning("⚠️ No evidence record found — cannot sign a report without an evidence ID.")



    section_header("📄", "Report Controls")

    col1, col2 = st.columns(2)



    with col1:

        st.markdown(

            '<div class="card" style="min-height:110px;">'

            '<div style="font-size:0.85rem;font-weight:600;color:#e6edf3;margin-bottom:6px;">'

            '🖊️ Generate &amp; Sign Report</div>'

            '<div style="font-size:0.78rem;color:#8b949e;margin-bottom:14px;">'

            'Produces <code>reports/forensic_report.html</code> and signs it '

            'with the RSA private key. The action is recorded in the audit log.</div>'

            '</div>',

            unsafe_allow_html=True,

        )

        if st.button("🖊️  Generate & Sign Report", key="generate_report"):

            try:

                report_path    = generate_report()

                signature_path = sign_report(report_path)

                if latest_evidence:

                    add_audit_log(evidence_id=ev_id, operation="REPORT_SIGN", status="SUCCESS")

                st.success("✅ Report generated and cryptographically signed.")

                st.markdown(

                    f'<div class="card" style="margin-top:10px;">'

                    f'<div class="card-title">Output Paths</div>'

                    f'<div class="mono" style="margin-top:6px;">{escape(str(report_path))}</div>'

                    f'<div class="mono" style="margin-top:4px;">{escape(str(signature_path))}</div>'

                    f'</div>',

                    unsafe_allow_html=True,

                )

            except Exception as e:

                st.error(f"Report generation failed: {e}")



    with col2:

        st.markdown(

            '<div class="card" style="min-height:110px;">'

            '<div style="font-size:0.85rem;font-weight:600;color:#e6edf3;margin-bottom:6px;">'

            '🔍 Verify Report</div>'

            '<div style="font-size:0.78rem;color:#8b949e;margin-bottom:14px;">'

            'Verifies <code>reports/forensic_report.html</code> against '

            '<code>signatures/forensic_report.html.sig</code> using the RSA public key.</div>'

            '</div>',

            unsafe_allow_html=True,

        )

        if st.button("🔍  Verify Report", key="verify_report"):

            try:

                report_path    = "reports/forensic_report.html"

                signature_path = "signatures/forensic_report.html.sig"

                is_valid = verify_report(report_path, signature_path)

                if is_valid:

                    st.success("✅ VALID — Report has not been modified.")

                else:

                    st.error("❌ INVALID — Report may have been tampered with.")

            except Exception as e:

                st.error(f"Report verification failed: {e}")



    section_header("📂", "File Locations")

    st.markdown(

        '<div class="card">'

        '<div class="info-grid">'

        '<span class="info-label">Report</span><span class="mono">reports/forensic_report.html</span>'

        '<span class="info-label">Signature</span><span class="mono">signatures/forensic_report.html.sig</span>'

        '<span class="info-label">Public Key</span><span class="mono">keys/public_key.pem</span>'

        '<span class="info-label">Private Key</span><span class="mono">keys/private_key.pem</span>'

        '</div></div>',

        unsafe_allow_html=True,

    )





# ──────────────────────────────────────────────────────────────────────────────

# Router

# ──────────────────────────────────────────────────────────────────────────────

page = st.session_state.get("page", "Overview")



if page == "Overview":

    page_overview()

elif page == "Alerts":

    page_alerts()

elif page == "Evidence Security":

    page_evidence()

elif page == "Audit Log":

    page_audit()

elif page == "Reports":

    page_reports()