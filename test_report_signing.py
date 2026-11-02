import sqlite3

from report_generator import generate_report
from crypto_utils import (
    sign_report,
    verify_report
)
from database import add_audit_log


# ==========================================
# 1. Generate report
# ==========================================

report_path = generate_report()

print("Report generated:")
print(report_path)


# ==========================================
# 2. Get latest evidence ID
# ==========================================

conn = sqlite3.connect("forensic.db")

cursor = conn.cursor()

cursor.execute("""
    SELECT evidence_id
    FROM evidence
    ORDER BY evidence_id DESC
    LIMIT 1
""")

row = cursor.fetchone()

conn.close()

if row is None:
    raise RuntimeError("No evidence record found in database.")

evidence_id = row[0]


# ==========================================
# 3. Sign report
# ==========================================

signature_path = sign_report(
    report_path
)

print("\nReport signed successfully!")
print("Signature:", signature_path)


# ==========================================
# 4. Record REPORT_SIGN in audit log
# ==========================================

add_audit_log(
    evidence_id=evidence_id,
    operation="REPORT_SIGN",
    status="SUCCESS"
)

print("REPORT_SIGN recorded in audit log.")


# ==========================================
# 5. Verify report
# ==========================================

is_valid = verify_report(
    report_path,
    signature_path
)

print("\nReport Verification:")

if is_valid:
    print("VALID - Report has not been modified.")
else:
    print("INVALID - Report may have been modified.")