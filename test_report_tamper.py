from pathlib import Path

from report_generator import generate_report
from crypto_utils import sign_report, verify_report


report_path = generate_report()
signature_path = sign_report(report_path)

print("Original report signed.")

# Verify before tampering
valid_before = verify_report(
    report_path,
    signature_path
)

print("\nBefore tampering:")

if valid_before:
    print("VALID - Report has not been modified.")
else:
    print("INVALID - Unexpected verification failure.")


# ------------------------------------------
# Tamper with the report
# ------------------------------------------

report_file = Path(report_path)

original_content = report_file.read_text(
    encoding="utf-8"
)

report_file.write_text(
    original_content + "\n<!-- TAMPERED -->\n",
    encoding="utf-8"
)

print("\nReport modified for tamper test.")


# ------------------------------------------
# Verify after tampering
# ------------------------------------------

valid_after = verify_report(
    report_path,
    signature_path
)

print("\nAfter tampering:")

if valid_after:
    print("ERROR - Tampering was NOT detected.")
else:
    print("SUCCESS - Tampering detected.")


# ------------------------------------------
# Restore original report
# ------------------------------------------

report_file.write_text(
    original_content,
    encoding="utf-8"
)

print("\nOriginal report restored.")