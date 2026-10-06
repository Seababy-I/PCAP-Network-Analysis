from crypto_utils import (
    secure_evidence,
    verify_evidence_file
)


pcap_path = "data/tampered.pcap"
signature_path = "signatures/sample.pcap.sig"


# Secure the evidence
hash_value, saved_signature = secure_evidence(pcap_path)

print("Evidence secured successfully!")
print("SHA-256:", hash_value)
print("Signature:", saved_signature)


# Verify the evidence
is_valid = verify_evidence_file(
    pcap_path,
    signature_path
)

print("\nEvidence Verification:")

if is_valid:
    print("VALID - Evidence has not been modified.")
else:
    print("INVALID - Evidence may have been modified.")