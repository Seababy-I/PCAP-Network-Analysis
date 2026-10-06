from crypto_utils import (
    load_public_key,
    load_signature,
    verify_signature
)


pcap_path = "data/sample.pcap"
signature_path = "signatures/sample.pcap.sig"

# Load saved public key
public_key = load_public_key()

# Load saved signature
signature = load_signature(signature_path)

# Verify evidence
is_valid = verify_signature(
    pcap_path,
    signature,
    public_key
)

print("Evidence Verification:")

if is_valid:
    print("VALID - Evidence has not been modified.")
else:
    print("INVALID - Evidence may have been modified.")