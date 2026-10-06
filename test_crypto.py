from crypto_utils import (
    calculate_sha256,
    generate_rsa_keys,
    save_keys,
    sign_file,
    save_signature,
    verify_signature
)


pcap_path = "data/sample.pcap"

# SHA-256
hash_value = calculate_sha256(pcap_path)

print("SHA-256 Hash:")
print(hash_value)

# RSA key generation
private_key, public_key = generate_rsa_keys()
save_keys(private_key, public_key)
print("\nRSA-2048 key pair generated and saved successfully!")

print("Private Key:", type(private_key))
print("Public Key:", type(public_key))
# Digital signature
signature = sign_file(pcap_path, private_key)

print("\nDigital signature generated successfully!")
print("Signature size:", len(signature), "bytes")

signature_path = "signatures/sample.pcap.sig"

save_signature(signature, signature_path)

print("Signature saved to:", signature_path)
# Verify digital signature
is_valid = verify_signature(
    pcap_path,
    signature,
    public_key
)

print("\nSignature Verification:")

if is_valid:
    print("VALID - Evidence has not been modified.")
else:
    print("INVALID - Evidence may have been modified.")

# Create a tampered copy
with open(pcap_path, "rb") as file:
    data = bytearray(file.read())

# Modify one byte
data[-1] = (data[-1] + 1) % 256

with open("data/tampered.pcap", "wb") as file:
    file.write(data)

print("\nTampered PCAP created.")

# Verify the tampered PCAP using the ORIGINAL signature
tampered_valid = verify_signature(
    "data/tampered.pcap",
    signature,
    public_key
)

print("\nTampered PCAP Verification:")

if tampered_valid:
    print("VALID - No tampering detected.")
else:
    print("INVALID - Tampering detected!")