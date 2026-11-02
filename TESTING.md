# Testing and Preliminary Results

## 1. SHA-256 Evidence Hashing

### Test
Run the evidence security workflow on `data/sample.pcap`.

### Expected Result
A SHA-256 fingerprint should be generated for the complete PCAP file.

### Actual Result
A 64-character hexadecimal SHA-256 hash was generated successfully.

### Status
PASS

---

## 2. RSA-2048 Key Generation

### Test
Generate the RSA key pair for evidence signing.

### Expected Result
An RSA-2048 private key and corresponding public key should be generated.

### Actual Result
The key pair was generated successfully and stored as PEM files.

- `keys/private_key.pem` — kept local and excluded from Git
- `keys/public_key.pem` — used for verification

### Status
PASS

---

## 3. RSA-PSS Digital Signature

### Test
Sign `data/sample.pcap` using the RSA-2048 private key.

### Expected Result
A digital signature should be generated and stored separately.

### Actual Result
A 256-byte RSA signature was generated successfully and stored as:

`signatures/sample.pcap.sig`

### Status
PASS

---

## 4. Original Evidence Verification

### Test
Verify `data/sample.pcap` using the saved public key and
`signatures/sample.pcap.sig`.

### Expected Result
The evidence should be reported as valid.

### Actual Result

```text
Evidence Verification:
VALID - Evidence has not been modified.

### Status
PASS

---

## 5. Tamper Detection

### Test
Verify `data/tampered.pcap` using the original
`sample.pcap.sig` and public key.

### Expected Result
Verification should fail because the file contents have been modified.

### Actual Result

```text
Evidence Verification:
INVALID - Evidence may have been modified.