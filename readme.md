# Cryptographically Secured PCAP-to-Database Forensic Analysis Tool

## Project Overview

This project is a network forensic analysis tool that processes PCAP evidence,
preserves evidence integrity using cryptographic mechanisms, stores extracted
network information, and identifies potentially suspicious traffic patterns.

## Objectives

- Preserve the integrity of captured network evidence.
- Generate SHA-256 fingerprints for PCAP evidence.
- Digitally sign evidence using RSA-2048 and RSA-PSS.
- Verify the authenticity and integrity of stored evidence.
- Detect evidence tampering.
- Identify potentially suspicious network activity using forensic heuristics.
- Store extracted network information for forensic analysis.

## Current Implementation

### Evidence Security

- SHA-256 hashing of the complete PCAP file
- RSA-2048 key-pair generation
- RSA-PSS digital signatures using SHA-256
- Persistent public/private key storage
- Persistent digital signature storage
- Independent evidence verification
- Tamper detection

### Forensic Detection

A heuristic port-scan detector identifies sources contacting a large number
of distinct destination ports.

Current threshold:

- More than 20 distinct destination ports → Possible Port Scan

## System Workflow

PCAP Evidence
     |
     v
SHA-256 Integrity Hash
     |
     v
RSA-2048 Digital Signature
     |
     v
PCAP Parsing
     |
     v
Database Storage
     |
     v
Forensic Detection
     |
     v
Verification and Investigation Results

## Project Structure

```text
PCAP-Forensic-Tool/
├── data/
│   ├── sample.pcap
│   ├── tampered.pcap
│   └── detection_test.pcap
├── keys/
│   └── public_key.pem
├── signatures/
│   └── sample.pcap.sig
├── crypto_utils.py
├── detection.py
├── verify_evidence.py
├── run_security.py
├── create_sample_pcap.py
├── create_detection_pcap.py
├── test_crypto.py
└── README.md
