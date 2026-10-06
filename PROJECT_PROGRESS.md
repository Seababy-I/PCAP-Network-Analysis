# Project Progress

## Project

Cryptographically Secured PCAP-to-Database Forensic Analysis Tool
for Network Traffic Investigation

---

## Planned System Workflow

```text
PCAP / PCAPNG
      |
      v
Evidence Security
SHA-256 + RSA Signature
      |
      v
PCAP Parsing
      |
      v
Normalization
      |
      v
SQLite Database
      |
      v
Flows / SQL Queries / Detection
      |
      v
Dashboard and Reports