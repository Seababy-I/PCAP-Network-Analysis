# Problems, Root Causes and Solutions

## 1. Empty PCAP Test Files

### Problem
The initially created `sample.pcap` and `tampered.pcap` files were
empty because they had been created as file placeholders rather than
actual packet captures.

### Root Cause
The files contained zero bytes and therefore did not contain packet data.
This also meant there was no byte available for the tamper test.

### Solution
A valid synthetic PCAP containing structured Ethernet, IPv4 and UDP
traffic was generated using Python.

### Result
The cryptographic signing, verification and tamper-detection workflow
could be tested using a non-empty, structurally valid PCAP.

---

## 2. Tamper Test Failure on Empty Evidence

### Problem
The tampering operation initially produced:

```text
IndexError: bytearray index out of range