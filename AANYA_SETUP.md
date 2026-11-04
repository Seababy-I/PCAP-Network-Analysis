# Aanya's database module — setup and team handoff

Reviewed against branch `aanya-parser-db` at commit `3514666117a367fdb2ca62ab2de448193a016451`, plus the three supplied files. This package contains only Aanya's updated/new files. Copy them into the root of your existing PCAP-Network-Analysis checkout. Keep the team's other files.

## Quick start in PyCharm or Windows Terminal

Back up your existing `forensic.db` before migration. Open the project root as the working directory, then run:

```bash
python database.py
python demo_data.py
python -m unittest test_database -v
python query_api.py --db demo_forensic.db --port 8000
```

- `database.py` creates or upgrades `forensic.db`, without adding dummy evidence.
- `demo_data.py` uses a separate `demo_forensic.db`. Every run adds one clearly labeled dummy capture, ten packets and six bidirectional flows. The HTTPS conversation contains four packets and 2,081 bytes; all ten packets total 2,561 bytes. Repeated runs use the actual generated packet IDs.
- The module, API and tests use Python's standard library; no new pip dependencies are required.
- Open `http://127.0.0.1:8000/api/flows?evidence_id=1` in your browser for JSON output. Stop the API with Ctrl+C.
- Switch `--db` to `forensic.db` when real parser output has been stored.
- To inspect tables in DB Browser for SQLite, open the database and use Browse Data or Execute SQL. SQLite database files are binary; do not open them as text.

## What is implemented

| Assignment | Implementation |
|---|---|
| SQLite schema and tables | One authoritative `schema.sql`; evidence, packets, TLS, DNS, HTTP, alerts, flows, flow membership and audit tables |
| Schema updates | Adds missing packet evidence ID, certificate subject and audit version/details columns without deleting old data; creates indexes |
| Flow construction | `reconstruct_flows()` combines both directions of an endpoint/port/protocol conversation separately for each evidence capture |
| Flow investigation | `query_flows()` and `query_flow_packets()` expose counters, bytes, first/last timestamps and associated packets |
| Forensic SQL | `queries.sql` includes protocol/IP/port investigations, joins, timeline, talkers and raw counts for detection inputs |
| Top talkers | `query_top_talkers()` ranks source hosts by transmitted bytes, also returning packet and distinct destination counts |
| Timeline | `query_timeline()` groups packets into configurable UTC intervals |
| Protocol breakdown | `query_protocol_breakdown()` returns packet counts and bytes by transport/network protocol |
| Audit log | Versioned hash chain, evidence ID/details bound into new hashes, serialized concurrent appends, verification and optional trusted head comparison |
| Query APIs | Python functions plus optional local read-only JSON HTTP endpoints |
| Parser handoff | `parser_db_bridge.store_parsed_capture()` stores structured extracted fields transactionally |

## Jahnnavi: store parser output

The current `parser_backup.py` prints extracted values; it does not return records or write them to SQLite. Jahnnavi should produce dictionaries using this contract. This example is deliberately synthetic:

```python
from parser_db_bridge import store_parsed_capture
from database import reconstruct_flows

packets = [
    {
        "timestamp": "2026-10-06T08:30:03.120Z",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "protocol": "TCP",
        "src_port": "53002",
        "dst_port": "443",
        "length": "517",
        "tls_records": [
            {
                "tls_version": "TLS 1.3",
                "cipher_selected": "TLS_AES_128_GCM_SHA256",
                "sni": "example.com",
                "cert_subject": "CN=example.com",
                "cert_issuer": "Example CA",
                "cert_not_before": "2026-01-01",
                "cert_not_after": "2027-01-01",
                "cert_sha256": None,
            }
        ],
        "dns_records": [],
        "http_records": [],
    }
]

result = store_parsed_capture(
    "sample.pcap", packets,
    sha256=None,   # Supply the real digest returned by Priyali's module.
    signature=None, # Supply the team's signature representation/path.
    db_name="forensic.db",
)
reconstruct_flows("forensic.db", result["evidence_id"])
print(result)  # evidence_id and actual packet_ids
```

TLS, DNS and HTTP lists may each contain multiple extracted records for one packet. DNS keys: `query_name`, `query_type`, `response_code`, `answers` (JSON-serializable list). HTTP keys: `method`, `host`, `uri`, `status_code`. TLS keys are shown above. Missing fields are stored as NULL.

Keep `protocol` as TCP/UDP/etc. and store application fields in their dedicated tables. Numeric string ports and lengths from PyShark are accepted; `N/A` IPs/ports become NULL. Invalid IPs, ports, lengths or timestamps reject the transaction. Prefer `packet.sniff_timestamp` converted to a float epoch value for unambiguous UTC. Naive datetimes are interpreted as UTC, so local naive times must be converted correctly before storage.

Alternatively, existing insertion helpers remain compatible:

```python
from database import insert_packet, insert_tls_record
packet_id = insert_packet(timestamp, src_ip, dst_ip, protocol,
                          src_port, dst_port, length,
                          db_name="forensic.db", evidence_id=evidence_id)
insert_tls_record(packet_id, tls_version=version, cipher_selected=cipher,
                  cert_subject=subject, db_name="forensic.db")
```

`insert_packets(rows, db_name=..., evidence_id=...)` accepts the original seven-field tuples and now returns generated IDs. Helpers do not automatically rebuild flows; call `reconstruct_flows()` when import finishes. The bridge atomically commits packets, protocol records, evidence and an IMPORT audit entry. Flow rebuilding is a separate transaction; if it fails, stored evidence remains available and the rebuild can be retried.

## Priyali: dashboard and detection handoff

Use the Python functions directly if the dashboard is Python:

```python
from database import (query_top_talkers, query_timeline,
                      query_protocol_breakdown, query_flows,
                      query_protocol_records, insert_alert, add_audit_log)

hosts = query_top_talkers("forensic.db", evidence_id=1, limit=10)
timeline = query_timeline("forensic.db", evidence_id=1, bucket_seconds=60)
protocols = query_protocol_breakdown("forensic.db", evidence_id=1)
flows = query_flows("forensic.db", evidence_id=1)
tls = query_protocol_records("tls", "forensic.db", evidence_id=1)

# After YOUR detector calculates an alert:
# insert_alert(packet_id, "WEAK_TLS", "High", description, db_name="forensic.db")
# After YOUR verification completes:
# add_audit_log(1, "VERIFY", "SUCCESS", db_name="forensic.db", details={"valid": True})
```

For a dashboard with a backend in another language, the optional HTTP adapter exposes:

| GET endpoint | Parameters |
|---|---|
| `/api/evidence` | none |
| `/api/packets` | evidence_id, ip, protocol, start, end, limit, offset |
| `/api/top-talkers` | evidence_id, limit |
| `/api/timeline` | evidence_id, bucket_seconds |
| `/api/protocols` | evidence_id |
| `/api/flows` | evidence_id |
| `/api/flow-packets` | flow_id (required) |
| `/api/tls`, `/api/dns`, `/api/http` | evidence_id |
| `/api/alerts` | evidence_id |
| `/api/audit` | evidence_id |
| `/api/audit/verify` | expected_head (optional trusted checkpoint) |

Responses are JSON arrays, except audit verification returns `{valid, message}`. Missing evidence IDs return empty arrays. Invalid parameters produce HTTP 400; unknown endpoints produce 404. The API is a local integration adapter, bound to loopback, without authentication or CORS. Browser frontends on a different origin should use their backend/proxy; do not expose this adapter publicly as-is.

TLS scoring, weak-version/cipher rules, certificate classification, host-scan/SSH detection, threat intelligence, risk scoring, RSA verification, dashboard charts and reports remain Priyali's work. The schema keeps the old `is_self_signed` field for compatibility; its legacy default 0 must not be treated as proof that a certificate is trusted or even analyzed. Use raw certificate fields for classification. Port 443/53 query helpers identify candidate traffic by port, not confirmed HTTPS/DNS.

## Flow semantics and migration limits

- Each flow groups a bidirectional five-tuple for one entire capture: two IP/port endpoints and protocol. TCP connections reusing a tuple in the same capture are combined. This is conversation aggregation, not sequence-number/payload reassembly or session splitting.
- Endpoints are sorted canonically; `src_ip` in the flows table is not necessarily the initiator. Forward counters refer to that canonical endpoint. Packets retain their original source/destination.
- Non-IP packets without both addresses are stored but skipped by flow reconstruction. ARP with extracted protocol IP addresses can be grouped. Portless protocols use NULL ports.
- Flow IDs may change on rebuild. Requery before following a flow ID. Counts reflect the most recent rebuild.
- Old packets have `evidence_id=NULL`: their original capture ownership cannot be inferred. They are kept as an unassigned group. Fresh parser imports must provide an evidence ID. Unscoped queries include legacy rows; scoped queries do not.
- Previously stored timestamps are preserved. Query time filtering uses SQLite date conversion; reconstruction normalizes valid ISO timestamps. Fix non-ISO legacy timestamps before reconstructing those rows.

## Audit verification and trust

New audit entries hash canonical JSON containing their ID, evidence ID, operation, status, timestamp, prior hash, details and hash version. Appends take a write lock so concurrent writers cannot fork the chain. Verification checks both the prior-link field and the entry digest.

Legacy audit entries retain their original hashes, are marked version 1 and verify with the original algorithm. Their evidence ID and details were never bound into those hashes; migration cannot retroactively prove those fields. The verifier explicitly reports legacy entries. Audited evidence cannot be deleted through normal SQLite operations, including the older schema's cascading foreign key.

A local hash chain does not stop a database administrator from rewriting the whole chain. Without an externally trusted head, deletion of the final entries is also undetectable. Priyali should sign/store checkpoints outside this database if stronger tamper evidence is required:

```python
from database import query_audit_log, verify_audit_chain
head = query_audit_log("forensic.db")[-1]["entry_hash"]
# Persist/sign this head externally at a known capture milestone.
valid, message = verify_audit_chain("forensic.db", expected_head=head)
```

Recording business events is explicit: the import bridge and flow rebuild audit automatically; Priyali must call `add_audit_log` after verification/report operations. Database reads and individual low-level inserts are not automatically business-event audited.

## Validation completed

Ten database/integration tests pass: bidirectional grouping and capture isolation, scoped analytics/time filters, rollback and foreign keys, audit field tampering and tail checkpoint, audited-evidence protection, TLS/DNS/HTTP storage, old-schema migration, atomic parser handoff, concurrent audit appends and actual HTTP responses. Repeated demo runs were also checked (20 packets, 12 flows, two captures).

Real PCAP extraction/TLS extraction and dashboard integration have not been run: the current parser is print-only and those changes belong to the other owners. No GitHub branch was modified by this delivery.
