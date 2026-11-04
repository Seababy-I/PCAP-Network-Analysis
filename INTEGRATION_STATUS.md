# Functional integration status

The application now connects vault-protected evidence, the reviewed teammate parser, Aanya's packet/DNS/HTTP storage, bidirectional conversations, scan detection, investigation views and signed reports.

## Current acceptance level

`INTEGRATED_LIMITED` means functional packet/protocol/flow integration with a documented supported subset. Completion patches now preserve repeated DNS answers, their owner names and multiple HTTP protocol layers in a frame. Numeric fields are validated; extraction failures abort with structured frame/progress information, and the standalone CLI exits nonzero on failure. The independent adapter also rejects missing/duplicated/reordered frames.

DNS resource extraction covers A/AAAA/CNAME/MX/NS/PTR/TXT. Other resource types are not extracted. Multi-string TXT resources and ambiguous HTTP groupings are rejected explicitly rather than silently truncated. Encrypted application content and TCP payload reconstruction are not decoded. These are supported-format limits, not claims of complete traffic extraction.

SQLite packet/protocol metadata is still plaintext. Full mode requires an explicit acknowledgement before storing it. Evidence/report files remain encrypted. Database encryption is explicitly deferred by project decision, and no full-project confidentiality claim is made. TLS analysis remains excluded.

## Sources and ownership

`TEAM_SOURCES.json` records upstream hashes/source paths and installed hashes for team files from `aanya-parser-db` commit `843b6898c29b27714e97da1010900496b7c7a88c`. This branch bundles Jahnnavi's parser plus Aanya's container validation/cleanup changes. The standalone `jahnnavi-parser` branch is still older. The parser includes a documented local completion patch on top of that snapshot; the database, bridge, schema and owner tests remain unchanged. The upstream source hashes are retained alongside installed hashes.

The user-owned `integration_runtime.py` supplies a separate parser thread/event loop and a restricted temporary plaintext input for TShark. Permissions are set before writing; the file/directory are removed in `finally`. This is not a promise of forensic secure erasure against an administrator or storage recovery. Managed evidence stays encrypted at rest.

The user-owned `integration_storage.py` reuses Aanya's connection-level packet helper so evidence, packets, application metadata, alerts and import/detection audit events share one transaction. Do not also call the standalone bridge, which would insert a second evidence record. The bridge itself remains unchanged and available for its owner's tests.

Flow reconstruction uses Aanya's separate atomic rebuild API after the import transaction. A failure retains valid signed evidence/packets with `FLOW_FAILED`, never a successful completion label. Investigation provides a retry action. Retrying does not reimport packets.

## Usage

```powershell
python launch_dashboard.py
```

The launcher prefers the project's `.venv-parser` interpreter when present. Unlock the vault, select full-parser mode, acknowledge the current metadata-storage limitation, and analyze a capture. Investigation provides packet pagination/IP/protocol/UTC filters, DNS/HTTP records, protocol/talker/timeline summaries and conversation drilldown. Reports include evidence-scoped stored-data summaries. Existing network-only records remain viewable as network-only and are not silently backfilled.

CLI:

```powershell
.\.venv-parser\Scripts\python.exe run_security.py --pcap runtime/demo-inputs/port-scan.pcap --mode full --allow-plaintext-metadata
.\.venv-parser\Scripts\python.exe run_security.py --pcap runtime/demo-inputs/normal.pcap --mode network
.\.venv-parser\Scripts\python.exe -m unittest discover -s team_tests -v
.\.venv-parser\Scripts\python.exe -m pytest -q
```

Use the established vault passphrase. The general Python API retains `mode='network'` as its backward-compatible default; full mode is explicit. CLI defaults to full and requires acknowledgement. No fallback silently downgrades a failed full parse to a clean network-only result.

`length` is the original/wire frame length from the team parser. Captured byte totals are kept separately using the independent reader. TCP flags preserve the team's full 12-bit field.

## Verification and delivery

Run the application suite, unchanged owner tests and `python integration_demo.py` using `.venv-parser`. The integrated rehearsal creates a new isolated database/disposable keys and checks normal/scan/DNS/HTTP imports, isolation, rollback, idempotency, evidence tampering, encrypted reports, offline verification and audit integrity. It also runs the independent checkpoint and confidentiality demonstrations. Its explicitly decrypted offline-verification folder contains synthetic/public demo content only.

Database encryption is deferred; TLS is excluded. Remote CI results must be checked after the integration branch is pushed. Older historical files remain untouched and unencrypted unless explicitly migrated.
