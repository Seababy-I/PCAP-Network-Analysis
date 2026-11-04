# PCAP Forensic Tool

## Demo and viva materials

- [Complete demo walkthrough](docs/PCAP_Demo_Walkthrough.md) with clicks, expected outputs, spoken explanations, a short version and recovery notes. [Printable PDF](docs/PCAP_Demo_Walkthrough.pdf).
- [Viva handbook](docs/PCAP_Viva_Handbook.md) covering architecture, algorithms, cryptography, storage, failure paths, testing, limits and 70 questions with answers. [Printable PDF](docs/PCAP_Viva_Handbook.pdf).
- [Source code study index](docs/PCAP_Source_Index.md) with exact function links at the tested code baseline.
- [System flow diagram](docs/PCAP_System_Architecture.png) and [database relationships](docs/PCAP_Database_Relationships.png).

**Functional integration is now available:** full-parser mode stores packets/DNS/HTTP/conversations and adds Investigation views/report summaries. It is labeled `INTEGRATED_LIMITED` because supported parsing has documented limits and database metadata remains plaintext by project decision. See `INTEGRATION_STATUS.md`. Start with `python launch_dashboard.py`; it uses `.venv-parser` when available. Full mode requires acknowledgement that parsed SQLite metadata is currently unencrypted.

**Confidentiality update:** new managed captures/reports and report-export bundles are encrypted by default. Start with `python launch_dashboard.py`, create your local vault passphrase on first launch, then unlock. CLI imports/signing prompt privately for that passphrase. See `CONFIDENTIALITY.md` for the threat model, encrypted-export commands, legacy-data limits and the deferred database encryption limitation. Historical data is preserved; SQLite metadata is still plaintext.

Saved-capture evidence signing, network scan heuristics and evidence-scoped Streamlit investigation reports. TLS analysis is excluded from the active workflow.

## Current capability

- Persistent RSA-2048/PSS keys, incremental SHA-256, versioned signatures and signing-key fingerprints.
- Saved Ethernet PCAP/PCAPNG, both classic PCAP byte orders, nanosecond PCAP, IPv4/IPv6 and VLAN network analysis.
- TCP initial-SYN heuristics: more than 20 distinct ports per source/target or hosts per source/destination port within 60 seconds. One summary per source/target grouping, using its largest qualifying window; these indicators do not prove an attack.
- Evidence-scoped alerts, audit entries, report generation/signing and downloads.
- Idempotent dashboard submissions and explicit malformed/truncated-container errors.

Full mode uses the pinned teammate parser and SQLite packet/protocol/conversation storage. Successful imports are labeled `INTEGRATED_LIMITED`; network-only mode remains available and is labeled `NETWORK_ONLY`. Limits: 20 MiB / 100,000 frames, Ethernet interfaces only. Conversations group packets in both directions; TCP payload/session reconstruction is not implemented. See `INTEGRATION_STATUS.md` for remaining owner tasks.

## Run on Windows

Use Python 3.11 from the project directory:

Dependency versions are pinned to the environment used for the regression checks.

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m streamlit run dashboard.py
```

If using the existing environment, `python -m streamlit run dashboard.py` also works once dependencies are installed.

For a fresh clone, the repository includes a historical public verification key but no private signing key. Choose a separate new signing directory explicitly before launching:

```powershell
$env:PCAP_KEYS = "$PWD\runtime\keys"
python launch_dashboard.py
```

For fresh-clone CLI imports, also pass `--keys runtime/keys`. Existing installations with an established key pair should keep that pair. Never replace or delete historical keys to resolve an incomplete-key error.

Run `.\.venv-parser\Scripts\python.exe integration_demo.py` for the full isolated rehearsal, or follow `DEMO_CHECKLIST.md` for the interactive demo.

The dashboard defaults to `runtime/forensic.db`, a clean separate analysis database. Existing `forensic.db`, reports and evidence artifacts are retained. Change the sidebar database path to inspect the historical database; application initialization adds only its bookkeeping tables/missing columns. Historical findings can include synthetic demonstrations; records with no evidence owner are excluded from selected-evidence views.

Configuration: `PCAP_DB`, `PCAP_STORAGE`, `PCAP_KEYS` environment variables. Default keys are the existing project `keys/` pair. Signing refuses incomplete or mismatched pairs and never overwrites keys. Do not delete an established pair to fix an error: restore its matching half. Historical signatures without manifests verify with the legacy public key; their original per-import key history cannot be recovered.

## CLI

```powershell
python run_security.py --pcap data/sample.pcap --mode full --allow-plaintext-metadata
python run_security.py --pcap data/detection_test.pcap --mode full --allow-plaintext-metadata
python verify_evidence.py --evidence-id 1
python verify_evidence.py --evidence-id 1 --file data/tampered.pcap
python report_generator.py --evidence-id 1 --sign
```

IDs above assume a fresh runtime database. Use returned IDs otherwise. Runner accepts `--db`, `--storage`, `--keys`; verifier/report accept `--db` and `--keys`; report accepts `--output`. Normal verification exits 0, digest/signature mismatch exits 1, unavailable verification exits 2. Verification never signs its input. Reports must have an explicit evidence ID. Explicit output paths must not already exist, preventing replacement of signed reports.

From the dashboard, select evidence, open Evidence Security to verify the stored original or an uploaded candidate copy. Reports provides HTML, detached signature, manifest and archived public-key downloads. RSA validity establishes integrity relative to the supplied key; the public key's provenance must be established separately.

## Tests and historical demo scripts

```powershell
python -m pytest -q
```

`pytest.ini` collects only isolated tests in `tests/`. These use temporary keys/databases/artifacts. The older root-level `test_*.py` files are historical demonstration scripts with fixed output paths and old APIs; do not run them as the regression suite. Legacy TLS source/scripts remain historical files and are not imported by the runner, dashboard or current tests. Screenshots show earlier demo state and are retained.

Audit appends preserve the installed schema's hash format, including Aanya's v2 when available. Current legacy chains have limited field coverage and do not independently authenticate packet/alert rows or detect tail deletion without an external trusted checkpoint.

The dashboard can now save signed audit checkpoints outside the database and export a report-verification ZIP containing only the report, detached signature/manifest, public key and standalone verifier. `verify_artifact.py` also verifies artifacts with an explicit public key, without the application database/private key. `audit_security.py` checks prior links/digests for legacy and v2 entries and can validate a saved signed checkpoint after restart. Later legitimate appends remain valid; removal of checkpointed history fails verification.

For a complete independent rehearsal, run `python demo_smoke.py`. It uses a new isolated database and disposable demo keys, tests both scans/tamper cases/rollback/idempotency/checkpoints, and writes `results.json`. See `DEMO_CHECKLIST.md` for presentation steps and `INTEGRATION_HANDOFF.md` for the exact remaining teammate interfaces. `.github/workflows/tests.yml` defines Python 3.11 tests on Windows/Linux; remote CI has not run until the branch is pushed.

## Teammate integration boundary

`TEAM_SOURCES.json` pins unchanged parser/database modules and their owner tests. `integration_runtime.py`, `integration_storage.py`, `analysis_service.py` and `investigation.py` provide the user-owned coordination. Evidence, packet/protocol rows, alerts and import audit entries share one transaction; flow reconstruction is a separate atomic step with a visible failure status and retry action. See `INTEGRATION_STATUS.md` for exact ownership and current limitations.
