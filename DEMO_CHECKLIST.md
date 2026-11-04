# End-to-end demonstration

**Current security mode:** use `python launch_dashboard.py` and set up/unlock the local vault first. CLI import/report/demo commands now prompt privately for the same vault passphrase. Report bundles download as encrypted `.zip.vault`; explicitly decrypt with `vault_cli.py` before extracting and running the standalone verifier. Run `python confidentiality_demo.py` for the new passive-disclosure protection demo. Existing historical files and SQLite metadata are not automatically encrypted; see `CONFIDENTIALITY.md`.

## Full integration rehearsal

1. Run `python prepare_demo.py`, then `python launch_dashboard.py`. Unlock the vault. Choose full-parser mode and acknowledge that SQLite metadata remains plaintext.
2. Import `runtime/demo-inputs/normal.pcap`: expect 3 stored packets and no scan finding. Open Investigation and show protocol/talker/timeline summaries, packet filters and conversation detail.
3. Import `port-scan.pcap` and `host-scan.pcap`: expect 41 and 30 packets respectively, with one heuristic alert each. Switch evidence and confirm packet, flow and alert isolation.
4. Import `team_tests/fixtures/dns_valid.pcap`: expect 2 stored packets, 1 conversation and 2 DNS rows. Import `team_tests/fixtures/ipv6_vlan_http.pcapng` to demonstrate IPv6/VLAN/HTTP parsing.
5. In Evidence Security, verify an original; verify `normal-tampered.pcap` as a candidate against the normal original and expect INVALID. Do not sign/import it for this check.
6. Generate a signed report and download its encrypted verification bundle. Decrypt explicitly with `vault_cli.py`, extract, and run its standalone verifier. Modify a copy of the decrypted report and expect verification failure.
7. Show the valid audit chain and save a signed checkpoint. Explain that this authenticates checkpointed history, not arbitrary database contents.
8. Import a malformed capture: expect an error without a new evidence row. Show `INTEGRATED_LIMITED` and explain supported-format limits and the decision to defer database encryption. Do not claim to detect a silent passive observer; demonstrate stored-file confidentiality and integrity instead.

Verification commands (use the project parser environment):

```powershell
.\.venv-parser\Scripts\python.exe -m pytest -q
.\.venv-parser\Scripts\python.exe -m unittest discover -s team_tests -v
```

## Independent network-only rehearsal

From the project directory:

```powershell
python -m pip check
python -m pytest -q
python demo_smoke.py
```

The last command creates a unique directory under `runtime/demo-runs/` with synthetic captures, a separate database, disposable demo signing keys, signed report bundle, checkpoint, intentionally damaged copies and `results.json`. It refuses to replace an existing explicit `--output` directory. It does not modify the historical database or established keys.

Expected checks: 3 normal frames/0 alerts, 41-port SYN scan/1 alert, 30-host SYN scan/1 alert; duplicate submission does not add evidence; original evidence and its early report still verify after later imports; modified copies fail; malformed input adds no evidence; signed checkpoint detects deleted audit tail while allowing legitimate later appends.

## Optional network-only dashboard rehearsal

```powershell
python prepare_demo.py
python -m streamlit run dashboard.py
```

1. Choose network-only mode. Use the default separate `runtime/forensic.db`. Upload `runtime/demo-inputs/normal.pcap`, select Analyze, then show frame/protocol counts and the network-only status.
2. Import `port-scan.pcap` and `host-scan.pcap`. Expect one Medium heuristic finding per capture. Switch between evidence IDs and confirm counts/alerts remain scoped.
3. Verify normal evidence. Then upload `normal-tampered.pcap` in Evidence Security's candidate-copy control and verify against the selected original. Expect INVALID; do not import/sign that modified copy for this step.
4. Generate a normal-capture report. Download and explicitly decrypt the verification bundle with `vault_cli.py`, extract it into an empty directory, then run `python verify.py` there. It requires cryptography, but no database or private key. Modify a copy of `report.html` in the extracted bundle and rerun; expect INVALID.
5. In Audit Log, verify the global chain and Save Signed Audit Checkpoint. Preserve the checkpoint, signature, manifest and public key outside the database. The smoke-run's intentionally damaged DB demonstrates tail-deletion detection without damaging the application DB.
6. Restart the app, select earlier evidence and verify again. Analyze the same upload within one session again; its submission is reused. A new session may intentionally create another analysis, with distinct artifacts.
7. Try `invalid.pcap`. Show a clear failure and no additional successful evidence row.

## Offline CLI checks

```powershell
python verify_artifact.py --file report.html --signature report.sig --public-key public_key.pem --manifest report.sig.json
python audit_security.py --db runtime/forensic.db
python audit_security.py --db runtime/forensic.db --create runtime/checkpoints
# Use the returned paths to validate a saved checkpoint after restart:
python audit_security.py --db runtime/forensic.db --checkpoint PATH_TO_CHECKPOINT --signature PATH_TO_SIGNATURE
```

Establish the public-key fingerprint through a trusted channel before treating signature validity as provenance. Keep signed checkpoints/signatures outside the database; a writable local audit chain alone cannot prevent an administrator rewriting history. Legacy entries cover fewer fields than v2; packet/alert tables are not automatically authenticated by chain verification.

## Scope to state during presentation

Implemented: saved-capture signing/verification, network heuristics, scoped evidence/alerts, audit verification/checkpoints and signed report export. Pending: Jahnnavi's full DNS/HTTP parser, Aanya's latest packet/flow storage and their integration. No TLS analysis, full TCP payload reassembly, confirmed attack attribution or large-capture support is claimed. Current limit: 20 MiB / 100,000 Ethernet frames.
