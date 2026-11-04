# Parser integration preparation

This is the user's adapter/acceptance layer. Jahnnavi still owns parser extraction, repeated DNS/HTTP handling, strict failure behavior, CLI exit codes, real-capture tests and tested dependency versions. Aanya still owns her storage/migration compatibility work. Neither module is repaired or merged by this preparation.

## Ready now

- `parser_adapter.py` validates the agreed dictionary contract before records reach the existing detectors. It checks finite UTC timestamps, positive frame numbers, nonnegative lengths, IPs, transport ports, flags and JSON-compatible application records.
- `preview_capture()` compares returned frame coverage with the independent bounded reader. Missing/duplicated/reordered frames and partial output fail the preview; invalid data does not become clean traffic. Generator cleanup runs on failure.
- `parser_preview.py` loads an explicitly supplied reviewed parser and prints a `PARSER_PREVIEW_ONLY` result. It does not import evidence into SQLite, sign captures or modify the active dashboard workflow.
- `parser_readiness.py` checks package/executable availability and statically inspects the parser API. It does not import/execute the parser or mark it accepted. Readiness is separate from real-capture correctness.

The active application remains `NETWORK_ONLY`. DNS/HTTP/flow database persistence is still pending integration.

## Optional isolated environment

```powershell
py -3.11 -m venv --system-site-packages .venv-parser
.\.venv-parser\Scripts\python.exe -m pip install -r requirements-parser.txt
.\.venv-parser\Scripts\python.exe -m pip check
```

This inherits the already-tested application dependencies and adds PyShark in a separate environment, leaving the main Python environment unchanged. PyShark 0.6 is an optional review pin, not a claim that Jahnnavi's parser has passed real decoding. Confirm her tested Python/PyShark/TShark combination before acceptance. TShark is a separate executable; Python installation of PyShark does not install it.

On Windows the equivalent repeatable helper is `powershell -File .\setup_parser_preview.ps1`. It creates/reuses only `.venv-parser`, installs binary wheels there and checks imports/dependencies. It does not install TShark, change the global Python environment or activate any parser. The executable can be installed from the [official Wireshark Windows instructions](https://www.wireshark.org/docs/wsug_html_chunked/ChapterBuildInstall.html) once the team's tested version is selected.

## After receiving her corrected module

Use an explicit checkout/file path first, keeping the unaccepted parser out of the main application:

```powershell
.\.venv-parser\Scripts\python.exe parser_readiness.py --parser PATH_TO_REVIEWED_PARSER --tshark PATH_TO_TSHARK
.\.venv-parser\Scripts\python.exe parser_preview.py --parser PATH_TO_REVIEWED_PARSER --pcap runtime/demo-inputs/port-scan.pcap --tshark PATH_TO_TSHARK
```

Run normal/port-scan/host-scan, IPv6, VLAN, PCAPNG, multi-answer DNS, multiple HTTP messages and malformed/truncated fixtures. The adapter can reject missing frames and invalid records but cannot infer that a parser omitted one DNS answer or HTTP message; those require owner extraction tests. Decide and document wire-length versus captured-length semantics before combining byte totals.

Exit status: readiness 0 means preview prerequisites are present, 2 means prerequisites are missing/invalid. Preview 0 means the explicitly supplied input passed boundary/coverage checks, 2 means it failed. Neither command declares the parser accepted for production.

## Acceptance before activation

Jahnnavi provides a corrected commit, parser tests, proper fixtures, setup instructions and passing real-capture results. Run those tests plus the application's independent tests. Then connect the accepted parser to signing/detection, retaining partial-integration status until Aanya's transactional packet/DNS/HTTP storage and flows are integrated. Preserve unique evidence/signature paths and existing submission idempotency. No TLS extraction or analysis is required.
