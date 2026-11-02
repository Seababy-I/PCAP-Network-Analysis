# PCAP Forensic Tool Demo Walkthrough

Prepared for Priyali, Aanya and Jahnnavi on 2 November 2026. This guide explains exactly what to open, what to click, what results to expect, and what to say during a 15 to 20 minute demonstration. It describes the implemented code, not proposed features. The tested integration has been merged into the repository's default branch, which is named master.

## 1 What the demonstration proves

Your project takes a saved network capture, preserves an encrypted copy, parses supported packet fields, stores related metadata in SQLite, groups conversations, flags two kinds of TCP SYN scanning, and produces signed encrypted investigation reports. It also verifies evidence and audit history.

Say this in your opening:

> Sir, our project is a cryptographically secured tool for analysing saved PCAP network captures. We combine packet parsing, a relational investigation database, scan detection, a dashboard, and independently verifiable evidence and reports. We will demonstrate both the analysis results and how the tool detects changes to signed evidence.

Then state the boundary once:

> This version analyses saved captures. TLS analysis is excluded. Managed captures and reports are encrypted, but parsed SQLite metadata remains unencrypted by our scope decision. Detection results are investigation indicators rather than proof of an attack.

Do not claim that this application captures live traffic, blocks attackers, detects every attack, detects silent eavesdroppers, encrypts the database, or reconstructs complete TCP application streams.

## 2 Prepare before entering the room

Use the same laptop on which TShark and the parser environment have been verified. Plug it into power. Keep your vault passphrase available privately; do not put it in slides or type it where it is visible. Close personal captures and private browser tabs.

Open PowerShell in the project and run:

```powershell
cd D:\Projects\PCAP-Forensic-Tool
git branch --show-current
git log -1 --oneline
& 'C:\Program Files\Wireshark\tshark.exe' --version
.\.venv-parser\Scripts\python.exe -m pip check
.\.venv-parser\Scripts\python.exe prepare_demo.py
```

The default branch is master. TShark was verified as 4.6.9 on this laptop. Do not reinstall dependencies during the live presentation. prepare_demo.py writes deterministic synthetic files and refuses to replace different existing content. If that refusal occurs, use a new output directory and update the upload paths accordingly.

For an uncluttered live session, create a new runtime database while retaining the established signing keys and vault account:

```powershell
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$demoRun = Join-Path $PWD ('runtime\presentation-' + $stamp)
$env:PCAP_DB = Join-Path $demoRun 'forensic.db'
$env:PCAP_STORAGE = Join-Path $demoRun 'evidence'
python launch_dashboard.py
```

Leave PCAP_KEYS unchanged on this existing laptop. The launcher selects .venv-parser automatically when available and binds Streamlit to 127.0.0.1. Open the localhost URL printed in the terminal, usually http://127.0.0.1:8501. Unlock with the established vault passphrase. A new browser session does not require a new account.

If another dashboard is running, stop that process with Ctrl+C in its own terminal before starting this session. Environment variables apply to the new process; refreshing an older process will not change its database. Keep the terminal running throughout the demo.

Run the automated rehearsal before presenting, not while sir is waiting:

```powershell
.\.venv-parser\Scripts\python.exe integration_demo.py
```

It prompts privately for a passphrase, creates separate demo databases and disposable signing keys, and prints a PASS result if the end-to-end checks succeed. The final merge passed 101 application tests, 24 teammate tests, and this rehearsal. A successful test run is evidence for tested cases, not a guarantee for every possible capture.

## 3 Keep these files ready

Paths below are relative to D:\Projects\PCAP-Forensic-Tool. Paste the full path into the file picker's File name field if browsing is slow.

| Capture | What it demonstrates | Expected full mode result |
| --- | --- | --- |
| runtime/demo-inputs/normal.pcap | DNS request and ordinary UDP exchange | 3 packets, 2 conversations, 1 DNS row, 0 alerts |
| runtime/demo-inputs/port-scan.pcap | One source sends SYNs to ports 20 through 60 on one destination | 41 packets, 41 conversations, 1 Medium port scan alert |
| runtime/demo-inputs/host-scan.pcap | One source sends SYNs to TCP port 22 on 30 destinations | 30 packets, 30 conversations, 1 Medium host scan alert |
| team_tests/fixtures/dns_valid.pcap | A DNS request and response | 2 packets, 1 conversation, 2 DNS rows, 0 alerts |
| team_tests/fixtures/ipv6_vlan_http.pcapng | IPv6 and VLAN capture with HTTP | 55 packets, 6 conversations, 2 HTTP rows, 0 alerts |
| runtime/demo-inputs/normal-tampered.pcap | A changed copy of the normal capture | Verify as a candidate against normal evidence and expect INVALID |
| runtime/demo-inputs/invalid.pcap | Invalid capture container | Analysis error and no additional evidence record |

Evidence IDs depend on the database. Write down the IDs returned by your own session rather than assuming that normal is always ID 1. DNS rows represent extracted messages or questions; answers are stored inside each row's answer list, so row count is not the number of individual DNS answers.

## 4 Opening and system explanation

### Minute 0 to 2 Introduce the problem

Show Overview and the system diagram from the viva guide.

Say:

> Network captures can contain many packets, and an investigator needs a way to search them, identify suspicious patterns and preserve the analysis evidence. Our tool brings those tasks into one workflow. The original capture bytes are the evidence, parsed database rows are derived investigation data, and the signed report is a versioned summary of the selected evidence.

Point to the diagram and say:

> Upload reaches one shared analysis service. A bounded reader checks the capture, the file vault encrypts the managed copy, PyShark uses TShark to extract fields, and a validation adapter checks every record and frame count. We run scan rules, sign the original-content digest, and store evidence, packets, protocol records, alerts and audit events. Conversation reconstruction follows in a separate transaction. The dashboard and report generator query that evidence's data.

If asked about roles, say:

> Aanya developed the SQLite schema, storage, conversation reconstruction and query functions. Jahnnavi developed the packet parser. Priyali developed cryptography, detection, dashboard and integration. The integrated release also contains completion patches for repeated parser fields and stricter failures; source provenance is recorded in TEAM_SOURCES.json.

Do not claim authorship more precisely than the actual Git history supports.

## 5 Demonstrate ordinary analysis

### Minute 2 to 4 Import normal traffic

1. In the left sidebar click Upload under Upload saved capture.
2. Select runtime/demo-inputs/normal.pcap.
3. Keep Analysis mode set to Full parser and database limited.
4. Tick I understand parsed metadata is stored in unencrypted SQLite.
5. Click Analyze capture.
6. Note the selected evidence ID and successful INTEGRATED_LIMITED status.
7. Open Investigation using its navigation button.

Expected: 3 stored packets, 2 conversations, 1 DNS row, and 0 scan alerts.

Say:

> This sample has one DNS query and a small UDP request and response. The request and response belong to the same bidirectional conversation, so three packets form two conversations. No configured scan rule fired. That does not prove the traffic is safe; it only means these rules found no qualifying pattern.

Show Protocol breakdown, Top source talkers and the UTC timeline. Explain that these are calculated from stored packet rows for the selected evidence. Under Packet filters select UDP and optionally enter 10.0.0.1. Select a Conversation to inspect and show packet directions.

Say:

> A conversation groups matching endpoint pairs in both directions. Forward here follows a consistent canonical endpoint ordering; it is not necessarily the client or the first sender. We group metadata and counts rather than reconstruct application payload streams.

## 6 Demonstrate scan detection

### Minute 4 to 7 Port scan followed by host scan

Upload port-scan.pcap using the same sidebar process. Open Alerts. Expect one Medium Possible Port Scan finding for source 10.0.0.1 against destination 10.0.0.2. Open Investigation and show 41 packets and 41 conversations.

Say:

> The rule looks for TCP packets with SYN set and ACK clear. It groups them by source and destination IP. More than 20 distinct destination ports in a 60 second sliding window produces an alert. This sample has 41 ports, so it crosses the threshold. Repeated SYNs to the same port do not count as different ports.

Then upload host-scan.pcap and show the host scan alert.

Say:

> The second rule keeps a destination port fixed and counts distinct destination hosts contacted by one source. Here one source probes TCP port 22 on 30 hosts. The same threshold and time window apply. We report these as possible scans because legitimate administrative scanning can look similar.

Use Selected evidence to switch back to normal traffic. Show that its alert count remains zero and its packet count stays three.

Say:

> Findings and queries are scoped by evidence ID, so importing a suspicious capture does not contaminate the normal capture's results.

If the aggregate risk indicator reads LOW despite a Medium alert, explain: each Medium alert contributes 20 points, and the aggregate category becomes MEDIUM at 25. Alert severity and aggregate risk category are different. This simple severity index is not a learned probability.

## 7 Demonstrate protocol extraction

### Minute 7 to 9 DNS and HTTP

Upload team_tests/fixtures/dns_valid.pcap and open Investigation. Show the two packets, one conversation and two DNS rows. Expand or scroll to the DNS answer data.

Say:

> We keep transport information in packets and application information in separate DNS and HTTP tables linked by packet ID. A DNS response may carry multiple answers, so the answer list preserves repeated supported resource values rather than only the first value.

Upload team_tests/fixtures/ipv6_vlan_http.pcapng. Show 55 packets, 6 conversations and 2 HTTP rows. Point to method, host, URI and status fields where present. A known HTTP host in this public sample is cl-1985.ham-01.de.sixxs.net.

Say:

> This demonstrates PCAPNG, IPv6 and VLAN handling. HTTP fields come from TShark dissections. HTTP is application metadata; the packet's transport protocol can still be TCP. We do not decrypt encrypted application traffic.

If short on time, show either DNS or HTTP and describe the other using the rehearsal results.

## 8 Demonstrate evidence integrity

### Minute 9 to 11 Verify the original and a modified copy

Select the normal capture's evidence ID. Open Evidence Security. Make sure Optional modified copy to verify against this evidence is empty. Click Verify Evidence. Expect VALID.

Say:

> The capture's original plaintext bytes have a SHA 256 digest. Our RSA 2048 PSS signature covers that digest. Verification checks the current bytes against the recorded digest, the signature manifest and the archived signing public key. It does not create a new signature while verifying.

Now use the optional modified-copy uploader on this page, not the main capture uploader. Choose runtime/demo-inputs/normal-tampered.pcap. Click Verify Evidence again. Expect INVALID and a recorded failed verification event.

Say:

> We changed a copy by one byte and compare it against the original evidence's signature. The mismatch is detected. We have not overwritten the original evidence. Signing a changed file as new evidence would establish a new baseline and would not demonstrate this tamper test.

Clarify if asked:

> A valid signature establishes consistency with the trusted signing key after our signing baseline. It does not prove the capture was truthful before import or identify a human signer without a separate trust process.

Remove the candidate upload if you want the next verification to check the stored original again.

## 9 Demonstrate confidentiality

### Minute 11 to 12 Explain what encryption protects

In Evidence Security point to Download encrypted evidence and its .vault output. Do not display your real private key or vault passphrase. Use the automated confidentiality rehearsal to show wrong-password and changed-ciphertext failures if sir asks for an extra test.

Say:

> AES 256 GCM protects new managed capture and report files. Scrypt derives a key from our passphrase with a fresh random salt, and each encrypted artifact has a fresh nonce. GCM also detects changes to the encrypted content or authenticated header. RSA signatures provide a separate public-key integrity check over the original content.

Then state:

> The original file chosen for upload remains where it was; encryption applies to our managed copy. Parsed SQLite metadata is not encrypted in this version. We therefore do not claim complete confidentiality of all project data or protection against a person who already controls the unlocked laptop.

Do not say that encrypting the saved file prevents an observer from seeing plaintext traffic that was already transmitted.

## 10 Demonstrate reports and portable verification

### Minute 12 to 15 Create and verify a report

Select the port scan evidence for an interesting report. Open Reports. Click Generate and Sign Report, displayed as Generate & Sign Report in the UI. Click Verify Report and expect VALID. Show the selected-evidence summary and unique report version.

Say:

> The report contains this evidence's metadata, verification result at generation time, stored-data summaries and alerts. All capture-derived text is escaped before insertion into HTML. Each report is a new version, so generating a later report does not overwrite an earlier signed report. The report file and default export bundle are encrypted.

For a readable display, tick Allow a decrypted HTML export for this session, download the decrypted HTML and open that authorized demo copy. Explain that it is intentionally readable and must be protected separately.

For the full portable verification extension, save Download encrypted verification bundle as report-bundle.zip.vault in a new runtime/demo-export directory. Then run:

```powershell
.\.venv-parser\Scripts\python.exe vault_cli.py decrypt `
  --input runtime\demo-export\report-bundle.zip.vault `
  --output runtime\demo-export\report-bundle.zip
Expand-Archive -LiteralPath runtime\demo-export\report-bundle.zip `
  -DestinationPath runtime\demo-export\unpacked
.\.venv-parser\Scripts\python.exe runtime\demo-export\unpacked\verify.py
```

Use a fresh export directory on each rehearsal; the decryption CLI refuses to overwrite existing output. The verifier prints VALID and exits zero. It needs cryptography but no application database or private key. Preserve the received public key's fingerprint through a trusted channel; replacing the entire artifact, signature and key set can otherwise create a different self-consistent bundle.

Optional changed-report test, only in this extracted synthetic/public demo copy:

```powershell
$report = 'runtime\demo-export\unpacked\report.html'
Add-Content -LiteralPath $report -Value '<!-- demo modification -->'
.\.venv-parser\Scripts\python.exe runtime\demo-export\unpacked\verify.py
```

Expect INVALID and a nonzero exit. Do not regenerate or re-sign the changed report before this test. The automated integration rehearsal already performs both portable tests if live time is limited.

## 11 Demonstrate audit integrity and graceful failure

### Minute 15 to 17 Audit trail

Open Audit Log. Click Verify Audit Chain. Expect a valid global chain. Show the selected evidence's import, detection, flow, verification and report entries. Click Save Signed Audit Checkpoint and show that its data, signature, manifest and public key can be downloaded.

Say:

> Audit entries link to the previous entry's hash. Version two also binds the entry ID, evidence ID, operation, status, timestamp, details and version into the digest. The chain detects inconsistent history. Because someone could rewrite a whole unkeyed chain or delete its tail, we can preserve a separately signed checkpoint outside the database to anchor the history already observed.

Say:

> The visible table is filtered to the selected evidence, but chain verification checks the global history because links cross evidence boundaries. The checkpoint does not independently sign every packet or alert row. Original evidence and report signatures have their own verification.

Never delete audit rows in the real demonstration database. The isolated rehearsal uses a separate deliberately damaged database to test checkpoint detection of tail removal.

### Minute 17 to 18 Invalid input

Upload invalid.pcap through the main sidebar and click Analyze capture. Expect an error. Confirm that Selected evidence contains no additional successful evidence entry.

Say:

> Invalid captures are rejected rather than treated as empty or clean traffic. Packet or protocol insert failures roll back the first database transaction. If the later conversation rebuild fails, signed evidence and packets remain with a visible FLOW_FAILED state and a retry action. We do not mark that as complete.

Do not try to trigger a real disk or database failure during the presentation; those paths are covered by controlled regression tests.

## 12 Closing statement

Say:

> We have demonstrated capture import, packet and protocol investigation, bidirectional conversation summaries, two scan heuristics, evidence tamper detection, encrypted managed files, signed reports and audit verification. The tested default branch is ready for this scope. Our declared limitations are plaintext database metadata, a bounded supported parsing subset, no TLS analysis, no live blocking and no application-level TCP stream reconstruction.

Then stop talking and invite questions. If unsure of an answer, distinguish what the code implements from what could be added later. Use the viva handbook to locate the relevant function rather than inventing a feature.

## 13 Five minute version

1. Introduce the purpose and scope in 30 seconds.
2. Import normal.pcap and show three packets with no scan finding.
3. Import port-scan.pcap and explain 41 distinct ports versus the threshold of more than 20 in 60 seconds.
4. Select normal evidence, verify it, and verify normal-tampered.pcap as a candidate to show INVALID.
5. Generate and verify one report, then verify the audit chain.
6. State that the full rehearsal covers DNS, HTTP, host scan, rollback, encryption and offline verification; mention the limits.

## 14 Recovery notes

| Symptom | What to do and say |
| --- | --- |
| Full parsing needs PyShark | Stop the old dashboard and start with python launch_dashboard.py so .venv-parser is selected. |
| TShark not found | Check the installed executable path. Set TSHARK_PATH before restarting if needed. Do not silently switch modes and present that as full integration. |
| Port 8501 is occupied | Stop your earlier server or set STREAMLIT_SERVER_PORT to another local port before launch. |
| Empty packet tables | Check whether the selected evidence was imported in network-only mode. Import the source in full mode for stored packet and protocol rows. |
| Missing or mismatched signing key | Keep established keys intact. Restore the matching pair or use a deliberately separate directory for a new installation. Do not delete keys to make the error disappear. |
| Wrong vault passphrase | Re-enter it privately. There is no recovery feature for encrypted artifacts. Resetting the login configuration does not decrypt old data. |
| Filter shows no packets | Confirm selected evidence, reset protocol to All, clear IP/time filters and use packet page 1. |
| FLOW_FAILED or PROCESSING_FLOWS | Open Investigation and use Retry flow reconstruction. Explain retained evidence; do not claim success before completion. |
| Different evidence IDs | Use the IDs actually returned by the session; earlier captures may already exist. |
| Duplicate click adds no new capture | This is expected within the same dashboard submission token. A new session or separate CLI import may create another evidence record. |
| External verifier reports INVALID | Confirm that the original bundle is intact, decrypted once and extracted fully; the intentionally modified demo report is expected to fail. |

## 15 Team speaking plan

Priyali leads the opening, integration flow, detection rules, cryptographic checks, dashboard and report demonstration. Jahnnavi explains PyShark/TShark, normalized fields, repeated protocol data and fatal extraction handling. Aanya explains keys and relationships in the schema, transactions, indexes, conversation grouping and scoped queries. Everyone should know the purpose, thresholds, confidentiality boundary and signature trust limitations.

Read the viva handbook's core answers first, then practise the questions assigned to your own component. Keep the diagram and fixture-results table open as backups. Use your own words after rehearsing; the quoted script is a preparation aid rather than a claim that every sentence must be memorised.
