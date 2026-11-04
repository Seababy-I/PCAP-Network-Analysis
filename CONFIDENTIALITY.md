# Confidentiality and passive observation

## What this protects

New application-managed PCAP files, HTML reports and report-export bundles use AES-256-GCM authenticated encryption. Each artifact has a fresh random 16-byte salt and 12-byte nonce. A 32-byte key is derived from the analyst passphrase with Scrypt (N=32768, r=8, p=1). The version/type/salt/nonce header is authenticated as associated data. Modified ciphertext, a wrong passphrase or a damaged header fails decryption. Passwords and derived encryption keys are not written alongside artifacts.

Original SHA-256/RSA signatures still cover the original plaintext evidence/report bytes. Authorized verification decrypts in memory before checking them. The application processes uploaded bytes in memory rather than creating a plaintext staging file. New signing-key pairs use password-encrypted PKCS8; established signing keys are preserved for compatibility and are not silently replaced or migrated.

This addresses unauthorized reading of managed stored files. It does not establish that someone previously sniffed network traffic, hide traffic-analysis metadata, or prevent a privileged administrator/malware reading an already-unlocked process. Strong passphrases are required. Keep the passphrase safe: the application cannot recover it.

## Dashboard access

```powershell
cd D:\Projects\PCAP-Forensic-Tool
python launch_dashboard.py
```

The launcher binds only to loopback. On first launch, create a local analyst passphrase in the password-masked setup form, then unlock. No production passphrase is generated, hardcoded or requested in chat. A salted Scrypt verifier is stored in `.secrets/dashboard_auth.json`, not the plaintext passphrase. The same secret unlocks the session's vault operations. The app refuses non-loopback configuration before presenting setup/login or reading evidence.

All investigation pages and download controls are behind unlock. Use Lock vault when leaving. An inactive session requires a fresh unlock on its next interaction after 15 minutes. This is a local single-analyst gate, not an internet-facing multi-user identity system. Session state/plaintext data can exist in memory while unlocked. Do not expose Streamlit on a LAN/public interface; TLS remains excluded from project analysis scope.

There is no password-reset shortcut: deleting the verifier does not decrypt old artifacts. Password rotation/recovery requires an explicit verified re-encryption/key-migration procedure and is not automated here.

## CLI use

Signing/import/report commands prompt privately for the vault passphrase in an interactive terminal. Use the same vault passphrase as the dashboard for shared artifacts. `PCAP_VAULT_PASSWORD` is supported for controlled automation; do not put secrets in command arguments, source, Git or logs. Public-key verification of an already-decrypted report does not need the vault password.

New managed artifacts end in `.vault`. Evidence, HTML and report bundles download encrypted by default, including exports of historical files. The unlocked dashboard permits explicitly selected decrypted evidence/HTML exports; these actions are audited and the resulting files are readable authorized copies.

```powershell
python run_security.py --pcap data/sample.pcap
python verify_evidence.py --evidence-id 1
python report_generator.py --evidence-id 1 --sign
python vault_cli.py decrypt --input PATH_TO_REPORT_BUNDLE.zip.vault --output report-bundle.zip
```

Extract the intentionally decrypted ZIP and run its `python verify.py` to verify the report without SQLite/private keys. `vault_cli.py` never overwrites an output and never deletes the source. An authorized decrypted export must be protected separately. Filesystem permissions follow the analyst's account; this is not a defense against that account's administrator or a captured password.

## Existing files and database limits

Historical captures, databases, reports and signing keys are retained unchanged. Original source files selected for CLI import remain under the analyst's control outside managed storage. Those legacy/source files are not retroactively encrypted. Public signature metadata, file sizes and some names/timing remain visible.

**SQLite metadata and extracted records remain plaintext; database encryption is explicitly deferred for this version.** The dashboard gate controls application access but does not encrypt or prevent direct copying/querying of the SQLite file. Do not claim full project/data confidentiality while that storage gap remains. The database requirement is recorded in `INTEGRATION_HANDOFF.md`; no teammate module is modified by this change.

## Demonstration

```powershell
python confidentiality_demo.py
```

Enter a demonstration passphrase privately. A unique isolated run contains synthetic inputs, a separate DB/signing pair and encrypted managed artifacts. `results.json` records only results/paths, never the passphrase. Show encrypted bytes, successful authorized decryption, matching original hash/signature, rejected wrong-password/ciphertext tampering and encrypted signed report exports. Synthetic source inputs remain separately readable so the original-vs-encrypted comparison is explicit.

## Sources

The construction uses the library's [authenticated encryption API](https://cryptography.io/en/latest/hazmat/primitives/aead/) and [password key-derivation API](https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/). The [Internet Security Glossary](https://www.rfc-editor.org/rfc/rfc4949.html) distinguishes passive information gathering from alteration of system resources; integrity-only checks cannot demonstrate confidentiality.
