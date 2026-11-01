"""Evidence-scoped, escaped HTML reports with unique signed artifacts."""
import argparse
from datetime import datetime, timezone
from html import escape
import json
import io
import zipfile
import sqlite3
from pathlib import Path
from uuid import uuid4

from analysis_service import BASE_DIR, DEFAULT_DB, DEFAULT_KEYS, append_audit, connection, initialize_database
from crypto_utils import calculate_sha256, sign_report, verify_evidence_file, signing_public_key_path
from risk_scoring import calculate_risk_score
from confidentiality import read_artifact,write_encrypted,encrypt_bytes,resolve_password,prompt_password,set_session_password
import investigation


def get_data(evidence_id, *, db_name=DEFAULT_DB):
    with connection(db_name) as conn:
        evidence = conn.execute('SELECT * FROM evidence WHERE evidence_id=?', (evidence_id,)).fetchone()
        if evidence is None:
            raise ValueError('Select an existing evidence ID')
        alerts = conn.execute('SELECT * FROM alerts WHERE evidence_id=? ORDER BY alert_id', (evidence_id,)).fetchall()
        info = conn.execute('SELECT * FROM app_analysis WHERE evidence_id=?', (evidence_id,)).fetchone()
    return dict(evidence), [dict(row) for row in alerts], dict(info) if info else None


def generate_report(evidence_id, *, db_name=DEFAULT_DB, output_path=None, key_dir=DEFAULT_KEYS):
    resolve_password()
    evidence, alerts, analysis = get_data(evidence_id, db_name=db_name)
    target = Path(output_path) if output_path else Path(db_name).resolve().parent / 'reports' / f'evidence-{evidence_id}-{uuid4().hex}.html'
    if target.suffix!='.vault':target=Path(str(target)+'.vault')
    target.parent.mkdir(parents=True, exist_ok=True)
    def safe(value):
        return escape(str(value if value is not None else 'Unknown'), quote=True)
    verification = 'Verification unavailable'
    try:
        evidence_path, signature = Path(evidence['filename']), Path(evidence['signature'])
        if not evidence_path.is_absolute(): evidence_path = BASE_DIR / evidence_path
        if not signature.is_absolute(): signature = BASE_DIR / signature
        valid = verify_evidence_file(evidence_path, signature, expected_sha256=evidence['sha256'], key_dir=key_dir)
        verification = 'VALID' if valid else 'INVALID: digest or signature mismatch'
    except (OSError, ValueError, KeyError, TypeError):
        pass
    risk = calculate_risk_score(alerts)
    metadata = dict(evidence)
    metadata['verification_at_generation'] = verification
    metadata['analysis_status'] = analysis['status'] if analysis else 'LEGACY: provenance/processing status not recorded'
    if analysis:
        metadata.update(original_filename=analysis['original_filename'], key_id=analysis['key_id'],
                        packet_count=analysis['packet_count'], **json.loads(analysis['context_json']))
    fields = ''.join(f'<tr><th>{safe(k)}</th><td>{safe(v)}</td></tr>' for k, v in metadata.items())
    snapshot=investigation.overview(evidence_id,db_name)
    summary='<h2>Stored investigation summary</h2><table>'+''.join(f'<tr><th>{safe(k)}</th><td>{safe(v)}</td></tr>' for k,v in snapshot['counts'].items())+'</table>'
    for title,key in [('Protocol breakdown','protocols'),('Top source talkers','top_talkers'),('Conversations (first 20)','flows')]:
        summary+=f'<h3>{safe(title)}</h3><pre>{safe(json.dumps(snapshot[key][:20],indent=2))}</pre>'
    rows = ''.join('<tr>' + ''.join(f'<td>{safe(a[key])}</td>' for key in
        ('alert_id', 'alert_type', 'severity', 'description', 'timestamp')) + '</tr>' for a in alerts)
    if not rows:
        rows = '<tr><td colspan="5">No alerts recorded for this evidence.</td></tr>'
    document = f'''<!doctype html><html><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Evidence {evidence_id} forensic report</title>
<style>body{{font:15px Arial;margin:32px;color:#182432}}table{{border-collapse:collapse;width:100%;margin:20px 0}}td,th{{border:1px solid #ccd;padding:9px;text-align:left;overflow-wrap:anywhere}}th{{background:#eef}}</style>
</head><body><h1>PCAP Forensic Investigation Report</h1>
<p>Generated UTC: {safe(datetime.now(timezone.utc).isoformat())}</p>
<h2>Selected evidence</h2><table>{fields}</table>{summary}
<p>Heuristic severity index: {risk['score']}/100 ({safe(risk['risk_level'])}). This is not a safety verdict.</p>
<h2>Evidence-scoped alerts</h2><table><tr><th>ID</th><th>Type</th><th>Severity</th><th>Description</th><th>Time</th></tr>{rows}</table>
<p>Analysis status and parser limitations are recorded above. Network-only imports have no stored packets/flows. Integrated-limited imports have functional packet/DNS/HTTP/flow storage, within the documented parser format limits. SQLite metadata remains unencrypted. Historical evidence may contain demonstrations. Heuristics require further investigation.</p>
</body></html>'''
    # Prevent an export from replacing an earlier signed report.
    write_encrypted(target,document.encode('utf-8'),purpose='report')
    return str(target.resolve())


def generate_signed_report(evidence_id, *, db_name=DEFAULT_DB, output_path=None, key_dir=DEFAULT_KEYS):
    report = generate_report(evidence_id, db_name=db_name, output_path=output_path, key_dir=key_dir)
    signature = sign_report(report, signature_dir=Path(report).parent, key_dir=key_dir)
    with connection(db_name) as conn:
        conn.execute('BEGIN IMMEDIATE')
        conn.execute('INSERT INTO app_reports(evidence_id,path,signature_path,sha256,created_at) VALUES(?,?,?,?,?)',
            (evidence_id, report, signature, calculate_sha256(report), datetime.now(timezone.utc).isoformat()))
        append_audit(conn, evidence_id, 'REPORT_SIGN')
    return report, signature


def report_bundle(report_path, signature_path, *, key_dir=DEFAULT_KEYS, plaintext=False):
    """Portable public-only export. No private keys or evidence/database files."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('report.html',read_artifact(report_path))
        archive.write(signature_path, 'report.sig')
        archive.write(str(signature_path) + '.json', 'report.sig.json')
        archive.write(signing_public_key_path(signature_path, key_dir), 'public_key.pem')
        # Export a tiny standalone verifier, requiring only the cryptography dependency.
        archive.writestr('verify.py', '''import hashlib, json
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
root=Path(__file__).resolve().parent
metadata=json.loads((root/'report.sig.json').read_text())
public=serialization.load_pem_public_key((root/'public_key.pem').read_bytes())
fingerprint=hashlib.sha256(public.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
data=(root/'report.html').read_bytes()
valid=metadata.get('version')==1 and metadata.get('algorithm')=='RSA-PSS-SHA256' and metadata.get('key_id')==fingerprint and metadata.get('sha256')==hashlib.sha256(data).hexdigest()
try:
    public.verify((root/'report.sig').read_bytes(),data,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
except InvalidSignature:
    valid=False
print('VALID' if valid else 'INVALID')
raise SystemExit(0 if valid else 1)
''')
        archive.writestr('README.txt', 'Install cryptography, then run: python verify.py\nVerify report.html without regenerating it.\nValidity is relative to public_key.pem; establish the key fingerprint through a trusted channel.\n')
    return buffer.getvalue() if plaintext else encrypt_bytes(buffer.getvalue(),purpose='report-export')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence-id', type=int, required=True)
    parser.add_argument('--db', default=str(DEFAULT_DB))
    parser.add_argument('--keys', default=str(DEFAULT_KEYS))
    parser.add_argument('--output')
    parser.add_argument('--sign', action='store_true')
    args = parser.parse_args(argv)
    try:
        set_session_password(prompt_password())
        if not Path(args.db).is_file():
            raise FileNotFoundError(f'Evidence database does not exist: {args.db}')
        initialize_database(args.db)
        function = generate_signed_report if args.sign else generate_report
        print(function(args.evidence_id, db_name=args.db, output_path=args.output, key_dir=args.keys))
    except (ValueError, OSError, sqlite3.Error) as error:
        parser.exit(1, f'Report failed: {error}\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
