"""Shared vault, parser, storage, detection and report workflow."""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import shutil
import sqlite3
from pathlib import Path
from uuid import uuid4

from capture_records import MAX_CAPTURE_BYTES, read_network_records
from crypto_utils import calculate_sha256, secure_evidence, signature_metadata, verify_evidence_file, verify_evidence_bytes
from confidentiality import resolve_password,write_encrypted,read_artifact
from database import create_database
from security_detection import run_network_detection

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = BASE_DIR / 'runtime' / 'forensic.db'
DEFAULT_STORAGE = BASE_DIR / 'runtime' / 'evidence'
DEFAULT_KEYS = BASE_DIR / 'keys'


@contextmanager
def connection(db_name):
    conn = sqlite3.connect(str(db_name), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys=ON')
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def initialize_database(db_name=DEFAULT_DB):
    Path(db_name).parent.mkdir(parents=True, exist_ok=True)
    create_database(str(db_name))
    with connection(db_name) as conn:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS app_analysis (
                evidence_id INTEGER PRIMARY KEY REFERENCES evidence(evidence_id),
                submission_id TEXT UNIQUE NOT NULL, original_filename TEXT NOT NULL,
                key_id TEXT NOT NULL, status TEXT NOT NULL, packet_count INTEGER NOT NULL,
                context_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS app_reports (
                report_id INTEGER PRIMARY KEY, evidence_id INTEGER NOT NULL REFERENCES evidence(evidence_id),
                path TEXT NOT NULL UNIQUE, signature_path TEXT NOT NULL, sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
        ''')


def append_audit(conn, evidence_id, operation, status='SUCCESS'):
    """Append using whichever audit hash version the installed DB schema supports."""
    columns = {row[1] for row in conn.execute('PRAGMA table_info(audit_log)')}
    previous = conn.execute('SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1').fetchone()
    prior = previous[0] if previous else 'GENESIS'
    timestamp = datetime.now(timezone.utc).isoformat()
    if {'details', 'hash_version'} <= columns:
        row = dict(evidence_id=evidence_id, operation=operation, status=status, timestamp=timestamp,
                   prev_hash=prior, details='{}', hash_version=2)
        cursor = conn.execute('''INSERT INTO audit_log
            (evidence_id,operation,status,timestamp,prev_hash,entry_hash,details,hash_version)
            VALUES(:evidence_id,:operation,:status,:timestamp,:prev_hash,'PENDING',:details,:hash_version)''', row)
        row['id'] = cursor.lastrowid
        payload = json.dumps(row, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
        conn.execute('UPDATE audit_log SET entry_hash=? WHERE id=?', (hashlib.sha256(payload.encode()).hexdigest(), row['id']))
    else:
        digest = hashlib.sha256((operation + status + timestamp + prior).encode()).hexdigest()
        conn.execute('''INSERT INTO audit_log(evidence_id,operation,status,timestamp,prev_hash,entry_hash)
            VALUES(?,?,?,?,?,?)''', (evidence_id, operation, status, timestamp, prior, digest))


def _result(conn, evidence_id):
    row = conn.execute('SELECT * FROM app_analysis WHERE evidence_id=?', (evidence_id,)).fetchone()
    context=json.loads(row['context_json'])
    return dict(evidence_id=evidence_id, packet_count=row['packet_count'], status=row['status'],
                alert_count=conn.execute('SELECT COUNT(*) FROM alerts WHERE evidence_id=?', (evidence_id,)).fetchone()[0],
                flow_count=context.get('flow_count',0))


def process_capture(path, *, db_name=DEFAULT_DB, storage_dir=DEFAULT_STORAGE,
                    key_dir=DEFAULT_KEYS, submission_id=None, original_filename=None,
                    mode='network',allow_plaintext_metadata=False,tshark_path=None):
    if mode not in ('network','full'):raise ValueError('Analysis mode must be network or full')
    if mode=='full' and not allow_plaintext_metadata:
        raise PermissionError('Full parsing stores unencrypted SQLite metadata; explicit acknowledgement is required')
    source = None if isinstance(path,bytes) else Path(path).resolve()
    if (len(path) if source is None else source.stat().st_size) > MAX_CAPTURE_BYTES:
        raise ValueError('Capture exceeds the 20 MiB analysis limit')
    resolve_password()
    content=path if source is None else source.read_bytes()
    if len(content)>MAX_CAPTURE_BYTES:raise ValueError('Capture exceeds the 20 MiB analysis limit')
    initialize_database(db_name)
    token = submission_id or uuid4().hex
    with connection(db_name) as conn:
        old = conn.execute('SELECT evidence_id FROM app_analysis WHERE submission_id=?', (token,)).fetchone()
        if old:
            digest = conn.execute('SELECT sha256 FROM evidence WHERE evidence_id=?', (old[0],)).fetchone()[0]
            if hashlib.sha256(content).hexdigest() != digest:
                raise ValueError('Submission token already belongs to another file')
            old_context=json.loads(conn.execute('SELECT context_json FROM app_analysis WHERE evidence_id=?',(old[0],)).fetchone()[0])
            if old_context.get('analysis_mode','network')!=mode:
                raise ValueError('Submission token already belongs to another analysis mode')
            return _result(conn, old[0])
    folder = Path(storage_dir).resolve() / uuid4().hex
    folder.mkdir(parents=True)
    name=Path(str(original_filename or (source.name if source else 'upload.pcap')).replace('\\','/')).name
    staged = folder / ('capture' + ('.pcapng' if name.lower().endswith('.pcapng') else '.pcap') + '.vault')
    signature = None
    committed=False
    try:
        reference = read_network_records(content)
        write_encrypted(staged,content,purpose='evidence')
        if mode=='full':
            from integration_runtime import parse_content,PARSER_LIMITATIONS,TEAM_COMMIT
            records=parse_content(read_artifact(staged),tshark_path=tshark_path)['records']
        else:records=reference
        alerts = run_network_detection(records)
        digest, signature = secure_evidence(staged, signature_dir=folder, key_dir=key_dir)
        metadata = signature_metadata(signature)
        counts = {}
        for record in records:
            protocol = record['protocol']
            counts[protocol] = counts.get(protocol, 0) + 1
        context = dict(protocol_counts=counts, captured_bytes=sum(p['length'] for p in reference),
                       wire_bytes=sum(p['length'] for p in records),analysis_mode=mode,
                       dns_record_count=sum(len(p.get('dns_records',[])) for p in records),
                       http_record_count=sum(len(p.get('http_records',[])) for p in records),
                       rule_version=1, threshold=20, window_seconds=60,
                       artifact_storage='AES-256-GCM password-derived vault; SQLite metadata is not encrypted',
                       parser_status='Network-only mode selected; DNS/HTTP/packet/flow storage was not requested')
        if mode=='full':context.update(parser_status='Functional parser integration with known limitations',
                                      parser_source_commit=TEAM_COMMIT,limitations=PARSER_LIMITATIONS)
        with connection(db_name) as conn:
            conn.execute('BEGIN IMMEDIATE')
            # A simultaneous retry can arrive after staging. Only one may commit.
            old = conn.execute('SELECT evidence_id FROM app_analysis WHERE submission_id=?', (token,)).fetchone()
            if old:
                prior = conn.execute('SELECT sha256 FROM evidence WHERE evidence_id=?', (old[0],)).fetchone()[0]
                if prior != digest:
                    raise ValueError('Submission token already belongs to another file')
                existing=json.loads(conn.execute('SELECT context_json FROM app_analysis WHERE evidence_id=?',(old[0],)).fetchone()[0])
                if existing.get('analysis_mode','network')!=mode:raise ValueError('Submission token already belongs to another analysis mode')
                result = _result(conn, old[0])
            else:
                timestamp = datetime.now(timezone.utc).isoformat()
                eid = conn.execute('INSERT INTO evidence(filename,sha256,import_time,signature) VALUES(?,?,?,?)',
                    (str(staged), digest, timestamp, signature)).lastrowid
                conn.execute('INSERT INTO app_analysis VALUES(?,?,?,?,?,?,?)',
                    (eid, token, name, metadata['key_id'], 'PROCESSING_FLOWS' if mode=='full' else 'NETWORK_ONLY', len(records), json.dumps(context, sort_keys=True)))
                if mode=='full':
                    from integration_storage import store_packets
                    store_packets(conn,eid,records)
                for alert in alerts:
                    conn.execute('''INSERT INTO alerts(packet_id,alert_type,severity,description,timestamp,evidence_id)
                        VALUES(NULL,?,?,?,?,?)''', (alert['type'], alert['severity'], alert['description'], timestamp, eid))
                append_audit(conn, eid, 'IMPORT_FULL_PARSER' if mode=='full' else 'IMPORT_NETWORK_ONLY')
                append_audit(conn, eid, 'DETECT_NETWORK')
                result = _result(conn, eid)
                committed=True
        if committed:
            if mode=='full':return rebuild_flows(eid,db_name=db_name)
            return result
        # Retry lost the race; remove only artifacts created by this invocation.
        for artifact in folder.iterdir():
            artifact.unlink()
        folder.rmdir()
        return result
    except Exception:
        if committed:raise  # A flow failure retains signed evidence and a visible retryable status.
        for artifact in folder.iterdir():
            if artifact.is_file():
                artifact.unlink()
        folder.rmdir()
        raise


def rebuild_flows(evidence_id, *, db_name=DEFAULT_DB):
    resolve_password()
    from database import reconstruct_flows
    with connection(db_name) as conn:
        row=conn.execute('SELECT * FROM app_analysis WHERE evidence_id=?',(evidence_id,)).fetchone()
        if row is None or json.loads(row['context_json']).get('analysis_mode')!='full':
            raise ValueError('Flow rebuilding requires a full-parser analysis')
    try:
        count=reconstruct_flows(str(db_name),evidence_id)
    except Exception as error:
        with connection(db_name) as conn:
            conn.execute('BEGIN IMMEDIATE')
            conn.execute("UPDATE app_analysis SET status='FLOW_FAILED' WHERE evidence_id=?",(evidence_id,))
            append_audit(conn,evidence_id,'FLOW_REBUILD','FAILED')
        raise RuntimeError(f'Evidence #{evidence_id} and packets retained; flow rebuild failed and can be retried') from error
    with connection(db_name) as conn:
        conn.execute('BEGIN IMMEDIATE')
        context=json.loads(conn.execute('SELECT context_json FROM app_analysis WHERE evidence_id=?',(evidence_id,)).fetchone()[0])
        context['flow_count']=count
        conn.execute("UPDATE app_analysis SET status='INTEGRATED_LIMITED',context_json=? WHERE evidence_id=?",(json.dumps(context,sort_keys=True),evidence_id))
        append_audit(conn,evidence_id,'FINALIZE_LIMITED')
        return _result(conn,evidence_id)


def get_evidence(evidence_id, db_name=DEFAULT_DB):
    if not Path(db_name).is_file():
        raise FileNotFoundError(f'Evidence database does not exist: {db_name}')
    with connection(db_name) as conn:
        row = conn.execute('SELECT * FROM evidence WHERE evidence_id=?', (evidence_id,)).fetchone()
        if row is None:
            raise ValueError('Evidence ID does not exist')
        return dict(row)


def verify_evidence(evidence_id, *, db_name=DEFAULT_DB, candidate_path=None, candidate_data=None, key_dir=DEFAULT_KEYS):
    evidence = get_evidence(evidence_id, db_name)
    path = Path(candidate_path or evidence['filename'])
    if not path.is_absolute():
        path = BASE_DIR / path
    signature = Path(evidence['signature'])
    if not signature.is_absolute():
        signature = BASE_DIR / signature
    try:
        valid = (verify_evidence_file(path, signature, expected_sha256=evidence['sha256'], key_dir=key_dir)
                 if candidate_data is None else verify_evidence_bytes(candidate_data,signature,expected_sha256=evidence['sha256'],key_dir=key_dir))
    except Exception:
        with connection(db_name) as conn:
            conn.execute('BEGIN IMMEDIATE')
            append_audit(conn, evidence_id, 'VERIFY', 'FAILED')
        raise
    with connection(db_name) as conn:
        conn.execute('BEGIN IMMEDIATE')
        append_audit(conn, evidence_id, 'VERIFY', 'SUCCESS' if valid else 'FAILED')
    return valid
