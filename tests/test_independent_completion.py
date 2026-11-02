from concurrent.futures import ThreadPoolExecutor
import io
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import zipfile

import pytest
import crypto_utils as crypto
import analysis_service as service
from audit_security import create_checkpoint, verify_audit
from report_generator import generate_signed_report, report_bundle
from verify_artifact import verify_artifact
from confidentiality import decrypt_bytes
from test_security_workflow import environment, capture


def test_concurrent_first_signing_reuses_one_key(environment,tmp_path):
    source=tmp_path/'input'; source.write_bytes(b'original')
    def sign(_): return crypto.secure_evidence(source,signature_dir=tmp_path/'sig',key_dir=environment['key_dir'])[1]
    with ThreadPoolExecutor(max_workers=4) as pool:
        signatures=list(pool.map(sign,range(4)))
    assert len(set(signatures))==4
    assert len({crypto.signature_metadata(path)['key_id'] for path in signatures})==1
    assert all(crypto.verify_evidence_file(source,path,key_dir=environment['key_dir']) for path in signatures)


def test_portable_bundle_without_database_or_private_key(environment,tmp_path):
    item=service.process_capture(capture(tmp_path),**environment)
    report,signature=generate_signed_report(item['evidence_id'],db_name=environment['db_name'],key_dir=environment['key_dir'])
    bundle=report_bundle(report,signature,key_dir=environment['key_dir'])
    export=tmp_path/'export'; export.mkdir()
    with zipfile.ZipFile(io.BytesIO(decrypt_bytes(bundle))) as archive:
        assert set(archive.namelist())=={'report.html','report.sig','report.sig.json','public_key.pem','verify.py','README.txt'}
        archive.extractall(export)
    args=[sys.executable,str(export/'verify.py')]
    assert subprocess.run(args,capture_output=True).returncode==0
    assert verify_artifact(export/'report.html',export/'report.sig',export/'public_key.pem',export/'report.sig.json')
    (export/'report.html').write_text('modified')
    assert subprocess.run(args,capture_output=True).returncode==1


def test_checkpoint_detects_tail_loss_but_allows_later_appends(environment,tmp_path):
    item=service.process_capture(capture(tmp_path),**environment)
    path,signature=create_checkpoint(environment['db_name'],tmp_path/'checkpoints',key_dir=environment['key_dir'])
    options=dict(checkpoint=path,signature=signature,key_dir=environment['key_dir'])
    assert verify_audit(environment['db_name'],**options)[0]
    service.verify_evidence(item['evidence_id'],db_name=environment['db_name'],key_dir=environment['key_dir'])
    assert verify_audit(environment['db_name'],**options)[0]
    with service.connection(environment['db_name']) as conn:
        conn.execute('DELETE FROM audit_log WHERE id >= 2')
    assert verify_audit(environment['db_name'])[0] # Remaining prefix is internally valid.
    assert not verify_audit(environment['db_name'],**options)[0]


def test_checkpoint_signature_tamper_and_previous_link(environment,tmp_path):
    service.process_capture(capture(tmp_path),**environment)
    path,signature=create_checkpoint(environment['db_name'],tmp_path/'checkpoints',key_dir=environment['key_dir'])
    Path(path).write_text('{}')
    assert not verify_audit(environment['db_name'],checkpoint=path,signature=signature,key_dir=environment['key_dir'])[0]
    with service.connection(environment['db_name']) as conn:
        conn.execute("UPDATE audit_log SET prev_hash='modified' WHERE id=2")
    assert not verify_audit(environment['db_name'])[0]
    with pytest.raises(ValueError): create_checkpoint(environment['db_name'],tmp_path/'bad',key_dir=environment['key_dir'])


def test_v2_chain_compatible_without_teammate_import(tmp_path):
    db=tmp_path/'v2.db'
    with service.connection(db) as conn:
        conn.execute('''CREATE TABLE audit_log(id INTEGER PRIMARY KEY,evidence_id INTEGER,operation TEXT,status TEXT,
            timestamp TEXT,prev_hash TEXT,entry_hash TEXT,details TEXT,hash_version INTEGER)''')
        service.append_audit(conn,1,'IMPORT')
        service.append_audit(conn,1,'VERIFY')
    assert verify_audit(db)[0]
    with service.connection(db) as conn:
        conn.execute("UPDATE audit_log SET details='changed' WHERE id=1")
    assert not verify_audit(db)[0]


def test_import_failure_rolls_back_and_preserves_input(environment,tmp_path,monkeypatch):
    path=capture(tmp_path); original=path.read_bytes()
    def fail(*args,**kwargs): raise RuntimeError('Simulated audit write failure')
    monkeypatch.setattr(service,'append_audit',fail)
    with pytest.raises(RuntimeError): service.process_capture(path,**environment)
    with service.connection(environment['db_name']) as conn:
        assert conn.execute('SELECT COUNT(*) FROM evidence').fetchone()[0]==0
        assert conn.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]==0
    assert path.read_bytes()==original
    assert list(environment['storage_dir'].iterdir())==[]


def test_verification_never_creates_missing_database(environment,tmp_path):
    with pytest.raises(FileNotFoundError): service.verify_evidence(1,db_name=environment['db_name'])
    assert not environment['db_name'].exists()


def test_complete_demo_rehearsal_and_no_overwrite(tmp_path):
    from demo_smoke import run_demo
    result=run_demo(tmp_path/'demo')
    assert result['status']=='PASS'
    assert result['port_scan']['alert_count']==1
    assert result['host_scan']['alert_count']==1
    assert Path(result['bundle']).is_file()
    with pytest.raises(FileExistsError): run_demo(tmp_path/'demo')


def test_demo_fixtures_are_repeatable_and_preserve_conflicting_inputs(tmp_path):
    from prepare_demo import prepare_demo
    inputs=prepare_demo(tmp_path/'inputs')
    snapshot={name:Path(path).read_bytes() for name,path in inputs.items()}
    prepare_demo(tmp_path/'inputs')
    assert snapshot=={name:Path(path).read_bytes() for name,path in inputs.items()}
    Path(inputs['normal.pcap']).write_bytes(b'keep')
    with pytest.raises(FileExistsError): prepare_demo(tmp_path/'inputs')
    assert Path(inputs['normal.pcap']).read_bytes()==b'keep'


def test_oversized_input_rejected_before_database_creation(environment,tmp_path):
    from capture_records import MAX_CAPTURE_BYTES
    path=tmp_path/'large.pcap'
    with path.open('wb') as stream: stream.truncate(MAX_CAPTURE_BYTES+1)
    with pytest.raises(ValueError,match='limit'): service.process_capture(path,**environment)
    assert not environment['db_name'].exists()


def test_packet_limit_and_unsupported_link_type(environment,tmp_path,monkeypatch):
    import capture_records
    path=capture(tmp_path,2)
    monkeypatch.setattr(capture_records,'MAX_PACKETS',1)
    with pytest.raises(ValueError,match='packet'): service.process_capture(path,**environment)
    data=bytearray(path.read_bytes()); data[20:24]=(101).to_bytes(4,'little')
    path.write_bytes(data)
    with pytest.raises(ValueError,match='Ethernet'): capture_records.read_network_records(path)


def test_impossible_captured_length_is_rejected(environment,tmp_path):
    from capture_records import read_network_records
    path=capture(tmp_path,2)
    data=bytearray(path.read_bytes()); data[36:40]=(1).to_bytes(4,'little')
    path.write_bytes(data)
    with pytest.raises(ValueError,match='length'): read_network_records(path)


@pytest.mark.parametrize('payload',['[]','{}','{"version":9}','{"version":1,"algorithm":"RSA-PSS-SHA256","key_id":"bad"}'])
def test_invalid_manifest_is_clear_error(environment,tmp_path,payload):
    path=tmp_path/'input'; path.write_bytes(b'original')
    _,signature=crypto.secure_evidence(path,key_dir=environment['key_dir'])
    Path(signature+'.json').write_text(payload)
    with pytest.raises(ValueError): crypto.verify_evidence_file(path,signature,key_dir=environment['key_dir'])
