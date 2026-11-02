import io
import json
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest
from cryptography.hazmat.primitives import serialization
from confidentiality import (encrypt_bytes,decrypt_bytes,read_artifact,write_encrypted,
                             VaultIntegrityError,set_session_password)
from dashboard_auth import create_account,check_password
from analysis_service import process_capture,get_evidence,verify_evidence
from report_generator import generate_signed_report,report_bundle
from crypto_utils import verify_report
from test_security_workflow import environment,capture
from conftest import TEST_PASSPHRASE


def test_encryption_confidentiality_roundtrip_and_randomness():
    secret=b'Private packet content: account=synthetic-12345'
    one=encrypt_bytes(secret);two=encrypt_bytes(secret)
    assert one!=two and secret not in one and TEST_PASSPHRASE.encode() not in one
    assert decrypt_bytes(one)==secret
    with pytest.raises(VaultIntegrityError):decrypt_bytes(one,password='Wrong passphrase with enough length')


@pytest.mark.parametrize('index',[0,10,20,-1])
def test_encrypted_tamper_fails_authentication(index):
    data=bytearray(encrypt_bytes(b'private content'));data[index]^=1
    with pytest.raises(VaultIntegrityError):decrypt_bytes(bytes(data))


def test_missing_secret_fails_before_database_write(environment,tmp_path,monkeypatch):
    source=capture(tmp_path)
    monkeypatch.delenv('PCAP_VAULT_PASSWORD');set_session_password(None)
    with pytest.raises(PermissionError):process_capture(source,**environment)
    assert not environment['db_name'].exists()


def test_managed_capture_encrypted_and_signatures_still_verify(environment,tmp_path):
    source=capture(tmp_path);original=source.read_bytes()
    item=process_capture(original,original_filename='capture.pcap',**environment)
    evidence=get_evidence(item['evidence_id'],environment['db_name'])
    path=Path(evidence['filename'])
    assert path.suffix=='.vault' and path.read_bytes()!=original
    assert read_artifact(path)==original and source.read_bytes()==original
    assert not list(environment['storage_dir'].rglob('*.pcap'))
    assert verify_evidence(item['evidence_id'],db_name=environment['db_name'],key_dir=environment['key_dir'])
    private=(environment['key_dir']/'private_key.pem').read_bytes()
    assert b'ENCRYPTED PRIVATE KEY' in private
    with pytest.raises(TypeError):serialization.load_pem_private_key(private,password=None)
    damaged=bytearray(path.read_bytes());damaged[-1]^=1;path.write_bytes(damaged)
    assert not verify_evidence(item['evidence_id'],db_name=environment['db_name'],key_dir=environment['key_dir'])


def test_reports_and_bundles_are_encrypted_by_default(environment,tmp_path):
    item=process_capture(capture(tmp_path),**environment)
    report,signature=generate_signed_report(item['evidence_id'],db_name=environment['db_name'],key_dir=environment['key_dir'])
    assert Path(report).suffix=='.vault'
    assert b'PCAP Forensic Investigation Report' not in Path(report).read_bytes()
    assert b'PCAP Forensic Investigation Report' in read_artifact(report)
    assert verify_report(report,signature,key_dir=environment['key_dir'])
    bundle=report_bundle(report,signature,key_dir=environment['key_dir'])
    assert not bundle.startswith(b'PK')
    with zipfile.ZipFile(io.BytesIO(decrypt_bytes(bundle))) as archive:
        assert archive.read('report.html')==read_artifact(report)
        assert not any('private_key' in name for name in archive.namelist())


def test_downgrade_and_overwrite_rejected(tmp_path):
    path=tmp_path/'evidence.vault'
    write_encrypted(path,b'secret')
    with pytest.raises(FileExistsError):write_encrypted(path,b'replacement')
    path.write_bytes(b'plaintext replacement')
    with pytest.raises(VaultIntegrityError):read_artifact(path)


def test_password_verifier_not_plaintext_and_no_reset_overwrite(tmp_path):
    config=tmp_path/'auth.json';create_account(TEST_PASSPHRASE,config)
    assert TEST_PASSPHRASE not in config.read_text()
    assert check_password(TEST_PASSPHRASE,config)
    assert not check_password('Wrong passphrase long enough',config)
    with pytest.raises(FileExistsError):create_account('Another secret passphrase',config)


def test_decrypt_cli_requires_secret_and_explicit_new_output(tmp_path,monkeypatch):
    root=Path(__file__).resolve().parents[1]
    path=tmp_path/'input.vault';write_encrypted(path,b'authorized plaintext')
    output=tmp_path/'decrypted.txt'
    command=[sys.executable,str(root/'vault_cli.py'),'decrypt','--input',str(path),'--output',str(output)]
    result=subprocess.run(command,capture_output=True,text=True)
    assert result.returncode==0 and output.read_bytes()==b'authorized plaintext'
    assert TEST_PASSPHRASE not in result.stdout+result.stderr
    assert subprocess.run(command,capture_output=True).returncode==2
    monkeypatch.delenv('PCAP_VAULT_PASSWORD')
    result=subprocess.run(command[:-1]+[str(tmp_path/'unauthorized.txt')],input='',capture_output=True,text=True,timeout=20)
    assert result.returncode==2 and not (tmp_path/'unauthorized.txt').exists()


def test_isolated_confidentiality_demonstration(tmp_path):
    from confidentiality_demo import run_demo
    result=run_demo(tmp_path/'demo')
    assert result['status']=='PASS' and all(result['checks'].values())
    assert result['scope']=='NEW_MANAGED_FILES_ONLY'
    with pytest.raises(FileExistsError):run_demo(tmp_path/'demo')
