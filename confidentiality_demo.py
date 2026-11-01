"""Demonstrate managed-file confidentiality with isolated synthetic evidence."""
import argparse
import hashlib
import json
from pathlib import Path
from uuid import uuid4

from analysis_service import BASE_DIR,get_evidence,process_capture,verify_evidence
from confidentiality import (VaultIntegrityError,decrypt_bytes,read_artifact,prompt_password,
                             set_session_password)
from prepare_demo import prepare_demo
from report_generator import generate_signed_report,report_bundle
from crypto_utils import verify_report


def run_demo(output_dir):
    root=Path(output_dir).resolve();root.mkdir(parents=True,exist_ok=False)
    inputs=prepare_demo(root/'synthetic-inputs')
    options=dict(db_name=root/'demo.db',storage_dir=root/'managed-evidence',key_dir=root/'demo-signing-keys')
    item=process_capture(inputs['normal.pcap'],**options)
    evidence=get_evidence(item['evidence_id'],options['db_name'])
    original=Path(inputs['normal.pcap']).read_bytes()
    stored=Path(evidence['filename']).read_bytes()
    checks=dict(stored_bytes_are_encrypted=stored!=original,
                authorized_decryption_recovers_original=read_artifact(evidence['filename'])==original,
                original_sha256_preserved=hashlib.sha256(original).hexdigest()==evidence['sha256'],
                original_signature_valid=verify_evidence(item['evidence_id'],db_name=options['db_name'],key_dir=options['key_dir']))
    try:decrypt_bytes(stored,password='Deliberately wrong demo passphrase')
    except VaultIntegrityError:checks['wrong_password_rejected']=True
    else:checks['wrong_password_rejected']=False
    damaged=bytearray(stored);damaged[-1]^=1
    try:decrypt_bytes(bytes(damaged))
    except VaultIntegrityError:checks['ciphertext_tampering_rejected']=True
    else:checks['ciphertext_tampering_rejected']=False
    report,signature=generate_signed_report(item['evidence_id'],db_name=options['db_name'],key_dir=options['key_dir'])
    checks['report_encrypted']=b'PCAP Forensic Investigation Report' not in Path(report).read_bytes()
    checks['decrypted_report_signature_valid']=verify_report(report,signature,key_dir=options['key_dir'])
    bundle=report_bundle(report,signature,key_dir=options['key_dir'])
    checks['export_bundle_encrypted']=not bundle.startswith(b'PK')
    (root/'report-bundle.zip.vault').write_bytes(bundle)
    if not all(checks.values()):raise RuntimeError('Confidentiality demonstration failed')
    result=dict(status='PASS',checks=checks,scope='NEW_MANAGED_FILES_ONLY',
                database_confidentiality='PLAINTEXT_METADATA: database encryption deferred by project decision',
                source_inputs='Synthetic demonstration inputs intentionally retained separately',
                report=report)
    (root/'results.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',default=str(BASE_DIR/'runtime'/'confidentiality-demo'/uuid4().hex))
    args=parser.parse_args(argv)
    set_session_password(prompt_password())
    print(json.dumps(run_demo(args.output),indent=2))


if __name__=='__main__':main()
