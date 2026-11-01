"""Rehearse the independent workflow using an isolated DB and disposable demo keys."""
import argparse
import json
from pathlib import Path
import sqlite3
from uuid import uuid4

from analysis_service import BASE_DIR, connection, process_capture, verify_evidence
from audit_security import create_checkpoint, verify_audit
from crypto_utils import verify_report
from prepare_demo import prepare_demo
from report_generator import generate_signed_report, report_bundle
from confidentiality import read_artifact,prompt_password,set_session_password


def run_demo(output_dir):
    root = Path(output_dir).resolve()
    root.mkdir(parents=True, exist_ok=False)
    files = prepare_demo(root/'inputs')
    options = dict(db_name=root/'demo.db', storage_dir=root/'evidence', key_dir=root/'demo-keys')
    normal = process_capture(files['normal.pcap'], submission_id='demo-normal', **options)
    report, signature = generate_signed_report(normal['evidence_id'], db_name=options['db_name'], key_dir=options['key_dir'])
    scan = process_capture(files['port-scan.pcap'], **options)
    hosts = process_capture(files['host-scan.pcap'], **options)
    repeated = process_capture(files['normal.pcap'], submission_id='demo-normal', **options)
    def check(condition, label):
        if not condition: raise RuntimeError('Demo check failed: '+label)
    check([normal['packet_count'],scan['packet_count'],hosts['packet_count']]==[3,41,30], 'frame counts')
    check([normal['alert_count'],scan['alert_count'],hosts['alert_count']]==[0,1,1], 'alert counts')
    check(repeated['evidence_id']==normal['evidence_id'], 'duplicate submission')
    check(verify_evidence(normal['evidence_id'], db_name=options['db_name'], key_dir=options['key_dir']), 'original evidence after later imports')
    check(not verify_evidence(normal['evidence_id'], db_name=options['db_name'], key_dir=options['key_dir'],candidate_path=files['normal-tampered.pcap']), 'evidence tampering')
    check(verify_report(report,signature,key_dir=options['key_dir']), 'report after later imports')
    modified = root/'modified-report.html'
    modified.write_bytes(Path(report).read_bytes()+b'<!-- changed -->')
    check(not verify_report(modified,signature,key_dir=options['key_dir']), 'report tampering')
    try:
        process_capture(files['invalid.pcap'], **options)
    except ValueError:
        pass
    else:
        raise RuntimeError('Malformed capture was accepted')
    with connection(options['db_name']) as conn:
        check(conn.execute('SELECT COUNT(*) FROM evidence').fetchone()[0]==3, 'import rollback/count')
        check(conn.execute('SELECT COUNT(*) FROM packets').fetchone()[0]==0, 'honest network-only status')
    checkpoint, checkpoint_signature = create_checkpoint(options['db_name'],root/'checkpoints',key_dir=options['key_dir'])
    checkpoint_options = dict(checkpoint=checkpoint,signature=checkpoint_signature,key_dir=options['key_dir'])
    damaged_db = root/'audit-tail-deleted.db'
    destination = sqlite3.connect(damaged_db)
    try:
        with connection(options['db_name']) as conn:
            conn.backup(destination)
    finally:
        destination.close()
    with connection(damaged_db) as conn:
        conn.execute('DELETE FROM audit_log WHERE id=(SELECT MAX(id) FROM audit_log)')
    check(verify_audit(damaged_db)[0], 'internally valid truncated prefix')
    check(not verify_audit(damaged_db,**checkpoint_options)[0], 'signed checkpoint detects tail deletion')
    verify_evidence(normal['evidence_id'], db_name=options['db_name'], key_dir=options['key_dir'])
    check(verify_audit(options['db_name'],**checkpoint_options)[0], 'checkpoint permits legitimate later events')
    bundle=root/'normal-report-verification.zip.vault'
    bundle.write_bytes(report_bundle(report,signature,key_dir=options['key_dir']))
    results = dict(status='PASS', scope='NETWORK_ONLY', normal=normal, port_scan=scan, host_scan=hosts,
                   duplicate_submission='PASS', evidence_tamper='PASS', report_tamper='PASS', malformed_input='PASS',
                   checkpoint_tail_deletion='PASS', checkpoint_later_appends='PASS',report=report,bundle=str(bundle),
                   database=str(options['db_name']), checkpoint=checkpoint)
    (root/'results.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
    return results


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',default=str(BASE_DIR/'runtime'/'demo-runs'/uuid4().hex))
    args=parser.parse_args(argv)
    set_session_password(prompt_password())
    print(json.dumps(run_demo(args.output),indent=2))


if __name__=='__main__':
    main()
