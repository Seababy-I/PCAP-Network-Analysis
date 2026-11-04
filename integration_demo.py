"""Rehearse the integrated workflow with synthetic/public data and disposable keys."""
import argparse
import io
import json
from pathlib import Path
import subprocess
import sys
from uuid import uuid4
import zipfile

import analysis_service as service
from audit_security import verify_audit
from confidentiality import prompt_password,set_session_password,read_artifact,decrypt_bytes
from crypto_utils import verify_report
from demo_smoke import run_demo as network_demo
from confidentiality_demo import run_demo as confidentiality_demo
from investigation import overview
from prepare_demo import prepare_demo
from report_generator import generate_signed_report,report_bundle


def run_demo(output):
    root=Path(output).resolve()
    root.mkdir(parents=True,exist_ok=False)
    network=network_demo(root/'network-checks')
    privacy=confidentiality_demo(root/'confidentiality-checks')
    inputs=prepare_demo(root/'inputs')
    options=dict(db_name=root/'full.db',storage_dir=root/'evidence',key_dir=root/'disposable-keys',
                 mode='full',allow_plaintext_metadata=True)
    fixtures=Path(__file__).resolve().parent/'team_tests'/'fixtures'
    sources=[inputs['normal.pcap'],inputs['port-scan.pcap'],inputs['host-scan.pcap'],
             fixtures/'dns_valid.pcap',fixtures/'ipv6_vlan_http.pcapng']
    items=[service.process_capture(p,submission_id=f'demo-{i}',**options) for i,p in enumerate(sources)]
    def check(condition,label):
        if not condition:raise RuntimeError('Integration rehearsal failed: '+label)
    check([x['packet_count'] for x in items]==[3,41,30,2,55],'packet counts')
    check([x['alert_count'] for x in items[:3]]==[0,1,1],'scan alerts')
    check(all(x['status']=='INTEGRATED_LIMITED' for x in items),'final status')
    snapshots=[overview(x['evidence_id'],options['db_name']) for x in items]
    check(all(s['counts']['packets']==x['packet_count'] for s,x in zip(snapshots,items)),'scoped stored packets')
    check(snapshots[3]['counts']['dns']==2 and snapshots[4]['counts']['http']>0,'DNS and HTTP records')
    check(service.process_capture(sources[0],submission_id='demo-0',**options)==items[0],'idempotency')
    try:service.process_capture(inputs['invalid.pcap'],**options)
    except (ValueError,RuntimeError):pass
    else:raise RuntimeError('Malformed capture was accepted')
    with service.connection(options['db_name']) as conn:
        check(conn.execute('SELECT COUNT(*) FROM evidence').fetchone()[0]==5,'rollback')
    eid=items[0]['evidence_id']
    check(service.verify_evidence(eid,db_name=options['db_name'],key_dir=options['key_dir']),'evidence signature')
    check(not service.verify_evidence(eid,db_name=options['db_name'],key_dir=options['key_dir'],candidate_path=inputs['normal-tampered.pcap']),'evidence tamper')
    report,signature=generate_signed_report(eid,db_name=options['db_name'],key_dir=options['key_dir'])
    check(verify_report(report,signature,key_dir=options['key_dir']),'signed encrypted report')
    check(b'Stored investigation summary' in read_artifact(report),'integrated report')
    export=root/'offline-verification'
    export.mkdir()
    archive=decrypt_bytes(report_bundle(report,signature,key_dir=options['key_dir']))
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:bundle.extractall(export)
    run=subprocess.run([sys.executable,str(export/'verify.py')],cwd=export,capture_output=True,text=True)
    check(run.returncode==0,'offline bundle verifier')
    (export/'report.html').write_bytes((export/'report.html').read_bytes()+b' altered')
    run=subprocess.run([sys.executable,str(export/'verify.py')],cwd=export,capture_output=True,text=True)
    check(run.returncode!=0,'offline verifier detects modified report')
    check(verify_audit(options['db_name'])[0],'audit chain')
    result=dict(status='PASS',scope='FULL_WITH_DOCUMENTED_LIMITS',imports=items,
        counts=[s['counts'] for s in snapshots],network_checks=network['status'],
        confidentiality_checks=privacy['checks'],offline_bundle='PASS',offline_tamper='PASS',
        database_encryption='DEFERRED_BY_USER: plaintext metadata',tls='EXCLUDED')
    (root/'results.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',default=str(service.BASE_DIR/'runtime'/'integration-rehearsals'/uuid4().hex))
    args=parser.parse_args()
    set_session_password(prompt_password())
    print(json.dumps(run_demo(args.output),indent=2))


if __name__=='__main__':main()
