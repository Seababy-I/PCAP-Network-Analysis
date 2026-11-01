import importlib.util
import json
from pathlib import Path
import sqlite3

import pytest
from scapy.all import PcapNgWriter,wrpcap

import analysis_service as service
import database
import investigation
import integration_runtime
from confidentiality import read_artifact
from parser_readiness import locate_tshark
from report_generator import generate_signed_report
from crypto_utils import verify_report
from test_security_workflow import environment,capture,frames

TSHARK=locate_tshark()
REAL=bool(TSHARK and importlib.util.find_spec('pyshark'))
requires_parser=pytest.mark.skipif(not REAL,reason='Full integration requires PyShark and TShark')


def options(environment):return dict(**environment,mode='full',allow_plaintext_metadata=True,tshark_path=TSHARK)


def test_metadata_acknowledgement_is_required_before_any_write(environment,tmp_path):
    source=capture(tmp_path,1)
    with pytest.raises(PermissionError,match='acknowledgement'):service.process_capture(source,**environment,mode='full')
    assert not environment['db_name'].exists()


@requires_parser
def test_real_dns_capture_reaches_storage_flows_and_signed_report(environment,tmp_path):
    fixture=Path(__file__).resolve().parents[1]/'team_tests'/'fixtures'/'dns_valid.pcap'
    item=service.process_capture(fixture,**options(environment))
    assert item['status']=='INTEGRATED_LIMITED' and item['packet_count']==2 and item['flow_count']==1
    snapshot=investigation.overview(item['evidence_id'],environment['db_name'])
    assert snapshot['counts']['packets']==2 and snapshot['counts']['dns']==2 and snapshot['counts']['http']==0
    records=investigation.protocol_records(item['evidence_id'],'dns',environment['db_name'])
    assert any('192.0.2.80' in row['answers'] for row in records)
    stored=service.get_evidence(item['evidence_id'],environment['db_name'])
    assert Path(stored['filename']).suffix=='.vault'
    assert read_artifact(stored['filename'])==fixture.read_bytes()
    assert service.verify_evidence(item['evidence_id'],db_name=environment['db_name'],key_dir=environment['key_dir'])
    report,signature=generate_signed_report(item['evidence_id'],db_name=environment['db_name'],key_dir=environment['key_dir'])
    assert verify_report(report,signature,key_dir=environment['key_dir'])
    assert b'Stored investigation summary' in read_artifact(report)
    assert database.verify_audit_chain(environment['db_name'])[0]


@requires_parser
@pytest.mark.parametrize('variant',['classic','pcapng','ipv6','vlan'])
def test_scan_detection_and_packet_storage_share_parser(environment,tmp_path,variant):
    path=tmp_path/('scan.pcapng' if variant=='pcapng' else 'scan.pcap')
    packets=frames(ipv6=variant=='ipv6',vlan=variant=='vlan')
    if variant=='pcapng':
        with PcapNgWriter(str(path)) as writer:
            for packet in packets:writer.write(packet)
    else:wrpcap(str(path),packets)
    item=service.process_capture(path,submission_id='scan',**options(environment))
    assert item['packet_count']==41 and item['alert_count']==1 and item['flow_count']==41
    assert service.process_capture(path,submission_id='scan',**options(environment))==item
    stored=investigation.packets(item['evidence_id'],environment['db_name'])
    assert len(stored)==41 and all(row['tcp_flags'] & 2 for row in stored)


@requires_parser
def test_ipv6_vlan_http_and_two_capture_isolation(environment,tmp_path):
    root=Path(__file__).resolve().parents[1]/'team_tests'
    first=service.process_capture(root/'fixtures'/'ipv6_vlan_http.pcapng',**options(environment))
    second=service.process_capture(root/'data'/'sample.pcap',**options(environment))
    assert first['packet_count']==55 and second['packet_count']==3
    http=investigation.protocol_records(first['evidence_id'],'http',environment['db_name'])
    assert any(row['host']=='cl-1985.ham-01.de.sixxs.net' for row in http)
    assert investigation.protocol_records(second['evidence_id'],'http',environment['db_name'])==[]
    flow=investigation.overview(first['evidence_id'],environment['db_name'])['flows'][0]
    with pytest.raises(ValueError):investigation.flow_packets(second['evidence_id'],flow['flow_id'],environment['db_name'])
    assert all(row['evidence_id']==first['evidence_id'] for row in investigation.flow_packets(first['evidence_id'],flow['flow_id'],environment['db_name']))


@requires_parser
def test_flow_failure_is_visible_retains_signed_evidence_and_retries(environment,tmp_path,monkeypatch):
    original=database.reconstruct_flows
    monkeypatch.setattr(database,'reconstruct_flows',lambda *a,**k:(_ for _ in ()).throw(RuntimeError('controlled failure')))
    with pytest.raises(RuntimeError,match='retained'):service.process_capture(capture(tmp_path,2),**options(environment))
    with service.connection(environment['db_name']) as conn:
        assert conn.execute('SELECT COUNT(*) FROM packets').fetchone()[0]==2
        assert conn.execute('SELECT status FROM app_analysis').fetchone()[0]=='FLOW_FAILED'
        evidence_id=conn.execute('SELECT evidence_id FROM evidence').fetchone()[0]
    assert service.verify_evidence(evidence_id,db_name=environment['db_name'],key_dir=environment['key_dir'])
    monkeypatch.setattr(database,'reconstruct_flows',original)
    result=service.rebuild_flows(evidence_id,db_name=environment['db_name'])
    assert result['status']=='INTEGRATED_LIMITED' and result['flow_count']==2


@requires_parser
def test_packet_transaction_rolls_back_and_parser_temporary_input_is_removed(environment,tmp_path,monkeypatch):
    import integration_storage
    created=[];restrict=integration_runtime._restrict_directory
    def track(path):created.append(path);return restrict(path)
    monkeypatch.setattr(integration_runtime,'_restrict_directory',track)
    def fail(*args):raise sqlite3.IntegrityError('controlled insert failure')
    monkeypatch.setattr(integration_storage,'store_packets',fail)
    with pytest.raises(sqlite3.IntegrityError):service.process_capture(capture(tmp_path,2),**options(environment))
    with service.connection(environment['db_name']) as conn:
        assert conn.execute('SELECT COUNT(*) FROM evidence').fetchone()[0]==0
        assert conn.execute('SELECT COUNT(*) FROM packets').fetchone()[0]==0
    assert created and all(not path.exists() for path in created)
    assert not list(environment['storage_dir'].iterdir())


@requires_parser
def test_silently_skipped_owner_packet_is_rejected_by_integration(environment,tmp_path,monkeypatch):
    import parser
    original=parser.parse_pcap
    def skip(*args,**kwargs):
        for record in original(*args,**kwargs):
            if record['frame_number']!=2:yield record
    monkeypatch.setattr(parser,'parse_pcap',skip)
    with pytest.raises(ValueError,match='frame numbers|Incomplete'):
        service.process_capture(capture(tmp_path,3),**options(environment))
    with service.connection(environment['db_name']) as conn:
        assert conn.execute('SELECT COUNT(*) FROM evidence').fetchone()[0]==0


def test_full_12bit_flags_preserved_by_boundary():
    from parser_adapter import validate_record
    from test_parser_adapter import record
    assert validate_record(record(tcp_flags=0x802))['tcp_flags']==0x802
