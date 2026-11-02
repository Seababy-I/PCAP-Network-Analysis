import importlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest
from scapy.all import Ether, IP, IPv6, TCP, UDP, Dot1Q, PcapNgWriter, wrpcap

import crypto_utils as crypto
from confidentiality import read_artifact
import analysis_service as service
from capture_records import read_network_records
from detection import detect_port_scan
from host_scan import detect_host_scan
from report_generator import generate_report, generate_signed_report


@pytest.fixture
def environment(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return dict(db_name=tmp_path/'test.db', storage_dir=tmp_path/'evidence', key_dir=tmp_path/'keys')


def frames(count=41, *, ipv6=False, vlan=False, host=False):
    result = []
    for i in range(count):
        ethernet = Ether(src='00:11:22:33:44:55', dst='66:77:88:99:aa:bb')
        network = IPv6(src='2001:db8::1',dst='2001:db8::2') if ipv6 else IP(src='10.0.0.1',dst=f'10.0.1.{i+1}' if host else '10.0.0.2')
        packet = ethernet / Dot1Q(vlan=5) / network if vlan else ethernet / network
        packet = packet / TCP(sport=50000, dport=22 if host else 20+i, flags='S')
        packet.time = 1700000000 + i / 10
        result.append(packet)
    return result


def capture(tmp_path, count=41, name='scan.pcap'):
    path = tmp_path / name
    wrpcap(str(path), frames(count))
    return path


def test_two_files_and_report_survive_reload(environment, tmp_path):
    first = tmp_path/'a'; first.write_bytes(b'A')
    second = tmp_path/'b'; second.write_bytes(b'B')
    keys = environment['key_dir']
    digest, sig_a = crypto.secure_evidence(first, key_dir=keys)
    private_bytes = (keys/'private_key.pem').read_bytes()
    report_sig = crypto.sign_report(first, key_dir=keys)
    _, sig_b = crypto.secure_evidence(second, key_dir=keys)
    importlib.reload(crypto)
    assert sig_a != sig_b != report_sig
    assert private_bytes == (keys/'private_key.pem').read_bytes()
    assert crypto.verify_evidence_file(first, sig_a, expected_sha256=digest, key_dir=keys)
    assert crypto.verify_evidence_file(second, sig_b, key_dir=keys)
    assert crypto.verify_report(first, report_sig, key_dir=keys)
    first.write_bytes(b'TAMPERED')
    assert not crypto.verify_evidence_file(first, sig_a, key_dir=keys)


def test_legacy_signature_and_digest_check(environment, tmp_path):
    path = tmp_path/'capture'; path.write_bytes(b'original')
    private, public = crypto.get_or_create_keys(environment['key_dir'])
    sig = tmp_path/'old.sig'
    crypto.save_signature(crypto.sign_file(path, private),sig)
    assert crypto.verify_evidence_file(path,sig,key_dir=environment['key_dir'])
    assert not crypto.verify_evidence_file(path,sig,expected_sha256='0'*64,key_dir=environment['key_dir'])
    with pytest.raises(FileExistsError):
        crypto.save_signature(b'new',sig)


def test_same_basenames_have_independent_signatures(environment,tmp_path):
    one,two=tmp_path/'one',tmp_path/'two'
    one.mkdir(); two.mkdir()
    (one/'same.pcap').write_bytes(b'one')
    (two/'same.pcap').write_bytes(b'two')
    _,first=crypto.secure_evidence(one/'same.pcap',key_dir=environment['key_dir'])
    _,second=crypto.secure_evidence(two/'same.pcap',key_dir=environment['key_dir'])
    assert first!=second
    assert crypto.verify_evidence_file(one/'same.pcap',first,key_dir=environment['key_dir'])
    assert crypto.verify_evidence_file(two/'same.pcap',second,key_dir=environment['key_dir'])


def test_existing_database_initialization_preserves_rows(environment):
    import database
    path=environment['db_name']
    database.create_database(str(path))
    evidence=database.insert_evidence('historical.pcap','digest','signature',db_name=str(path))
    database.insert_alert(None,'Historical Finding','High','keep this',db_name=str(path),evidence_id=evidence)
    database.add_audit_log(evidence,'IMPORT',db_name=str(path))
    with service.connection(path) as conn:
        before={table:[tuple(row) for row in conn.execute('SELECT * FROM '+table)] for table in ['evidence','alerts','packets','audit_log']}
    service.initialize_database(path)
    service.initialize_database(path)
    with service.connection(path) as conn:
        after={table:[tuple(row) for row in conn.execute('SELECT * FROM '+table)] for table in before}
    assert after==before
    assert database.verify_audit_chain(str(path))[0]


def test_key_mismatch_and_missing_half_do_not_overwrite(environment, tmp_path):
    keys=environment['key_dir']
    crypto.get_or_create_keys(keys)
    private_bytes=(keys/'private_key.pem').read_bytes()
    _, wrong=crypto.generate_rsa_keys()
    (keys/'public_key.pem').write_bytes(crypto.public_bytes(wrong))
    with pytest.raises(ValueError): crypto.get_or_create_keys(keys)
    assert (keys/'private_key.pem').read_bytes()==private_bytes
    (keys/'public_key.pem').unlink()
    with pytest.raises(FileNotFoundError): crypto.get_or_create_keys(keys)
    assert (keys/'private_key.pem').read_bytes()==private_bytes


@pytest.mark.parametrize('variant',['classic','big','nano','pcapng','ipv6','vlan'])
def test_equivalent_scan_formats(environment,tmp_path,variant):
    path=tmp_path/('scan.pcapng' if variant=='pcapng' else 'scan.pcap')
    packets=frames(ipv6=variant=='ipv6',vlan=variant=='vlan')
    if variant=='pcapng':
        with PcapNgWriter(str(path)) as writer:
            for packet in packets: writer.write(packet)
    else:
        wrpcap(str(path),packets,endianness='>' if variant=='big' else '<',nano=variant=='nano')
    records=read_network_records(path)
    assert len(records)==41
    assert detect_port_scan(records)[0]['destination_port_count']==41


def test_threshold_duplicates_windows_and_hosts():
    packets=[dict(timestamp=i/10,src_ip='a',dst_ip='b',protocol='TCP',dst_port=i,tcp_flags=2) for i in range(21)]
    assert detect_port_scan(packets[:20])==[]
    assert len(detect_port_scan(packets))==1
    assert detect_port_scan(packets[:20]*3)==[]
    assert detect_port_scan([dict(p,timestamp=i*100) for i,p in enumerate(packets)])==[]
    assert detect_port_scan([dict(p,dst_ip=str(i)) for i,p in enumerate(packets)])==[]
    assert detect_port_scan([dict(p,tcp_flags=18) for p in packets])==[]
    hosts=[dict(p,dst_ip=str(i),dst_port=22) for i,p in enumerate(packets)]
    assert len(detect_host_scan(hosts))==1
    assert detect_host_scan(hosts[:20])==[]
    assert detect_port_scan(reversed(packets))==detect_port_scan(packets)


@pytest.mark.parametrize('data',[bytes(24),b'bad',b'\xd4\xc3\xb2\xa1'])
def test_invalid_input_has_no_partial_import(environment,tmp_path,data):
    path=tmp_path/'invalid.pcap'; path.write_bytes(data)
    with pytest.raises(ValueError): service.process_capture(path,**environment)
    with service.connection(environment['db_name']) as conn:
        assert conn.execute('SELECT COUNT(*) FROM evidence').fetchone()[0]==0
        assert conn.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]==0
    assert not list(environment['storage_dir'].iterdir())


def test_truncated_record_is_rejected(environment,tmp_path):
    path=capture(tmp_path)
    path.write_bytes(path.read_bytes()[:-1])
    with pytest.raises(ValueError,match='Truncated'): read_network_records(path)


def test_import_is_scoped_idempotent_and_network_only(environment,tmp_path):
    path=capture(tmp_path)
    one=service.process_capture(path,submission_id='same',**environment)
    assert service.process_capture(path,submission_id='same',**environment)==one
    two=service.process_capture(path,**environment)
    assert two['evidence_id']!=one['evidence_id']
    assert one['packet_count']==41 and one['alert_count']==1 and one['status']=='NETWORK_ONLY'
    assert service.verify_evidence(one['evidence_id'],db_name=environment['db_name'],key_dir=environment['key_dir'])
    with service.connection(environment['db_name']) as conn:
        assert conn.execute('SELECT COUNT(*) FROM evidence').fetchone()[0]==2
        assert conn.execute('SELECT COUNT(*) FROM packets').fetchone()[0]==0
        assert {r[0] for r in conn.execute('SELECT evidence_id FROM alerts')}=={one['evidence_id'],two['evidence_id']}
        assert not conn.execute("SELECT 1 FROM alerts WHERE alert_type LIKE '%TLS%' OR alert_type LIKE '%Certificate%'").fetchone()
    different=capture(tmp_path,2,'different.pcap')
    with pytest.raises(ValueError,match='token'): service.process_capture(different,submission_id='same',**environment)


def test_report_scoping_escaping_versions_and_tamper(environment,tmp_path):
    path=capture(tmp_path)
    one=service.process_capture(path,**environment)
    two=service.process_capture(capture(tmp_path,2,'normal.pcap'),**environment)
    with service.connection(environment['db_name']) as conn:
        conn.execute('INSERT INTO alerts(packet_id,alert_type,severity,description,timestamp,evidence_id) VALUES(NULL,?,?,?,?,?)',
            ('<script>attack</script>','High','<img src=x onerror=alert(1)>','2026-01-01',one['evidence_id']))
    report,sig=generate_signed_report(one['evidence_id'],db_name=environment['db_name'],key_dir=environment['key_dir'],output_path=tmp_path/'report.html')
    document=read_artifact(report).decode('utf-8')
    assert '<script>attack</script>' not in document
    assert '&lt;script&gt;attack&lt;/script&gt;' in document
    other=generate_report(two['evidence_id'],db_name=environment['db_name'],key_dir=environment['key_dir'],output_path=tmp_path/'other.html')
    assert 'Possible Port Scan' not in read_artifact(other).decode('utf-8')
    assert crypto.verify_report(report,sig,key_dir=environment['key_dir'])
    Path(report).write_text(document+'changed')
    assert not crypto.verify_report(report,sig,key_dir=environment['key_dir'])
    with pytest.raises(FileExistsError): generate_report(one['evidence_id'],db_name=environment['db_name'],output_path=report)


def test_cli_and_imports_do_not_run_workflow(environment,tmp_path):
    source=Path(service.__file__).parent
    result=subprocess.run([sys.executable,'-c',f'import sys; sys.path.insert(0,{str(source)!r}); import run_security, verify_evidence, report_generator'],cwd=tmp_path,capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    assert list(tmp_path.iterdir())==[]
    path=capture(tmp_path,2)
    args=[sys.executable,str(source/'run_security.py'),'--pcap',str(path),'--db',str(environment['db_name']),'--storage',str(environment['storage_dir']),'--keys',str(environment['key_dir']),'--mode','network']
    result=subprocess.run(args,capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    assert 'NETWORK_ONLY' in result.stdout
    command=[sys.executable,str(source/'verify_evidence.py'),'--db',str(environment['db_name']),'--keys',str(environment['key_dir']),'--evidence-id','1']
    assert subprocess.run(command,capture_output=True).returncode==0
    path.write_bytes(b'changed')
    assert subprocess.run(command+['--file',str(path)],capture_output=True).returncode==1
