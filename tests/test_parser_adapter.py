from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest
from capture_records import read_network_records
from parser_adapter import ParserContractError, preview_capture, validate_record
import parser_readiness
from test_security_workflow import capture


def record(**changes):
    value = dict(timestamp=1700000000.125,frame_number=1,src_ip='10.0.0.1',dst_ip='10.0.0.2',
                 protocol='TCP',src_port=50000,dst_port=80,length=74,tcp_flags=2,dns_records=[],http_records=[])
    value.update(changes)
    return value


def test_timezone_normalization_and_application_records_preserved():
    incoming=record(timestamp=datetime(2026,1,1,tzinfo=timezone.utc),protocol='tcp',
        dns_records=[dict(query_name='example.com',query_type='A',response_code='0',answers=['192.0.2.1','192.0.2.2'])],
        http_records=[dict(method='GET',host='one.example',uri='/a',status_code=None),
                      dict(method='GET',host='two.example',uri='/b',status_code=None)])
    value=validate_record(incoming)
    assert value['protocol']=='TCP' and isinstance(value['timestamp'],float)
    assert len(value['dns_records'][0]['answers'])==2 and len(value['http_records'])==2


@pytest.mark.parametrize('changes',[
    dict(timestamp=float('nan')),dict(timestamp=float('inf')),dict(timestamp='1700000000'),
    dict(timestamp=True),dict(timestamp=datetime(2026,1,1)),dict(length=-1),dict(length='74'),
    dict(frame_number=0),dict(frame_number=True),dict(src_port=65536),dict(dst_port=-1),
    dict(src_ip='not-an-ip'),dict(dst_ip=None),dict(tcp_flags=None),dict(tcp_flags=4096),
    dict(dns_records={}),dict(http_records=[{}]),dict(protocol='')])
def test_invalid_contract_rejected(changes):
    with pytest.raises(ParserContractError):validate_record(record(**changes))


def test_missing_fields_and_non_dictionary_rejected():
    value=record();del value['frame_number']
    with pytest.raises(ParserContractError):validate_record(value)
    with pytest.raises(ParserContractError):validate_record(None)


def test_preview_reaches_existing_detector_without_storage(tmp_path):
    source=capture(tmp_path)
    def teammate_stub(path,tshark_path=None):
        for item in read_network_records(path):
            yield dict(item,dns_records=[],http_records=[])
    result=preview_capture(source,parser_fn=teammate_stub)
    assert result['status']=='PARSER_PREVIEW_ONLY' and result['packet_count']==41
    assert result['alerts'][0]['destination_port_count']==41
    assert not list(tmp_path.glob('*.db')) and not (tmp_path/'keys').exists()


def test_skipped_frame_and_short_output_fail_closed(tmp_path):
    source=capture(tmp_path,3)
    with pytest.raises(ParserContractError,match='Incomplete'):
        preview_capture(source,parser_fn=lambda *a,**k:iter([record()]))
    with pytest.raises(ParserContractError,match='frame numbers'):
        preview_capture(source,parser_fn=lambda *a,**k:iter([record(),record(frame_number=3)]))


def test_generator_closed_on_validation_error(tmp_path):
    source=capture(tmp_path,1); closed=[]
    def teammate_stub(*args,**kwargs):
        try:yield record(timestamp=float('nan'))
        finally:closed.append(True)
    with pytest.raises(ParserContractError):preview_capture(source,parser_fn=teammate_stub)
    assert closed==[True]


def test_readiness_inspects_without_importing_or_accepting(tmp_path,monkeypatch):
    source=tmp_path/'parser.py'
    source.write_text("raise RuntimeError('must not execute')\ndef parse_pcap(path, tshark_path=None): pass\n")
    monkeypatch.setattr(parser_readiness.importlib.util,'find_spec',lambda name:None)
    result=parser_readiness.check_readiness(source,tshark_path=str(tmp_path/'absent'))
    assert result['parser_interface_present']
    assert not result['preview_environment_ready']
    assert result['active_workflow']=='NETWORK_ONLY'
    assert result['database_integration']=='PENDING_AANYA'


def test_readiness_rejects_wrong_executable(tmp_path,monkeypatch):
    source=tmp_path/'parser.py';source.write_text('def parse_pcap(path,tshark_path=None): pass\n')
    monkeypatch.setattr(parser_readiness.importlib.util,'find_spec',lambda name:object())
    monkeypatch.setattr(parser_readiness.importlib.metadata,'version',lambda name:'test')
    monkeypatch.setattr(parser_readiness.subprocess,'run',lambda *a,**k:SimpleNamespace(returncode=0,stdout='Python 3.11\n'))
    result=parser_readiness.check_readiness(source,tshark_path=sys.executable)
    assert not result['preview_environment_ready'] and 'not identify' in result['tshark_error']


def test_preview_cli_has_clear_failure_and_valid_preview(tmp_path):
    root=Path(__file__).resolve().parents[1]
    source=capture(tmp_path,21)
    module=tmp_path/'candidate_parser.py'
    module.write_text('from capture_records import read_network_records\ndef parse_pcap(path,tshark_path=None):\n    for item in read_network_records(path):\n        yield dict(item,dns_records=[],http_records=[])\n')
    import os
    env=dict(os.environ,PYTHONPATH=str(root))
    command=[sys.executable,'-B',str(root/'parser_preview.py'),'--parser',str(module),'--pcap',str(source)]
    success=subprocess.run(command,env=env,capture_output=True,text=True)
    assert success.returncode==0,success.stderr
    value=json.loads(success.stdout)
    assert value['status']=='PARSER_PREVIEW_ONLY' and 'records' not in value and len(value['alerts'])==1
    missing=subprocess.run(command[:-1]+[str(tmp_path/'missing.pcap')],env=env,capture_output=True,text=True)
    assert missing.returncode==2 and 'preview failed' in missing.stderr
