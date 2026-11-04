import importlib.util
from pathlib import Path
import subprocess
import sys

import pytest
from scapy.all import Ether,IP,UDP,TCP,DNS,DNSQR,DNSRR,Raw,wrpcap

from parser_readiness import locate_tshark

pytestmark=pytest.mark.skipif(not locate_tshark() or not importlib.util.find_spec('pyshark'),reason='TShark/PyShark required')


def parse(path):
    from integration_runtime import parse_content
    return parse_content(path.read_bytes())['records']


def test_repeated_dns_answers_and_cname_keep_values_and_owners(tmp_path):
    path=tmp_path/'dns.pcap'
    packet=Ether()/IP(src='192.0.2.53',dst='192.0.2.1')/UDP(sport=53,dport=50000)/DNS(
        id=1,qr=1,qd=DNSQR(qname='alias.example'),an=[
            DNSRR(rrname='alias.example',type='CNAME',rdata='target.example'),
            DNSRR(rrname='target.example',type='A',rdata='192.0.2.80'),
            DNSRR(rrname='target.example',type='A',rdata='192.0.2.81')])
    wrpcap(str(path),[packet])
    answers=parse(path)[0]['dns_records'][0]['answers']
    assert [(a['type'],a['value']) for a in answers]==[
        ('CNAME','target.example'),('A','192.0.2.80'),('A','192.0.2.81')]
    assert [a['name'] for a in answers]==['alias.example','target.example','target.example']


def test_two_http_messages_in_one_frame(tmp_path):
    path=tmp_path/'http.pcap'
    payload=b'GET /first HTTP/1.1\r\nHost: first.example\r\n\r\nGET /second HTTP/1.1\r\nHost: second.example\r\n\r\n'
    wrpcap(str(path),[Ether()/IP(src='192.0.2.1',dst='192.0.2.80')/TCP(sport=50000,dport=80,flags='PA',seq=1)/Raw(payload)])
    records=parse(path)[0]['http_records']
    assert [(r['host'],r['uri']) for r in records]==[('first.example','/first'),('second.example','/second')]


def test_cli_errors_return_nonzero(tmp_path):
    result=subprocess.run([sys.executable,str(Path(__file__).resolve().parents[1]/'parser.py'),str(tmp_path/'missing.pcap')],capture_output=True,text=True)
    assert result.returncode!=0 and 'Parsing failed' in result.stderr


@pytest.mark.parametrize('field,value',[('sniff_timestamp','nan'),('sniff_timestamp','inf'),('number','0'),('length','-1')])
def test_invalid_required_numbers_raise(field,value):
    from parser import extract_packet
    class Packet:
        sniff_timestamp='1700000000'
        number='1'
        length='60'
        layers=[]
    packet=Packet()
    setattr(packet,field,value)
    with pytest.raises(ValueError):extract_packet(packet)


def test_extraction_failure_is_fatal_and_capture_closes(monkeypatch,tmp_path):
    import parser
    path=tmp_path/'valid.pcap'
    wrpcap(str(path),[Ether()/IP()/UDP()])
    class Capture:
        closed=False
        def __iter__(self):return iter([object()])
        def close(self):self.closed=True
    capture=Capture()
    monkeypatch.setattr(parser.pyshark,'FileCapture',lambda **kwargs:capture)
    with pytest.raises(parser.ParserExtractionError,match='Extraction failed') as error:list(parser.parse_pcap(path))
    assert error.value.parsed_count==0 and error.value.failed_count==1
    assert capture.closed


@pytest.mark.parametrize('field,value',[('srcport','65536'),('dstport','-1'),('flags','0x1000')])
def test_invalid_transport_numbers_fail(field,value):
    from parser import extract_packet
    class Layer:
        def __init__(self,name,values):self.layer_name=name;self.values=values
        def get_field_value(self,name):return self.values.get(name)
    class Packet:
        sniff_timestamp='1700000000';number='1';length='60'
    tcp=dict(srcport='12345',dstport='80',flags='0x02')
    tcp[field]=value
    packet=Packet()
    packet.layers=[Layer('ip',dict(src='192.0.2.1',dst='192.0.2.2')),Layer('tcp',tcp)]
    with pytest.raises(ValueError):extract_packet(packet)
