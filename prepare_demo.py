"""Generate deterministic synthetic inputs without replacing existing captures."""
import argparse
from pathlib import Path
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR
import struct


def _ether():
    return Ether(src='00:11:22:33:44:55', dst='66:77:88:99:aa:bb')


def _pcap(packets):
    data = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for index, packet in enumerate(packets):
        raw = bytes(packet)
        data.extend(struct.pack('<IIII', 1700000000 + index//10, (index%10)*100000, len(raw), len(raw)))
        data.extend(raw)
    return bytes(data)


def prepare_demo(output_dir):
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    normal = [
        _ether()/IP(src='10.0.0.1',dst='8.8.8.8')/UDP(sport=50000,dport=53)/DNS(id=1,qd=DNSQR(qname='example.com')),
        _ether()/IP(src='10.0.0.1',dst='10.0.0.2')/UDP(sport=50001,dport=8080)/b'normal request',
        _ether()/IP(src='10.0.0.2',dst='10.0.0.1')/UDP(sport=8080,dport=50001)/b'normal response',
    ]
    port_scan = [_ether()/IP(src='10.0.0.1',dst='10.0.0.2')/TCP(sport=50000,dport=port,flags='S') for port in range(20,61)]
    host_scan = [_ether()/IP(src='10.0.0.1',dst=f'10.0.2.{i}')/TCP(sport=50000,dport=22,flags='S') for i in range(1,31)]
    sample = _pcap(normal)
    tampered = sample[:-1] + bytes([sample[-1]^1])
    files = {'normal.pcap':sample,'port-scan.pcap':_pcap(port_scan),'host-scan.pcap':_pcap(host_scan),
             'normal-tampered.pcap':tampered,'invalid.pcap':bytes(24)}
    for name, content in files.items():
        path = root/name
        if path.exists():
            if path.read_bytes() != content:
                raise FileExistsError(f'Refusing to replace different existing input: {path}')
        else:
            with path.open('xb') as stream:
                stream.write(content)
    return {name:str(root/name) for name in files}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', default='runtime/demo-inputs')
    args = parser.parse_args(argv)
    for name, path in prepare_demo(args.output).items():
        print(name, path)


if __name__ == '__main__':
    main()
