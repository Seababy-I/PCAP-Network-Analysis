"""Real Jahnnavi parser -> database tests. Requires PyShark and TShark.
Run: python -m unittest test_parser_database -v
Use TSHARK_PATH for an executable not on PATH.
"""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
import database as db
from import_real_pcap import import_capture

TSHARK = os.environ.get('TSHARK_PATH') or shutil.which('tshark') or next(
    (p for p in (r'C:\Program Files\Wireshark\tshark.exe',
                 r'C:\Program Files (x86)\Wireshark\tshark.exe') if Path(p).is_file()), None)
AVAILABLE = bool(TSHARK and Path(TSHARK).is_file() and importlib.util.find_spec('pyshark'))

@unittest.skipUnless(AVAILABLE, 'Real parser test requires PyShark and TShark')
class ParserDatabaseTests(unittest.TestCase):
    def test_committed_capture_counts_and_metadata(self):
        root = Path(__file__).parent
        for name,count in [('data/sample.pcap',3),('data/detection_test.pcap',41),('v6-http.cap',55)]:
            with self.subTest(capture=name), tempfile.TemporaryDirectory() as temp:
                path=str(Path(temp)/'parsed.db')
                result=import_capture(root/name,path,TSHARK)
                packets=db.fetch_all('SELECT * FROM packets ORDER BY packet_id',db_name=path)
                self.assertEqual(len(packets),count)
                self.assertEqual([p['frame_number'] for p in packets],list(range(1,count+1)))
                self.assertEqual([p['packet_id'] for p in packets],result['packet_ids'])
                self.assertTrue(all(p['length']>=0 for p in packets))
                self.assertTrue(all(p['tcp_flags'] is not None for p in packets if p['protocol']=='TCP'))
                self.assertTrue(db.verify_audit_chain(path)[0])
                if name=='v6-http.cap':
                    self.assertTrue(any(':' in (p['src_ip'] or '') for p in packets))
                    http=db.query_protocol_records('http',path,result['evidence_id'])
                    self.assertTrue(any(r['host']=='cl-1985.ham-01.de.sixxs.net' for r in http))

    def test_dns_answers_are_stored_from_valid_wire_fixture(self):
        with tempfile.TemporaryDirectory() as temp:
            path=str(Path(temp)/'dns.db')
            result=import_capture(Path(__file__).parent/'fixtures'/'dns_valid.pcap',path,TSHARK)
            self.assertEqual(len(result['packet_ids']),2)
            rows=db.query_protocol_records('dns',path,result['evidence_id'])
            self.assertEqual(len(rows),2)
            self.assertTrue(all(r['query_name']=='example.com' for r in rows))
            answers=[a for row in rows for a in json.loads(row['answers'])]
            self.assertTrue(any(a['type']=='A' and a['value']=='192.0.2.80' for a in answers))

    def test_pcapng_vlan_ipv6_http(self):
        with tempfile.TemporaryDirectory() as temp:
            path=str(Path(temp)/'vlan.db')
            result=import_capture(Path(__file__).parent/'fixtures'/'ipv6_vlan_http.pcapng',path,TSHARK)
            packets=db.query_packets(path,result['evidence_id'])
            self.assertEqual(len(packets),55)
            self.assertTrue(any(p['protocol']=='TCP' for p in packets))
            self.assertTrue(any(':' in (p['src_ip'] or '') for p in packets))
            rows=db.query_protocol_records('http',path,result['evidence_id'])
            self.assertTrue(any(r['host']=='cl-1985.ham-01.de.sixxs.net' for r in rows))

    def test_malformed_input_rolls_back_import(self):
        with tempfile.TemporaryDirectory() as temp:
            path=str(Path(temp)/'invalid.db')
            with self.assertRaises(RuntimeError):
                import_capture(Path(__file__).parent/'fixtures'/'malformed_capture.pcap',path,TSHARK)
            self.assertEqual(db.query_packets(path),[])
            self.assertEqual(db.fetch_all('SELECT * FROM evidence',db_name=path),[])
            self.assertEqual(db.query_audit_log(path),[])

    def test_database_rejection_closes_parser_and_rolls_back(self):
        import sqlite3
        from contextlib import closing
        with tempfile.TemporaryDirectory() as temp:
            path=str(Path(temp)/'rejected.db')
            db.create_database(path)
            with closing(db.get_connection(path)) as conn,conn:
                conn.execute("CREATE TRIGGER reject_demo BEFORE INSERT ON packets BEGIN SELECT RAISE(ABORT,'test rejection'); END")
            with self.assertRaises(sqlite3.IntegrityError):
                import_capture(Path(__file__).parent/'v6-http.cap',path,TSHARK)
            self.assertEqual(db.fetch_all('SELECT * FROM evidence',db_name=path),[])

if __name__=='__main__': unittest.main()
