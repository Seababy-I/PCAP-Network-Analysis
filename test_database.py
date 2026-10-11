"""Run independently of PyShark, TShark and the security modules."""
import sqlite3
from contextlib import closing
import tempfile
import unittest
from pathlib import Path
import database as db


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.temp.name) / 'test.db')
        db.create_database(self.path)
        self.evidence = db.insert_evidence('test.pcap', db_name=self.path)

    def tearDown(self):
        self.temp.cleanup()

    def packets(self, evidence=None):
        return db.insert_packets([
            ('2026-10-06T08:30:02Z', '10.0.0.1', '10.0.0.2', 'tcp', '50000', '443', '60'),
            ('2026-10-06T10:30:01+02:00', '10.0.0.2', '10.0.0.1', 'TCP', 443, 50000, 80),
        ], db_name=self.path, evidence_id=evidence or self.evidence)

    def test_bidirectional_and_capture_isolation(self):
        ids = self.packets()
        second = db.insert_evidence('other.pcap', db_name=self.path)
        self.packets(second)
        self.assertEqual(db.reconstruct_flows(self.path), 2)
        flow = db.query_flows(self.path, self.evidence)[0]
        self.assertEqual((flow['packet_count'], flow['total_bytes']), (2, 140))
        self.assertEqual((flow['forward_packets'], flow['reverse_packets']), (1, 1))
        self.assertLess(flow['first_seen'], flow['last_seen'])
        self.assertEqual({r['packet_id'] for r in db.query_flow_packets(flow['flow_id'], self.path)}, set(ids))
        db.reconstruct_flows(self.path, self.evidence)
        self.assertEqual(len(db.query_flows(self.path)), 2)
        self.assertEqual(len(db.fetch_all('SELECT * FROM flow_packets', db_name=self.path)), 4)

    def test_analytics_and_filters(self):
        self.packets()
        self.assertEqual(db.query_protocol_breakdown(self.path, self.evidence)[0]['packet_count'], 2)
        self.assertEqual(db.query_timeline(self.path, self.evidence)[0]['total_bytes'], 140)
        self.assertEqual(db.query_top_talkers(self.path, self.evidence)[0]['src_ip'], '10.0.0.2')
        self.assertEqual(len(db.query_packets(self.path, start='2026-10-06T08:30:02Z')), 1)
        self.assertEqual(db.query_packets(self.path, ip="' OR 1=1 --"), [])

    def test_batch_rollback_and_foreign_keys(self):
        rows = [('2026-01-01', '10.0.0.1', '10.0.0.2', 'UDP', 53, 1, 50),
                ('bad time', '10.0.0.1', '10.0.0.2', 'UDP', 53, 1, 50)]
        with self.assertRaises(ValueError):
            db.insert_packets(rows, self.path, self.evidence)
        self.assertEqual(db.query_packets(self.path), [])
        with self.assertRaises(sqlite3.IntegrityError):
            db.insert_dns_record(999, 'example.com', db_name=self.path)

    def test_audit_tampering(self):
        for field, value in [('evidence_id', None), ('prev_hash', 'changed'), ('details', '{}x')]:
            db.add_audit_log(self.evidence, 'IMPORT', db_name=self.path, details={'count': 2})
            row = db.query_audit_log(self.path)[-1]
            self.assertTrue(db.verify_audit_chain(self.path)[0])
            with closing(sqlite3.connect(self.path)) as conn, conn:
                conn.execute(f'UPDATE audit_log SET {field}=? WHERE id=?', (value, row['id']))
            self.assertFalse(db.verify_audit_chain(self.path)[0])
            with closing(sqlite3.connect(self.path)) as conn, conn:
                conn.execute(f'UPDATE audit_log SET {field}=? WHERE id=?', (row[field], row['id']))
        head = db.query_audit_log(self.path)[-1]['entry_hash']
        with closing(sqlite3.connect(self.path)) as conn, conn:
            conn.execute('DELETE FROM audit_log WHERE id=(SELECT MAX(id) FROM audit_log)')
        self.assertFalse(db.verify_audit_chain(self.path, expected_head=head)[0])

    def test_audited_evidence_cannot_be_deleted(self):
        db.add_audit_log(self.evidence, 'IMPORT', db_name=self.path)
        with closing(sqlite3.connect(self.path)) as conn, conn, self.assertRaises(sqlite3.IntegrityError):
            conn.execute('PRAGMA foreign_keys=ON')
            conn.execute('DELETE FROM evidence WHERE evidence_id=?', (self.evidence,))

    def test_auxiliary_records(self):
        ids = self.packets()
        db.insert_tls_record(ids[0], cert_subject='CN=example.com', db_name=self.path)
        db.insert_dns_record(ids[0], 'example.com', answers=['10.0.0.2'], db_name=self.path)
        db.insert_http_record(ids[1], 'GET', 'example.com', '/', 200, self.path)
        for kind in ['tls', 'dns', 'http']:
            self.assertEqual(len(db.query_protocol_records(kind, self.path, self.evidence)), 1)

    def test_legacy_migration(self):
        old = str(Path(self.temp.name) / 'old.db')
        # Reproduce the original packet/evidence/audit tables and a v1 chain.
        with closing(sqlite3.connect(old)) as conn, conn:
            conn.executescript('''CREATE TABLE evidence(evidence_id INTEGER PRIMARY KEY,filename TEXT,sha256 TEXT,import_time TEXT,signature TEXT);
                CREATE TABLE packets(packet_id INTEGER PRIMARY KEY,timestamp TEXT,src_ip TEXT,dst_ip TEXT,protocol TEXT,src_port INTEGER,dst_port INTEGER,length INTEGER);
                CREATE TABLE audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT,evidence_id INTEGER,operation TEXT,status TEXT,timestamp TEXT,prev_hash TEXT,entry_hash TEXT);
                INSERT INTO packets VALUES(1,'2026-01-01','10.0.0.1','10.0.0.2','UDP',53,1,50);''')
            import hashlib
            digest = hashlib.sha256(b'IMPORTSUCCESS2026-01-01GENESIS').hexdigest()
            conn.execute("INSERT INTO audit_log VALUES(1,NULL,'IMPORT','SUCCESS','2026-01-01','GENESIS',?)", (digest,))
        db.create_database(old)
        db.create_database(old)
        self.assertEqual(db.query_packets(old)[0]['evidence_id'], None)
        self.assertTrue(db.verify_audit_chain(old)[0])
        db.add_audit_log(None, 'MIGRATED', db_name=old)
        self.assertTrue(db.verify_audit_chain(old)[0])
        self.assertEqual(db.reconstruct_flows(old), 1)

    def test_parser_bridge_atomic_import(self):
        from parser_db_bridge import store_parsed_capture
        packet = dict(timestamp='2026-01-01', src_ip='10.0.0.1', dst_ip='10.0.0.2',
                      protocol='UDP', src_port='N/A', dst_port=53, length='70',
                      dns_records=[dict(query_name='example.com', answers=['10.0.0.2'])])
        result = store_parsed_capture('parsed.pcap', [packet], db_name=self.path)
        self.assertEqual(len(db.query_protocol_records('dns', self.path, result['evidence_id'])), 1)
        before = len(db.fetch_all('SELECT * FROM evidence', db_name=self.path))
        with self.assertRaises(ValueError):
            store_parsed_capture('bad.pcap', [packet, dict(packet, timestamp='invalid')], db_name=self.path)
        self.assertEqual(len(db.fetch_all('SELECT * FROM evidence', db_name=self.path)), before)
        self.assertTrue(db.verify_audit_chain(self.path)[0])

    def test_concurrent_audit_appends(self):
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda i: db.add_audit_log(self.evidence, 'EVENT', db_name=self.path,
                                                   details={'i': i}), range(20)))
        self.assertEqual(len(db.query_audit_log(self.path)), 20)
        self.assertTrue(db.verify_audit_chain(self.path)[0])

    def test_http_api(self):
        import threading
        import json
        from urllib.request import urlopen
        from urllib.error import HTTPError
        from http.server import ThreadingHTTPServer
        from query_api import make_handler
        self.packets()
        server = ThreadingHTTPServer(('127.0.0.1', 0), make_handler(self.path))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f'http://127.0.0.1:{server.server_port}'
        try:
            with urlopen(base + '/api/protocols?evidence_id=' + str(self.evidence)) as response:
                self.assertEqual(json.load(response)[0]['packet_count'], 2)
            for route, code in [('/api/timeline?bucket_seconds=0', 400), ('/missing', 404)]:
                with self.assertRaises(HTTPError) as caught:
                    urlopen(base + route)
                try:
                    self.assertEqual(caught.exception.code, code)
                finally:
                    caught.exception.close()
        finally:
            server.shutdown(); server.server_close(); thread.join()


if __name__ == '__main__':
    unittest.main()
