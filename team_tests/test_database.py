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
        db.insert_dns_record(ids[0], 'example.com', answers=['10.0.0.2'], db_name=self.path)
        db.insert_http_record(ids[1], 'GET', 'example.com', '/', 200, self.path)
        for kind in ['dns', 'http']:
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

    def test_capture_level_and_packet_alerts_are_isolated(self):
        p = self.packets()[0]
        second = db.insert_evidence('second.pcap', db_name=self.path)
        first_id = db.insert_alert(None, 'Possible Port Scan', 'Medium', 'capture-level',
                                   db_name=self.path, evidence_id=self.evidence)
        inferred = db.insert_alert(p, 'Packet finding', 'Low', 'inferred', db_name=self.path)
        other_id = db.insert_alert(None, 'Other capture', 'Medium', 'other',
                                   db_name=self.path, evidence_id=second)
        unassigned = db.insert_alert(None, 'Historical', 'Low', 'unknown', db_name=self.path)
        self.assertEqual({r['alert_id'] for r in db.query_alerts(self.path,self.evidence)}, {first_id,inferred})
        self.assertEqual([r['alert_id'] for r in db.query_alerts(self.path,second)], [other_id])
        self.assertIsNone(next(r for r in db.query_alerts(self.path) if r['alert_id']==unassigned)['evidence_id'])
        from query_api import dispatch
        self.assertEqual(len(dispatch('/api/alerts', {'evidence_id':[str(self.evidence)]},self.path)),2)

    def test_alert_ownership_validation_and_raw_sql(self):
        p = self.packets()[0]
        other = db.insert_evidence('other', db_name=self.path)
        for packet, evidence in [(p,other), (999,self.evidence), (None,999)]:
            with self.subTest(packet=packet,evidence=evidence), self.assertRaises(ValueError):
                db.insert_alert(packet,'Finding','Medium','bad',db_name=self.path,evidence_id=evidence)
        with closing(db.get_connection(self.path)) as conn, conn:
            for packet, evidence in [(p,other), (999,self.evidence), (None,999)]:
                with self.subTest(raw_packet=packet), self.assertRaises(sqlite3.IntegrityError):
                    conn.execute("INSERT INTO alerts(packet_id,evidence_id,alert_type,severity,description,timestamp) VALUES(?,?,'X','Low','bad','2026-01-01')",(packet,evidence))
        aid = db.insert_alert(p,'Finding','Low','good',db_name=self.path)
        with closing(db.get_connection(self.path)) as conn, conn:
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute('UPDATE alerts SET evidence_id=? WHERE alert_id=?',(other,aid))
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute('UPDATE packets SET evidence_id=? WHERE packet_id=?',(other,p))
        orphan = db.insert_packet('2026-01-01',None,None,'OTHER',db_name=self.path)
        with self.assertRaises(ValueError):
            db.insert_alert(orphan,'Finding','Low','unknown owner',db_name=self.path,evidence_id=self.evidence)

    def test_original_layout_migration_preserves_unknown_ownership(self):
        old = str(Path(self.temp.name)/'original.db')
        with closing(sqlite3.connect(old)) as conn, conn:
            conn.executescript("""
                CREATE TABLE evidence(evidence_id INTEGER PRIMARY KEY,filename TEXT,sha256 TEXT,import_time TEXT,signature TEXT);
                CREATE TABLE packets(packet_id INTEGER PRIMARY KEY,timestamp TEXT,src_ip TEXT,dst_ip TEXT,protocol TEXT,src_port INTEGER,dst_port INTEGER,length INTEGER);
                CREATE TABLE alerts(alert_id INTEGER PRIMARY KEY,packet_id INTEGER,alert_type TEXT,severity TEXT,description TEXT,timestamp TEXT);
                CREATE TABLE tls_records(tls_id INTEGER PRIMARY KEY,packet_id INTEGER,tls_version TEXT);
                CREATE TABLE app_analysis(id INTEGER PRIMARY KEY,content TEXT);
                CREATE TABLE app_reports(id INTEGER PRIMARY KEY,content TEXT);
                INSERT INTO evidence VALUES(42,'old.pcap',NULL,'2026-01-01',NULL);
                INSERT INTO packets VALUES(7,'2026-01-01','10.0.0.1','10.0.0.2','TCP',1,443,100);
                INSERT INTO alerts VALUES(3,7,'old','Low','unknown capture','2026-01-01');
                INSERT INTO alerts VALUES(4,NULL,'old','Low','unknown capture','2026-01-01');
                INSERT INTO tls_records VALUES(9,7,'TLS 1.2');
                INSERT INTO app_analysis VALUES(4,'keep analysis');
                INSERT INTO app_reports VALUES(5,'keep report');
            """)
        for _ in range(2): db.create_database(old)
        self.assertEqual({r['evidence_id'] for r in db.query_alerts(old)}, {None})
        self.assertEqual(db.fetch_all('SELECT evidence_id FROM evidence',db_name=old),[{'evidence_id':42}])
        self.assertEqual(db.fetch_all('SELECT * FROM tls_records',db_name=old),[{'tls_id':9,'packet_id':7,'tls_version':'TLS 1.2'}])
        for table,content in [('app_analysis','keep analysis'),('app_reports','keep report')]:
            self.assertEqual(db.fetch_all('SELECT content FROM '+table,db_name=old)[0]['content'],content)

    def test_updated_layout_migration_backfills_only_known_alert_owners(self):
        old = str(Path(self.temp.name)/'updated.db')
        with closing(sqlite3.connect(old)) as conn, conn:
            conn.executescript("""
                CREATE TABLE evidence(evidence_id INTEGER PRIMARY KEY,filename TEXT,sha256 TEXT,import_time TEXT,signature TEXT);
                CREATE TABLE packets(packet_id INTEGER PRIMARY KEY,evidence_id INTEGER,timestamp TEXT,src_ip TEXT,dst_ip TEXT,protocol TEXT,src_port INTEGER,dst_port INTEGER,length INTEGER);
                CREATE TABLE alerts(alert_id INTEGER PRIMARY KEY,packet_id INTEGER,alert_type TEXT,severity TEXT,description TEXT,timestamp TEXT);
                INSERT INTO evidence VALUES(42,'known',NULL,'2026-01-01',NULL);
                INSERT INTO packets VALUES(8,42,'2026-01-01',NULL,NULL,'TCP',1,443,100);
                INSERT INTO alerts VALUES(6,8,'known','Low','inferred','2026-01-01');
                INSERT INTO alerts VALUES(7,NULL,'unowned','Low','unknown','2026-01-01');
            """)
        for _ in range(2): db.create_database(old)
        self.assertEqual(db.query_alerts(old,42)[0]['alert_id'],6)
        self.assertIsNone(db.query_alerts(old)[1]['evidence_id'])
        with closing(db.get_connection(old)) as conn, conn:
            self.assertTrue(any(r['from']=='evidence_id' and r['table']=='evidence'
                                for r in conn.execute('PRAGMA foreign_key_list(alerts)')))

    def test_existing_alert_owners_and_application_data_survive(self):
        p = self.packets()[0]
        other = db.insert_evidence('other', db_name=self.path)
        # A layout with evidence_id already present but no FK/ownership checks.
        with closing(db.get_connection(self.path)) as conn, conn:
            conn.executescript("""
                DROP TRIGGER alerts_validate_insert;
                DROP TRIGGER alerts_infer_insert;
                CREATE TABLE app_analysis(id INTEGER PRIMARY KEY,payload BLOB);
                CREATE TABLE app_reports(id INTEGER PRIMARY KEY,evidence_id INTEGER,body TEXT);
                INSERT INTO app_analysis VALUES(12,X'0001FF');
                INSERT INTO app_reports VALUES(13,1,'signed report metadata');
            """)
            conn.execute("INSERT INTO alerts(alert_id,packet_id,evidence_id,alert_type,severity,description,timestamp) VALUES(99,?,?,'historical','Low','preserve existing owner','2026-01-01')",(p,other))
        for _ in range(2): db.create_database(self.path)
        self.assertEqual(db.query_alerts(self.path,other)[0]['alert_id'],99)
        self.assertEqual(db.fetch_all('SELECT payload FROM app_analysis',db_name=self.path)[0]['payload'],bytes([0,1,255]))
        self.assertEqual(db.fetch_all('SELECT id,body FROM app_reports',db_name=self.path),[{'id':13,'body':'signed report metadata'}])

    def test_metadata_and_actual_generated_ids(self):
        from parser_db_bridge import store_parsed_capture
        self.packets()  # consume IDs independently of capture frame numbers
        packets = [dict(timestamp=1700000000.125,frame_number=frame,src_ip='10.0.0.1',dst_ip='10.0.0.2',
                        protocol='TCP',src_port=50000,dst_port=80,length=74,tcp_flags=flags,
                        dns_records=[],http_records=[]) for frame,flags in [(1,2),(2,18),(9,0)]]
        result = store_parsed_capture('metadata',packets,db_name=self.path)
        stored = db.query_packets(self.path,result['evidence_id'])
        self.assertEqual([r['packet_id'] for r in stored],result['packet_ids'])
        self.assertNotEqual(result['packet_ids'],[1,2,9])
        self.assertEqual([r['frame_number'] for r in stored],[1,2,9])
        self.assertEqual([r['tcp_flags'] for r in stored],[2,18,0])
        self.assertEqual(stored[0]['timestamp'],'2023-11-14T22:13:20.125000+00:00')
        self.assertEqual(stored[0]['length'],74)
        legacy = db.query_packets(self.path,self.evidence)[0]
        self.assertIsNone(legacy['frame_number']); self.assertIsNone(legacy['tcp_flags'])

    def test_bridge_rolls_back_protocol_rows_and_audit_on_failure(self):
        from parser_db_bridge import store_parsed_capture
        good = dict(timestamp=1700000000.125,frame_number=1,protocol='TCP',length=74,tcp_flags=2,
                    dns_records=[{'query_name':'example.com','answers':[{'type':'A','value':'10.0.0.2'}]}],
                    http_records=[{'host':'example.com','method':'GET','uri':'/'}])
        tables=['evidence','packets','dns_records','http_records','audit_log']
        before={t:db.fetch_all('SELECT * FROM '+t,db_name=self.path) for t in tables}
        for bad in [dict(good,frame_number=0),dict(good,tcp_flags=-1),dict(good,tcp_flags=1.5)]:
            with self.assertRaises(ValueError):store_parsed_capture('bad',[good,bad],db_name=self.path)
            for t in tables:self.assertEqual(db.fetch_all('SELECT * FROM '+t,db_name=self.path),before[t])
        def failing_parser():
            yield good
            raise RuntimeError('parser read failed')
        with self.assertRaises(RuntimeError):store_parsed_capture('bad',failing_parser(),db_name=self.path)
        for t in tables:self.assertEqual(db.fetch_all('SELECT * FROM '+t,db_name=self.path),before[t])

    def test_fresh_schema_has_no_tls_paths_and_tcp443_is_kept(self):
        from parser_db_bridge import store_parsed_capture
        tables={r['name'] for r in db.fetch_all("SELECT name FROM sqlite_master WHERE type='table'",db_name=self.path)}
        self.assertNotIn('tls_records',tables)
        self.assertFalse(hasattr(db,'insert_tls_record'))
        self.assertFalse(hasattr(db,'query_tls'))
        from query_api import dispatch
        with self.assertRaises(KeyError):dispatch('/api/tls',{},self.path)
        with self.assertRaises(ValueError):db.query_protocol_records('tls',self.path)
        result=store_parsed_capture('443',[dict(timestamp=1700000000,protocol='TCP',src_port=50000,
                 dst_port=443,length=74,frame_number=1,tcp_flags=2)],db_name=self.path)
        self.assertEqual(db.query_packets(self.path,result['evidence_id'])[0]['dst_port'],443)
        self.assertEqual(len(db.query_https(self.path)),1)

    def test_jahnnavi_representative_packet_contract(self):
        from parser_db_bridge import store_parsed_capture
        import json
        fixture=Path(__file__).parent/'fixtures'/'representative_packets.json'
        packets=json.loads(fixture.read_text())
        result=store_parsed_capture('representative contract',packets,db_name=self.path)
        self.assertEqual(len(result['packet_ids']),3)
        self.assertEqual(len(db.query_protocol_records('http',self.path,result['evidence_id'])),1)
        self.assertEqual(len(db.query_protocol_records('dns',self.path,result['evidence_id'])),1)
        answer=db.query_protocol_records('dns',self.path,result['evidence_id'])[0]['answers']
        self.assertEqual(json.loads(answer),packets[1]['dns_records'][0]['answers'])


if __name__ == '__main__':
    unittest.main()
