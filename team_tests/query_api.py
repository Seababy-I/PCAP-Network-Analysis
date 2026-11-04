"""Optional local read-only JSON adapter for Priyali's dashboard.
Run: python query_api.py --db forensic.db --port 8000
Uses only Python's standard library; binds to loopback.
"""
import argparse
import json
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
import database as db


def dispatch(path, params, db_name):
    def integer(name, default=None):
        values = params.get(name)
        return int(values[0]) if values else default
    def value(name):
        values = params.get(name)
        return values[0] if values else None
    evidence_id = integer('evidence_id')
    if path == '/api/packets':
        return db.query_packets(db_name, evidence_id, value('ip'), value('protocol'),
                                value('start'), value('end'), integer('limit', 1000), integer('offset', 0))
    if path == '/api/top-talkers':
        return db.query_top_talkers(db_name, evidence_id, integer('limit', 10))
    if path == '/api/timeline':
        return db.query_timeline(db_name, evidence_id, integer('bucket_seconds', 60))
    if path == '/api/protocols':
        return db.query_protocol_breakdown(db_name, evidence_id)
    if path == '/api/flows':
        return db.query_flows(db_name, evidence_id)
    if path == '/api/flow-packets':
        flow_id = integer('flow_id')
        if flow_id is None:
            raise ValueError('flow_id is required')
        return db.query_flow_packets(flow_id, db_name)
    if path in ('/api/dns', '/api/http'):
        return db.query_protocol_records(path.split('/')[-1], db_name, evidence_id)
    if path == '/api/audit':
        return db.query_audit_log(db_name, evidence_id)
    if path == '/api/audit/verify':
        valid, message = db.verify_audit_chain(db_name, value('expected_head'))
        return {'valid': valid, 'message': message}
    if path == '/api/evidence':
        return db.fetch_all('SELECT * FROM evidence ORDER BY evidence_id', db_name=db_name)
    if path == '/api/alerts':
        return db.query_alerts(db_name=db_name, evidence_id=evidence_id)
    raise KeyError('Unknown endpoint')


def make_handler(db_name):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            url = urlsplit(self.path)
            try:
                result = dispatch(url.path, parse_qs(url.query), db_name)
                status = 200
            except (ValueError, TypeError) as error:
                status, result = 400, {'error': str(error)}
            except KeyError:
                status, result = 404, {'error': 'Unknown endpoint'}
            except sqlite3.Error:
                status, result = 500, {'error': 'Database query failed'}
            body = json.dumps(result).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    return Handler


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', default=db.DB_NAME)
    parser.add_argument('--port', type=int, default=8000)
    args = parser.parse_args()
    db.create_database(args.db)
    server = ThreadingHTTPServer(('127.0.0.1', args.port), make_handler(args.db))
    print(f'Query API: http://127.0.0.1:{args.port}/api/evidence')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
