"""Storage contract for Jahnnavi's parser. No packet extraction or detection here."""
import json
from contextlib import closing
from datetime import datetime, timezone
import database as db


def store_parsed_capture(filename, packets, sha256=None, signature=None, db_name=db.DB_NAME):
    """Atomically store an evidence record, parser dictionaries and IMPORT audit entry.

    Each dictionary has timestamp, src_ip, dst_ip, protocol, optional src_port,
    dst_port, length, and optional lists tls_records/dns_records/http_records.
    Returns {evidence_id, packet_ids}. Call reconstruct_flows after import.
    sha256/signature must be supplied by Priyali's security module.
    This does not validate a supplied hash/signature or parse a PCAP itself.
    """
    db.create_database(db_name)
    ids = []
    with closing(db.get_connection(db_name)) as conn, conn:
        conn.execute('BEGIN IMMEDIATE')
        evidence_id = conn.execute('''INSERT INTO evidence(filename,sha256,import_time,signature)
            VALUES(?,?,?,?)''', (filename, sha256, datetime.now(timezone.utc).isoformat(), signature)).lastrowid
        for packet in packets:
            packet_id = conn.execute('''INSERT INTO packets(evidence_id,timestamp,src_ip,dst_ip,protocol,src_port,dst_port,length)
                VALUES(?,?,?,?,?,?,?,?)''', (evidence_id, db._timestamp(packet['timestamp']), db._ip(packet.get('src_ip')),
                    db._ip(packet.get('dst_ip')), str(packet['protocol']).upper(), db._port(packet.get('src_port')),
                    db._port(packet.get('dst_port')), db._length(packet.get('length', 0)))).lastrowid
            ids.append(packet_id)
            for kind, columns in {
                'tls': ('tls_version','cipher_selected','sni','cert_subject','cert_issuer','cert_not_before','cert_not_after','cert_sha256'),
                'dns': ('query_name','query_type','response_code','answers'),
                'http': ('method','host','uri','status_code'),
            }.items():
                for record in packet.get(kind + '_records', []):
                    values = [record.get(column) for column in columns]
                    if kind == 'dns' and values[-1] is not None:
                        values[-1] = json.dumps(values[-1])
                    # Self-signed classification belongs to Priyali; store raw certificate fields here.
                    conn.execute(f"INSERT INTO {kind}_records(packet_id,{','.join(columns)}) VALUES({','.join('?' for _ in range(len(columns)+1))})",
                                 [packet_id] + values)
        db._append_audit(conn, evidence_id, 'IMPORT', 'SUCCESS', {'packet_count': len(ids), 'filename': filename})
    return {'evidence_id': evidence_id, 'packet_ids': ids}
