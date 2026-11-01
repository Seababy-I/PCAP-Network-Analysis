"""Storage contract for Jahnnavi's parser. No packet extraction or detection here."""
import json
from contextlib import closing
from datetime import datetime, timezone
import database as db


def store_parsed_capture(filename, packets, sha256=None, signature=None, db_name=db.DB_NAME):
    """Atomically store an evidence record, parser dictionaries and IMPORT audit entry.

    Each dictionary has timestamp, src_ip, dst_ip, protocol, optional src_port,
    dst_port, length, and nullable frame_number/tcp_flags and optional dns_records/http_records lists.
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
            if packet.get('tls_records'):
                raise ValueError("TLS extraction is excluded from this workflow")
            packet_id = db._insert_packet(
                conn, packet['timestamp'], packet.get('src_ip'), packet.get('dst_ip'),
                packet['protocol'], packet.get('src_port'), packet.get('dst_port'),
                packet.get('length', 0), evidence_id,
                packet.get('frame_number'), packet.get('tcp_flags'))
            ids.append(packet_id)
            for kind, columns in {
                'dns': ('query_name','query_type','response_code','answers'),
                'http': ('method','host','uri','status_code'),
            }.items():
                for record in packet.get(kind + '_records', []):
                    values = [record.get(column) for column in columns]
                    if kind == 'dns' and values[-1] is not None:
                        values[-1] = json.dumps(values[-1])
                    conn.execute(f"INSERT INTO {kind}_records(packet_id,{','.join(columns)}) VALUES({','.join('?' for _ in range(len(columns)+1))})",
                                 [packet_id] + values)
        db._append_audit(conn, evidence_id, 'IMPORT', 'SUCCESS', {'packet_count': len(ids), 'filename': filename})
    return {'evidence_id': evidence_id, 'packet_ids': ids}
