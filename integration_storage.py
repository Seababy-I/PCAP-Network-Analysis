"""App transaction adapter around Aanya's unchanged connection-level storage helper."""
import json
import database as db


def store_packets(conn,evidence_id,records):
    ids=[]
    for record in records:
        packet_id=db._insert_packet(conn,record['timestamp'],record.get('src_ip'),record.get('dst_ip'),
            record['protocol'],record.get('src_port'),record.get('dst_port'),record['length'],evidence_id,
            record['frame_number'],record.get('tcp_flags'))
        ids.append(packet_id)
        for kind,columns in {'dns':('query_name','query_type','response_code','answers'),
                             'http':('method','host','uri','status_code')}.items():
            for item in record[kind+'_records']:
                values=[item.get(column) for column in columns]
                if kind=='dns' and values[-1] is not None:values[-1]=json.dumps(values[-1])
                conn.execute(f"INSERT INTO {kind}_records(packet_id,{','.join(columns)}) VALUES({','.join('?' for _ in range(len(columns)+1))})",[packet_id]+values)
    return ids
