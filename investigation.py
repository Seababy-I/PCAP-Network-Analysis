"""Evidence-scoped investigation queries over Aanya's storage API."""
import database as db
from contextlib import closing


def overview(evidence_id,db_name):
    with closing(db.get_connection(str(db_name))) as conn:
        counts={table:conn.execute(f'SELECT COUNT(*) FROM {table} WHERE evidence_id=?',(evidence_id,)).fetchone()[0]
                for table in ('packets','flows','alerts')}
        for kind in ('dns','http'):
            counts[kind]=conn.execute(f'SELECT COUNT(*) FROM {kind}_records r JOIN packets p USING(packet_id) WHERE p.evidence_id=?',(evidence_id,)).fetchone()[0]
    return dict(counts=counts,protocols=db.query_protocol_breakdown(str(db_name),evidence_id),
                top_talkers=db.query_top_talkers(str(db_name),evidence_id),
                timeline=db.query_timeline(str(db_name),evidence_id),flows=db.query_flows(str(db_name),evidence_id))


def packets(evidence_id,db_name,**filters):
    return db.query_packets(str(db_name),evidence_id=evidence_id,**filters)


def flow_packets(evidence_id,flow_id,db_name):
    if not db.fetch_all('SELECT 1 FROM flows WHERE evidence_id=? AND flow_id=?',(evidence_id,flow_id),str(db_name)):
        raise ValueError('Flow does not belong to the selected evidence')
    return db.query_flow_packets(flow_id,str(db_name))


def protocol_records(evidence_id,kind,db_name):
    return db.query_protocol_records(kind,str(db_name),evidence_id)
