-- PCAP Forensic Tool SQLite schema

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    sha256 TEXT,
    import_time TEXT NOT NULL,
    signature TEXT
);

CREATE TABLE IF NOT EXISTS packets (
    packet_id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id INTEGER REFERENCES evidence(evidence_id),
    timestamp TEXT NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    protocol TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    length INTEGER NOT NULL,
    frame_number INTEGER CHECK(frame_number IS NULL OR frame_number >= 1),
    tcp_flags INTEGER CHECK(tcp_flags IS NULL OR tcp_flags BETWEEN 0 AND 4095)
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id INTEGER REFERENCES evidence(evidence_id) ON DELETE RESTRICT,
    packet_id INTEGER,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (packet_id) REFERENCES packets(packet_id)
        ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS dns_records (
    dns_id INTEGER PRIMARY KEY, packet_id INTEGER NOT NULL REFERENCES packets(packet_id) ON DELETE CASCADE,
    query_name TEXT, query_type TEXT, response_code TEXT, answers TEXT
);
CREATE TABLE IF NOT EXISTS http_records (
    http_id INTEGER PRIMARY KEY, packet_id INTEGER NOT NULL REFERENCES packets(packet_id) ON DELETE CASCADE,
    method TEXT, host TEXT, uri TEXT, status_code INTEGER
);
CREATE TABLE IF NOT EXISTS flows (
    flow_id INTEGER PRIMARY KEY, evidence_id INTEGER REFERENCES evidence(evidence_id),
    src_ip TEXT NOT NULL, dst_ip TEXT NOT NULL, src_port INTEGER, dst_port INTEGER,
    protocol TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    packet_count INTEGER NOT NULL, total_bytes INTEGER NOT NULL,
    forward_packets INTEGER NOT NULL, reverse_packets INTEGER NOT NULL,
    forward_bytes INTEGER NOT NULL, reverse_bytes INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS flow_packets (
    packet_id INTEGER PRIMARY KEY REFERENCES packets(packet_id) ON DELETE CASCADE,
    flow_id INTEGER NOT NULL REFERENCES flows(flow_id) ON DELETE CASCADE,
    direction TEXT NOT NULL CHECK(direction IN ('forward','reverse'))
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id INTEGER REFERENCES evidence(evidence_id) ON DELETE RESTRICT,
    operation TEXT NOT NULL, status TEXT NOT NULL, timestamp TEXT NOT NULL,
    prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '{}', hash_version INTEGER NOT NULL DEFAULT 2
);

-- Also protects legacy audit tables whose FK originally used ON DELETE CASCADE.
CREATE TRIGGER IF NOT EXISTS preserve_audited_evidence
BEFORE DELETE ON evidence WHEN EXISTS(SELECT 1 FROM audit_log WHERE evidence_id=OLD.evidence_id)
BEGIN SELECT RAISE(ABORT, 'Cannot delete audited evidence'); END;

CREATE INDEX IF NOT EXISTS idx_packets_evidence_time ON packets(evidence_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(src_ip);
CREATE INDEX IF NOT EXISTS idx_packets_dst ON packets(dst_ip);
CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(protocol);
CREATE INDEX IF NOT EXISTS idx_alerts_evidence ON alerts(evidence_id);
CREATE INDEX IF NOT EXISTS idx_dns_packet ON dns_records(packet_id);
CREATE INDEX IF NOT EXISTS idx_http_packet ON http_records(packet_id);
CREATE INDEX IF NOT EXISTS idx_flows_evidence ON flows(evidence_id);
CREATE INDEX IF NOT EXISTS idx_flow_packets_flow ON flow_packets(flow_id);

-- Validation triggers also cover legacy columns without a declared FK.
CREATE TRIGGER IF NOT EXISTS alerts_validate_insert
BEFORE INSERT ON alerts BEGIN
    SELECT CASE WHEN NEW.evidence_id IS NOT NULL AND NOT EXISTS
        (SELECT 1 FROM evidence WHERE evidence_id=NEW.evidence_id)
        THEN RAISE(ABORT, 'Unknown alert evidence_id') END;
    SELECT CASE WHEN NEW.packet_id IS NOT NULL AND NOT EXISTS
        (SELECT 1 FROM packets WHERE packet_id=NEW.packet_id)
        THEN RAISE(ABORT, 'Unknown alert packet_id') END;
    SELECT CASE WHEN NEW.packet_id IS NOT NULL AND NEW.evidence_id IS NOT NULL AND NOT EXISTS
        (SELECT 1 FROM packets WHERE packet_id=NEW.packet_id AND evidence_id=NEW.evidence_id)
        THEN RAISE(ABORT, 'Packet/evidence ownership mismatch') END;
END;
CREATE TRIGGER IF NOT EXISTS alerts_validate_update
BEFORE UPDATE OF evidence_id,packet_id ON alerts BEGIN
    SELECT CASE WHEN NEW.evidence_id IS NOT NULL AND NOT EXISTS
        (SELECT 1 FROM evidence WHERE evidence_id=NEW.evidence_id)
        THEN RAISE(ABORT, 'Unknown alert evidence_id') END;
    SELECT CASE WHEN NEW.packet_id IS NOT NULL AND NOT EXISTS
        (SELECT 1 FROM packets WHERE packet_id=NEW.packet_id)
        THEN RAISE(ABORT, 'Unknown alert packet_id') END;
    SELECT CASE WHEN NEW.packet_id IS NOT NULL AND NEW.evidence_id IS NOT NULL AND NOT EXISTS
        (SELECT 1 FROM packets WHERE packet_id=NEW.packet_id AND evidence_id=NEW.evidence_id)
        THEN RAISE(ABORT, 'Packet/evidence ownership mismatch') END;
END;
CREATE TRIGGER IF NOT EXISTS alerts_infer_insert
AFTER INSERT ON alerts WHEN NEW.evidence_id IS NULL AND NEW.packet_id IS NOT NULL BEGIN
    UPDATE alerts SET evidence_id=(SELECT evidence_id FROM packets WHERE packet_id=NEW.packet_id)
    WHERE alert_id=NEW.alert_id;
END;
CREATE TRIGGER IF NOT EXISTS preserve_alert_evidence
BEFORE DELETE ON evidence WHEN EXISTS(SELECT 1 FROM alerts WHERE evidence_id=OLD.evidence_id)
BEGIN SELECT RAISE(ABORT, 'Cannot delete evidence referenced by alerts'); END;
CREATE TRIGGER IF NOT EXISTS packets_preserve_alert_owner
BEFORE UPDATE OF evidence_id ON packets
WHEN EXISTS(SELECT 1 FROM alerts WHERE packet_id=OLD.packet_id AND evidence_id IS NOT NULL
            AND evidence_id IS NOT NEW.evidence_id)
BEGIN SELECT RAISE(ABORT, 'Packet update would change alert ownership'); END;
