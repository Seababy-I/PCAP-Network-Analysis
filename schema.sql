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
    length INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tls_records (
    tls_id INTEGER PRIMARY KEY AUTOINCREMENT,
    packet_id INTEGER NOT NULL,
    tls_version TEXT,
    cipher_selected TEXT,
    sni TEXT,
    cert_subject TEXT,
    cert_issuer TEXT,
    cert_not_before TEXT,
    cert_not_after TEXT,
    cert_sha256 TEXT,
    is_self_signed INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (packet_id) REFERENCES packets(packet_id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
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
