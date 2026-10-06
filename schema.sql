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
