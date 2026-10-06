"""
PCAP Forensic Tool - SQLite Database Layer
Aanya's module

Creates forensic.db and provides:
- evidence table
- packets table
- tls_records table
- alerts table
- packet/evidence/TLS/alert insertion helpers
- forensic SQL query helpers
- demo data insertion for testing without the parser
"""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import os
DB_NAME = "forensic.db"


def get_connection(db_name=DB_NAME):
    """Return a SQLite connection with foreign keys enabled."""
    conn = sqlite3.connect(db_name)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn


def create_database(db_name=DB_NAME):
    """Create all required tables if they do not already exist."""
    conn = get_connection(db_name)

    conn.executescript("""
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
    CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id INTEGER,
    operation TEXT NOT NULL,
    status TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    prev_hash TEXT,
    entry_hash TEXT NOT NULL,
    FOREIGN KEY (evidence_id)
        REFERENCES evidence(evidence_id)
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
    """)

    conn.commit()
    conn.close()


def insert_evidence(filename, sha256=None, signature=None, db_name=DB_NAME):
    """Insert one PCAP evidence record and return its ID."""
    conn = get_connection(db_name)
    cur = conn.execute(
        """
        INSERT INTO evidence (filename, sha256, import_time, signature)
        VALUES (?, ?, ?, ?)
        """,
        (
            filename,
            sha256,
            datetime.now(timezone.utc).isoformat(),
            signature,
        ),
    )
    evidence_id = cur.lastrowid
    conn.commit()
    conn.close()
    return evidence_id


def insert_packet(timestamp, src_ip, dst_ip, protocol,
                  src_port=None, dst_port=None, length=0,
                  db_name=DB_NAME):
    """Insert one packet record and return its packet ID."""
    conn = get_connection(db_name)
    cur = conn.execute(
        """
        INSERT INTO packets
        (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, length)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (timestamp, src_ip, dst_ip, protocol.upper(), src_port, dst_port, length),
    )
    packet_id = cur.lastrowid
    conn.commit()
    conn.close()
    return packet_id


def insert_tls_record(packet_id, tls_version=None, cipher_selected=None,
                       sni=None, cert_issuer=None, cert_not_before=None,
                       cert_not_after=None, cert_sha256=None,
                       is_self_signed=False, db_name=DB_NAME):
    """Insert TLS information associated with a packet."""
    conn = get_connection(db_name)
    cur = conn.execute(
        """
        INSERT INTO tls_records
        (packet_id, tls_version, cipher_selected, sni, cert_issuer,
         cert_not_before, cert_not_after, cert_sha256, is_self_signed)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            packet_id, tls_version, cipher_selected, sni, cert_issuer,
            cert_not_before, cert_not_after, cert_sha256,
            int(bool(is_self_signed)),
        ),
    )
    tls_id = cur.lastrowid
    conn.commit()
    conn.close()
    return tls_id


def insert_alert(packet_id, alert_type, severity, description,
                  timestamp=None, db_name=DB_NAME):
    """Insert a forensic alert."""
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()

    conn = get_connection(db_name)
    cur = conn.execute(
        """
        INSERT INTO alerts
        (packet_id, alert_type, severity, description, timestamp)
        VALUES (?, ?, ?, ?, ?)
        """,
        (packet_id, alert_type, severity, description, timestamp),
    )
    alert_id = cur.lastrowid
    conn.commit()
    conn.close()
    return alert_id


def insert_packets(packet_rows, db_name=DB_NAME):
    """
    Insert multiple packets.

    Each row must be:
    (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, length)
    """
    conn = get_connection(db_name)
    conn.executemany(
        """
        INSERT INTO packets
        (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, length)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                row[0], row[1], row[2], str(row[3]).upper(),
                row[4], row[5], row[6]
            )
            for row in packet_rows
        ],
    )
    conn.commit()
    conn.close()


def fetch_all(query, params=(), db_name=DB_NAME):
    """Run a SELECT query and return rows as dictionaries."""
    conn = get_connection(db_name)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def query_tcp(db_name=DB_NAME):
    return fetch_all(
        "SELECT * FROM packets WHERE protocol = 'TCP' ORDER BY packet_id",
        db_name=db_name,
    )


def query_udp(db_name=DB_NAME):
    return fetch_all(
        "SELECT * FROM packets WHERE protocol = 'UDP' ORDER BY packet_id",
        db_name=db_name,
    )


def query_dns(db_name=DB_NAME):
    return fetch_all(
        """
        SELECT * FROM packets
        WHERE src_port = 53 OR dst_port = 53
        ORDER BY packet_id
        """,
        db_name=db_name,
    )


def query_https(db_name=DB_NAME):
    return fetch_all(
        """
        SELECT * FROM packets
        WHERE src_port = 443 OR dst_port = 443
        ORDER BY packet_id
        """,
        db_name=db_name,
    )


def query_by_ip(ip, db_name=DB_NAME):
    return fetch_all(
        """
        SELECT * FROM packets
        WHERE src_ip = ? OR dst_ip = ?
        ORDER BY packet_id
        """,
        (ip, ip),
        db_name=db_name,
    )


def query_tls(db_name=DB_NAME):
    return fetch_all(
        """
        SELECT
            t.tls_id,
            t.packet_id,
            t.tls_version,
            t.cipher_selected,
            t.sni,
            t.cert_issuer,
            t.cert_not_before,
            t.cert_not_after,
            t.cert_sha256,
            t.is_self_signed
        FROM tls_records t
        ORDER BY t.tls_id
        """,
        db_name=db_name,
    )


def query_alerts(db_name=DB_NAME):
    return fetch_all(
        """
        SELECT
            a.alert_id,
            a.packet_id,
            a.alert_type,
            a.severity,
            a.description,
            a.timestamp
        FROM alerts a
        ORDER BY a.alert_id
        """,
        db_name=db_name,
    )


def count_packets_by_protocol(db_name=DB_NAME):
    return fetch_all(
        """
        SELECT protocol, COUNT(*) AS packet_count
        FROM packets
        GROUP BY protocol
        ORDER BY packet_count DESC
        """,
        db_name=db_name,
    )


def print_rows(title, rows):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)

    if not rows:
        print("No records found.")
        return

    for row in rows:
        print(row)

def add_audit_log(
    evidence_id,
    operation,
    status="SUCCESS",
    db_name=DB_NAME
):
    """
    Add one audit log entry using hash chaining.
    """

    conn = get_connection(db_name)

    # Get previous hash
    prev = conn.execute(
        """
        SELECT entry_hash
        FROM audit_log
        ORDER BY id DESC
        LIMIT 1
        """
    ).fetchone()

    prev_hash = prev["entry_hash"] if prev else "GENESIS"

    timestamp = datetime.now(
        timezone.utc
    ).isoformat()

    chain_data = (
        operation +
        status +
        timestamp +
        prev_hash
    )

    entry_hash = hashlib.sha256(
        chain_data.encode()
    ).hexdigest()

    conn.execute(
        """
        INSERT INTO audit_log
        (
            evidence_id,
            operation,
            status,
            timestamp,
            prev_hash,
            entry_hash
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            evidence_id,
            operation,
            status,
            timestamp,
            prev_hash,
            entry_hash
        )
    )
    conn.commit()
    conn.close()

def verify_audit_chain(
    db_name=DB_NAME
):
    """
    Verify the complete audit chain.
    """

    conn = get_connection(db_name)

    rows = conn.execute(
        """
        SELECT *
        FROM audit_log
        ORDER BY id
        """
    ).fetchall()

    previous_hash = "GENESIS"

    for row in rows:

        expected_hash = hashlib.sha256(
            (
                row["operation"]
                + row["status"]
                + row["timestamp"]
                + previous_hash
            ).encode()
        ).hexdigest()

        if expected_hash != row["entry_hash"]:

            conn.close()

            return False, (
                f"Chain broken at log ID "
                f"{row['id']}"
            )

        previous_hash = row["entry_hash"]

    conn.close()

    return True, "Audit chain valid"

if __name__ == "__main__":
    create_database()
    print(f"Database ready: {Path(DB_NAME).resolve()}")

    evidence_id = insert_evidence(
        "sample.pcap",
        "abc123hash",
        "signature123"
    )

    add_audit_log(
        evidence_id,
        "IMPORT"
    )

    add_audit_log(
        evidence_id,
        "VERIFY"
    )

    add_audit_log(
        evidence_id,
        "REPORT_SIGN"
    )

    print("Audit entries created")
    
    print(os.path.exists(r"C:\Users\aanya\Downloads\PCAP-Network-Analysis\forensic.db"))
