"""SQLite storage, bidirectional flows, scoped forensic queries and audit integrity.

Active application records are DNS and HTTP. Legacy TLS tables are preserved
without creating, inserting or querying them through the new workflow.
Packet length means original frame length reported by PyShark packet.length.
"""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
from contextlib import closing
DB_NAME = "forensic.db"


def get_connection(db_name=DB_NAME):
    """Return a SQLite connection with foreign keys enabled."""
    conn = sqlite3.connect(db_name)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn


def _schema_statements():
    """Split trusted bundled SQL, preserving complete CREATE TRIGGER bodies."""
    statement = ""
    for line in Path(__file__).with_name("schema.sql").read_text(encoding="utf-8").splitlines(True):
        statement += line
        if sqlite3.complete_statement(statement):
            yield statement.strip()
            statement = ""
    if statement.strip():
        raise ValueError("Incomplete bundled schema SQL")


def create_database(db_name=DB_NAME):
    """Atomic, repeatable additive migration; never rebuild/drop application tables.

    Only infer a missing alert owner from its actual packet's known owner.
    Existing non-NULL alert owners are never overwritten. Unknown historical
    owners stay NULL; inconsistent pre-existing associations are preserved for
    review and new/changed associations are checked by triggers.
    """
    statements = list(_schema_statements())
    with closing(get_connection(db_name)) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        for statement in statements:
            # Tables first: indexes/triggers need the migrated columns below.
            sql = "\n".join(line for line in statement.splitlines() if not line.lstrip().startswith("--")).lstrip()
            if sql.upper().startswith("CREATE TABLE"):
                conn.execute(statement)
        additions = {
            "packets": [("evidence_id", "INTEGER REFERENCES evidence(evidence_id)"),
                        ("frame_number", "INTEGER CHECK(frame_number IS NULL OR frame_number >= 1)"),
                        ("tcp_flags", "INTEGER CHECK(tcp_flags IS NULL OR tcp_flags BETWEEN 0 AND 4095)")],
            "alerts": [("evidence_id", "INTEGER REFERENCES evidence(evidence_id) ON DELETE RESTRICT")],
            "audit_log": [("details", "TEXT NOT NULL DEFAULT '{}'"),
                          ("hash_version", "INTEGER NOT NULL DEFAULT 1")],
        }
        for table, columns in additions.items():
            existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
            for name, definition in columns:
                if name not in existing:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
        conn.execute("""UPDATE alerts SET evidence_id=(SELECT p.evidence_id FROM packets p
                        WHERE p.packet_id=alerts.packet_id)
                        WHERE evidence_id IS NULL AND packet_id IS NOT NULL
                        AND EXISTS(SELECT 1 FROM packets p JOIN evidence e ON e.evidence_id=p.evidence_id
                                   WHERE p.packet_id=alerts.packet_id)""")
        for statement in statements:
            sql = "\n".join(line for line in statement.splitlines() if not line.lstrip().startswith("--")).lstrip()
            if not sql.upper().startswith("CREATE TABLE"):
                conn.execute(statement)


def insert_evidence(filename, sha256=None, signature=None, db_name=DB_NAME):
    """Insert one PCAP evidence record and return its ID."""
    with closing(get_connection(db_name)) as conn, conn:
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
        return evidence_id


def _optional_integer(value, name, minimum=0, maximum=None):
    if value is None:
        return None
    if isinstance(value, bool) or isinstance(value, float) and not value.is_integer():
        raise ValueError(f"{name} must be an integer")
    try:
        number = int(value, 16) if isinstance(value, str) and value.lower().startswith("0x") else int(value)
    except (TypeError, ValueError, OverflowError) as error:
        raise ValueError(f"{name} must be an integer") from error
    if number < minimum or maximum is not None and number > maximum:
        raise ValueError(f"{name} is out of range")
    return number


def _insert_packet(conn, timestamp, src_ip, dst_ip, protocol, src_port=None,
                   dst_port=None, length=0, evidence_id=None, frame_number=None, tcp_flags=None):
    protocol = str(protocol).strip().upper()
    if not protocol or protocol == "NONE":
        raise ValueError("Protocol is required")
    return conn.execute("""INSERT INTO packets(timestamp,src_ip,dst_ip,protocol,src_port,dst_port,
        length,evidence_id,frame_number,tcp_flags) VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (_timestamp(timestamp), _ip(src_ip), _ip(dst_ip), protocol, _port(src_port), _port(dst_port),
         _length(length), evidence_id, _optional_integer(frame_number, "frame_number", 1),
         _optional_integer(tcp_flags, "tcp_flags", 0, 4095))).lastrowid


def insert_packet(timestamp, src_ip, dst_ip, protocol, src_port=None, dst_port=None,
                  length=0, db_name=DB_NAME, evidence_id=None, frame_number=None, tcp_flags=None):
    """Return the SQLite ID; frame_number is an independent capture identifier."""
    with closing(get_connection(db_name)) as conn, conn:
        return _insert_packet(conn, timestamp, src_ip, dst_ip, protocol, src_port, dst_port,
                              length, evidence_id, frame_number, tcp_flags)


def insert_alert(packet_id, alert_type, severity, description, timestamp=None,
                 db_name=DB_NAME, evidence_id=None):
    """Insert packet or capture-level findings, validating and inferring ownership.

    Old positional arguments are preserved; evidence_id is an added keyword.
    If both owners are unknown, retain an unassigned historical-style finding.
    """
    with closing(get_connection(db_name)) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        if evidence_id is not None and not conn.execute(
                "SELECT 1 FROM evidence WHERE evidence_id=?", (evidence_id,)).fetchone():
            raise ValueError("Unknown evidence_id")
        if packet_id is not None:
            packet = conn.execute("SELECT evidence_id FROM packets WHERE packet_id=?", (packet_id,)).fetchone()
            if packet is None:
                raise ValueError("Unknown packet_id")
            if evidence_id is not None and evidence_id != packet["evidence_id"]:
                raise ValueError("Packet/evidence ownership mismatch")
            evidence_id = packet["evidence_id"] if evidence_id is None else evidence_id
        return conn.execute("""INSERT INTO alerts(evidence_id,packet_id,alert_type,severity,description,timestamp)
            VALUES(?,?,?,?,?,?)""", (evidence_id,packet_id,alert_type,severity,description,
                _timestamp(timestamp or datetime.now(timezone.utc)))).lastrowid


def insert_packets(packet_rows, db_name=DB_NAME, evidence_id=None):
    """Atomically store legacy seven-field rows; return actual generated IDs.

    Use the structured bridge or insert_packet for frame_number/tcp_flags.
    """
    ids = []
    with closing(get_connection(db_name)) as conn, conn:
        for row in packet_rows:
            if len(row) != 7:
                raise ValueError("Each packet requires seven fields")
            ids.append(_insert_packet(conn, *row, evidence_id=evidence_id))
    return ids


def fetch_all(query, params=(), db_name=DB_NAME):
    """Run a SELECT query and return rows as dictionaries."""
    with closing(get_connection(db_name)) as conn:
        rows = conn.execute(query, params).fetchall()
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


def query_alerts(db_name=DB_NAME, evidence_id=None):
    """Include packet and NULL-packet alerts owned by the selected evidence."""
    clause, params = _scope(evidence_id)
    return fetch_all("SELECT * FROM alerts" + clause + " ORDER BY alert_id", params, db_name)


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

def _timestamp(value):
    """Store UTC consistently. Naive parser timestamps are interpreted as UTC."""
    if isinstance(value, (int, float)):
        dt = datetime.fromtimestamp(value, timezone.utc)
    elif isinstance(value, datetime):
        dt = value
    else:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _ip(value):
    if value in (None, "", "N/A"):
        return None
    import ipaddress
    return str(ipaddress.ip_address(value))


def _port(value):
    if value in (None, "", "N/A"):
        return None
    number = int(value)
    if not 0 <= number <= 65535:
        raise ValueError("Port must be 0..65535")
    return number


def _length(value):
    number = int(value)
    if number < 0:
        raise ValueError("Packet length cannot be negative")
    return number


def _audit_hash(row):
    if row["hash_version"] == 1:
        payload = row["operation"] + row["status"] + row["timestamp"] + row["prev_hash"]
    elif row["hash_version"] == 2:
        payload = json.dumps({key: row[key] for key in
            ("id", "evidence_id", "operation", "status", "timestamp", "prev_hash", "details", "hash_version")},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    else:
        raise ValueError("Unsupported audit hash version")
    return hashlib.sha256(payload.encode()).hexdigest()


def _append_audit(conn, evidence_id, operation, status, details):
    prev = conn.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    row = dict(evidence_id=evidence_id, operation=operation, status=status,
               timestamp=datetime.now(timezone.utc).isoformat(),
               prev_hash=prev[0] if prev else "GENESIS",
               details=json.dumps(details or {}, sort_keys=True, separators=(",", ":")), hash_version=2)
    cur = conn.execute("""INSERT INTO audit_log(evidence_id,operation,status,timestamp,prev_hash,entry_hash,details,hash_version)
        VALUES(:evidence_id,:operation,:status,:timestamp,:prev_hash,'PENDING',:details,:hash_version)""", row)
    row["id"] = cur.lastrowid
    conn.execute("UPDATE audit_log SET entry_hash=? WHERE id=?", (_audit_hash(row), row["id"]))
    return row["id"]


def add_audit_log(evidence_id, operation, status="SUCCESS", db_name=DB_NAME, details=None):
    """Serialize appends and bind every v2 field, including evidence ID, into the hash."""
    with closing(get_connection(db_name)) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        return _append_audit(conn, evidence_id, operation, status, details)


def verify_audit_chain(db_name=DB_NAME, expected_head=None):
    """Optional trusted external head detects tail truncation too."""
    rows = fetch_all("SELECT * FROM audit_log ORDER BY id", db_name=db_name)
    previous = "GENESIS"
    for row in rows:
        try:
            valid = row["prev_hash"] == previous and _audit_hash(row) == row["entry_hash"]
        except (ValueError, TypeError):
            valid = False
        if not valid:
            return False, f"Chain broken at log ID {row['id']}"
        previous = row["entry_hash"]
    if expected_head is not None and previous != expected_head:
        return False, "Audit head does not match trusted checkpoint"
    legacy = sum(row["hash_version"] == 1 for row in rows)
    return True, f"Audit chain valid; {legacy} legacy entries have limited field coverage"


def query_audit_log(db_name=DB_NAME, evidence_id=None):
    clause, params = _scope(evidence_id)
    return fetch_all("SELECT * FROM audit_log" + clause + " ORDER BY id", params, db_name)


def insert_dns_record(packet_id, query_name=None, query_type=None, response_code=None,
                      answers=None, db_name=DB_NAME):
    with closing(get_connection(db_name)) as conn, conn:
        return conn.execute("""INSERT INTO dns_records(packet_id,query_name,query_type,response_code,answers)
            VALUES(?,?,?,?,?)""", (packet_id, query_name, query_type, response_code,
                                   json.dumps(answers) if answers is not None else None)).lastrowid


def insert_http_record(packet_id, method=None, host=None, uri=None, status_code=None, db_name=DB_NAME):
    with closing(get_connection(db_name)) as conn, conn:
        return conn.execute("INSERT INTO http_records(packet_id,method,host,uri,status_code) VALUES(?,?,?,?,?)",
                            (packet_id, method, host, uri, status_code)).lastrowid


def _scope(evidence_id, prefix=""):
    return ("", ()) if evidence_id is None else (f" WHERE {prefix}evidence_id = ?", (evidence_id,))


def reconstruct_flows(db_name=DB_NAME, evidence_id=None):
    """Rebuild bidirectional 5-tuple conversations per capture, atomically.

    This aggregates endpoints, not TCP payload streams or individual TCP sessions.
    Packet IDs are stable; flow IDs can change after a rebuild.
    NULL evidence packets form a separate legacy/unassigned capture group.
    """
    with closing(get_connection(db_name)) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        clause, params = _scope(evidence_id)
        packets = conn.execute("SELECT * FROM packets" + clause + " ORDER BY packet_id", params).fetchall()
        conn.execute("DELETE FROM flows" + clause, params)
        groups = {}
        for packet in packets:
            if not packet["src_ip"] or not packet["dst_ip"]:
                continue
            left = (packet["src_ip"], packet["src_port"] if packet["src_port"] is not None else -1)
            right = (packet["dst_ip"], packet["dst_port"] if packet["dst_port"] is not None else -1)
            low, high = sorted((left, right))
            key = (packet["evidence_id"], packet["protocol"], low, high)
            groups.setdefault(key, []).append(packet)
        for (capture, protocol, low, high), members in groups.items():
            forward = [m for m in members if (m["src_ip"], m["src_port"] if m["src_port"] is not None else -1) == low]
            times = [_timestamp(m["timestamp"]) for m in members]
            forward_bytes = sum(m["length"] for m in forward)
            total_bytes = sum(m["length"] for m in members)
            cur = conn.execute("""INSERT INTO flows(evidence_id,src_ip,dst_ip,src_port,dst_port,protocol,
                first_seen,last_seen,packet_count,total_bytes,forward_packets,reverse_packets,forward_bytes,reverse_bytes)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (capture, low[0], high[0], None if low[1] == -1 else low[1], None if high[1] == -1 else high[1],
                 protocol, min(times), max(times), len(members), total_bytes,
                 len(forward), len(members)-len(forward), forward_bytes, total_bytes-forward_bytes))
            forward_ids = {m["packet_id"] for m in forward}
            conn.executemany("INSERT INTO flow_packets(packet_id,flow_id,direction) VALUES(?,?,?)",
                [(m["packet_id"], cur.lastrowid, "forward" if m["packet_id"] in forward_ids else "reverse") for m in members])
        _append_audit(conn, evidence_id, "RECONSTRUCT_FLOWS", "SUCCESS", {"flow_count": len(groups)})
        return len(groups)


def query_flows(db_name=DB_NAME, evidence_id=None):
    clause, params = _scope(evidence_id)
    return fetch_all("SELECT * FROM flows" + clause + " ORDER BY total_bytes DESC, flow_id", params, db_name)


def query_flow_packets(flow_id, db_name=DB_NAME):
    return fetch_all("""SELECT p.*, fp.direction FROM packets p JOIN flow_packets fp USING(packet_id)
        WHERE fp.flow_id=? ORDER BY julianday(p.timestamp), p.packet_id""", (flow_id,), db_name)


def query_top_talkers(db_name=DB_NAME, evidence_id=None, limit=10):
    clause, params = _scope(evidence_id)
    limit = int(limit)
    if not 1 <= limit <= 1000:
        raise ValueError("Limit must be 1..1000")
    return fetch_all("""SELECT src_ip, COUNT(*) AS packet_count, SUM(length) AS total_bytes,
        COUNT(DISTINCT dst_ip) AS destination_count FROM packets""" + clause +
        (" AND" if clause else " WHERE") + " src_ip IS NOT NULL GROUP BY src_ip ORDER BY total_bytes DESC, src_ip LIMIT ?",
        params + (limit,), db_name)


def query_protocol_breakdown(db_name=DB_NAME, evidence_id=None):
    clause, params = _scope(evidence_id)
    return fetch_all("SELECT protocol, COUNT(*) AS packet_count, SUM(length) AS total_bytes FROM packets" +
                     clause + " GROUP BY protocol ORDER BY packet_count DESC, protocol", params, db_name)


def query_timeline(db_name=DB_NAME, evidence_id=None, bucket_seconds=60):
    bucket = int(bucket_seconds)
    if not 1 <= bucket <= 86400:
        raise ValueError("Bucket must be 1..86400 seconds")
    clause, params = _scope(evidence_id)
    return fetch_all("""SELECT datetime(CAST(strftime('%s',timestamp) AS INTEGER) / ? * ?, 'unixepoch') AS bucket_start_utc,
        COUNT(*) AS packet_count, SUM(length) AS total_bytes FROM packets""" + clause +
        " GROUP BY bucket_start_utc ORDER BY bucket_start_utc", (bucket, bucket) + params, db_name)


def query_packets(db_name=DB_NAME, evidence_id=None, ip=None, protocol=None,
                  start=None, end=None, limit=1000, offset=0):
    conditions, params = [], []
    for value, condition in [(evidence_id, "evidence_id=?"), (protocol.upper() if protocol else None, "protocol=?")]:
        if value is not None:
            conditions.append(condition); params.append(value)
    if ip is not None:
        conditions.append("(src_ip=? OR dst_ip=?)"); params.extend([ip, ip])
    for value, operator in [(start, ">="), (end, "<=")]:
        if value is not None:
            conditions.append(f"julianday(timestamp) {operator} julianday(?)"); params.append(_timestamp(value))
    if not 1 <= int(limit) <= 10000 or int(offset) < 0:
        raise ValueError("Invalid pagination")
    where = " WHERE " + " AND ".join(conditions) if conditions else ""
    return fetch_all("SELECT * FROM packets" + where +
        " ORDER BY julianday(timestamp),packet_id LIMIT ? OFFSET ?", tuple(params) + (int(limit), int(offset)), db_name)


def query_protocol_records(kind, db_name=DB_NAME, evidence_id=None):
    tables = {"dns": "dns_records", "http": "http_records"}
    if kind not in tables:
        raise ValueError("Kind must be dns or http")
    clause, params = _scope(evidence_id, "p.")
    return fetch_all(f"SELECT r.*, p.evidence_id,p.timestamp,p.src_ip,p.dst_ip FROM {tables[kind]} r "
                     "JOIN packets p USING(packet_id)" + clause + " ORDER BY p.packet_id", params, db_name)


if __name__ == "__main__":
    create_database()
    print(f"Database ready: {Path(DB_NAME).resolve()}")
