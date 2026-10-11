-- PCAP Forensic Tool - Aanya's SQL queries

-- 1. View all packets
SELECT * FROM packets
ORDER BY packet_id;

-- 2. TCP traffic
SELECT *
FROM packets
WHERE protocol = 'TCP'
ORDER BY packet_id;

-- 3. UDP traffic
SELECT *
FROM packets
WHERE protocol = 'UDP'
ORDER BY packet_id;

-- 4. HTTPS traffic
SELECT *
FROM packets
WHERE src_port = 443 OR dst_port = 443
ORDER BY packet_id;

-- 5. DNS traffic
SELECT *
FROM packets
WHERE src_port = 53 OR dst_port = 53
ORDER BY packet_id;

-- 6. Traffic involving a selected IP
-- Change the IP below as required.
SELECT *
FROM packets
WHERE src_ip = '192.168.1.10'
   OR dst_ip = '192.168.1.10'
ORDER BY packet_id;

-- 7. Packet count by protocol
SELECT protocol, COUNT(*) AS packet_count
FROM packets
GROUP BY protocol
ORDER BY packet_count DESC;

-- 8. TLS records
SELECT *
FROM tls_records
ORDER BY tls_id;

-- 9. Alerts
SELECT *
FROM alerts
ORDER BY alert_id;

-- 10. Join TLS information with its packet
SELECT
    p.packet_id,
    p.timestamp,
    p.src_ip,
    p.dst_ip,
    p.src_port,
    p.dst_port,
    t.tls_version,
    t.cipher_selected,
    t.sni,
    t.cert_issuer,
    t.is_self_signed
FROM packets p
JOIN tls_records t
    ON p.packet_id = t.packet_id
ORDER BY p.packet_id;

-- Evidence-scoped examples: replace :evidence_id with an ID or bind it in Python.
-- 11. Top source talkers by bytes (counts outbound traffic only)
SELECT src_ip, COUNT(*) AS packet_count, SUM(length) AS total_bytes,
       COUNT(DISTINCT dst_ip) AS destination_count
FROM packets WHERE evidence_id = :evidence_id AND src_ip IS NOT NULL
GROUP BY src_ip ORDER BY total_bytes DESC, src_ip LIMIT 10;

-- 12. Protocol breakdown
SELECT protocol, COUNT(*) AS packet_count, SUM(length) AS total_bytes
FROM packets WHERE evidence_id = :evidence_id
GROUP BY protocol ORDER BY packet_count DESC, protocol;

-- 13. Minute timeline in UTC
SELECT strftime('%Y-%m-%dT%H:%M:00Z',timestamp) AS minute_utc,
       COUNT(*) AS packet_count, SUM(length) AS total_bytes
FROM packets WHERE evidence_id = :evidence_id
GROUP BY minute_utc ORDER BY minute_utc;

-- 14. Reconstructed conversations
SELECT * FROM flows WHERE evidence_id = :evidence_id
ORDER BY total_bytes DESC, flow_id;

-- 15. Packets belonging to a conversation
SELECT p.*, fp.direction FROM flow_packets fp JOIN packets p USING(packet_id)
WHERE fp.flow_id = :flow_id ORDER BY julianday(p.timestamp), p.packet_id;

-- 16. DNS and HTTP fields, scoped through packets
SELECT d.*, p.src_ip, p.dst_ip FROM dns_records d JOIN packets p USING(packet_id)
WHERE p.evidence_id = :evidence_id ORDER BY p.packet_id;
SELECT h.*, p.src_ip, p.dst_ip FROM http_records h JOIN packets p USING(packet_id)
WHERE p.evidence_id = :evidence_id ORDER BY p.packet_id;

-- 17. Audit inspection (verification must use verify_audit_chain, not this SELECT)
SELECT * FROM audit_log ORDER BY id;

-- 18. Raw inputs for Priyali's detectors: no thresholds or security classifications here
SELECT src_ip, COUNT(DISTINCT dst_ip) AS destination_count,
       COUNT(DISTINCT dst_port) AS destination_port_count
FROM packets WHERE evidence_id = :evidence_id GROUP BY src_ip;
SELECT src_ip, COUNT(*) AS packets_to_port_22
FROM packets WHERE evidence_id = :evidence_id AND dst_port = 22 GROUP BY src_ip;
