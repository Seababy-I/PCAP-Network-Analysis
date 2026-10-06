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
