# PCAP Source Code Study Index

Code baseline 90686e27d8cb9286f293475ddfb37758dd9e8884 on master. Generated from Python AST definitions.
Use the function names with the handbook explanations; a function list alone is not an explanation of its security guarantees. Nested helpers are included under their containing definition.

## launch_dashboard.py

Launch the analyst dashboard on loopback, independently of the working directory.

- [main at line 7](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/launch_dashboard.py#L7)

## dashboard.py

PCAP Forensic Security Dashboard

- [html at line 33](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/dashboard.py#L33) Flatten HTML so Markdown never sees indented lines as a code block.
- [get_database_connection at line 210](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/dashboard.py#L210)
- [get_alerts at line 214](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/dashboard.py#L214)
- [get_evidence at line 227](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/dashboard.py#L227)
- [get_audit_log at line 240](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/dashboard.py#L240)
- [section_header at line 377](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/dashboard.py#L377)
- [_render_alert_table at line 389](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/dashboard.py#L389)
- [page_overview at line 442](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/dashboard.py#L442)
- [page_alerts at line 546](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/dashboard.py#L546)
- [page_evidence at line 612](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/dashboard.py#L612)
- [page_audit at line 721](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/dashboard.py#L721)
- [page_investigation at line 842](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/dashboard.py#L842)
- [page_reports at line 892](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/dashboard.py#L892)

## analysis_service.py

Shared vault, parser, storage, detection and report workflow.

- [connection at line 24](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/analysis_service.py#L24)
- [initialize_database at line 35](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/analysis_service.py#L35)
- [append_audit at line 54](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/analysis_service.py#L54) Append using whichever audit hash version the installed DB schema supports.
- [_result at line 75](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/analysis_service.py#L75)
- [process_capture at line 83](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/analysis_service.py#L83)
- [rebuild_flows at line 180](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/analysis_service.py#L180)
- [get_evidence at line 204](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/analysis_service.py#L204)
- [verify_evidence at line 214](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/analysis_service.py#L214)

## capture_records.py

Temporary network-only reader. Does not replace the team's DNS/HTTP parser.

- [validate_container at line 12](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/capture_records.py#L12) Reject damaged/truncated containers instead of silently treating them as clean.
- [read_network_records at line 67](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/capture_records.py#L67)

## parser.py

See the module role in the viva handbook.

- [ParserExtractionError at line 20](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/parser.py#L20) Fatal extraction failure with structured frame/progress information.
- [ParserExtractionError.__init__ at line 22](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/parser.py#L22)
- [find_tshark at line 28](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/parser.py#L28)
- [get_layer at line 71](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/parser.py#L71)
- [get_field at line 81](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/parser.py#L81)
- [to_integer at line 97](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/parser.py#L97)
- [get_timestamp at line 114](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/parser.py#L114)
- [get_packet_length at line 120](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/parser.py#L120)
- [extract_ip_addresses at line 126](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/parser.py#L126)
- [extract_protocol at line 157](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/parser.py#L157)
- [extract_ports at line 170](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/parser.py#L170)
- [extract_tcp_flags at line 183](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/parser.py#L183)
- [field_values at line 190](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/parser.py#L190) Read every PDML occurrence, rather than only PyShark's default field.
- [checked_number at line 210](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/parser.py#L210)
- [extract_dns_records at line 217](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/parser.py#L217)
- [extract_http_records at line 265](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/parser.py#L265)
- [extract_packet at line 286](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/parser.py#L286)
- [validate_capture_format at line 359](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/parser.py#L359) Reject invalid/truncated PCAP/PCAPNG before PyShark is started.
- [validate_capture_format.invalid at line 367](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/parser.py#L367)
- [parse_pcap at line 425](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/parser.py#L425)

## parser_adapter.py

User-owned boundary checks for a teammate parser; contains no packet extraction.

- [ParserContractError at line 12](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/parser_adapter.py#L12)
- [_integer at line 16](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/parser_adapter.py#L16)
- [validate_record at line 24](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/parser_adapter.py#L24)
- [preview_capture at line 78](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/parser_adapter.py#L78) Acceptance preview only. Does not sign, write evidence or alter a database.

## integration_runtime.py

User-owned coordination for the pinned teammate parser, without changing it.

- [_restrict_directory at line 23](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/integration_runtime.py#L23)
- [_parse_worker at line 38](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/integration_runtime.py#L38)
- [parse_content at line 62](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/integration_runtime.py#L62)

## integration_storage.py

App transaction adapter around Aanya's unchanged connection-level storage helper.

- [store_packets at line 6](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/integration_storage.py#L6)

## database.py

SQLite storage, bidirectional flows, scoped forensic queries and audit integrity.

- [get_connection at line 17](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L17) Return a SQLite connection with foreign keys enabled.
- [_schema_statements at line 25](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L25) Split trusted bundled SQL, preserving complete CREATE TRIGGER bodies.
- [create_database at line 37](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L37) Atomic, repeatable additive migration; never rebuild/drop application tables.
- [insert_evidence at line 77](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L77) Insert one PCAP evidence record and return its ID.
- [_optional_integer at line 96](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L96)
- [_insert_packet at line 110](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L110)
- [insert_packet at line 122](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L122) Return the SQLite ID; frame_number is an independent capture identifier.
- [insert_alert at line 130](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L130) Insert packet or capture-level findings, validating and inferring ownership.
- [insert_packets at line 154](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L154) Atomically store legacy seven-field rows; return actual generated IDs.
- [fetch_all at line 168](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L168) Run a SELECT query and return rows as dictionaries.
- [query_tcp at line 175](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L175)
- [query_udp at line 182](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L182)
- [query_dns at line 189](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L189)
- [query_https at line 200](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L200)
- [query_by_ip at line 211](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L211)
- [query_alerts at line 223](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L223) Include packet and NULL-packet alerts owned by the selected evidence.
- [count_packets_by_protocol at line 229](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L229)
- [print_rows at line 241](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L241)
- [_timestamp at line 253](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L253) Store UTC consistently. Naive parser timestamps are interpreted as UTC.
- [_ip at line 266](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L266)
- [_port at line 273](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L273)
- [_length at line 282](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L282)
- [_audit_hash at line 289](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L289)
- [_append_audit at line 301](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L301)
- [add_audit_log at line 314](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L314) Serialize appends and bind every v2 field, including evidence ID, into the hash.
- [verify_audit_chain at line 321](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L321) Optional trusted external head detects tail truncation too.
- [query_audit_log at line 339](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L339)
- [insert_dns_record at line 344](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L344)
- [insert_http_record at line 352](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L352)
- [_scope at line 358](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L358)
- [reconstruct_flows at line 362](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L362) Rebuild bidirectional 5-tuple conversations per capture, atomically.
- [query_flows at line 401](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L401)
- [query_flow_packets at line 406](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L406)
- [query_top_talkers at line 411](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L411)
- [query_protocol_breakdown at line 422](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L422)
- [query_timeline at line 428](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L428)
- [query_packets at line 438](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L438)
- [query_protocol_records at line 456](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/database.py#L456)

## investigation.py

Evidence-scoped investigation queries over Aanya's storage API.

- [overview at line 6](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/investigation.py#L6)
- [packets at line 17](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/investigation.py#L17)
- [flow_packets at line 21](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/investigation.py#L21)
- [protocol_records at line 27](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/investigation.py#L27)

## parser_db_bridge.py

Storage contract for Jahnnavi's parser. No packet extraction or detection here.

- [store_parsed_capture at line 8](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/parser_db_bridge.py#L8) Atomically store an evidence record, parser dictionaries and IMPORT audit entry.

## detection.py

TCP SYN scan heuristics over normalized records or saved captures.

- [parse_packets at line 10](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/detection.py#L10)
- [_scan at line 14](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/detection.py#L14)
- [detect_port_scan at line 53](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/detection.py#L53)

## host_scan.py

See the module role in the viva handbook.

- [detect_host_scan at line 8](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/host_scan.py#L8)

## security_detection.py

Network detection only; TLS analysis has been removed from the active workflow.

- [run_network_detection at line 8](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/security_detection.py#L8)
- [run_all_detection at line 13](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/security_detection.py#L13)

## crypto_utils.py

Persistent RSA-PSS signing with independent, versioned artifacts.

- [calculate_sha256 at line 16](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/crypto_utils.py#L16)
- [generate_rsa_keys at line 26](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/crypto_utils.py#L26)
- [public_bytes at line 31](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/crypto_utils.py#L31)
- [key_fingerprint at line 35](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/crypto_utils.py#L35)
- [load_private_key at line 40](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/crypto_utils.py#L40)
- [load_public_key at line 48](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/crypto_utils.py#L48)
- [save_keys at line 52](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/crypto_utils.py#L52) Initialize a pair; never replace existing evidence keys.
- [_key_lock at line 75](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/crypto_utils.py#L75)
- [get_or_create_keys at line 94](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/crypto_utils.py#L94)
- [_pss at line 114](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/crypto_utils.py#L114)
- [sign_file at line 118](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/crypto_utils.py#L118)
- [verify_signature at line 122](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/crypto_utils.py#L122)
- [load_signature at line 131](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/crypto_utils.py#L131)
- [save_signature at line 135](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/crypto_utils.py#L135)
- [signature_metadata at line 143](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/crypto_utils.py#L143)
- [signing_public_key_path at line 157](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/crypto_utils.py#L157)
- [_secure at line 168](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/crypto_utils.py#L168)
- [secure_evidence at line 181](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/crypto_utils.py#L181)
- [verify_evidence_file at line 185](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/crypto_utils.py#L185)
- [verify_evidence_bytes at line 193](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/crypto_utils.py#L193)
- [sign_report at line 210](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/crypto_utils.py#L210)
- [verify_report at line 214](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/crypto_utils.py#L214)

## confidentiality.py

Password-derived authenticated encryption for managed evidence and exports.

- [VaultIntegrityError at line 19](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/confidentiality.py#L19)
- [resolve_password at line 23](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/confidentiality.py#L23)
- [prompt_password at line 32](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/confidentiality.py#L32)
- [vault_session at line 45](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/confidentiality.py#L45)
- [set_session_password at line 53](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/confidentiality.py#L53)
- [derive_key at line 57](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/confidentiality.py#L57)
- [encrypt_bytes at line 61](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/confidentiality.py#L61)
- [decrypt_bytes at line 69](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/confidentiality.py#L69)
- [is_encrypted at line 83](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/confidentiality.py#L83)
- [read_artifact at line 88](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/confidentiality.py#L88)
- [write_encrypted at line 100](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/confidentiality.py#L100)

## dashboard_auth.py

Single-analyst local dashboard gate. No password is stored in plaintext.

- [auth_path at line 12](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/dashboard_auth.py#L12)
- [create_account at line 16](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/dashboard_auth.py#L16)
- [check_password at line 26](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/dashboard_auth.py#L26)
- [require_unlock at line 40](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/dashboard_auth.py#L40)

## report_generator.py

Evidence-scoped, escaped HTML reports with unique signed artifacts.

- [get_data at line 19](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/report_generator.py#L19)
- [generate_report at line 29](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/report_generator.py#L29)
- [generate_report.safe at line 35](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/report_generator.py#L35)
- [generate_signed_report at line 78](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/report_generator.py#L78)
- [report_bundle at line 89](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/report_generator.py#L89) Portable public-only export. No private keys or evidence/database files.
- [main at line 120](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/report_generator.py#L120)

## risk_scoring.py

See the module role in the viva handbook.

- [calculate_risk_score at line 1](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/risk_scoring.py#L1) Calculate an overall security risk score from detected alerts.

## audit_security.py

Read-only audit verification and independently signed checkpoints.

- [_rows at line 13](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/audit_security.py#L13)
- [verify_audit at line 22](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/audit_security.py#L22)
- [create_checkpoint at line 55](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/audit_security.py#L55)
- [main at line 77](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/audit_security.py#L77)

## run_security.py

Sign saved evidence and run network heuristics without synthetic TLS findings.

- [main at line 9](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/run_security.py#L9)

## verify_evidence.py

See the module role in the viva handbook.

- [main at line 7](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/verify_evidence.py#L7)

## verify_artifact.py

Verify an exported artifact with an explicit public key; no database/private key needed.

- [verify_artifact at line 10](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/verify_artifact.py#L10)
- [main at line 23](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/verify_artifact.py#L23)

## vault_cli.py

Explicit file encryption/decryption. Never overwrites an existing output.

- [main at line 7](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/vault_cli.py#L7)

## prepare_demo.py

Generate deterministic synthetic inputs without replacing existing captures.

- [_ether at line 8](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/prepare_demo.py#L8)
- [_pcap at line 12](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/prepare_demo.py#L12)
- [prepare_demo at line 21](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/prepare_demo.py#L21)
- [main at line 46](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/prepare_demo.py#L46)

## demo_smoke.py

Rehearse the independent workflow using an isolated DB and disposable demo keys.

- [run_demo at line 16](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/demo_smoke.py#L16)
- [run_demo.check at line 26](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/demo_smoke.py#L26)
- [main at line 71](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/demo_smoke.py#L71)

## confidentiality_demo.py

Demonstrate managed-file confidentiality with isolated synthetic evidence.

- [run_demo at line 16](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/confidentiality_demo.py#L16)
- [main at line 50](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/confidentiality_demo.py#L50)

## integration_demo.py

Rehearse the integrated workflow with synthetic/public data and disposable keys.

- [run_demo at line 22](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/integration_demo.py#L22)
- [run_demo.check at line 34](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/integration_demo.py#L34)
- [main at line 72](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/integration_demo.py#L72)

## parser_readiness.py

Read-only environment check; does not accept, import or activate a teammate parser.

- [locate_tshark at line 14](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/parser_readiness.py#L14)
- [check_readiness at line 21](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/parser_readiness.py#L21)
- [main at line 62](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/parser_readiness.py#L62)

## parser_preview.py

Explicit parser acceptance preview. Never changes production storage or activates parsing.

- [load_parser at line 10](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/parser_preview.py#L10)
- [main at line 23](https://github.com/Seababy-I/PCAP-Network-Analysis/blob/90686e27d8cb9286f293475ddfb37758dd9e8884/parser_preview.py#L23)

## Other repository files

- schema.sql defines authoritative packet/protocol/flow/audit storage and safeguards.
- TEAM_SOURCES.json records upstream files, original hashes, installed hashes and parser patch status.
- tests contains the supported isolated application regressions. team_tests retains the owner tests and fixtures.
- .github/workflows/tests.yml defines the cross-platform and real-parser CI jobs.
- .gitignore protects runtime/private keys/vault settings from new commits; it does not untrack an already committed file.
- .gitattributes preserves binary capture/signature bytes and consistent source line endings.
- parser_backup.py, root test_*.py and old TLS/weak-crypto scripts are historical code, not the active supported workflow.
- Existing public keys and sample signatures are historical artifacts; private keys and local databases are not part of source delivery.
