# Compatibility fixtures

- representative_packets.json: synthetic dictionaries exercising the shared parser/bridge contract. Not extracted network evidence.
- dns_valid.pcap: synthetic Ethernet/IPv4 UDP DNS query and response for example.com -> 192.0.2.80. Proper DNS structure and IPv4 header checksums, UDP checksum zero (valid for IPv4). Two frames, original frame lengths 71/87 bytes. Documentation-only IP ranges and example domain.
- ipv6_vlan_http.pcap: all 55 frames from the repository's v6-http.cap, with an 802.1Q tag (VLAN 100) inserted in each Ethernet header. Derived test fixture, not an unmodified original capture.
- ipv6_vlan_http.pcapng: editcap conversion of that derived VLAN fixture to PCAPNG.
- malformed_capture.pcap: deliberately invalid text input; expected parser error and transaction rollback.
- parser_sample_output.json: actual dictionaries emitted by Jahnnavi's parser during this validation run, with source_capture labels. The DNS source is synthetic; the HTTP source is the committed IPv6 capture. These examples do not claim malicious activity.

The committed data/sample.pcap contains an illustrative DNS-like payload. It is used only for its frame count/metadata test, not as evidence that DNS parsing works.
