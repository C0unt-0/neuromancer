use cyberspace_capture::parser::parse_packet;

#[test]
fn test_parse_tcp_packet() {
    // Minimal Ethernet + IPv4 + TCP packet (SYN)
    let eth_ipv4_tcp: Vec<u8> = vec![
        // Ethernet header (14 bytes)
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, // dst mac
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, // src mac
        0x08, 0x00, // EtherType: IPv4
        // IPv4 header (20 bytes)
        0x45, 0x00, 0x00, 0x28, // version, IHL, total length = 40
        0x00, 0x01, 0x00, 0x00, // identification, flags, fragment
        0x40, 0x06, 0x00, 0x00, // TTL=64, protocol=TCP, checksum
        0x0a, 0x0a, 0x0b, 0x0a, // src IP: 10.10.11.10
        0x0a, 0x0a, 0x0b, 0xea, // dst IP: 10.10.11.234
        // TCP header (20 bytes)
        0x04, 0xd2, 0x00, 0x50, // src port: 1234, dst port: 80
        0x00, 0x00, 0x00, 0x01, // seq number
        0x00, 0x00, 0x00, 0x00, // ack number
        0x50, 0x02, 0x72, 0x10, // data offset, SYN flag, window
        0x00, 0x00, 0x00, 0x00, // checksum, urgent
    ];

    let result = parse_packet(&eth_ipv4_tcp);
    assert!(result.is_some());
    let pkt = result.unwrap();
    assert_eq!(pkt.src_ip, "10.10.11.10");
    assert_eq!(pkt.dst_ip, "10.10.11.234");
    assert_eq!(pkt.protocol, "TCP");
    assert_eq!(pkt.src_port, Some(1234));
    assert_eq!(pkt.dst_port, Some(80));
    assert_eq!(pkt.bytes, 54); // total packet length
}

#[test]
fn test_parse_udp_dns_packet() {
    let eth_ipv4_udp: Vec<u8> = vec![
        // Ethernet (14)
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x08, 0x00,
        // IPv4 (20)
        0x45, 0x00, 0x00, 0x1c, // total length = 28
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00, // protocol = UDP (17)
        0xc0, 0xa8, 0x01, 0x01, // src: 192.168.1.1
        0x08, 0x08, 0x08, 0x08, // dst: 8.8.8.8
        // UDP (8)
        0xc0, 0x00, 0x00, 0x35, // src: 49152, dst: 53 (DNS)
        0x00, 0x08, 0x00, 0x00, // length, checksum
    ];

    let result = parse_packet(&eth_ipv4_udp);
    assert!(result.is_some());
    let pkt = result.unwrap();
    assert_eq!(pkt.src_ip, "192.168.1.1");
    assert_eq!(pkt.dst_ip, "8.8.8.8");
    assert_eq!(pkt.protocol, "DNS"); // Port 53 -> classified as DNS
    assert_eq!(pkt.dst_port, Some(53));
}

#[test]
fn test_parse_malformed_packet() {
    let garbage = vec![0x00, 0x01, 0x02];
    assert!(parse_packet(&garbage).is_none());
}
