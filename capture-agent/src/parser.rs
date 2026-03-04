use etherparse::SlicedPacket;

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedPacket {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: String,
    pub bytes: u64,
}

pub fn parse_packet(data: &[u8]) -> Option<ParsedPacket> {
    let packet = SlicedPacket::from_ethernet(data).ok()?;

    let (src_ip, dst_ip) = match packet.net? {
        etherparse::NetSlice::Ipv4(ipv4) => (
            format!("{}", ipv4.header().source_addr()),
            format!("{}", ipv4.header().destination_addr()),
        ),
        etherparse::NetSlice::Ipv6(ipv6) => (
            format!("{}", ipv6.header().source_addr()),
            format!("{}", ipv6.header().destination_addr()),
        ),
    };

    let (src_port, dst_port, base_protocol) = match packet.transport {
        Some(etherparse::TransportSlice::Tcp(tcp)) => {
            (Some(tcp.source_port()), Some(tcp.destination_port()), "TCP")
        }
        Some(etherparse::TransportSlice::Udp(udp)) => {
            (Some(udp.source_port()), Some(udp.destination_port()), "UDP")
        }
        Some(etherparse::TransportSlice::Icmpv4(_)) => (None, None, "ICMP"),
        Some(etherparse::TransportSlice::Icmpv6(_)) => (None, None, "ICMP"),
        None => (None, None, "OTHER"),
    };

    // Classify protocol by well-known ports
    let protocol = classify_protocol(base_protocol, src_port, dst_port);

    Some(ParsedPacket {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        bytes: data.len() as u64,
    })
}

fn classify_protocol(base: &str, src_port: Option<u16>, dst_port: Option<u16>) -> String {
    let ports = [src_port, dst_port];
    for p in ports.iter().flatten() {
        match p {
            53 => return "DNS".to_string(),
            443 => {
                if base == "UDP" {
                    return "QUIC".to_string();
                }
                return "TLS".to_string();
            }
            _ => {}
        }
    }
    base.to_string()
}
