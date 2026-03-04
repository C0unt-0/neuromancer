use cyberspace_capture::flow::FlowAggregator;
use cyberspace_capture::parser::ParsedPacket;

fn make_packet(src: &str, dst: &str, proto: &str, bytes: u64) -> ParsedPacket {
    ParsedPacket {
        src_ip: src.to_string(),
        dst_ip: dst.to_string(),
        src_port: Some(1234),
        dst_port: Some(80),
        protocol: proto.to_string(),
        bytes,
    }
}

#[test]
fn test_new_flow_created() {
    let mut agg = FlowAggregator::new();
    let pkt = make_packet("10.0.0.1", "10.0.0.2", "TCP", 100);
    agg.process_packet(&pkt);

    assert_eq!(agg.flow_count(), 1);
}

#[test]
fn test_same_flow_aggregated() {
    let mut agg = FlowAggregator::new();
    let pkt1 = make_packet("10.0.0.1", "10.0.0.2", "TCP", 100);
    let pkt2 = make_packet("10.0.0.1", "10.0.0.2", "TCP", 200);
    agg.process_packet(&pkt1);
    agg.process_packet(&pkt2);

    assert_eq!(agg.flow_count(), 1);
    let flows = agg.get_flows();
    let flow = flows.values().next().unwrap();
    assert_eq!(flow.total_bytes, 300);
    assert_eq!(flow.total_packets, 2);
}

#[test]
fn test_bidirectional_flows_normalized() {
    let mut agg = FlowAggregator::new();
    let pkt1 = make_packet("10.0.0.1", "10.0.0.2", "TCP", 100);
    let pkt2 = make_packet("10.0.0.2", "10.0.0.1", "TCP", 50);
    agg.process_packet(&pkt1);
    agg.process_packet(&pkt2);

    // Bidirectional flows should be merged (normalized key: lower IP first)
    assert_eq!(agg.flow_count(), 1);
}

#[test]
fn test_different_protocols_separate_flows() {
    let mut agg = FlowAggregator::new();
    let tcp = make_packet("10.0.0.1", "10.0.0.2", "TCP", 100);
    let udp = make_packet("10.0.0.1", "10.0.0.2", "UDP", 100);
    agg.process_packet(&tcp);
    agg.process_packet(&udp);

    assert_eq!(agg.flow_count(), 2);
}
