use cyberspace_capture::graph::GraphBuilder;
use cyberspace_capture::parser::ParsedPacket;

fn make_pkt(src: &str, dst: &str, proto: &str) -> ParsedPacket {
    ParsedPacket {
        src_ip: src.to_string(),
        dst_ip: dst.to_string(),
        src_port: Some(1234),
        dst_port: Some(80),
        protocol: proto.to_string(),
        bytes: 100,
    }
}

#[test]
fn test_graph_adds_nodes_and_edges() {
    let mut builder = GraphBuilder::new();
    builder.process_packet(&make_pkt("10.0.0.1", "10.0.0.2", "TCP"));

    let snapshot = builder.snapshot();
    assert_eq!(snapshot.nodes.len(), 2);
    assert_eq!(snapshot.edges.len(), 1);
}

#[test]
fn test_delta_only_returns_changes() {
    let mut builder = GraphBuilder::new();
    builder.process_packet(&make_pkt("10.0.0.1", "10.0.0.2", "TCP"));
    let _snap = builder.snapshot(); // Consume initial state

    // Process same flow again — should only produce updates, not additions
    builder.process_packet(&make_pkt("10.0.0.1", "10.0.0.2", "TCP"));
    let delta = builder.delta();

    assert_eq!(delta.nodes_added.len(), 0);
    assert!(delta.nodes_updated.len() > 0);
    assert_eq!(delta.edges_added.len(), 0);
}

#[test]
fn test_delta_shows_new_node() {
    let mut builder = GraphBuilder::new();
    builder.process_packet(&make_pkt("10.0.0.1", "10.0.0.2", "TCP"));
    let _snap = builder.snapshot();

    builder.process_packet(&make_pkt("10.0.0.1", "10.0.0.3", "UDP"));
    let delta = builder.delta();

    assert_eq!(delta.nodes_added.len(), 1); // 10.0.0.3 is new
    assert_eq!(delta.edges_added.len(), 1); // new edge
}
