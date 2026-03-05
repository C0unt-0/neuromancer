use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config;
use crate::flow::FlowAggregator;
use crate::parser::ParsedPacket;
use crate::protocol::*;

#[derive(Default)]
pub struct GraphBuilder {
    flow_agg: FlowAggregator,
    known_nodes: HashMap<String, NodeData>,
    known_edges: HashMap<String, EdgeData>,
    dirty_nodes: HashSet<String>,
    dirty_edges: HashSet<String>,
    new_nodes: HashSet<String>,
    new_edges: HashSet<String>,
    seq: u64,
}

impl GraphBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn process_packet(&mut self, pkt: &ParsedPacket) {
        self.flow_agg.process_packet(pkt);
        let now = now_ms();

        // Ensure source and destination nodes exist
        self.ensure_node(&pkt.src_ip, now);
        self.ensure_node(&pkt.dst_ip, now);

        // Update node stats
        if let Some(node) = self.known_nodes.get_mut(&pkt.src_ip) {
            node.total_bytes_out += pkt.bytes;
            node.total_packets_out += 1;
            node.last_seen = now;
            self.dirty_nodes.insert(pkt.src_ip.clone());
        }
        if let Some(node) = self.known_nodes.get_mut(&pkt.dst_ip) {
            node.total_bytes_in += pkt.bytes;
            node.last_seen = now;
            self.dirty_nodes.insert(pkt.dst_ip.clone());
        }

        // Ensure edge exists — normalize IPs to match make_edge_id ordering
        let edge_id = make_edge_id(&pkt.src_ip, &pkt.dst_ip, &pkt.protocol);
        let (sorted_src, sorted_dst) = if pkt.src_ip <= pkt.dst_ip {
            (pkt.src_ip.clone(), pkt.dst_ip.clone())
        } else {
            (pkt.dst_ip.clone(), pkt.src_ip.clone())
        };
        if !self.known_edges.contains_key(&edge_id) {
            let edge = EdgeData {
                id: edge_id.clone(),
                source_ip: sorted_src,
                target_ip: sorted_dst,
                protocol: pkt.protocol.clone(),
                total_bytes: pkt.bytes,
                total_packets: 1,
                packets_per_sec: 0.0,
                first_seen: now,
                last_seen: now,
            };
            self.known_edges.insert(edge_id.clone(), edge);
            self.new_edges.insert(edge_id);
        } else if let Some(edge) = self.known_edges.get_mut(&edge_id) {
            edge.total_bytes += pkt.bytes;
            edge.total_packets += 1;
            edge.last_seen = now;
            self.dirty_edges.insert(edge_id);
        }
    }

    fn ensure_node(&mut self, ip: &str, now: u64) {
        if !self.known_nodes.contains_key(ip) {
            if self.known_nodes.len() >= config::MAX_NODES {
                tracing::warn!("MAX_NODES limit ({}) reached, dropping new node {}", config::MAX_NODES, ip);
                return;
            }
            let node = NodeData {
                id: ip.to_string(),
                ip: ip.to_string(),
                hostname: None,
                node_type: classify_node_type(ip),
                is_local: is_rfc1918(ip),
                total_bytes_in: 0,
                total_bytes_out: 0,
                total_packets_out: 0,
                packets_per_sec: 0.0,
                first_seen: now,
                last_seen: now,
                geo: None,
            };
            self.known_nodes.insert(ip.to_string(), node);
            self.new_nodes.insert(ip.to_string());
        }
    }

    pub fn snapshot(&mut self) -> SnapshotFrame {
        let frame = SnapshotFrame {
            frame_type: "snapshot".to_string(),
            timestamp: now_ms(),
            nodes: self.known_nodes.values().cloned().collect(),
            edges: self.known_edges.values().cloned().collect(),
        };
        self.clear_dirty();
        frame
    }

    pub fn delta(&mut self) -> DeltaFrame {
        self.seq += 1;

        let nodes_added: Vec<NodeData> = self.new_nodes.iter()
            .filter_map(|id| self.known_nodes.get(id).cloned())
            .collect();

        let nodes_updated: Vec<NodeUpdate> = self.dirty_nodes.iter()
            .filter(|id| !self.new_nodes.contains(*id))
            .filter_map(|id| {
                let n = self.known_nodes.get(id)?;
                Some(NodeUpdate {
                    id: n.id.clone(),
                    total_bytes_in: Some(n.total_bytes_in),
                    total_bytes_out: Some(n.total_bytes_out),
                    total_packets_out: Some(n.total_packets_out),
                    packets_per_sec: Some(n.packets_per_sec),
                    last_seen: Some(n.last_seen),
                })
            })
            .collect();

        let edges_added: Vec<EdgeData> = self.new_edges.iter()
            .filter_map(|id| self.known_edges.get(id).cloned())
            .collect();

        let edges_updated: Vec<EdgeUpdate> = self.dirty_edges.iter()
            .filter(|id| !self.new_edges.contains(*id))
            .filter_map(|id| {
                let e = self.known_edges.get(id)?;
                Some(EdgeUpdate {
                    id: e.id.clone(),
                    total_bytes: Some(e.total_bytes),
                    total_packets: Some(e.total_packets),
                    packets_per_sec: Some(e.packets_per_sec),
                    last_seen: Some(e.last_seen),
                })
            })
            .collect();

        let frame = DeltaFrame {
            frame_type: "delta".to_string(),
            timestamp: now_ms(),
            seq: self.seq,
            nodes_added,
            nodes_updated,
            nodes_removed: vec![],
            edges_added,
            edges_updated,
            edges_removed: vec![],
            packet_events: vec![],
        };

        self.clear_dirty();
        frame
    }

    fn clear_dirty(&mut self) {
        self.dirty_nodes.clear();
        self.dirty_edges.clear();
        self.new_nodes.clear();
        self.new_edges.clear();
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis() as u64
}

fn make_edge_id(src: &str, dst: &str, proto: &str) -> String {
    if src <= dst {
        format!("{}-{}-{}", src, dst, proto)
    } else {
        format!("{}-{}-{}", dst, src, proto)
    }
}

fn is_rfc1918(ip: &str) -> bool {
    match Ipv4Addr::from_str(ip) {
        Ok(addr) => addr.is_private() || addr.is_loopback() || addr.is_link_local(),
        Err(_) => false,
    }
}

fn classify_node_type(ip: &str) -> NodeType {
    if is_rfc1918(ip) {
        // Simple heuristic: .1 addresses are likely gateways
        if ip.ends_with(".1") {
            NodeType::Gateway
        } else {
            NodeType::Local
        }
    } else {
        NodeType::Remote
    }
}
