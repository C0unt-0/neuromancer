use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeData {
    pub id: String,
    pub ip: String,
    pub hostname: Option<String>,
    pub node_type: NodeType,
    pub is_local: bool,
    pub total_bytes_in: u64,
    pub total_bytes_out: u64,
    pub total_packets_out: u64,
    pub packets_per_sec: f64,
    pub first_seen: u64,
    pub last_seen: u64,
    pub geo: Option<GeoInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeType {
    Local,
    Gateway,
    Dns,
    Cdn,
    Remote,
    Target,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoInfo {
    pub country: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub asn: Option<u32>,
    pub as_org: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeData {
    pub id: String,
    pub source_ip: String,
    pub target_ip: String,
    pub protocol: String,
    pub total_bytes: u64,
    pub total_packets: u64,
    pub packets_per_sec: f64,
    pub first_seen: u64,
    pub last_seen: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotFrame {
    pub frame_type: String, // "snapshot"
    pub timestamp: u64,
    pub nodes: Vec<NodeData>,
    pub edges: Vec<EdgeData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaFrame {
    pub frame_type: String, // "delta"
    pub timestamp: u64,
    pub seq: u64,
    pub nodes_added: Vec<NodeData>,
    pub nodes_updated: Vec<NodeUpdate>,
    pub nodes_removed: Vec<String>,
    pub edges_added: Vec<EdgeData>,
    pub edges_updated: Vec<EdgeUpdate>,
    pub edges_removed: Vec<String>,
    pub packet_events: Vec<PacketEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeUpdate {
    pub id: String,
    pub total_bytes_in: Option<u64>,
    pub total_bytes_out: Option<u64>,
    pub total_packets_out: Option<u64>,
    pub packets_per_sec: Option<f64>,
    pub last_seen: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeUpdate {
    pub id: String,
    pub total_bytes: Option<u64>,
    pub total_packets: Option<u64>,
    pub packets_per_sec: Option<f64>,
    pub last_seen: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketEvent {
    pub source_ip: String,
    pub target_ip: String,
    pub protocol: String,
    pub bytes: u64,
}
