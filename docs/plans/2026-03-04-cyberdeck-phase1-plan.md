# CYBERDECK Phase 1 MVP — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a browser-based spatial cybersecurity OS with live 3D network visualization, tool execution in Docker containers, AI-powered chat operator, and cyberpunk aesthetics.

**Architecture:** Three-layer system — Rust capture agent (packet capture → graph → WebSocket), Node.js orchestrator (tool execution + AI + scope), TypeScript web client (Three.js 3D scene + xterm.js terminal + Zustand state). Layers communicate via WebSocket (MsgPack on port 9900, JSON on port 9901).

**Tech Stack:** Rust (pcap, tokio, petgraph), Node.js (Fastify, dockerode, node-pty, @anthropic-ai/sdk), TypeScript (Three.js, xterm.js, Zustand, Vite)

**Design doc:** `docs/plans/2026-03-04-cyberdeck-phase1-design.md`
**Full spec:** `spec.md` (reference for all type definitions, wire protocols, tool schemas)
**UI reference:** `mock.html` (working Three.js prototype with all CSS)

---

## Week 1: Capture Agent + Orchestrator Shell

### Task 1.1: Monorepo Scaffolding

**Files:**
- Create: `package.json`
- Create: `pnpm-workspace.yaml`
- Create: `.gitignore`
- Create: `.npmrc`

**Step 1: Create root package.json**

```json
{
  "name": "cyberdeck",
  "private": true,
  "scripts": {
    "dev:orchestrator": "pnpm --filter cyberdeck-orchestrator dev",
    "dev:web": "pnpm --filter cyberdeck-web dev",
    "build": "pnpm -r build",
    "test": "pnpm -r test"
  }
}
```

**Step 2: Create pnpm-workspace.yaml**

```yaml
packages:
  - "orchestrator"
  - "web-client"
```

**Step 3: Create .gitignore**

```
node_modules/
dist/
target/
*.log
.env
.DS_Store
audit.jsonl
```

**Step 4: Create .npmrc**

```
shamefully-hoist=false
strict-peer-dependencies=false
```

**Step 5: Commit**

```bash
git add package.json pnpm-workspace.yaml .gitignore .npmrc
git commit -m "chore: scaffold pnpm monorepo"
```

---

### Task 1.2: Capture Agent — Cargo Project Setup

**Files:**
- Create: `capture-agent/Cargo.toml`
- Create: `capture-agent/src/main.rs`
- Create: `capture-agent/src/config.rs`

**Step 1: Create Cargo.toml**

```toml
[package]
name = "cyberspace-capture"
version = "0.1.0"
edition = "2021"

[dependencies]
pcap = { version = "2", features = ["capture-stream"] }
etherparse = "0.16"
tokio = { version = "1", features = ["full"] }
tokio-tungstenite = "0.24"
petgraph = "0.7"
rmp-serde = "1"
serde = { version = "1", features = ["derive"] }
maxminddb = "0.24"
clap = { version = "4", features = ["derive"] }
tracing = "0.1"
tracing-subscriber = "0.3"
trust-dns-resolver = "0.23"

[dev-dependencies]
tokio-test = "0.4"
```

**Step 2: Create minimal main.rs**

```rust
use clap::Parser;

mod config;

#[derive(Parser, Debug)]
#[command(name = "cyberspace-capture", about = "Cyberdeck network capture agent")]
struct Args {
    /// Network interface to capture on
    #[arg(short, long, default_value = "en0")]
    interface: String,

    /// WebSocket server port
    #[arg(short, long, default_value_t = 9900)]
    port: u16,

    /// BPF filter expression
    #[arg(short, long, default_value = "")]
    filter: String,
}

fn main() {
    let args = Args::parse();
    tracing_subscriber::fmt::init();
    tracing::info!("Cyberdeck capture agent starting on interface {}", args.interface);

    // Check for root/elevated privileges
    if !nix_check_root() {
        tracing::error!("Capture agent requires root privileges. Run with sudo.");
        std::process::exit(1);
    }

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        tracing::info!("WebSocket server will listen on port {}", args.port);
        // Modules will be wired here in subsequent tasks
    });
}

fn nix_check_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}
```

Add `libc` to Cargo.toml dependencies:
```toml
libc = "0.2"
```

**Step 3: Create config.rs**

```rust
/// Capture agent configuration constants
pub const WS_PORT: u16 = 9900;
pub const DELTA_INTERVAL_MS: u64 = 500;
pub const FLOW_TIMEOUT_SEC: u64 = 30;
pub const MAX_FLOWS: usize = 100_000;
pub const MAX_NODES: usize = 10_000;
pub const CAPTURE_BUFFER_SIZE: i32 = 16 * 1024 * 1024; // 16MB
pub const SNAPLEN: i32 = 96; // Enough for headers
```

**Step 4: Verify it compiles**

Run: `cd capture-agent && cargo check`
Expected: Compiles without errors (won't run without root)

**Step 5: Commit**

```bash
git add capture-agent/
git commit -m "feat(capture): scaffold Rust capture agent with CLI args"
```

---

### Task 1.3: Capture Agent — Protocol Types

**Files:**
- Create: `capture-agent/src/protocol.rs`

**Step 1: Create protocol.rs with all wire types**

Implement all types from spec §7.1 — SnapshotFrame, DeltaFrame, NodeData, EdgeData, NodeUpdate, EdgeUpdate. All derive `Serialize, Deserialize` for MessagePack.

Reference: `spec.md` lines 1736-1742 for type overview. The full types are:

```rust
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeData {
    pub id: String,
    pub ip: String,
    pub hostname: Option<String>,
    pub node_type: NodeType,
    pub is_local: bool,
    pub total_bytes_in: u64,
    pub total_bytes_out: u64,
    pub active_connections: u32,
    pub packets_per_sec: f64,
    pub first_seen: u64,
    pub last_seen: u64,
    pub geo: Option<GeoInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub active_connections: Option<u32>,
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
```

**Step 2: Add module to main.rs**

Add `mod protocol;` to main.rs.

**Step 3: Verify it compiles**

Run: `cd capture-agent && cargo check`
Expected: Compiles

**Step 4: Commit**

```bash
git add capture-agent/src/protocol.rs capture-agent/src/main.rs
git commit -m "feat(capture): add wire protocol types (MsgPack serializable)"
```

---

### Task 1.4: Capture Agent — Parser Module

**Files:**
- Create: `capture-agent/src/parser.rs`
- Create: `capture-agent/tests/parser_test.rs`

**Step 1: Write parser tests**

```rust
// capture-agent/tests/parser_test.rs
use cyberspace_capture::parser::{parse_packet, ParsedPacket};

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
    assert_eq!(pkt.protocol, "DNS"); // Port 53 → classified as DNS
    assert_eq!(pkt.dst_port, Some(53));
}

#[test]
fn test_parse_malformed_packet() {
    let garbage = vec![0x00, 0x01, 0x02];
    assert!(parse_packet(&garbage).is_none());
}
```

**Step 2: Run tests to verify they fail**

Run: `cd capture-agent && cargo test`
Expected: FAIL — `parser` module doesn't exist

**Step 3: Implement parser.rs**

```rust
use etherparse::SlicedPacket;

#[derive(Debug, Clone)]
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

    let (src_ip, dst_ip) = match packet.ip? {
        etherparse::InternetSlice::Ipv4(ipv4, _) => (
            format!("{}", ipv4.source_addr()),
            format!("{}", ipv4.destination_addr()),
        ),
        etherparse::InternetSlice::Ipv6(ipv6, _) => (
            format!("{}", ipv6.source_addr()),
            format!("{}", ipv6.destination_addr()),
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
        _ => (None, None, "OTHER"),
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
            80 | 8080 | 8443 => return "HTTP".to_string(),
            443 => return "TLS".to_string(),
            // QUIC uses UDP on 443
            _ => {}
        }
    }
    // UDP on 443 is QUIC
    if base == "UDP" {
        if ports.iter().flatten().any(|p| *p == 443) {
            return "QUIC".to_string();
        }
    }
    base.to_string()
}
```

Make parser module public — add `pub mod parser;` to `main.rs`, and create `capture-agent/src/lib.rs`:
```rust
pub mod parser;
pub mod protocol;
pub mod config;
```

**Step 4: Run tests to verify they pass**

Run: `cd capture-agent && cargo test`
Expected: All 3 tests pass

**Step 5: Commit**

```bash
git add capture-agent/
git commit -m "feat(capture): add packet parser with protocol classification"
```

---

### Task 1.5: Capture Agent — Flow Aggregator

**Files:**
- Create: `capture-agent/src/flow.rs`
- Create: `capture-agent/tests/flow_test.rs`

**Step 1: Write flow aggregator tests**

```rust
// capture-agent/tests/flow_test.rs
use cyberspace_capture::flow::{FlowAggregator, FlowKey};
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
```

**Step 2: Run tests to verify they fail**

Run: `cd capture-agent && cargo test`
Expected: FAIL — `flow` module doesn't exist

**Step 3: Implement flow.rs**

```rust
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::parser::ParsedPacket;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct FlowKey {
    pub lower_ip: String,
    pub upper_ip: String,
    pub protocol: String,
}

impl FlowKey {
    pub fn from_packet(pkt: &ParsedPacket) -> Self {
        let (lower, upper) = if pkt.src_ip <= pkt.dst_ip {
            (pkt.src_ip.clone(), pkt.dst_ip.clone())
        } else {
            (pkt.dst_ip.clone(), pkt.src_ip.clone())
        };
        FlowKey {
            lower_ip: lower,
            upper_ip: upper,
            protocol: pkt.protocol.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FlowState {
    pub key: FlowKey,
    pub total_bytes: u64,
    pub total_packets: u64,
    pub bytes_forward: u64,  // lower_ip → upper_ip
    pub bytes_reverse: u64,  // upper_ip → lower_ip
    pub first_seen: u64,
    pub last_seen: u64,
}

pub struct FlowAggregator {
    flows: HashMap<FlowKey, FlowState>,
}

impl FlowAggregator {
    pub fn new() -> Self {
        FlowAggregator {
            flows: HashMap::new(),
        }
    }

    pub fn process_packet(&mut self, pkt: &ParsedPacket) {
        let key = FlowKey::from_packet(pkt);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let flow = self.flows.entry(key.clone()).or_insert_with(|| FlowState {
            key: key.clone(),
            total_bytes: 0,
            total_packets: 0,
            bytes_forward: 0,
            bytes_reverse: 0,
            first_seen: now,
            last_seen: now,
        });

        flow.total_bytes += pkt.bytes;
        flow.total_packets += 1;
        flow.last_seen = now;

        // Track directionality
        if pkt.src_ip <= pkt.dst_ip {
            flow.bytes_forward += pkt.bytes;
        } else {
            flow.bytes_reverse += pkt.bytes;
        }
    }

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    pub fn get_flows(&self) -> &HashMap<FlowKey, FlowState> {
        &self.flows
    }

    /// Remove flows older than timeout_sec
    pub fn evict_stale(&mut self, timeout_ms: u64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        self.flows.retain(|_, flow| now - flow.last_seen < timeout_ms);
    }
}
```

Add `pub mod flow;` to `lib.rs`.

**Step 4: Run tests**

Run: `cd capture-agent && cargo test`
Expected: All tests pass

**Step 5: Commit**

```bash
git add capture-agent/
git commit -m "feat(capture): add flow aggregator with bidirectional normalization"
```

---

### Task 1.6: Capture Agent — Graph Builder

**Files:**
- Create: `capture-agent/src/graph.rs`
- Create: `capture-agent/tests/graph_test.rs`

**Step 1: Write graph builder tests**

```rust
// capture-agent/tests/graph_test.rs
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
```

**Step 2: Run tests to verify failure**

Run: `cd capture-agent && cargo test`
Expected: FAIL

**Step 3: Implement graph.rs**

Uses petgraph for the graph structure. Tracks "seen" state to compute deltas.

```rust
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::flow::{FlowAggregator, FlowKey};
use crate::parser::ParsedPacket;
use crate::protocol::*;

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
        GraphBuilder {
            flow_agg: FlowAggregator::new(),
            known_nodes: HashMap::new(),
            known_edges: HashMap::new(),
            dirty_nodes: HashSet::new(),
            dirty_edges: HashSet::new(),
            new_nodes: HashSet::new(),
            new_edges: HashSet::new(),
            seq: 0,
        }
    }

    pub fn process_packet(&mut self, pkt: &ParsedPacket) {
        self.flow_agg.process_packet(pkt);
        let now = now_ms();

        // Ensure source node exists
        self.ensure_node(&pkt.src_ip, now);
        self.ensure_node(&pkt.dst_ip, now);

        // Update node stats
        if let Some(node) = self.known_nodes.get_mut(&pkt.src_ip) {
            node.total_bytes_out += pkt.bytes;
            node.active_connections += 1; // Simplified
            node.last_seen = now;
            self.dirty_nodes.insert(pkt.src_ip.clone());
        }
        if let Some(node) = self.known_nodes.get_mut(&pkt.dst_ip) {
            node.total_bytes_in += pkt.bytes;
            node.last_seen = now;
            self.dirty_nodes.insert(pkt.dst_ip.clone());
        }

        // Ensure edge exists
        let edge_id = make_edge_id(&pkt.src_ip, &pkt.dst_ip, &pkt.protocol);
        if !self.known_edges.contains_key(&edge_id) {
            let edge = EdgeData {
                id: edge_id.clone(),
                source_ip: pkt.src_ip.clone(),
                target_ip: pkt.dst_ip.clone(),
                protocol: pkt.protocol.clone(),
                total_bytes: pkt.bytes,
                total_packets: 1,
                packets_per_sec: 0.0,
                first_seen: now,
                last_seen: now,
            };
            self.known_edges.insert(edge_id.clone(), edge);
            self.new_edges.insert(edge_id);
        } else {
            let edge = self.known_edges.get_mut(&edge_id).unwrap();
            edge.total_bytes += pkt.bytes;
            edge.total_packets += 1;
            edge.last_seen = now;
            self.dirty_edges.insert(edge_id);
        }
    }

    fn ensure_node(&mut self, ip: &str, now: u64) {
        if !self.known_nodes.contains_key(ip) {
            let node = NodeData {
                id: ip.to_string(),
                ip: ip.to_string(),
                hostname: None,
                node_type: classify_node_type(ip),
                is_local: is_rfc1918(ip),
                total_bytes_in: 0,
                total_bytes_out: 0,
                active_connections: 0,
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
                    active_connections: Some(n.active_connections),
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
        .unwrap()
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
    ip.starts_with("10.")
        || ip.starts_with("192.168.")
        || (ip.starts_with("172.") && {
            ip.split('.').nth(1)
                .and_then(|s| s.parse::<u8>().ok())
                .map(|n| (16..=31).contains(&n))
                .unwrap_or(false)
        })
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
```

Add `pub mod graph;` to `lib.rs`.

**Step 4: Run tests**

Run: `cd capture-agent && cargo test`
Expected: All tests pass

**Step 5: Commit**

```bash
git add capture-agent/
git commit -m "feat(capture): add graph builder with snapshot/delta computation"
```

---

### Task 1.7: Capture Agent — Capture Module + WebSocket Server

**Files:**
- Create: `capture-agent/src/capture.rs`
- Create: `capture-agent/src/websocket.rs`
- Modify: `capture-agent/src/main.rs`

**Step 1: Implement capture.rs**

```rust
use pcap::{Capture, Device};
use tokio::sync::mpsc;
use crate::config;
use crate::parser::{parse_packet, ParsedPacket};

pub async fn start_capture(
    interface: &str,
    filter: &str,
    tx: mpsc::Sender<ParsedPacket>,
) -> Result<(), Box<dyn std::error::Error>> {
    let device = Device::list()?
        .into_iter()
        .find(|d| d.name == interface)
        .ok_or_else(|| format!("Interface '{}' not found", interface))?;

    let mut cap = Capture::from_device(device)?
        .promisc(true)
        .snaplen(config::SNAPLEN)
        .buffer_size(config::CAPTURE_BUFFER_SIZE)
        .immediate_mode(true)
        .open()?;

    if !filter.is_empty() {
        cap.filter(filter, true)?;
    }

    tracing::info!("Capture started on {}", interface);

    // Run in blocking thread since pcap is synchronous
    tokio::task::spawn_blocking(move || {
        while let Ok(packet) = cap.next_packet() {
            if let Some(parsed) = parse_packet(packet.data) {
                if tx.blocking_send(parsed).is_err() {
                    break; // Receiver dropped
                }
            }
        }
    });

    Ok(())
}
```

**Step 2: Implement websocket.rs**

```rust
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{interval, Duration};
use tokio_tungstenite::accept_async;
use tokio::net::TcpListener;
use futures_util::SinkExt;
use crate::graph::GraphBuilder;
use crate::config;

pub async fn start_ws_server(
    port: u16,
    graph: Arc<RwLock<GraphBuilder>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    tracing::info!("WebSocket server listening on port {}", port);

    loop {
        let (stream, addr) = listener.accept().await?;
        tracing::info!("New WebSocket connection from {}", addr);
        let graph = graph.clone();

        tokio::spawn(async move {
            let ws_stream = match accept_async(stream).await {
                Ok(ws) => ws,
                Err(e) => {
                    tracing::error!("WebSocket handshake failed: {}", e);
                    return;
                }
            };

            let (mut write, _read) = ws_stream.split();

            // Send initial snapshot
            {
                let mut g = graph.write().await;
                let snapshot = g.snapshot();
                let data = rmp_serde::to_vec(&snapshot).unwrap();
                if write.send(tokio_tungstenite::tungstenite::Message::Binary(data)).await.is_err() {
                    return;
                }
            }

            // Send deltas at fixed interval
            let mut tick = interval(Duration::from_millis(config::DELTA_INTERVAL_MS));
            loop {
                tick.tick().await;
                let mut g = graph.write().await;
                let delta = g.delta();

                // Only send if there are actual changes
                if delta.nodes_added.is_empty()
                    && delta.nodes_updated.is_empty()
                    && delta.edges_added.is_empty()
                    && delta.edges_updated.is_empty()
                    && delta.packet_events.is_empty()
                {
                    continue;
                }

                let data = rmp_serde::to_vec(&delta).unwrap();
                if write.send(tokio_tungstenite::tungstenite::Message::Binary(data)).await.is_err() {
                    tracing::info!("Client {} disconnected", addr);
                    break;
                }
            }
        });
    }
}
```

Add `futures-util = "0.3"` to Cargo.toml dependencies.

**Step 3: Wire everything in main.rs**

```rust
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use clap::Parser;

mod config;
mod capture;
mod parser;
mod flow;
mod graph;
mod protocol;
mod websocket;

#[derive(Parser, Debug)]
#[command(name = "cyberspace-capture", about = "Cyberdeck network capture agent")]
struct Args {
    #[arg(short, long, default_value = "en0")]
    interface: String,
    #[arg(short, long, default_value_t = 9900)]
    port: u16,
    #[arg(short, long, default_value = "")]
    filter: String,
}

fn main() {
    let args = Args::parse();
    tracing_subscriber::fmt::init();
    tracing::info!("Cyberdeck capture agent v0.1.0");

    if !nix_check_root() {
        tracing::error!("Requires root privileges. Run with sudo.");
        std::process::exit(1);
    }

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async move {
        let graph = Arc::new(RwLock::new(graph::GraphBuilder::new()));
        let (tx, mut rx) = mpsc::channel::<parser::ParsedPacket>(10_000);

        // Start packet capture
        let iface = args.interface.clone();
        let filter = args.filter.clone();
        capture::start_capture(&iface, &filter, tx)
            .await
            .expect("Failed to start capture");

        // Process packets → graph
        let graph_writer = graph.clone();
        tokio::spawn(async move {
            while let Some(pkt) = rx.recv().await {
                let mut g = graph_writer.write().await;
                g.process_packet(&pkt);
            }
        });

        // Start WebSocket server (blocks)
        websocket::start_ws_server(args.port, graph)
            .await
            .expect("WebSocket server failed");
    });
}

fn nix_check_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}
```

**Step 4: Verify it compiles**

Run: `cd capture-agent && cargo check`
Expected: Compiles (can't run without root + live interface)

**Step 5: Commit**

```bash
git add capture-agent/
git commit -m "feat(capture): add capture module and WebSocket server"
```

---

### Task 1.8: Capture Agent — Enrichment Module

**Files:**
- Create: `capture-agent/src/enrichment.rs`

**Step 1: Implement enrichment.rs**

Basic enrichment: reverse DNS and RFC1918 classification. GeoIP (MaxMind) added as optional — skip if no database file present.

```rust
use std::net::IpAddr;
use std::str::FromStr;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::*;
use crate::protocol::GeoInfo;

pub struct Enricher {
    resolver: TokioAsyncResolver,
    geoip: Option<maxminddb::Reader<Vec<u8>>>,
}

impl Enricher {
    pub async fn new(geoip_path: Option<&str>) -> Self {
        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );

        let geoip = geoip_path.and_then(|path| {
            maxminddb::Reader::open_readfile(path).ok()
        });

        if geoip.is_some() {
            tracing::info!("GeoIP database loaded");
        }

        Enricher { resolver, geoip }
    }

    pub async fn reverse_dns(&self, ip: &str) -> Option<String> {
        let addr: IpAddr = IpAddr::from_str(ip).ok()?;
        let result = self.resolver.reverse_lookup(addr).await.ok()?;
        result.iter().next().map(|name| name.to_string().trim_end_matches('.').to_string())
    }

    pub fn geoip_lookup(&self, ip: &str) -> Option<GeoInfo> {
        let reader = self.geoip.as_ref()?;
        let addr: IpAddr = IpAddr::from_str(ip).ok()?;

        // Use the city database for full info
        let city: maxminddb::geoip2::City = reader.lookup(addr).ok()?;

        Some(GeoInfo {
            country: city.country
                .and_then(|c| c.iso_code.map(|s| s.to_string())),
            city: city.city
                .and_then(|c| c.names)
                .and_then(|n| n.get("en").map(|s| s.to_string())),
            latitude: city.location.as_ref().and_then(|l| l.latitude),
            longitude: city.location.as_ref().and_then(|l| l.longitude),
            asn: None, // Requires separate ASN database
            as_org: None,
        })
    }
}
```

Add `pub mod enrichment;` to `lib.rs`.

**Step 2: Verify it compiles**

Run: `cd capture-agent && cargo check`
Expected: Compiles

**Step 3: Commit**

```bash
git add capture-agent/
git commit -m "feat(capture): add enrichment module (reverse DNS, GeoIP)"
```

---

### Task 1.9: Orchestrator — Project Setup

**Files:**
- Create: `orchestrator/package.json`
- Create: `orchestrator/tsconfig.json`
- Create: `orchestrator/src/index.ts`
- Create: `orchestrator/src/config.ts`

**Step 1: Create package.json**

Use the exact dependencies from spec §4.2.1.

```json
{
  "name": "cyberdeck-orchestrator",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "tsx watch src/index.ts",
    "build": "tsc",
    "start": "node dist/index.js",
    "test": "vitest"
  },
  "dependencies": {
    "fastify": "^5.0.0",
    "@fastify/websocket": "^11.0.0",
    "@fastify/cors": "^10.0.0",
    "dockerode": "^4.0.4",
    "node-pty": "^1.0.0",
    "@anthropic-ai/sdk": "^0.39.0",
    "@msgpack/msgpack": "^3.0.0",
    "zod": "^3.23.0",
    "pino": "^9.0.0",
    "nanoid": "^5.0.0"
  },
  "devDependencies": {
    "typescript": "^5.7.0",
    "tsx": "^4.19.0",
    "@types/dockerode": "^3.3.31",
    "@types/node": "^22.0.0",
    "vitest": "^2.1.0"
  }
}
```

**Step 2: Create tsconfig.json**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "outDir": "dist",
    "rootDir": "src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true
  },
  "include": ["src"],
  "exclude": ["node_modules", "dist"]
}
```

**Step 3: Create config.ts**

Copy exactly from spec §4.2.2.

```typescript
export const CONFIG = {
  PORT: 9901,
  HOST: "0.0.0.0",
  DOCKER_SOCKET: "/var/run/docker.sock",
  TOOL_IMAGE: "cyberdeck-tools:latest",
  CONTAINER_MEMORY_LIMIT: 2 * 1024 * 1024 * 1024,
  CONTAINER_CPU_LIMIT: 2,
  CONTAINER_TIMEOUT_SEC: 300,
  CONTAINER_PIDS_LIMIT: 256,
  ANTHROPIC_MODEL: "claude-sonnet-4-5-20250929",
  ANTHROPIC_MAX_TOKENS: 4096,
  LLM_RATE_LIMIT_RPM: 30,
  DEFAULT_SCOPE: ["10.10.11.0/24", "192.168.0.0/16"],
  SCOPE_FILE: "./scope.yaml",
  AUDIT_LOG_PATH: "./audit.jsonl",
  AUDIT_RETENTION_DAYS: 365,
  MAX_CONCURRENT_TOOLS: 5,
  MAX_JOBS_PER_MINUTE: 20,
  MAX_OUTPUT_BUFFER_MB: 50,
} as const;
```

**Step 4: Create minimal index.ts**

```typescript
import Fastify from "fastify";
import fastifyWebsocket from "@fastify/websocket";
import fastifyCors from "@fastify/cors";
import { CONFIG } from "./config.js";

const server = Fastify({
  logger: {
    transport: {
      target: "pino-pretty",
      options: { translateTime: "HH:MM:ss Z", ignore: "pid,hostname" },
    },
  },
});

async function start() {
  await server.register(fastifyCors, { origin: true });
  await server.register(fastifyWebsocket);

  server.get("/health", async () => ({ status: "ok", service: "cyberdeck-orchestrator" }));

  server.register(async function (fastify) {
    fastify.get("/ws", { websocket: true }, (socket, req) => {
      server.log.info("WebSocket client connected");
      socket.on("message", (msg: Buffer) => {
        // Message routing will be added in Task 2.5
        server.log.info(`Received: ${msg.toString().slice(0, 100)}`);
      });
      socket.on("close", () => {
        server.log.info("WebSocket client disconnected");
      });
    });
  });

  await server.listen({ port: CONFIG.PORT, host: CONFIG.HOST });
  server.log.info(`Cyberdeck orchestrator listening on port ${CONFIG.PORT}`);
}

start().catch((err) => {
  console.error("Failed to start:", err);
  process.exit(1);
});
```

**Step 5: Install dependencies and verify**

Run: `cd orchestrator && pnpm install && pnpm exec tsc --noEmit`
Expected: Compiles without errors

**Step 6: Commit**

```bash
git add orchestrator/ pnpm-lock.yaml
git commit -m "feat(orchestrator): scaffold Fastify server with WebSocket"
```

---

### Task 1.10: Orchestrator — Scope Validator

**Files:**
- Create: `orchestrator/src/scope/scope-validator.ts`
- Create: `orchestrator/src/scope/scope-config.ts`
- Create: `orchestrator/tests/scope-validator.test.ts`

**Step 1: Write tests**

```typescript
// orchestrator/tests/scope-validator.test.ts
import { describe, it, expect } from "vitest";
import { ScopeValidator } from "../src/scope/scope-validator.js";

describe("ScopeValidator", () => {
  const validator = new ScopeValidator({
    allowedCidrs: ["10.10.11.0/24", "192.168.1.0/24"],
    blockedCidrs: ["127.0.0.0/8", "169.254.0.0/16"],
  });

  it("allows IP within scope", async () => {
    const result = await validator.validate("10.10.11.234");
    expect(result.allowed).toBe(true);
    expect(result.matchedCidr).toBe("10.10.11.0/24");
  });

  it("rejects IP outside scope", async () => {
    const result = await validator.validate("8.8.8.8");
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("not within any allowed CIDR");
  });

  it("rejects blocked IPs even if in scope range", async () => {
    const v = new ScopeValidator({
      allowedCidrs: ["127.0.0.0/8"],
      blockedCidrs: ["127.0.0.0/8"],
    });
    const result = await v.validate("127.0.0.1");
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("blocked");
  });

  it("validates CIDR boundary correctly", async () => {
    const result1 = await validator.validate("10.10.11.0");
    expect(result1.allowed).toBe(true);
    const result2 = await validator.validate("10.10.11.255");
    expect(result2.allowed).toBe(true);
    const result3 = await validator.validate("10.10.12.1");
    expect(result3.allowed).toBe(false);
  });
});
```

**Step 2: Run tests to verify failure**

Run: `cd orchestrator && pnpm test`
Expected: FAIL — module doesn't exist

**Step 3: Implement scope-config.ts**

```typescript
import { z } from "zod";

export const ScopeConfigSchema = z.object({
  allowedCidrs: z.array(z.string()),
  allowedDomains: z.array(z.string()).optional(),
  blockedCidrs: z.array(z.string()).default([
    "127.0.0.0/8",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "255.255.255.255/32",
  ]),
  restrictions: z.object({
    allowActiveScanning: z.boolean().default(true),
    allowExploitation: z.boolean().default(false),
    allowBruteForce: z.boolean().default(false),
    maxConcurrentScans: z.number().default(5),
  }).optional(),
});

export type ScopeConfig = z.infer<typeof ScopeConfigSchema>;
```

**Step 4: Implement scope-validator.ts**

```typescript
import { ScopeConfig } from "./scope-config.js";

export interface ValidationResult {
  allowed: boolean;
  reason?: string;
  resolvedIp?: string;
  matchedCidr?: string;
}

export class ScopeValidator {
  private allowedCidrs: CidrRange[];
  private blockedCidrs: CidrRange[];

  constructor(config: Pick<ScopeConfig, "allowedCidrs" | "blockedCidrs">) {
    this.allowedCidrs = config.allowedCidrs.map(parseCidr);
    this.blockedCidrs = (config.blockedCidrs ?? []).map(parseCidr);
  }

  async validate(target: string): Promise<ValidationResult> {
    const ip = target; // TODO: DNS resolution for hostnames

    // Check blocklist first
    for (const cidr of this.blockedCidrs) {
      if (ipInCidr(ip, cidr)) {
        return { allowed: false, reason: `Target ${ip} is in blocked range ${cidr.original}` };
      }
    }

    // Check allowlist
    for (const cidr of this.allowedCidrs) {
      if (ipInCidr(ip, cidr)) {
        return { allowed: true, matchedCidr: cidr.original };
      }
    }

    return { allowed: false, reason: `Target ${ip} is not within any allowed CIDR range` };
  }

  isToolAllowed(riskLevel: "passive" | "active" | "invasive"): boolean {
    // Passive tools always allowed, active/invasive checked against restrictions
    return riskLevel === "passive";
  }
}

interface CidrRange {
  original: string;
  networkInt: number;
  maskInt: number;
}

function parseCidr(cidr: string): CidrRange {
  const [ip, bits] = cidr.split("/");
  const mask = bits ? parseInt(bits, 10) : 32;
  return {
    original: cidr,
    networkInt: ipToInt(ip),
    maskInt: mask === 0 ? 0 : (~0 << (32 - mask)) >>> 0,
  };
}

function ipToInt(ip: string): number {
  const parts = ip.split(".").map(Number);
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function ipInCidr(ip: string, cidr: CidrRange): boolean {
  const ipInt = ipToInt(ip);
  return (ipInt & cidr.maskInt) === (cidr.networkInt & cidr.maskInt);
}
```

**Step 5: Run tests**

Run: `cd orchestrator && pnpm test`
Expected: All tests pass

**Step 6: Commit**

```bash
git add orchestrator/
git commit -m "feat(orchestrator): add scope validator with CIDR matching"
```

---

### Task 1.11: Orchestrator — Audit Logger

**Files:**
- Create: `orchestrator/src/scope/audit-logger.ts`
- Create: `orchestrator/tests/audit-logger.test.ts`

**Step 1: Write tests**

```typescript
// orchestrator/tests/audit-logger.test.ts
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { AuditLogger } from "../src/scope/audit-logger.js";
import { existsSync, unlinkSync } from "fs";

const TEST_LOG = "/tmp/cyberdeck-test-audit.jsonl";

describe("AuditLogger", () => {
  let logger: AuditLogger;

  beforeEach(() => {
    logger = new AuditLogger(TEST_LOG);
  });

  afterEach(() => {
    if (existsSync(TEST_LOG)) unlinkSync(TEST_LOG);
  });

  it("writes entries to JSONL file", async () => {
    await logger.log({
      sessionId: "test-session",
      action: "tool_execute",
      tool: "nmap-scan",
      target: "10.10.11.234",
    });

    const entries = await logger.export("2020-01-01", "2030-01-01");
    expect(entries.length).toBe(1);
    expect(entries[0].action).toBe("tool_execute");
    expect(entries[0].tool).toBe("nmap-scan");
  });

  it("maintains hash chain integrity", async () => {
    await logger.log({ sessionId: "s1", action: "session_start" });
    await logger.log({ sessionId: "s1", action: "tool_execute", tool: "nmap-scan" });
    await logger.log({ sessionId: "s1", action: "session_end" });

    const result = await logger.verify();
    expect(result.valid).toBe(true);
  });

  it("includes timestamp and id", async () => {
    await logger.log({ sessionId: "s1", action: "scope_check" });

    const entries = await logger.export("2020-01-01", "2030-01-01");
    expect(entries[0].id).toBeDefined();
    expect(entries[0].timestamp).toBeDefined();
    expect(entries[0].prevHash).toBeDefined();
  });
});
```

**Step 2: Run tests to verify failure**

Run: `cd orchestrator && pnpm test`
Expected: FAIL

**Step 3: Implement audit-logger.ts**

```typescript
import { appendFile, readFile, writeFile } from "fs/promises";
import { existsSync } from "fs";
import { createHash } from "crypto";
import { nanoid } from "nanoid";

export interface AuditEntry {
  id: string;
  timestamp: string;
  sessionId: string;
  action: string;
  tool?: string;
  target?: string;
  params?: Record<string, unknown>;
  scopeResult?: "allowed" | "denied";
  result?: "success" | "failure" | "timeout" | "cancelled";
  details?: string;
  prevHash: string;
}

export class AuditLogger {
  private logPath: string;
  private lastHash: string = "GENESIS";

  constructor(logPath: string) {
    this.logPath = logPath;
  }

  async log(entry: Omit<AuditEntry, "id" | "timestamp" | "prevHash">): Promise<void> {
    const full: AuditEntry = {
      ...entry,
      id: nanoid(),
      timestamp: new Date().toISOString(),
      prevHash: this.lastHash,
    };

    const line = JSON.stringify(full);
    this.lastHash = createHash("sha256").update(line).digest("hex");

    await appendFile(this.logPath, line + "\n");
  }

  async verify(): Promise<{ valid: boolean; brokenAt?: number }> {
    if (!existsSync(this.logPath)) return { valid: true };

    const content = await readFile(this.logPath, "utf-8");
    const lines = content.trim().split("\n").filter(Boolean);

    let expectedPrevHash = "GENESIS";
    for (let i = 0; i < lines.length; i++) {
      const entry: AuditEntry = JSON.parse(lines[i]);
      if (entry.prevHash !== expectedPrevHash) {
        return { valid: false, brokenAt: i };
      }
      expectedPrevHash = createHash("sha256").update(lines[i]).digest("hex");
    }

    return { valid: true };
  }

  async export(startDate: string, endDate: string): Promise<AuditEntry[]> {
    if (!existsSync(this.logPath)) return [];

    const content = await readFile(this.logPath, "utf-8");
    const lines = content.trim().split("\n").filter(Boolean);

    return lines
      .map((line) => JSON.parse(line) as AuditEntry)
      .filter((entry) => {
        const ts = new Date(entry.timestamp).getTime();
        return ts >= new Date(startDate).getTime() && ts <= new Date(endDate).getTime();
      });
  }
}
```

**Step 4: Run tests**

Run: `cd orchestrator && pnpm test`
Expected: All tests pass

**Step 5: Commit**

```bash
git add orchestrator/
git commit -m "feat(orchestrator): add audit logger with SHA-256 hash chain"
```

---

### Task 1.12: Orchestrator — Docker Tool Image

**Files:**
- Create: `orchestrator/docker/Dockerfile.tools`
- Create: `orchestrator/docker/iptables-scope.sh`

**Step 1: Create Dockerfile.tools**

Copy from spec §4.2.3:

```dockerfile
FROM kalilinux/kali-rolling

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    nmap \
    nuclei \
    gobuster \
    nikto \
    sqlmap \
    ffuf \
    hydra \
    seclists \
    whois \
    dnsutils \
    traceroute \
    netcat-openbsd \
    curl \
    wget \
    jq \
    python3 \
    python3-pip \
    python3-requests \
    iptables \
    && rm -rf /var/lib/apt/lists/*

RUN nuclei -update-templates 2>/dev/null || true

RUN useradd -m -s /bin/bash operator
WORKDIR /home/operator

CMD ["sleep", "infinity"]
```

**Step 2: Create iptables-scope.sh**

```bash
#!/bin/bash
# Scope enforcement via iptables inside container network namespace
# Usage: iptables-scope.sh <allowed_cidr1> [allowed_cidr2] ...

set -euo pipefail

# Flush existing rules
iptables -F OUTPUT

# Allow loopback
iptables -A OUTPUT -o lo -j ACCEPT

# Allow DNS (needed for resolution)
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

# Allow established connections
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow specified CIDRs
for cidr in "$@"; do
    iptables -A OUTPUT -d "$cidr" -j ACCEPT
done

# Drop everything else
iptables -A OUTPUT -j DROP

echo "Scope enforced: allowed CIDRs: $*"
```

**Step 3: Commit**

```bash
chmod +x orchestrator/docker/iptables-scope.sh
git add orchestrator/docker/
git commit -m "feat(orchestrator): add Docker tool image and scope enforcement script"
```

---

## Week 2: Tool Execution Engine

### Task 2.1: Orchestrator — Tool Registry

**Files:**
- Create: `orchestrator/src/tools/tool-registry.ts`

**Step 1: Implement tool-registry.ts**

Copy the full tool definitions from spec §4.2.4. This includes all 7 tools: nmap-scan, nuclei-scan, gobuster-dir, whois-lookup, dig-dns, traceroute, custom-script. Each with Zod param schemas, buildCommand functions, capabilities, risk levels.

Reference: `spec.md` lines 506-711

**Step 2: Verify it compiles**

Run: `cd orchestrator && pnpm exec tsc --noEmit`

**Step 3: Commit**

```bash
git add orchestrator/src/tools/tool-registry.ts
git commit -m "feat(orchestrator): add tool registry with 7 security tool definitions"
```

---

### Task 2.2: Orchestrator — Tool Runner

**Files:**
- Create: `orchestrator/src/tools/tool-runner.ts`
- Create: `orchestrator/tests/tool-runner.test.ts`

**Step 1: Write tests**

Test that ToolRunner creates Docker containers, streams output, and enforces timeouts. Tests require Docker to be running — use `describe.skipIf(!process.env.DOCKER_HOST)` or a mock.

```typescript
// orchestrator/tests/tool-runner.test.ts
import { describe, it, expect, vi } from "vitest";
import { ToolRunner } from "../src/tools/tool-runner.js";

// Unit test: verify job creation without Docker
describe("ToolRunner", () => {
  it("creates a job with correct initial state", () => {
    const runner = new ToolRunner();
    // runTool would need Docker, so test job creation logic
    const job = runner.createJob("nmap-scan", { target: "10.10.11.234" });
    expect(job.toolId).toBe("nmap-scan");
    expect(job.status).toBe("queued");
    expect(job.id).toBeDefined();
  });

  it("tracks active jobs", () => {
    const runner = new ToolRunner();
    const job = runner.createJob("nmap-scan", { target: "10.10.11.234" });
    expect(runner.getJob(job.id)).toBeDefined();
    expect(runner.listJobs().length).toBe(1);
  });
});
```

**Step 2: Run tests to verify failure, then implement**

Implement tool-runner.ts following spec §4.2.5 — Docker container lifecycle with dockerode, event emitter for job:started/output/structured/completed/error, timeout enforcement, scope iptables injection.

Reference: `spec.md` lines 714-791

**Step 3: Run tests, commit**

```bash
git add orchestrator/src/tools/ orchestrator/tests/
git commit -m "feat(orchestrator): add tool runner with Docker container management"
```

---

### Task 2.3: Orchestrator — Result Parser

**Files:**
- Create: `orchestrator/src/tools/result-parser.ts`
- Create: `orchestrator/tests/result-parser.test.ts`

**Step 1: Write tests with sample nmap XML and nuclei JSON**

```typescript
// orchestrator/tests/result-parser.test.ts
import { describe, it, expect } from "vitest";
import { parseNmapXml, parseNucleiJson } from "../src/tools/result-parser.js";

const SAMPLE_NMAP_XML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.10.11.234" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.41"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="Apache httpd" version="2.4.41"/>
      </port>
    </ports>
  </host>
</nmaprun>`;

describe("parseNmapXml", () => {
  it("extracts open ports with services", () => {
    const result = parseNmapXml(SAMPLE_NMAP_XML, "10.10.11.234");
    expect(result.discoveries.length).toBe(3);
    expect(result.discoveries[0].type).toBe("port");
    expect(result.discoveries[0].port).toBe(22);
    expect(result.discoveries[0].serviceName).toBe("ssh");
    expect(result.discoveries[0].serviceVersion).toBe("OpenSSH 8.2p1");
  });
});

const SAMPLE_NUCLEI_JSONL = [
  '{"template-id":"apache-detect","info":{"severity":"info","name":"Apache Detection"},"host":"http://10.10.11.234","matched-at":"http://10.10.11.234"}',
  '{"template-id":"CVE-2021-41773","info":{"severity":"critical","name":"Apache Path Traversal"},"host":"http://10.10.11.234","matched-at":"http://10.10.11.234/icons/.%2e/%2e%2e/etc/passwd"}',
].join("\n");

describe("parseNucleiJson", () => {
  it("extracts vulnerabilities with severity", () => {
    const result = parseNucleiJson(SAMPLE_NUCLEI_JSONL, "10.10.11.234");
    expect(result.discoveries.length).toBe(2);

    const critical = result.discoveries.find(d => d.vulnSeverity === "critical");
    expect(critical).toBeDefined();
    expect(critical!.vulnId).toBe("CVE-2021-41773");
  });
});
```

**Step 2: Implement result-parser.ts**

Parse nmap XML (use a simple regex/string parser — no heavy XML library needed for Phase 1) and nuclei JSONL.

Reference: `spec.md` lines 794-851

**Step 3: Run tests, commit**

```bash
git add orchestrator/src/tools/result-parser.ts orchestrator/tests/result-parser.test.ts
git commit -m "feat(orchestrator): add result parsers for nmap XML and nuclei JSON"
```

---

### Task 2.4: Orchestrator — Job Manager

**Files:**
- Create: `orchestrator/src/tools/job-manager.ts`

**Step 1: Implement job manager**

Manages job queue, concurrency limits (MAX_CONCURRENT_TOOLS=5), rate limiting (MAX_JOBS_PER_MINUTE=20), status tracking, and cancellation. Wraps ToolRunner.

**Step 2: Commit**

```bash
git add orchestrator/src/tools/job-manager.ts
git commit -m "feat(orchestrator): add job manager with concurrency and rate limiting"
```

---

### Task 2.5: Orchestrator — WebSocket Handler

**Files:**
- Create: `orchestrator/src/api/ws-handler.ts`
- Modify: `orchestrator/src/index.ts`

**Step 1: Implement ws-handler.ts**

Routes all message types from spec §7.2: tool.execute, tool.cancel, tool.list, ai.message, ai.approve, ai.reject, scope.get, scope.validate.

Reference: `spec.md` lines 1156-1191 for message type definitions, lines 1746-1909 for wire protocol.

**Step 2: Wire into index.ts**

Replace the placeholder WebSocket handler with the full ws-handler.

**Step 3: Commit**

```bash
git add orchestrator/src/api/ws-handler.ts orchestrator/src/index.ts
git commit -m "feat(orchestrator): add full WebSocket message routing"
```

---

### Task 2.6: Orchestrator — PTY Bridge

**Files:**
- Create: `orchestrator/src/tools/pty-bridge.ts`

**Step 1: Implement PTY bridge**

node-pty creates a pseudo-terminal for each tool container. Streams raw terminal output (including ANSI escape codes) over WebSocket as `tool.output` messages.

**Step 2: Commit**

```bash
git add orchestrator/src/tools/pty-bridge.ts
git commit -m "feat(orchestrator): add PTY bridge for terminal streaming"
```

---

## Week 3: Web Client Core

### Task 3.1: Web Client — Project Setup

**Files:**
- Create: `web-client/package.json`
- Create: `web-client/tsconfig.json`
- Create: `web-client/vite.config.ts`
- Create: `web-client/index.html`
- Create: `web-client/src/main.ts`
- Create: `web-client/src/types.ts`
- Create: `web-client/src/config.ts`

**Step 1: Create package.json**

From spec §4.3.1, plus xterm.js dependencies:

```json
{
  "name": "cyberdeck-web",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview",
    "test": "vitest"
  },
  "dependencies": {
    "three": "^0.171.0",
    "@msgpack/msgpack": "^3.0.0",
    "@xterm/xterm": "^5.5.0",
    "@xterm/addon-webgl": "^0.18.0",
    "@xterm/addon-fit": "^0.10.0",
    "stats-gl": "^2.4.2",
    "zustand": "^5.0.0"
  },
  "devDependencies": {
    "typescript": "^5.7.0",
    "vite": "^6.0.0",
    "@types/three": "^0.171.0",
    "vitest": "^2.1.0"
  }
}
```

**Step 2: Create index.html**

Copy the full HTML structure from `mock.html` (lines 1282-1567, the `<body>` content), BUT replace the inline `<script type="module">` with:
```html
<script type="module" src="/src/main.ts"></script>
```

Copy all CSS from `mock.html` (lines 8-1280) into `web-client/src/styles.css` and link it.

**Step 3: Create types.ts**

All shared types from spec §4.3.2 (ClientNode, PortInfo, SubNode, AIMessage, PendingApproval, etc.) and §7.2 (WsMessage types).

Reference: `spec.md` lines 1228-1348

**Step 4: Create config.ts**

```typescript
export const CONFIG = {
  CAPTURE_WS_URL: "ws://localhost:9900",
  ORCHESTRATOR_WS_URL: "ws://localhost:9901/ws",
  MOCK_MODE: new URLSearchParams(window.location.search).has("mock"),
} as const;
```

**Step 5: Create minimal main.ts**

```typescript
import "./styles.css";
import { CONFIG } from "./config.js";

console.log("CYBERDECK initializing...", CONFIG.MOCK_MODE ? "(mock mode)" : "(live)");
```

**Step 6: Install, verify**

Run: `cd web-client && pnpm install && pnpm dev`
Expected: Vite serves the page, cyberpunk UI layout visible

**Step 7: Commit**

```bash
git add web-client/
git commit -m "feat(web): scaffold Vite project with cyberpunk UI layout"
```

---

### Task 3.2: Web Client — State Manager (Zustand)

**Files:**
- Create: `web-client/src/network/state-manager.ts`

**Step 1: Implement Zustand store**

All 5 slices from spec §4.3.2: graph state, tool state, AI state, UI state, scope state. With all actions: applySnapshot, applyDelta, addJob, updateJob, addDiscoveries, selectNode, addAIMessage, toggleProtocol.

Reference: `spec.md` lines 1228-1349

**Step 2: Commit**

```bash
git add web-client/src/network/state-manager.ts
git commit -m "feat(web): add Zustand state manager with all slices"
```

---

### Task 3.3: Web Client — Mock Data

**Files:**
- Create: `web-client/src/network/mock-data.ts`

**Step 1: Implement mock data generator**

Port the simulated hosts, edges, and traffic from `mock.html` (lines 1588-1651). Add periodic simulated delta frames with new connections and packet events. Add simulated scan results (ports with vulnerabilities) triggered by mock scan actions.

**Step 2: Commit**

```bash
git add web-client/src/network/mock-data.ts
git commit -m "feat(web): add mock data generator for offline development"
```

---

### Task 3.4: Web Client — Three.js Scene Core

**Files:**
- Create: `web-client/src/scene/scene-manager.ts`
- Create: `web-client/src/scene/grid.ts`
- Create: `web-client/src/scene/postprocessing.ts`

**Step 1: Implement scene-manager.ts**

Port the Three.js setup from `mock.html` (lines 1655-1710): WebGLRenderer, PerspectiveCamera, OrbitControls, fog, lights. Initialize the render loop with `requestAnimationFrame`.

Reference: `mock.html` lines 1655-1710 for renderer/camera/controls setup.

**Step 2: Implement grid.ts**

Two-layer Tron grid from `mock.html` (lines 1694-1703).

**Step 3: Implement postprocessing.ts**

EffectComposer with RenderPass, UnrealBloomPass, OutputPass from `mock.html` (lines 1682-1691).

**Step 4: Commit**

```bash
git add web-client/src/scene/
git commit -m "feat(web): add Three.js scene with grid and bloom postprocessing"
```

---

### Task 3.5: Web Client — Node Renderer

**Files:**
- Create: `web-client/src/scene/node-renderer.ts`

**Step 1: Implement node-renderer.ts**

Port node creation from `mock.html` (lines 1712-1852): geometry selection by type (IcosahedronGeometry for targets, TetrahedronGeometry for DNS, etc.), MeshStandardMaterial with emissive glow, glow ring child, selection ring child. Add/remove/update nodes from the state manager.

Reference: `mock.html` functions `getNodeGeo()`, `getNodeColor()`, `addNode()`

**Step 2: Commit**

```bash
git add web-client/src/scene/node-renderer.ts
git commit -m "feat(web): add node renderer with type-specific geometry and glow"
```

---

### Task 3.6: Web Client — Edge Renderer + Particles

**Files:**
- Create: `web-client/src/scene/edge-renderer.ts`
- Create: `web-client/src/scene/particle-system.ts`

**Step 1: Implement edge-renderer.ts**

Port from `mock.html` (lines 1854-1874): LineBasicMaterial with protocol colors, low opacity.

**Step 2: Implement particle-system.ts**

Port from `mock.html` (lines 1876-1896): particles travel along edges with interpolation, auto-cleanup when t > 1.

**Step 3: Commit**

```bash
git add web-client/src/scene/edge-renderer.ts web-client/src/scene/particle-system.ts
git commit -m "feat(web): add edge renderer and packet flow particle system"
```

---

### Task 3.7: Web Client — Force Layout

**Files:**
- Create: `web-client/src/scene/force-layout.ts`
- Create: `web-client/tests/force-layout.test.ts`

**Step 1: Write tests**

```typescript
import { describe, it, expect } from "vitest";
import { ForceLayout } from "../src/scene/force-layout.js";

describe("ForceLayout", () => {
  it("separates overlapping nodes", () => {
    const layout = new ForceLayout();
    layout.addNode("a", { x: 0, y: 0, z: 0 });
    layout.addNode("b", { x: 0, y: 0, z: 0 });

    // Run a few iterations
    for (let i = 0; i < 50; i++) layout.tick(0.016);

    const posA = layout.getPosition("a");
    const posB = layout.getPosition("b");
    const dist = Math.sqrt(
      (posA.x - posB.x) ** 2 + (posA.y - posB.y) ** 2 + (posA.z - posB.z) ** 2
    );
    expect(dist).toBeGreaterThan(1); // Nodes should have separated
  });

  it("pulls linked nodes together", () => {
    const layout = new ForceLayout();
    layout.addNode("a", { x: -100, y: 0, z: 0 });
    layout.addNode("b", { x: 100, y: 0, z: 0 });
    layout.addEdge("a", "b");

    for (let i = 0; i < 100; i++) layout.tick(0.016);

    const posA = layout.getPosition("a");
    const posB = layout.getPosition("b");
    const dist = Math.sqrt(
      (posA.x - posB.x) ** 2 + (posA.y - posB.y) ** 2 + (posA.z - posB.z) ** 2
    );
    expect(dist).toBeLessThan(200); // Should be closer than initial 200
  });
});
```

**Step 2: Implement force-layout.ts**

Simple Velocity Verlet integration: charge repulsion (all pairs), link attraction (connected pairs), centering force, velocity damping.

**Step 3: Run tests, commit**

```bash
git add web-client/src/scene/force-layout.ts web-client/tests/
git commit -m "feat(web): add custom force-directed layout engine"
```

---

### Task 3.8: Web Client — Sub-Node Renderer

**Files:**
- Create: `web-client/src/scene/subnode-renderer.ts`

**Step 1: Implement subnode-renderer.ts**

Port from `mock.html` (lines 1898-1969) and spec §4.3.3: orbiting spheres with severity-based colors/sizes, elastic creation animation, pulse animation for critical vulns, thin connecting lines to parent.

Reference: `spec.md` lines 1351-1403, `mock.html` function `addSubNodes()`

**Step 2: Commit**

```bash
git add web-client/src/scene/subnode-renderer.ts
git commit -m "feat(web): add sub-node renderer with orbiting scan results"
```

---

### Task 3.9: Web Client — WebSocket Clients

**Files:**
- Create: `web-client/src/network/capture-client.ts`
- Create: `web-client/src/network/orchestrator-client.ts`

**Step 1: Implement capture-client.ts**

WebSocket to port 9900, MessagePack decode, reconnection with exponential backoff. Applies SnapshotFrame and DeltaFrame to state manager.

**Step 2: Implement orchestrator-client.ts**

WebSocket to port 9901, JSON messages. Sends tool.execute, ai.message, etc. Receives tool.output, ai.chunk, etc. and routes to state manager.

**Step 3: Commit**

```bash
git add web-client/src/network/
git commit -m "feat(web): add WebSocket clients for capture agent and orchestrator"
```

---

### Task 3.10: Web Client — Wire Main Entry Point

**Files:**
- Modify: `web-client/src/main.ts`

**Step 1: Wire everything together**

Initialize state manager, scene manager, mock data (if `?mock=true`), WebSocket clients (if live), start render loop.

**Step 2: Verify**

Run: `cd web-client && pnpm dev` then open `http://localhost:5173?mock=true`
Expected: 3D cyberpunk graph with nodes, edges, particles, bloom

**Step 3: Commit**

```bash
git add web-client/src/main.ts
git commit -m "feat(web): wire main entry point with scene and state initialization"
```

---

## Week 4: Interaction + Terminal

### Task 4.1: Selection (Raycasting)
- File: `web-client/src/interaction/selection.ts`
- Port from `mock.html` lines 1988-2060
- Raycaster for click (select node) and right-click (open radial menu)

### Task 4.2: Radial Context Menu
- File: `web-client/src/interaction/radial-menu.ts`
- Port from `mock.html` lines 1030-1096 (CSS) + JS logic
- HTML overlay with 6 circular action buttons
- Reference: spec §4.3.4

### Task 4.3: Camera Controller
- File: `web-client/src/interaction/camera-controller.ts`
- OrbitControls wrapper + fly-to-node animation (smooth camera transition)

### Task 4.4: Keyboard Shortcuts
- File: `web-client/src/interaction/keyboard.ts`
- Escape (deselect), Cmd+K (command palette), arrow navigation

### Task 4.5: Terminal Manager (xterm.js)
- File: `web-client/src/terminal/terminal-manager.ts`
- xterm.js with WebGL addon, cyberpunk color theme from spec §4.3.5
- Fit addon for auto-resize

### Task 4.6: Command Handler
- File: `web-client/src/terminal/command-handler.ts`
- Routes: help, scope, targets, clear (local) vs nmap, nuclei, etc. (→ orchestrator)
- Command history with up/down arrows

### Task 4.7: Tool Dispatcher
- File: `web-client/src/tools/tool-dispatcher.ts`
- Sends tool.execute messages to orchestrator, listens for job events

### Task 4.8: Tool Definitions (Client-Side)
- File: `web-client/src/tools/tool-definitions.ts`
- Client-side metadata matching orchestrator's tool-registry (icons, colors, labels)

### Task 4.9: Result Visualizer
- File: `web-client/src/tools/result-visualizer.ts`
- Maps Discovery[] from tool.structured events → sub-node renderer

### Task 4.10: Integration Test
- Verify: right-click node → radial menu → "Scan" → terminal shows nmap output → sub-nodes appear

**Commit after each task.**

---

## Week 5: AI Integration + Command Palette

### Task 5.1: AI Operator (Claude API)
- File: `orchestrator/src/llm/ai-operator.ts`
- Claude API with streaming, tool_use, conversation management
- Reference: spec §4.2.7

### Task 5.2: Tool Schemas for Claude
- File: `orchestrator/src/llm/tool-schemas.ts`
- Map tool-registry definitions to Claude's tool format
- Reference: spec §4.2.7 lines 896-970

### Task 5.3: Context Builder
- File: `orchestrator/src/llm/context-builder.ts`
- Builds system prompt with current scope, selected node, recent jobs

### Task 5.4: Safety Gate
- File: `orchestrator/src/llm/safety-gate.ts`
- Invasive tools require human approval before execution

### Task 5.5: Chat Manager
- File: `web-client/src/ai/chat-manager.ts`
- Sends ai.message, receives ai.chunk stream, manages conversation state

### Task 5.6: Chat Renderer
- File: `web-client/src/ai/chat-renderer.ts`
- Streaming text render, tool call blocks, approval UI, code blocks
- Reference: spec §4.3.7

### Task 5.7: Command Palette
- File: `web-client/src/ui/command-palette.ts`
- Cmd+K overlay with fuzzy substring search
- Sources: tools, targets, UI actions
- Reference: spec §4.3.6, mock.html lines 1098-1206

### Task 5.8: Integration Test
- AI chat → Claude responds → tool executes → results in chat + terminal + 3D

**Commit after each task.**

---

## Week 6: Polish + UI Panels

### Task 6.1: Top Bar
- File: `web-client/src/ui/panels/top-bar.ts`
- Logo, scope badge, stats (nodes/edges/pps/bw), running tools indicator
- Reference: mock.html lines 1284-1335

### Task 6.2: Left Panel
- File: `web-client/src/ui/panels/left-panel.ts`
- Tool categories, protocol filters, active targets list
- Reference: mock.html lines 1337-1384

### Task 6.3: Right Panel (Detail Card)
- File: `web-client/src/ui/panels/right-panel.ts`
- Node detail: icon, name, metrics grid (ports/services/vulns/bandwidth), action buttons
- Reference: mock.html lines 1402-1473

### Task 6.4: Bottom Panel
- File: `web-client/src/ui/panels/bottom-panel.ts`
- Tab switching: terminal, traffic, packets

### Task 6.5: Toast Notifications
- File: `web-client/src/ui/toast.ts`
- Auto-dismiss, severity-colored left border
- Reference: mock.html lines 1241-1279

### Task 6.6: HUD Overlays
- File: `web-client/src/ui/hud.ts`
- Crosshair, corner brackets, zoom indicator, "CYBERDECK // TOPOLOGY MATRIX" label

### Task 6.7: Utility Modules
- Files: `web-client/src/utils/color.ts`, `format.ts`, `performance.ts`
- Protocol → color, severity → color, byte formatting, FPS counter

### Task 6.8: Loading Screen + Consent Flow
- First-run consent screen per spec §16.4
- Acknowledge authorization, accept audit policy, enter name

### Task 6.9: Reconnection Handling
- Exponential backoff in both WebSocket clients
- Toast on disconnect/reconnect

### Task 6.10: Performance Profiling
- Verify 60fps with 200 nodes / 500 edges / 50 sub-nodes
- Use stats-gl for real-time monitoring

### Task 6.11: Final Integration Test
- Full end-to-end: capture agent → 3D graph → right-click → scan → terminal → sub-nodes → AI chat
- All Phase 1 Definition of Done items verified

**Commit after each task. Create PR when all DoD items pass.**
