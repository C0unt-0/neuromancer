// ═══════════════════════════════════════════════════
//  CYBERDECK — Client-Side Type Definitions
//  Derived from spec.md §4.3.2
// ═══════════════════════════════════════════════════

// ── Graph Types (from capture agent) ──

export interface ClientNode {
  id: string;
  ip: string;
  hostname: string | null;
  nodeType: "local" | "gateway" | "dns" | "cdn" | "remote" | "target" | "router";
  position: Vec3 | null;
  totalBytesIn: number;
  totalBytesOut: number;
  activeConnections: number;
  packetsPerSec: number;
  firstSeen: number;
  lastSeen: number;
  staleness: number;
  // Cyberdeck additions:
  os?: string;
  ports?: PortInfo[];
  vulnCount?: number;
  scanned: boolean;
  scanJobs: string[];
}

export interface ClientEdge {
  id: string;
  sourceIp: string;
  targetIp: string;
  protocol: string;
  totalBytes: number;
  totalPackets: number;
  packetsPerSec: number;
  firstSeen: number;
  lastSeen: number;
}

export interface Vec3 {
  x: number;
  y: number;
  z: number;
}

export interface PortInfo {
  port: number;
  protocol: "tcp" | "udp";
  state: "open" | "filtered" | "closed";
  service?: string;
  version?: string;
  vulnSeverity?: VulnSeverity;
  vulnId?: string;
}

export type VulnSeverity = "critical" | "high" | "medium" | "low" | "info";

// ── Sub-Node Types (visual scan results) ──

export interface SubNode {
  id: string;
  parentIp: string;
  type: "port" | "service" | "vulnerability" | "directory";
  label: string;
  severity?: VulnSeverity;
  orbitAngle: number;
  orbitRadius: number;
}

// ── Tool/Job Types (from orchestrator) ──

export interface ToolJob {
  id: string;
  toolId: string;
  params: Record<string, unknown>;
  targetIp: string;
  status: "queued" | "running" | "completed" | "failed" | "cancelled" | "timeout";
  startedAt?: number;
  completedAt?: number;
  exitCode?: number;
  rawOutput: string;
  structuredResults?: unknown;
  error?: string;
}

export interface Discovery {
  type: "port" | "service" | "vulnerability" | "directory" | "credential" | "domain";
  port?: number;
  protocol?: "tcp" | "udp";
  state?: "open" | "filtered" | "closed";
  serviceName?: string;
  serviceVersion?: string;
  vulnId?: string;
  vulnSeverity?: VulnSeverity;
  vulnTitle?: string;
  path?: string;
  statusCode?: number;
  raw?: string;
}

// ── AI Types ──

export interface AIMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  timestamp: number;
  toolCalls?: { toolName: string; jobId: string; status: string }[];
}

export interface PendingApproval {
  id: string;
  toolName: string;
  target: string;
  command: string;
  riskLevel: string;
  requestedAt: number;
}

// ── Scope Types ──

export interface ScopeConfig {
  allowedCidrs: string[];
  allowedDomains?: string[];
  blockedCidrs?: string[];
  restrictions?: {
    allowActiveScanning: boolean;
    allowExploitation: boolean;
    allowBruteForce: boolean;
    maxConcurrentScans?: number;
  };
}

// ── Wire Protocol Types (Capture Agent → Client) ──

export interface SnapshotFrame {
  frame_type: "snapshot";
  timestamp: number;
  nodes: CaptureNodeData[];
  edges: CaptureEdgeData[];
}

export interface DeltaFrame {
  frame_type: "delta";
  seq: number;
  timestamp: number;
  nodes_added: CaptureNodeData[];
  nodes_updated: CaptureNodeData[];
  nodes_removed: string[];
  edges_added: CaptureEdgeData[];
  edges_updated: CaptureEdgeData[];
  edges_removed: string[];
  packet_events: PacketEvent[];
}

export interface CaptureNodeData {
  id: string;
  ip: string;
  hostname: string | null;
  node_type: string;
  is_local: boolean;
  total_bytes_in: number;
  total_bytes_out: number;
  active_connections: number;
  packets_per_sec: number;
  first_seen: number;
  last_seen: number;
  geo?: GeoInfo | null;
}

export interface CaptureEdgeData {
  id: string;
  source_ip: string;
  target_ip: string;
  protocol: string;
  total_bytes: number;
  total_packets: number;
  packets_per_sec: number;
  first_seen: number;
  last_seen: number;
}

export interface PacketEvent {
  src_ip: string;
  dst_ip: string;
  protocol: string;
  bytes: number;
}

export interface GeoInfo {
  country?: string | null;
  city?: string | null;
  latitude?: number | null;
  longitude?: number | null;
  asn?: string | null;
  as_org?: string | null;
}

// ── Wire Protocol Types (Orchestrator ↔ Client) ──

export interface WsMessage {
  type: string;
  payload: Record<string, unknown>;
  requestId?: string;
}

// ── UI State Types ──

export type ActiveTab = "terminal" | "traffic" | "packets";
