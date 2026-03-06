// ═══════════════════════════════════════════════════
//  CYBERDECK — Mock Data Generator
//  Simulates capture agent + orchestrator for offline dev
//  Ported from mock.html with periodic delta frames
// ═══════════════════════════════════════════════════

import type {
  SnapshotFrame,
  DeltaFrame,
  CaptureNodeData,
  CaptureEdgeData,
  PacketEvent,
  Discovery,
} from "../types.js";
import { useCyberdeckStore } from "./state-manager.js";

// ── Simulated host data (matches mock.html) ──

interface MockHost {
  ip: string;
  name: string;
  type: string;
  os?: string;
}

const HOSTS: MockHost[] = [
  { ip: "10.10.11.234", name: "target-web01", type: "target", os: "Ubuntu 20.04" },
  { ip: "10.10.11.235", name: "target-db01", type: "target", os: "Debian 11" },
  { ip: "10.10.11.236", name: "target-mail01", type: "target", os: "CentOS 8" },
  { ip: "10.10.11.1", name: "gateway.lab", type: "router" },
  { ip: "10.10.11.10", name: "kali.attacker", type: "local", os: "Kali Linux" },
  { ip: "8.8.8.8", name: "dns.google", type: "dns" },
  { ip: "1.1.1.1", name: "one.one.one.one", type: "dns" },
  { ip: "162.159.135.232", name: "cloudflare.com", type: "cdn" },
  { ip: "142.250.80.46", name: "google.com", type: "remote" },
  { ip: "52.94.236.248", name: "aws.amazon.com", type: "remote" },
  { ip: "13.107.42.14", name: "microsoft.com", type: "remote" },
  { ip: "185.199.108.153", name: "github.com", type: "remote" },
  { ip: "34.107.243.93", name: "anthropic.com", type: "remote" },
  { ip: "151.101.1.140", name: "reddit.com", type: "remote" },
  { ip: "104.244.42.1", name: "x.com", type: "remote" },
];

const PROTOCOLS = ["TCP", "UDP", "DNS", "TLS", "HTTP", "QUIC"];

// ── Mock scan results ──

const MOCK_PORT_SCANS: Record<string, Discovery[]> = {
  "10.10.11.234": [
    { type: "port", port: 22, protocol: "tcp", state: "open", serviceName: "ssh", serviceVersion: "OpenSSH 8.2p1" },
    { type: "port", port: 80, protocol: "tcp", state: "open", serviceName: "http", serviceVersion: "Apache 2.4.41" },
    { type: "port", port: 443, protocol: "tcp", state: "open", serviceName: "https", serviceVersion: "Apache 2.4.41" },
    { type: "port", port: 3306, protocol: "tcp", state: "filtered", serviceName: "mysql" },
    { type: "port", port: 8080, protocol: "tcp", state: "open", serviceName: "http-proxy", serviceVersion: "Tomcat 9.0" },
  ],
  "10.10.11.235": [
    { type: "port", port: 22, protocol: "tcp", state: "open", serviceName: "ssh", serviceVersion: "OpenSSH 7.9p1" },
    { type: "port", port: 3306, protocol: "tcp", state: "open", serviceName: "mysql", serviceVersion: "MySQL 8.0.26" },
    { type: "port", port: 5432, protocol: "tcp", state: "open", serviceName: "postgresql", serviceVersion: "PostgreSQL 14.1" },
  ],
  "10.10.11.236": [
    { type: "port", port: 22, protocol: "tcp", state: "open", serviceName: "ssh" },
    { type: "port", port: 25, protocol: "tcp", state: "open", serviceName: "smtp", serviceVersion: "Postfix" },
    { type: "port", port: 110, protocol: "tcp", state: "open", serviceName: "pop3", serviceVersion: "Dovecot" },
    { type: "port", port: 143, protocol: "tcp", state: "open", serviceName: "imap", serviceVersion: "Dovecot" },
    { type: "port", port: 443, protocol: "tcp", state: "open", serviceName: "https" },
  ],
};

const MOCK_VULN_SCANS: Record<string, Discovery[]> = {
  "10.10.11.234": [
    { type: "vulnerability", vulnId: "CVE-2021-41773", vulnSeverity: "critical", vulnTitle: "Apache Path Traversal", port: 80, protocol: "tcp" },
    { type: "vulnerability", vulnId: "CVE-2023-25690", vulnSeverity: "high", vulnTitle: "Apache HTTP Request Smuggling", port: 80, protocol: "tcp" },
    { type: "vulnerability", vulnId: "CVE-2022-22720", vulnSeverity: "medium", vulnTitle: "HTTP Request Smuggling via mod_proxy", port: 443, protocol: "tcp" },
  ],
  "10.10.11.235": [
    { type: "vulnerability", vulnId: "CVE-2023-22809", vulnSeverity: "high", vulnTitle: "Sudo Bypass via sudoedit", serviceName: "sudo" },
  ],
};

// ── State ──

let seq = 0;
let intervalId: ReturnType<typeof setInterval> | null = null;

// ── Public API ──

/**
 * Generate a full snapshot frame with all mock hosts and initial edges.
 */
export function generateMockSnapshot(): SnapshotFrame {
  const now = Date.now();
  const nodes: CaptureNodeData[] = HOSTS.map((h) => ({
    id: h.ip,
    ip: h.ip,
    hostname: h.name,
    node_type: h.type,
    is_local: h.type === "local" || h.ip.startsWith("10.10.11."),
    total_bytes_in: Math.floor(Math.random() * 50000),
    total_bytes_out: Math.floor(Math.random() * 30000),
    active_connections: Math.floor(Math.random() * 10),
    packets_per_sec: Math.random() * 100,
    first_seen: now - 60000,
    last_seen: now,
    geo: null,
  }));

  // Generate random edges
  const edges: CaptureEdgeData[] = [];
  const edgeSet = new Set<string>();

  for (let i = 0; i < 25; i++) {
    const a = HOSTS[Math.floor(Math.random() * HOSTS.length)];
    const b = HOSTS[Math.floor(Math.random() * HOSTS.length)];
    if (a.ip === b.ip) continue;

    const proto = PROTOCOLS[Math.floor(Math.random() * PROTOCOLS.length)];
    const edgeId = `${a.ip}-${b.ip}-${proto}`;
    if (edgeSet.has(edgeId)) continue;
    edgeSet.add(edgeId);

    edges.push({
      id: edgeId,
      source_ip: a.ip,
      target_ip: b.ip,
      protocol: proto,
      total_bytes: Math.floor(Math.random() * 100000),
      total_packets: Math.floor(Math.random() * 500),
      packets_per_sec: Math.random() * 50,
      first_seen: now - 60000,
      last_seen: now,
    });
  }

  return {
    frame_type: "snapshot",
    timestamp: now,
    nodes,
    edges,
  };
}

/**
 * Generate a delta frame with simulated traffic.
 */
function generateMockDelta(): DeltaFrame {
  const now = Date.now();
  seq++;

  // Simulate 3–8 packet events per tick
  const packetCount = 3 + Math.floor(Math.random() * 6);
  const packetEvents: PacketEvent[] = [];

  for (let i = 0; i < packetCount; i++) {
    const src = HOSTS[Math.floor(Math.random() * HOSTS.length)];
    const dst = HOSTS[Math.floor(Math.random() * HOSTS.length)];
    if (src.ip === dst.ip) continue;

    packetEvents.push({
      src_ip: src.ip,
      dst_ip: dst.ip,
      protocol: PROTOCOLS[Math.floor(Math.random() * PROTOCOLS.length)],
      bytes: 64 + Math.floor(Math.random() * 1400),
    });
  }

  // Occasionally update node stats
  const updatedNodes: CaptureNodeData[] = [];
  if (Math.random() < 0.3) {
    const host = HOSTS[Math.floor(Math.random() * HOSTS.length)];
    updatedNodes.push({
      id: host.ip,
      ip: host.ip,
      hostname: host.name,
      node_type: host.type,
      is_local: host.type === "local" || host.ip.startsWith("10.10.11."),
      total_bytes_in: Math.floor(Math.random() * 100000),
      total_bytes_out: Math.floor(Math.random() * 60000),
      active_connections: Math.floor(Math.random() * 15),
      packets_per_sec: Math.random() * 200,
      first_seen: now - 120000,
      last_seen: now,
      geo: null,
    });
  }

  return {
    frame_type: "delta",
    seq,
    timestamp: now,
    nodes_added: [],
    nodes_updated: updatedNodes,
    nodes_removed: [],
    edges_added: [],
    edges_updated: [],
    edges_removed: [],
    packet_events: packetEvents,
  };
}

/**
 * Start the mock data feed — applies a snapshot then periodic deltas.
 */
export function startMockDataFeed(): void {
  const store = useCyberdeckStore.getState();

  // Apply initial snapshot
  const snapshot = generateMockSnapshot();
  store.applySnapshot(snapshot);

  // Set scope
  store.setScope({
    allowedCidrs: ["10.10.11.0/24", "192.168.1.0/24"],
    blockedCidrs: ["127.0.0.0/8"],
    restrictions: {
      allowActiveScanning: true,
      allowExploitation: false,
      allowBruteForce: false,
    },
  });

  // Start delta feed (simulates capture agent at ~250ms intervals)
  intervalId = setInterval(() => {
    const delta = generateMockDelta();
    useCyberdeckStore.getState().applyDelta(delta);
  }, 250);

  console.log("[mock] Data feed started: %d nodes, %d edges",
    snapshot.nodes.length, snapshot.edges.length);
}

/**
 * Stop the mock data feed.
 */
export function stopMockDataFeed(): void {
  if (intervalId) {
    clearInterval(intervalId);
    intervalId = null;
    console.log("[mock] Data feed stopped");
  }
}

/**
 * Simulate a port scan against a target (used by UI actions).
 */
export function mockPortScan(targetIp: string): void {
  const discoveries = MOCK_PORT_SCANS[targetIp];
  if (!discoveries) {
    console.warn(`[mock] No port scan data for ${targetIp}`);
    return;
  }

  // Simulate delay
  const store = useCyberdeckStore.getState();
  store.addJob({
    id: `mock-scan-${Date.now()}`,
    toolId: "nmap-scan",
    params: { target: targetIp },
    targetIp,
    status: "running",
    startedAt: Date.now(),
    rawOutput: "",
  });

  setTimeout(() => {
    store.addDiscoveries(targetIp, discoveries);
    console.log(`[mock] Port scan complete for ${targetIp}: ${discoveries.length} ports found`);
  }, 2000);
}

/**
 * Simulate a vulnerability scan against a target.
 */
export function mockVulnScan(targetIp: string): void {
  const discoveries = MOCK_VULN_SCANS[targetIp];
  if (!discoveries) {
    console.warn(`[mock] No vuln scan data for ${targetIp}`);
    return;
  }

  setTimeout(() => {
    useCyberdeckStore.getState().addDiscoveries(targetIp, discoveries);
    console.log(`[mock] Vuln scan complete for ${targetIp}: ${discoveries.length} vulns found`);
  }, 3000);
}
