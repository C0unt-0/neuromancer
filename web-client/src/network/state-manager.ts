// ═══════════════════════════════════════════════════
//  CYBERDECK — Zustand State Manager
//  Single source of truth for all client-side state
//  Slices: graph, tool, AI, UI, scope
// ═══════════════════════════════════════════════════

import { create } from "zustand";
import type {
  ClientNode,
  ClientEdge,
  ToolJob,
  Discovery,
  SubNode,
  AIMessage,
  PendingApproval,
  ScopeConfig,
  SnapshotFrame,
  DeltaFrame,
  CaptureNodeData,
  CaptureEdgeData,
  ActiveTab,
  VulnSeverity,
} from "../types.js";

// ── Store Interface ──

export interface CyberdeckState {
  // ── Graph state (from capture agent) ──
  nodes: Map<string, ClientNode>;
  edges: Map<string, ClientEdge>;
  stats: {
    totalNodes: number;
    totalEdges: number;
    packetsPerSec: number;
    bytesPerSec: number;
    protocolCounts: Record<string, number>;
  };

  // ── Tool state (from orchestrator) ──
  jobs: Map<string, ToolJob>;
  activeJobCount: number;

  // ── Investigation graph (scan results) ──
  discoveries: Map<string, Discovery[]>;
  subNodes: Map<string, SubNode[]>;

  // ── AI state ──
  aiMessages: AIMessage[];
  pendingApprovals: PendingApproval[];

  // ── UI state ──
  selectedNodeId: string | null;
  hoveredNodeId: string | null;
  protocolFilters: Record<string, boolean>;
  activeTab: ActiveTab;
  commandPaletteOpen: boolean;
  radialMenuOpen: boolean;
  radialMenuPosition: { x: number; y: number } | null;

  // ── Scope ──
  scope: ScopeConfig | null;

  // ── Actions: Graph ──
  applySnapshot: (frame: SnapshotFrame) => void;
  applyDelta: (frame: DeltaFrame) => void;

  // ── Actions: Tools ──
  addJob: (job: ToolJob) => void;
  updateJob: (jobId: string, update: Partial<ToolJob>) => void;
  appendJobOutput: (jobId: string, chunk: string) => void;
  addDiscoveries: (targetIp: string, discoveries: Discovery[]) => void;

  // ── Actions: AI ──
  addAIMessage: (message: AIMessage) => void;
  addPendingApproval: (approval: PendingApproval) => void;
  removePendingApproval: (approvalId: string) => void;

  // ── Actions: UI ──
  selectNode: (nodeId: string | null) => void;
  hoverNode: (nodeId: string | null) => void;
  toggleProtocol: (protocol: string) => void;
  setActiveTab: (tab: ActiveTab) => void;
  toggleCommandPalette: () => void;
  openRadialMenu: (x: number, y: number) => void;
  closeRadialMenu: () => void;

  // ── Actions: Scope ──
  setScope: (scope: ScopeConfig) => void;
}

// ── Helper: Convert capture-agent wire format to client types ──

function captureNodeToClient(raw: CaptureNodeData): ClientNode {
  return {
    id: raw.id,
    ip: raw.ip,
    hostname: raw.hostname,
    nodeType: mapNodeType(raw.node_type, raw.is_local),
    position: null,
    totalBytesIn: raw.total_bytes_in,
    totalBytesOut: raw.total_bytes_out,
    activeConnections: raw.active_connections,
    packetsPerSec: raw.packets_per_sec,
    firstSeen: raw.first_seen,
    lastSeen: raw.last_seen,
    staleness: 0,
    scanned: false,
    scanJobs: [],
  };
}

function mapNodeType(
  rawType: string,
  isLocal: boolean,
): ClientNode["nodeType"] {
  const t = rawType.toLowerCase();
  if (t === "target") return "target";
  if (t === "router" || t === "gateway") return "router";
  if (t === "dns") return "dns";
  if (t === "cdn") return "cdn";
  if (isLocal) return "local";
  return "remote";
}

function captureEdgeToClient(raw: CaptureEdgeData): ClientEdge {
  return {
    id: raw.id,
    sourceIp: raw.source_ip,
    targetIp: raw.target_ip,
    protocol: raw.protocol,
    totalBytes: raw.total_bytes,
    totalPackets: raw.total_packets,
    packetsPerSec: raw.packets_per_sec,
    firstSeen: raw.first_seen,
    lastSeen: raw.last_seen,
  };
}

// ── Discovery → SubNode conversion ──

function discoveryToSubNodes(targetIp: string, discoveries: Discovery[]): SubNode[] {
  return discoveries
    .filter((d) => d.type === "port" || d.type === "vulnerability" || d.type === "directory")
    .map((d, i, arr) => {
      let label = "";
      if (d.type === "port" && d.port) {
        label = `${d.port}/${d.protocol ?? "tcp"}`;
        if (d.serviceName) label += ` ${d.serviceName}`;
      } else if (d.type === "vulnerability") {
        label = d.vulnId ?? d.vulnTitle ?? "vuln";
      } else if (d.type === "directory") {
        label = d.path ?? "/";
      }

      return {
        id: `${targetIp}-sub-${i}`,
        parentIp: targetIp,
        type: d.type as SubNode["type"],
        label,
        severity: d.vulnSeverity,
        orbitAngle: (i / arr.length) * Math.PI * 2,
        orbitRadius: 8,
      };
    });
}

// ── Create the Store ──

export const useCyberdeckStore = create<CyberdeckState>((set, get) => ({
  // ── Initial State ──
  nodes: new Map(),
  edges: new Map(),
  stats: {
    totalNodes: 0,
    totalEdges: 0,
    packetsPerSec: 0,
    bytesPerSec: 0,
    protocolCounts: {},
  },

  jobs: new Map(),
  activeJobCount: 0,

  discoveries: new Map(),
  subNodes: new Map(),

  aiMessages: [],
  pendingApprovals: [],

  selectedNodeId: null,
  hoveredNodeId: null,
  protocolFilters: {
    TCP: true,
    UDP: true,
    DNS: true,
    TLS: true,
    HTTP: true,
    QUIC: true,
  },
  activeTab: "terminal",
  commandPaletteOpen: false,
  radialMenuOpen: false,
  radialMenuPosition: null,

  scope: null,

  // ── Graph Actions ──

  applySnapshot: (frame) => {
    const nodes = new Map<string, ClientNode>();
    const edges = new Map<string, ClientEdge>();
    const protocolCounts: Record<string, number> = {};

    for (const raw of frame.nodes) {
      nodes.set(raw.id, captureNodeToClient(raw));
    }

    for (const raw of frame.edges) {
      edges.set(raw.id, captureEdgeToClient(raw));
      protocolCounts[raw.protocol] = (protocolCounts[raw.protocol] ?? 0) + 1;
    }

    set({
      nodes,
      edges,
      stats: {
        totalNodes: nodes.size,
        totalEdges: edges.size,
        packetsPerSec: 0,
        bytesPerSec: 0,
        protocolCounts,
      },
    });
  },

  applyDelta: (frame) => {
    const state = get();
    const nodes = new Map(state.nodes);
    const edges = new Map(state.edges);
    const protocolCounts = { ...state.stats.protocolCounts };
    let pps = 0;
    let bps = 0;

    // Add new nodes
    for (const raw of frame.nodes_added) {
      nodes.set(raw.id, captureNodeToClient(raw));
    }

    // Update existing nodes
    for (const raw of frame.nodes_updated) {
      const existing = nodes.get(raw.id);
      if (existing) {
        nodes.set(raw.id, {
          ...existing,
          totalBytesIn: raw.total_bytes_in,
          totalBytesOut: raw.total_bytes_out,
          activeConnections: raw.active_connections,
          packetsPerSec: raw.packets_per_sec,
          lastSeen: raw.last_seen,
          hostname: raw.hostname ?? existing.hostname,
        });
      }
    }

    // Remove nodes
    for (const id of frame.nodes_removed) {
      nodes.delete(id);
    }

    // Add new edges
    for (const raw of frame.edges_added) {
      edges.set(raw.id, captureEdgeToClient(raw));
      protocolCounts[raw.protocol] = (protocolCounts[raw.protocol] ?? 0) + 1;
    }

    // Update existing edges
    for (const raw of frame.edges_updated) {
      const existing = edges.get(raw.id);
      if (existing) {
        edges.set(raw.id, {
          ...existing,
          totalBytes: raw.total_bytes,
          totalPackets: raw.total_packets,
          packetsPerSec: raw.packets_per_sec,
          lastSeen: raw.last_seen,
        });
      }
    }

    // Remove edges
    for (const id of frame.edges_removed) {
      edges.delete(id);
    }

    // Process packet events for stats
    for (const pkt of frame.packet_events) {
      pps++;
      bps += pkt.bytes;
      protocolCounts[pkt.protocol] = (protocolCounts[pkt.protocol] ?? 0) + 1;
    }

    set({
      nodes,
      edges,
      stats: {
        totalNodes: nodes.size,
        totalEdges: edges.size,
        packetsPerSec: pps,
        bytesPerSec: bps,
        protocolCounts,
      },
    });
  },

  // ── Tool Actions ──

  addJob: (job) => {
    const jobs = new Map(get().jobs);
    jobs.set(job.id, job);
    set({
      jobs,
      activeJobCount: countActive(jobs),
    });
  },

  updateJob: (jobId, update) => {
    const jobs = new Map(get().jobs);
    const existing = jobs.get(jobId);
    if (existing) {
      jobs.set(jobId, { ...existing, ...update });
      set({
        jobs,
        activeJobCount: countActive(jobs),
      });
    }
  },

  appendJobOutput: (jobId, chunk) => {
    const jobs = new Map(get().jobs);
    const existing = jobs.get(jobId);
    if (existing) {
      jobs.set(jobId, {
        ...existing,
        rawOutput: existing.rawOutput + chunk,
      });
      set({ jobs });
    }
  },

  addDiscoveries: (targetIp, newDiscoveries) => {
    const discoveries = new Map(get().discoveries);
    const existing = discoveries.get(targetIp) ?? [];
    discoveries.set(targetIp, [...existing, ...newDiscoveries]);

    // Generate sub-nodes for the 3D scene
    const allDiscoveries = discoveries.get(targetIp)!;
    const subNodes = new Map(get().subNodes);
    subNodes.set(targetIp, discoveryToSubNodes(targetIp, allDiscoveries));

    // Update node's scan state
    const nodes = new Map(get().nodes);
    const node = nodes.get(targetIp);
    if (node) {
      const portDiscoveries = allDiscoveries.filter((d) => d.type === "port");
      const vulnDiscoveries = allDiscoveries.filter(
        (d) => d.vulnSeverity && d.vulnSeverity !== "info",
      );

      nodes.set(targetIp, {
        ...node,
        scanned: true,
        ports: portDiscoveries.map((d) => ({
          port: d.port!,
          protocol: (d.protocol ?? "tcp") as "tcp" | "udp",
          state: (d.state ?? "open") as "open" | "filtered" | "closed",
          service: d.serviceName,
          version: d.serviceVersion,
          vulnSeverity: d.vulnSeverity as VulnSeverity | undefined,
          vulnId: d.vulnId,
        })),
        vulnCount: vulnDiscoveries.length,
      });
    }

    set({ discoveries, subNodes, nodes });
  },

  // ── AI Actions ──

  addAIMessage: (message) => {
    set({ aiMessages: [...get().aiMessages, message] });
  },

  addPendingApproval: (approval) => {
    set({ pendingApprovals: [...get().pendingApprovals, approval] });
  },

  removePendingApproval: (approvalId) => {
    set({
      pendingApprovals: get().pendingApprovals.filter((a) => a.id !== approvalId),
    });
  },

  // ── UI Actions ──

  selectNode: (nodeId) => {
    set({
      selectedNodeId: nodeId,
      radialMenuOpen: false,
      radialMenuPosition: null,
    });
  },

  hoverNode: (nodeId) => {
    set({ hoveredNodeId: nodeId });
  },

  toggleProtocol: (protocol) => {
    const filters = { ...get().protocolFilters };
    filters[protocol] = !filters[protocol];
    set({ protocolFilters: filters });
  },

  setActiveTab: (tab) => {
    set({ activeTab: tab });
  },

  toggleCommandPalette: () => {
    set({ commandPaletteOpen: !get().commandPaletteOpen });
  },

  openRadialMenu: (x, y) => {
    set({
      radialMenuOpen: true,
      radialMenuPosition: { x, y },
    });
  },

  closeRadialMenu: () => {
    set({
      radialMenuOpen: false,
      radialMenuPosition: null,
    });
  },

  // ── Scope Actions ──

  setScope: (scope) => {
    set({ scope });
  },
}));

// ── Helpers ──

function countActive(jobs: Map<string, ToolJob>): number {
  let count = 0;
  for (const job of jobs.values()) {
    if (job.status === "running" || job.status === "queued") count++;
  }
  return count;
}
