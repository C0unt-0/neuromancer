# CYBERDECK — Product Specification v2.0

> A spatial cybersecurity operating system inspired by William Gibson's Neuromancer. Users jack into a 3D visualization of live network topology, interact with targets via radial context menus, execute security tools in sandboxed containers, generate custom scripts via LLM, and see results materialize as connected sub-nodes in cyberspace. Think "Claude Code meets Metasploit meets Gibson's cyberspace."

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture](#2-architecture)
3. [Repository Structure](#3-repository-structure)
4. [Phase 1 — "First Light" (MVP)](#4-phase-1--first-light-mvp)
5. [Phase 2 — "The Matrix Takes Shape"](#5-phase-2--the-matrix-takes-shape)
6. [Phase 3 — "Jacking In"](#6-phase-3--jacking-in)
7. [Data Models](#7-data-models)
8. [WebSocket Protocols](#8-websocket-protocols)
9. [Tool Execution Engine](#9-tool-execution-engine)
10. [LLM Integration (AI Operator)](#10-llm-integration-ai-operator)
11. [3D Scene Specification](#11-3d-scene-specification)
12. [Spatial Interaction System](#12-spatial-interaction-system)
13. [UI/UX Specification](#13-uiux-specification)
14. [Command Interface Layer](#14-command-interface-layer)
15. [Visual Design System](#15-visual-design-system)
16. [Safety & Scope Architecture](#16-safety--scope-architecture)
17. [Performance Budgets](#17-performance-budgets)
18. [Testing Strategy](#18-testing-strategy)
19. [Deployment](#19-deployment)
20. [Appendix A: Build Order](#appendix-a-build-order)
21. [Appendix B: Reference Commands](#appendix-b-reference-commands)

---

## 1. Project Overview

### 1.1 Vision

Build a browser-based spatial cybersecurity operating system that transforms network topology into navigable 3D cyberspace. Users don't browse web pages — they navigate a force-directed graph of live hosts, edges, and packet flows rendered with Gibson's neon-grid aesthetic. The cyberdeck extends passive visualization into **active interaction**: right-click a host to scan it, ask the AI operator to generate an extraction script, watch port sub-nodes materialize as results stream in, then drill deeper by running vulnerability checks — all without leaving 3D space.

The core interaction metaphor is from Neuromancer: a console cowboy jacks into cyberspace via a cyberdeck and interacts with ICE (Intrusion Countermeasures Electronics) protecting data. In this system, the "cyberdeck" is the browser interface, "cyberspace" is the 3D network topology, "ICE" is the visual representation of firewalls and security controls, and the operator navigates, probes, and interacts with elements in the space using tools and an LLM co-pilot.

### 1.2 Core Principles

- **Real data, not simulations.** Every node, edge, and particle represents actual network activity or topology.
- **Meaningful spatial mapping.** Position, color, size, and animation encode real information. No eye candy without analytical value.
- **Interact, don't just observe.** Every visible element is actionable. Right-click it. Scan it. Ask the AI about it.
- **Tools are first-class citizens.** Security tools execute in sandboxed containers with real-time output streaming to both terminal and 3D scene.
- **AI is the co-pilot.** The LLM can plan attacks, generate custom scripts, analyze results, and suggest next steps — but the human always approves destructive actions.
- **Scope is sacred.** No network traffic leaves the platform without passing scope validation. This is a legitimate security tool, not an attack platform.
- **Real-time.** End-to-end latency from packet capture to screen render under 100ms. Tool output streams as it's produced.
- **Browser-first.** Deploy as a URL. No installs except the local capture agent and Docker for tool execution.

### 1.3 Users

- **Primary:** Penetration testers conducting authorized security assessments who want a spatial interface for network exploration and tool orchestration.
- **Secondary:** Security analysts monitoring networks and investigating incidents with interactive visualization.
- **Tertiary:** Security educators and CTF players wanting an immersive environment for learning.

### 1.4 Core Capabilities

| Capability             | Description                                                                  | Phase |
| ---------------------- | ---------------------------------------------------------------------------- | ----- |
| Passive Visualization  | Live 3D force-directed graph of network traffic with cyberpunk aesthetics    | 1     |
| Node Interaction       | Click/right-click nodes to inspect, scan, enumerate                          | 1     |
| Terminal               | Browser-based terminal for direct command execution                          | 1     |
| AI Chat                | LLM-powered operator for natural language commands and script generation     | 1     |
| Tool Execution         | Run nmap, nuclei, gobuster, etc. in sandboxed Docker containers              | 1     |
| Radial Context Menu    | Right-click any node → circular menu with contextual security actions        | 1     |
| Command Palette        | `Cmd+K` fuzzy search across tools, targets, and actions                      | 1     |
| Sub-Node Visualization | Scan results spawn orbiting sub-nodes (ports, services, vulns) in 3D         | 1     |
| LLM Script Generation  | Ask AI to create custom Python/Bash scripts, review before execution         | 2     |
| Investigation Graph    | Maltego-style entity expansion — discovery adds nodes and edges to the graph | 2     |
| API Integrations       | Shodan, VirusTotal, Censys, SecurityTrails lookups from 3D context           | 2     |
| BGP/AS Topology        | Real-time BGP data from RIPE RIS Live overlaid on the graph                  | 2     |
| WebXR/VR               | Navigate cyberspace in VR with hand controllers                              | 3     |
| Autonomous Agent       | LLM plans and executes multi-step pentesting workflows with human gates      | 3     |
| Session Recording      | Record and replay investigation sessions with time-travel scrubbing          | 3     |

### 1.5 Non-Goals (for now)

- Mobile support (desktop browsers only)
- Multi-user real-time collaboration (single operator per instance)
- Production SIEM replacement (this is an interactive investigation tool)
- Automated exploitation without human approval
- Offensive operations against targets without explicit authorization

---

## 2. Architecture

### 2.1 High-Level System Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│  CAPTURE LAYER (Rust binary, runs with elevated privileges)          │
│                                                                      │
│  ┌──────────┐   ┌──────────────┐   ┌──────────────────┐             │
│  │  libpcap  │──▶│  etherparse  │──▶│ Flow Aggregator  │             │
│  │  capture  │   │  zero-copy   │   │ (HashMap<FlowKey, │            │
│  │           │   │  parse       │   │  FlowState>)     │             │
│  └──────────┘   └──────────────┘   └────────┬─────────┘             │
│                                              │                       │
│  ┌──────────────────────┐   ┌────────────────▼───────────┐          │
│  │  Enrichment          │──▶│  Graph Builder             │          │
│  │  - Reverse DNS       │   │  (petgraph adjacency list) │          │
│  │  - GeoIP (MaxMind)   │   │  Emits delta frames every  │          │
│  │  - ASN (Team Cymru)  │   │  500ms (Phase 1)           │          │
│  └──────────────────────┘   └────────────────┬───────────┘          │
│                                              │                       │
│                              ┌────────────────▼───────────┐         │
│                              │  WebSocket Server           │         │
│                              │  (tokio-tungstenite)        │         │
│                              │  Port 9900 — Binary MsgPack │         │
│                              └─────────────────────────────┘         │
└──────────────────────────────────────────────────────────────────────┘
                                       │
                                       │ WebSocket (binary MessagePack frames)
                                       │
┌──────────────────────────────────────┼───────────────────────────────┐
│  ORCHESTRATOR LAYER (Node.js/Rust, controls tool execution)          │
│                                      │                               │
│  ┌───────────────────────────────────▼─────────────────────────┐    │
│  │  API Gateway (Fastify / Axum)                                │    │
│  │  REST + WebSocket endpoints                                  │    │
│  │  Port 9901                                                   │    │
│  ├──────────────────────┬────────────────┬─────────────────────┤    │
│  │  Tool Runner          │  LLM Bridge    │  Scope Validator    │    │
│  │  - Docker API         │  - Claude API  │  - CIDR allowlist   │    │
│  │  - PTY streaming      │  - Tool schema │  - DNS rebind guard │    │
│  │  - Job queue          │  - Context mgr │  - Audit logger     │    │
│  │  - Result parser      │  - Script gen  │  - Rate limiter     │    │
│  └──────────┬───────────┘────────────────┘─────────────────────┘    │
│             │                                                        │
│  ┌──────────▼──────────────────────────────────────────────────┐    │
│  │  Docker Engine                                               │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │    │
│  │  │ nmap         │  │ nuclei      │  │ custom.py   │  ...    │    │
│  │  │ container    │  │ container   │  │ container   │         │    │
│  │  └─────────────┘  └─────────────┘  └─────────────┘         │    │
│  └─────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────┘
                                       │
                                       │ WebSocket (tool output + results)
                                       │
┌──────────────────────────────────────┼───────────────────────────────┐
│  BROWSER CLIENT (TypeScript + Three.js + WebGPU)                     │
│                                      │                               │
│  ┌───────────────────────────────────▼─────────────────────────┐    │
│  │  Connection Manager                                          │    │
│  │  - Capture WS (port 9900) — network topology deltas          │    │
│  │  - Orchestrator WS (port 9901) — tool output + AI chat       │    │
│  ├──────────────────────────────────────────────────────────────┤    │
│  │                                                              │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │    │
│  │  │ State Manager │  │ 3D Scene     │  │ UI Layer          │  │    │
│  │  │ - Graph state │  │ - Three.js   │  │ - Terminal        │  │    │
│  │  │ - Tool jobs   │  │ - Nodes      │  │ - AI Chat         │  │    │
│  │  │ - Scan results│  │ - Edges      │  │ - Cmd Palette     │  │    │
│  │  │ - AI context  │  │ - Particles  │  │ - Radial Menu     │  │    │
│  │  │ - Audit log   │  │ - Sub-nodes  │  │ - Detail Panel    │  │    │
│  │  │              │  │ - Bloom/FX   │  │ - Toasts          │  │    │
│  │  └──────────────┘  └──────────────┘  └──────────────────┘  │    │
│  └──────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────┘
```

### 2.2 Technology Stack

| Layer                | Technology                                          | Justification                                |
| -------------------- | --------------------------------------------------- | -------------------------------------------- |
| **Capture**          | Rust + `pcap` + `etherparse`                        | Zero-copy parsing, millions of packets/sec   |
| **Graph**            | `petgraph`                                          | Mature adjacency list with algorithms        |
| **Enrichment**       | `maxminddb`, `trust-dns-resolver`                   | GeoIP, reverse DNS                           |
| **Serialization**    | `rmp-serde` (MessagePack)                           | ~53% smaller than JSON, zero-copy in browser |
| **Capture WS**       | `tokio-tungstenite`                                 | Async, binary frame support                  |
| **Orchestrator**     | Node.js + Fastify (Phase 1), Rust + Axum (Phase 2+) | Rapid prototyping → performance              |
| **Tool Execution**   | Docker Engine API (`dockerode` npm)                 | Container-per-tool isolation                 |
| **Tool Image**       | `kalilinux/kali-rolling` + custom Dockerfile        | 200+ security tools pre-installed            |
| **PTY Streaming**    | `node-pty` → WebSocket                              | Full terminal emulation with ANSI support    |
| **LLM**              | Claude API (`@anthropic-ai/sdk`)                    | Tool use, streaming, code generation         |
| **Frontend**         | TypeScript + Vite                                   | Fast HMR, tree shaking, ESM-native           |
| **3D Rendering**     | Three.js r171+ (WebGPU/WebGL2)                      | InstancedMesh, postprocessing, WebXR         |
| **Force Layout**     | `3d-force-graph` (Phase 1), `ngraph` (Phase 2+)     | Prototype fast, then optimize                |
| **Terminal UI**      | `xterm.js` + `@xterm/addon-webgl`                   | GPU-accelerated terminal, VS Code proven     |
| **Command Palette**  | `cmdk`                                              | Unstyled, composable, fuzzy search           |
| **AI Chat UI**       | `assistant-ui` or custom                            | Streaming, tool call rendering               |
| **State Management** | Zustand                                             | Simple, performant, works outside React      |
| **Package Manager**  | pnpm                                                | Faster, disk-efficient                       |

### 2.3 Key Decisions & Rationale

**Why container-per-tool execution?**
Security tools require privileged capabilities (CAP_NET_RAW for nmap SYN scans, CAP_NET_ADMIN for OS detection). Running them directly on the host is dangerous. Docker containers provide: (1) process isolation, (2) network namespace control for scope enforcement via iptables, (3) resource limits (memory, CPU, timeout), (4) ephemeral execution (container destroyed after use), (5) pre-built images with all tools installed.

**Why a separate orchestrator instead of extending the Rust capture agent?**
The capture agent runs as root with libpcap. It should do exactly one thing: capture and aggregate packets. Tool execution, LLM integration, PTY management, and Docker orchestration are complex stateful services that benefit from Node.js's async ecosystem. Separation of concerns reduces the attack surface of the privileged component.

**Why Claude API for the LLM?**
Claude's tool use system maps directly to security tool schemas. Extended thinking enables multi-step pentesting planning. The streaming API provides real-time response rendering. MCP integration enables future extensibility.

**Why xterm.js instead of a custom terminal?**
xterm.js powers VS Code, JupyterLab, and hundreds of production apps. Its WebGL addon handles 5-35 MB/s throughput — essential for fast scan output. The `node-pty` → WebSocket → xterm.js pipeline is the de facto standard.

---

## 3. Repository Structure

```
cyberdeck/
├── README.md
├── SPEC.md                              # This document
├── docker-compose.yml                   # Development environment
├── package.json                         # Workspace root
├── pnpm-workspace.yaml
│
├── capture-agent/                       # Rust binary (privileged)
│   ├── Cargo.toml
│   ├── Cargo.lock
│   ├── src/
│   │   ├── main.rs                      # CLI args, privilege check, startup
│   │   ├── capture.rs                   # libpcap interface, async packet stream
│   │   ├── parser.rs                    # etherparse zero-copy header extraction
│   │   ├── flow.rs                      # Flow aggregator (HashMap<FlowKey, FlowState>)
│   │   ├── graph.rs                     # petgraph topology builder, delta computation
│   │   ├── enrichment.rs                # Reverse DNS, GeoIP, ASN lookups
│   │   ├── websocket.rs                 # tokio-tungstenite server, frame emission
│   │   ├── protocol.rs                  # Shared types: DeltaFrame, NodeData, EdgeData
│   │   └── config.rs                    # Configuration constants
│   ├── tests/
│   │   ├── parser_test.rs
│   │   ├── flow_test.rs
│   │   └── protocol_test.rs
│   └── fixtures/
│       └── sample.pcap                  # Test capture file
│
├── orchestrator/                        # Tool execution + LLM bridge (Node.js)
│   ├── package.json
│   ├── tsconfig.json
│   ├── src/
│   │   ├── index.ts                     # Fastify server bootstrap
│   │   ├── config.ts                    # Configuration constants
│   │   │
│   │   ├── tools/
│   │   │   ├── tool-runner.ts           # Docker container lifecycle management
│   │   │   ├── tool-registry.ts         # Tool definitions, schemas, defaults
│   │   │   ├── pty-bridge.ts            # node-pty → WebSocket PTY streaming
│   │   │   ├── result-parser.ts         # Parse nmap XML, nuclei JSON, etc.
│   │   │   ├── job-manager.ts           # Job queue, status tracking, cancellation
│   │   │   └── output-streamer.ts       # Dual-stream: raw terminal + structured data
│   │   │
│   │   ├── llm/
│   │   │   ├── ai-operator.ts           # Claude API client, conversation management
│   │   │   ├── tool-schemas.ts          # Tool definitions for Claude's tool_use
│   │   │   ├── context-builder.ts       # Build target context from graph state
│   │   │   ├── script-generator.ts      # Generate + validate custom scripts
│   │   │   └── safety-gate.ts           # Human approval for destructive operations
│   │   │
│   │   ├── scope/
│   │   │   ├── scope-validator.ts       # CIDR allowlist, DNS rebind guard
│   │   │   ├── scope-config.ts          # Scope definition types and parsing
│   │   │   └── audit-logger.ts          # Append-only audit trail (JSON + hash chain)
│   │   │
│   │   ├── api/
│   │   │   ├── routes.ts                # REST endpoints
│   │   │   ├── ws-handler.ts            # WebSocket upgrade + message routing
│   │   │   └── middleware.ts            # Auth, rate limiting, CORS
│   │   │
│   │   └── integrations/                # Phase 2
│   │       ├── shodan.ts                # Shodan API client
│   │       ├── virustotal.ts            # VirusTotal API client
│   │       └── censys.ts                # Censys API client
│   │
│   ├── docker/
│   │   ├── Dockerfile.tools             # Kali-based image with security tools
│   │   └── iptables-scope.sh            # Network namespace scope enforcement
│   │
│   └── tests/
│       ├── tool-runner.test.ts
│       ├── scope-validator.test.ts
│       ├── result-parser.test.ts
│       └── ai-operator.test.ts
│
├── web-client/                          # Browser frontend
│   ├── package.json
│   ├── tsconfig.json
│   ├── vite.config.ts
│   ├── index.html
│   ├── public/
│   │   └── favicon.svg
│   ├── src/
│   │   ├── main.ts                      # Entry point, bootstrap
│   │   ├── types.ts                     # All shared TypeScript types
│   │   ├── config.ts                    # Configuration constants
│   │   │
│   │   ├── network/
│   │   │   ├── capture-client.ts        # WebSocket to capture agent (port 9900)
│   │   │   ├── orchestrator-client.ts   # WebSocket to orchestrator (port 9901)
│   │   │   ├── state-manager.ts         # Canonical graph state + tool job state
│   │   │   └── mock-data.ts             # Simulated data for offline dev (?mock=true)
│   │   │
│   │   ├── scene/
│   │   │   ├── scene-manager.ts         # Three.js scene, camera, renderer, composer
│   │   │   ├── node-renderer.ts         # Node meshes (main hosts)
│   │   │   ├── subnode-renderer.ts      # Sub-nodes (ports, services, vulns) orbiting hosts
│   │   │   ├── edge-renderer.ts         # Edge lines between nodes
│   │   │   ├── particle-system.ts       # Animated packet flow particles
│   │   │   ├── grid.ts                  # Tron-style ground grid
│   │   │   ├── ice-renderer.ts          # ICE visual (polyhedra around secured nodes) [Phase 2]
│   │   │   ├── postprocessing.ts        # Bloom, chromatic aberration, scanlines
│   │   │   └── shaders/
│   │   │       ├── node.vert.glsl
│   │   │       ├── node.frag.glsl
│   │   │       └── particle.frag.glsl
│   │   │
│   │   ├── interaction/
│   │   │   ├── selection.ts             # Raycasting, node click/right-click
│   │   │   ├── radial-menu.ts           # Circular context menu on right-click
│   │   │   ├── camera-controller.ts     # Orbit, fly-to, semantic zoom
│   │   │   └── keyboard.ts             # Keyboard shortcuts
│   │   │
│   │   ├── tools/
│   │   │   ├── tool-dispatcher.ts       # Send tool execution requests to orchestrator
│   │   │   ├── tool-definitions.ts      # Client-side tool metadata (icons, colors, params)
│   │   │   └── result-visualizer.ts     # Map tool results → 3D sub-nodes
│   │   │
│   │   ├── ai/
│   │   │   ├── chat-manager.ts          # AI conversation state, message history
│   │   │   ├── chat-renderer.ts         # Render chat bubbles, tool calls, code blocks
│   │   │   └── prompt-detector.ts       # Detect natural language vs raw command
│   │   │
│   │   ├── terminal/
│   │   │   ├── terminal-manager.ts      # xterm.js initialization and config
│   │   │   ├── command-handler.ts       # Parse and route terminal commands
│   │   │   └── output-formatter.ts      # Color-code and format terminal output
│   │   │
│   │   ├── ui/
│   │   │   ├── panels/
│   │   │   │   ├── top-bar.ts           # Logo, scope badge, stats, running tools
│   │   │   │   ├── left-panel.ts        # Toolbox, protocol filters, target list
│   │   │   │   ├── right-panel.ts       # Node detail card + AI chat
│   │   │   │   └── bottom-panel.ts      # Terminal + traffic graph tabs
│   │   │   ├── command-palette.ts       # Cmd+K fuzzy search overlay
│   │   │   ├── hud.ts                   # Viewport overlays (crosshair, brackets)
│   │   │   ├── tooltip.ts              # Hover tooltip for nodes
│   │   │   └── toast.ts                # Notification toasts
│   │   │
│   │   └── utils/
│   │       ├── color.ts                 # Protocol/severity → color mapping
│   │       ├── format.ts               # Byte formatting, IP display, time
│   │       └── performance.ts           # FPS counter, memory monitoring
│   │
│   └── tests/
│       ├── state-manager.test.ts
│       ├── scope-validator.test.ts
│       ├── result-visualizer.test.ts
│       └── prompt-detector.test.ts
│
└── docs/
    ├── architecture.md
    ├── tool-integration-guide.md
    ├── llm-prompt-engineering.md
    └── scope-configuration.md
```

---

## 4. Phase 1 — "First Light" (MVP)

**Goal:** A browser page showing live network traffic as an interactive 3D force graph with cyberpunk aesthetics, a terminal for command execution, an AI chat operator, and basic tool execution (nmap, nuclei) with results visualized as sub-nodes orbiting target hosts.

**Timeline:** 4–6 weeks

### 4.1 Capture Agent (Rust) — Phase 1 Scope

The capture agent is **identical to v1.0 spec** — no changes. It captures packets, aggregates flows, and emits MessagePack delta frames over WebSocket on port 9900. See the v1.0 CYBERSPACE_PRODUCT_SPEC.md §3.1 for the complete Rust specification including:

- CLI interface (`cyberspace-capture [OPTIONS]`)
- Capture module (`capture.rs`) — libpcap with immediate mode
- Parser module (`parser.rs`) — etherparse zero-copy 5-tuple extraction
- Flow aggregator (`flow.rs`) — HashMap with 30s timeout, LRU eviction
- Graph builder (`graph.rs`) — petgraph adjacency list, delta computation
- Enrichment (`enrichment.rs`) — reverse DNS, RFC1918 detection
- WebSocket server (`websocket.rs`) — tokio-tungstenite, snapshot + delta frames

**Key Rust crates (unchanged):**

```toml
pcap = { version = "2", features = ["capture-stream"] }
etherparse = "0.16"
tokio = { version = "1", features = ["full"] }
tokio-tungstenite = "0.24"
petgraph = "0.7"
rmp-serde = "1"
maxminddb = "0.24"
```

### 4.2 Orchestrator (Node.js) — Phase 1 Scope

#### 4.2.1 Project Setup

```json
// orchestrator/package.json
{
  "name": "cyberdeck-orchestrator",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "tsx watch src/index.ts",
    "build": "tsc",
    "start": "node dist/index.js"
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
    "vitest": "^2.1.0"
  }
}
```

#### 4.2.2 Configuration (`config.ts`)

```typescript
export const CONFIG = {
  // Server
  PORT: 9901,
  HOST: "0.0.0.0",

  // Docker
  DOCKER_SOCKET: "/var/run/docker.sock",
  TOOL_IMAGE: "cyberdeck-tools:latest", // Built from Dockerfile.tools
  CONTAINER_MEMORY_LIMIT: 2 * 1024 * 1024 * 1024, // 2GB
  CONTAINER_CPU_LIMIT: 2, // 2 cores
  CONTAINER_TIMEOUT_SEC: 300, // 5 minutes max per tool
  CONTAINER_PIDS_LIMIT: 256,

  // LLM
  ANTHROPIC_MODEL: "claude-sonnet-4-5-20250929",
  ANTHROPIC_MAX_TOKENS: 4096,
  LLM_RATE_LIMIT_RPM: 30, // Requests per minute

  // Scope
  DEFAULT_SCOPE: ["10.10.11.0/24", "192.168.0.0/16"],
  SCOPE_FILE: "./scope.yaml",

  // Audit
  AUDIT_LOG_PATH: "./audit.jsonl",
  AUDIT_RETENTION_DAYS: 365,

  // Limits
  MAX_CONCURRENT_TOOLS: 5,
  MAX_JOBS_PER_MINUTE: 20,
  MAX_OUTPUT_BUFFER_MB: 50,
} as const;
```

#### 4.2.3 Tool Image Dockerfile (`docker/Dockerfile.tools`)

```dockerfile
FROM kalilinux/kali-rolling

# Install core security tools
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
    && rm -rf /var/lib/apt/lists/*

# Update nuclei templates
RUN nuclei -update-templates 2>/dev/null || true

# Create non-root user for tool execution
RUN useradd -m -s /bin/bash operator
WORKDIR /home/operator

# Default: keep container alive for exec
CMD ["sleep", "infinity"]
```

#### 4.2.4 Tool Registry (`tools/tool-registry.ts`)

```typescript
// Each tool definition specifies how to execute it, parse output, and validate scope.
// This is the source of truth for all tool metadata used by the UI, terminal, and LLM.

import { z } from "zod";

export interface ToolDefinition {
  id: string;
  name: string;
  description: string;
  category: "recon" | "scanning" | "exploit" | "auth" | "webapp" | "osint";
  icon: string; // Emoji for UI
  color: string; // Hex color for UI
  command: string; // Base command (e.g., 'nmap')

  // Schema for tool parameters (validated by Zod before execution)
  paramSchema: z.ZodSchema;

  // Build the full command string from validated params
  buildCommand: (params: Record<string, unknown>) => string;

  // Docker container capabilities needed
  capabilities: string[]; // e.g., ['CAP_NET_RAW']

  // Expected structured output format
  structuredOutputFlag?: string; // e.g., '-oX -' for nmap XML to stdout
  outputParser?: "nmap-xml" | "nuclei-json" | "json-lines" | "plain";

  // Does this tool require scope validation on target?
  requiresScope: boolean;

  // Risk level (determines approval requirements)
  riskLevel: "passive" | "active" | "invasive";

  // Estimated duration for UI progress indication
  estimatedDurationSec: number;
}

export const TOOLS: Record<string, ToolDefinition> = {
  "nmap-scan": {
    id: "nmap-scan",
    name: "Port Scan (nmap)",
    description: "Discover open ports and running services",
    category: "recon",
    icon: "🔍",
    color: "#00f0ff",
    command: "nmap",
    paramSchema: z.object({
      target: z.string().min(1),
      ports: z.string().optional().default("-"), // Default: top 1000
      flags: z.string().optional().default("-sV -sC -T4"),
      scripts: z.string().optional(),
    }),
    buildCommand: (p) => {
      let cmd = `nmap ${p.flags} -p ${p.ports}`;
      if (p.scripts) cmd += ` --script=${p.scripts}`;
      cmd += ` -oX - ${p.target}`; // XML output to stdout for parsing
      return cmd;
    },
    capabilities: ["CAP_NET_RAW", "CAP_NET_ADMIN"],
    structuredOutputFlag: "-oX -",
    outputParser: "nmap-xml",
    requiresScope: true,
    riskLevel: "active",
    estimatedDurationSec: 30,
  },

  "nuclei-scan": {
    id: "nuclei-scan",
    name: "Vulnerability Scan (nuclei)",
    description: "Check for known vulnerabilities using 8000+ templates",
    category: "scanning",
    icon: "🛡",
    color: "#ff3344",
    command: "nuclei",
    paramSchema: z.object({
      target: z.string().min(1),
      severity: z.string().optional().default("critical,high,medium"),
      tags: z.string().optional(),
    }),
    buildCommand: (p) => {
      let cmd = `nuclei -target ${p.target} -severity ${p.severity} -jsonl`;
      if (p.tags) cmd += ` -tags ${p.tags}`;
      return cmd;
    },
    capabilities: [],
    outputParser: "nuclei-json",
    requiresScope: true,
    riskLevel: "active",
    estimatedDurationSec: 120,
  },

  "gobuster-dir": {
    id: "gobuster-dir",
    name: "Directory Brute Force (gobuster)",
    description: "Discover hidden directories and files on web servers",
    category: "webapp",
    icon: "🕷",
    color: "#ff8844",
    command: "gobuster",
    paramSchema: z.object({
      target: z.string().url(),
      wordlist: z
        .string()
        .optional()
        .default("/usr/share/seclists/Discovery/Web-Content/common.txt"),
      extensions: z.string().optional(),
    }),
    buildCommand: (p) => {
      let cmd = `gobuster dir -u ${p.target} -w ${p.wordlist} -o /dev/stdout --no-color`;
      if (p.extensions) cmd += ` -x ${p.extensions}`;
      return cmd;
    },
    capabilities: [],
    outputParser: "plain",
    requiresScope: true,
    riskLevel: "active",
    estimatedDurationSec: 60,
  },

  "whois-lookup": {
    id: "whois-lookup",
    name: "WHOIS Lookup",
    description: "Query domain/IP registration information",
    category: "osint",
    icon: "📋",
    color: "#aa88ff",
    command: "whois",
    paramSchema: z.object({
      target: z.string().min(1),
    }),
    buildCommand: (p) => `whois ${p.target}`,
    capabilities: [],
    outputParser: "plain",
    requiresScope: false, // WHOIS is passive OSINT
    riskLevel: "passive",
    estimatedDurationSec: 5,
  },

  "dig-dns": {
    id: "dig-dns",
    name: "DNS Lookup (dig)",
    description: "Query DNS records for a domain",
    category: "recon",
    icon: "📖",
    color: "#f0ff00",
    command: "dig",
    paramSchema: z.object({
      target: z.string().min(1),
      recordType: z.string().optional().default("ANY"),
    }),
    buildCommand: (p) => `dig ${p.target} ${p.recordType} +noall +answer`,
    capabilities: [],
    outputParser: "plain",
    requiresScope: false,
    riskLevel: "passive",
    estimatedDurationSec: 3,
  },

  traceroute: {
    id: "traceroute",
    name: "Traceroute",
    description: "Trace network path to target",
    category: "recon",
    icon: "🔗",
    color: "#00ff88",
    command: "traceroute",
    paramSchema: z.object({
      target: z.string().min(1),
    }),
    buildCommand: (p) => `traceroute -n ${p.target}`,
    capabilities: ["CAP_NET_RAW"],
    outputParser: "plain",
    requiresScope: true,
    riskLevel: "active",
    estimatedDurationSec: 15,
  },

  // Custom script execution (LLM-generated)
  "custom-script": {
    id: "custom-script",
    name: "Custom Script",
    description: "Execute a generated Python/Bash script in sandbox",
    category: "recon",
    icon: "📝",
    color: "#ff00c8",
    command: "python3",
    paramSchema: z.object({
      script: z.string().min(1), // Script content
      language: z.enum(["python", "bash"]),
      args: z.string().optional(),
    }),
    buildCommand: (p) => {
      if (p.language === "python")
        return `python3 /tmp/script.py ${p.args || ""}`;
      return `bash /tmp/script.sh ${p.args || ""}`;
    },
    capabilities: [],
    outputParser: "plain",
    requiresScope: true,
    riskLevel: "invasive", // Always requires human approval
    estimatedDurationSec: 30,
  },
};
```

#### 4.2.5 Tool Runner (`tools/tool-runner.ts`)

```typescript
// Requirements:
// - Manage Docker container lifecycle for tool execution
// - Each tool invocation creates a new container from the TOOL_IMAGE
// - Container is configured with:
//   - Memory limit (CONFIG.CONTAINER_MEMORY_LIMIT)
//   - CPU limit (CONFIG.CONTAINER_CPU_LIMIT)
//   - PIDs limit (CONFIG.CONTAINER_PIDS_LIMIT)
//   - Auto-remove on stop (--rm equivalent)
//   - Network namespace with iptables scope rules (via iptables-scope.sh)
//   - Required Linux capabilities from ToolDefinition.capabilities
//   - All other capabilities DROPPED
// - Stream stdout/stderr in real-time via Docker exec API
// - Support cancellation (kill container on user request)
// - Enforce timeout (CONFIG.CONTAINER_TIMEOUT_SEC)
// - For custom scripts: write script content to /tmp/script.py inside container before exec
// - Return both raw output (for terminal) and structured result (for 3D visualization)
// - Emit events: 'started', 'output', 'structured-result', 'completed', 'error', 'timeout'

import Docker from "dockerode";
import { EventEmitter } from "events";

export interface ToolJob {
  id: string; // nanoid
  toolId: string;
  params: Record<string, unknown>;
  targetIp: string;
  status:
    | "queued"
    | "running"
    | "completed"
    | "failed"
    | "cancelled"
    | "timeout";
  containerId?: string;
  startedAt?: number;
  completedAt?: number;
  exitCode?: number;
  rawOutput: string; // Accumulated stdout/stderr
  structuredResults?: unknown; // Parsed output (nmap hosts, nuclei findings, etc.)
  error?: string;
}

export interface ToolRunnerEvents {
  "job:started": (job: ToolJob) => void;
  "job:output": (
    jobId: string,
    chunk: string,
    stream: "stdout" | "stderr",
  ) => void;
  "job:structured": (jobId: string, result: unknown) => void;
  "job:completed": (job: ToolJob) => void;
  "job:error": (jobId: string, error: string) => void;
}

export class ToolRunner extends EventEmitter {
  private docker: Docker;
  private activeJobs: Map<string, ToolJob>;

  constructor();

  // Execute a tool — returns the job ID immediately, streams results via events
  async runTool(
    toolId: string,
    params: Record<string, unknown>,
  ): Promise<string>;

  // Cancel a running job
  async cancelJob(jobId: string): Promise<void>;

  // Get job status
  getJob(jobId: string): ToolJob | undefined;

  // List all jobs
  listJobs(): ToolJob[];
}
```

#### 4.2.6 Result Parser (`tools/result-parser.ts`)

```typescript
// Requirements:
// - Parse structured output from security tools into normalized format
// - Supported parsers:
//   - 'nmap-xml': Parse nmap XML output into hosts → ports → services
//   - 'nuclei-json': Parse nuclei JSONL into findings with severity
//   - 'json-lines': Generic JSONL parser
//   - 'plain': Return raw text (no parsing)
// - Output a normalized ToolResult that maps to 3D sub-nodes

export interface ToolResult {
  toolId: string;
  targetIp: string;
  timestamp: number;

  // Discovered entities to add to the 3D graph
  discoveries: Discovery[];
}

export interface Discovery {
  type:
    | "port"
    | "service"
    | "vulnerability"
    | "directory"
    | "credential"
    | "domain";

  // Port discovery
  port?: number;
  protocol?: "tcp" | "udp";
  state?: "open" | "filtered" | "closed";

  // Service info
  serviceName?: string;
  serviceVersion?: string;

  // Vulnerability info
  vulnId?: string; // CVE-XXXX-XXXXX or template ID
  severity?: "critical" | "high" | "medium" | "low" | "info";
  vulnTitle?: string;

  // Directory discovery
  path?: string;
  statusCode?: number;

  // Raw data
  raw?: string;
}

// Parser for nmap XML
export function parseNmapXml(xml: string, targetIp: string): ToolResult;

// Parser for nuclei JSONL
export function parseNucleiJson(jsonl: string, targetIp: string): ToolResult;
```

#### 4.2.7 LLM AI Operator (`llm/ai-operator.ts`)

```typescript
// Requirements:
// - Maintain per-session conversation history with Claude
// - Expose security tools as Claude tool_use definitions
// - Build rich target context from the current graph state
// - Stream responses to the browser for real-time rendering
// - Implement the agentic loop: plan → execute tool → analyze → next step
// - Human gate: tools with riskLevel 'invasive' require explicit user approval
// - Generate custom scripts (Python/Bash) with safety analysis before execution
// - Track token usage and rate limits

import Anthropic from "@anthropic-ai/sdk";

export interface AIOperatorConfig {
  model: string;
  maxTokens: number;
  systemPrompt: string;
}

// System prompt template (injected with current scope and graph context)
export const SYSTEM_PROMPT = `You are an AI security operator embedded in a cyberdeck — a spatial cybersecurity analysis platform. The user navigates a 3D visualization of network topology and interacts with targets.

Current Engagement:
- Scope: {scope_cidrs}
- Active targets: {target_list}
- Selected node: {selected_node}

Available tools:
{tool_list}

Rules:
1. ONLY operate within the defined scope. Never suggest actions on out-of-scope targets.
2. For active scanning or exploitation, always confirm with the operator first.
3. When generating scripts, include comments explaining each section.
4. Cite CVE IDs and reference sources when discussing vulnerabilities.
5. After each tool execution, analyze the results and suggest logical next steps.
6. Be concise. The operator is experienced — don't over-explain basics.
7. Format commands as code blocks so they can be executed directly.
`;

// Claude tool definitions (subset — full list in tool-schemas.ts)
export const AI_TOOLS: Anthropic.Tool[] = [
  {
    name: "run_nmap",
    description: "Execute an nmap port scan against a target within scope",
    input_schema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "IP address or hostname to scan",
        },
        ports: {
          type: "string",
          description: 'Port range (e.g., "80,443" or "1-1000")',
        },
        flags: { type: "string", description: "Additional nmap flags" },
      },
      required: ["target"],
    },
  },
  {
    name: "run_nuclei",
    description: "Run vulnerability scan using nuclei templates",
    input_schema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target URL or IP" },
        severity: {
          type: "string",
          description: "Severity filter: critical,high,medium,low",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "generate_script",
    description: "Generate a custom Python or Bash script for a specific task",
    input_schema: {
      type: "object",
      properties: {
        task: { type: "string", description: "What the script should do" },
        language: { type: "string", enum: ["python", "bash"] },
        target: {
          type: "string",
          description: "Target the script will operate on",
        },
      },
      required: ["task", "language"],
    },
  },
  {
    name: "run_command",
    description:
      "Execute an arbitrary shell command in the sandboxed container",
    input_schema: {
      type: "object",
      properties: {
        command: { type: "string", description: "Shell command to execute" },
      },
      required: ["command"],
    },
  },
  {
    name: "analyze_results",
    description: "Analyze previous tool output and suggest next steps",
    input_schema: {
      type: "object",
      properties: {
        jobId: { type: "string", description: "Job ID to analyze" },
      },
      required: ["jobId"],
    },
  },
];

export class AIOperator {
  private client: Anthropic;
  private conversations: Map<string, Anthropic.MessageParam[]>;

  constructor(config: AIOperatorConfig);

  // Send a user message and stream the response
  // The callback receives chunks for real-time UI rendering
  async chat(
    sessionId: string,
    message: string,
    graphContext: GraphContext,
    onChunk: (chunk: AIResponseChunk) => void,
  ): Promise<AIResponse>;

  // Handle tool_use blocks from Claude's response
  // Returns tool results that are fed back to Claude for analysis
  private async executeToolCall(
    toolUse: Anthropic.ToolUseBlock,
    sessionId: string,
  ): Promise<Anthropic.ToolResultBlockParam>;
}

export interface GraphContext {
  selectedNode?: {
    ip: string;
    hostname?: string;
    os?: string;
    ports?: number[];
    vulns?: number;
  };
  recentJobs?: ToolJob[];
  scope: string[];
  nodeCount: number;
  edgeCount: number;
}

export type AIResponseChunk =
  | { type: "text"; content: string }
  | { type: "tool_use"; toolName: string; input: Record<string, unknown> }
  | { type: "tool_result"; jobId: string; status: string }
  | { type: "code"; language: string; content: string };

export interface AIResponse {
  fullText: string;
  toolCalls: { toolName: string; jobId: string; result: unknown }[];
  tokensUsed: number;
}
```

#### 4.2.8 Scope Validator (`scope/scope-validator.ts`)

```typescript
// Requirements:
// - EVERY tool execution MUST pass scope validation before any network traffic is generated
// - Scope is defined as a list of CIDR ranges and optionally domains
// - Validation checks:
//   1. Target IP is within at least one allowed CIDR range
//   2. If target is a hostname, resolve it and verify resolved IP is in scope
//   3. DNS rebind guard: re-verify DNS resolution hasn't changed to out-of-scope IP
//   4. Check against explicit blocklist (e.g., 127.0.0.1, 169.254.x.x, etc.)
// - Scope configuration loaded from scope.yaml file, hot-reloaded on change
// - Validation result is logged to audit trail regardless of pass/fail
// - Rejection returns a clear error message explaining why the target is out of scope

import { z } from "zod";

export const ScopeConfigSchema = z.object({
  engagement: z.object({
    name: z.string(),
    startDate: z.string().datetime(),
    endDate: z.string().datetime(),
    authorizedBy: z.string(),
  }),
  allowedCidrs: z.array(z.string()), // e.g., ['10.10.11.0/24']
  allowedDomains: z.array(z.string()).optional(), // e.g., ['*.example.com']
  blockedCidrs: z.array(z.string()).default([
    // Always blocked
    "127.0.0.0/8",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "255.255.255.255/32",
  ]),
  restrictions: z.object({
    allowActiveScanning: z.boolean().default(true),
    allowExploitation: z.boolean().default(false),
    allowBruteForce: z.boolean().default(false),
    allowDoS: z.boolean().default(false),
    maxConcurrentScans: z.number().default(5),
  }),
  timeWindows: z
    .array(
      z.object({
        days: z.array(
          z.enum(["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]),
        ),
        startHour: z.number().min(0).max(23),
        endHour: z.number().min(0).max(23),
      }),
    )
    .optional(),
});

export type ScopeConfig = z.infer<typeof ScopeConfigSchema>;

export interface ValidationResult {
  allowed: boolean;
  reason?: string; // Why it was rejected
  resolvedIp?: string; // If hostname was resolved
  matchedCidr?: string; // Which CIDR range matched
}

export class ScopeValidator {
  constructor(configPath: string);

  // Validate a target IP or hostname against scope
  async validate(target: string): Promise<ValidationResult>;

  // Check if a specific tool category is allowed
  isToolAllowed(riskLevel: "passive" | "active" | "invasive"): boolean;

  // Check if current time is within allowed window
  isWithinTimeWindow(): boolean;

  // Reload configuration from disk
  reload(): void;

  // Get current scope for display in UI
  getScope(): ScopeConfig;
}
```

#### 4.2.9 Audit Logger (`scope/audit-logger.ts`)

```typescript
// Requirements:
// - Append-only log file (JSONL format)
// - Each entry includes: timestamp, action, user/session, target, tool,
//   parameters, scope validation result, outcome
// - Hash chain: each entry includes SHA-256 hash of the previous entry
//   for tamper detection
// - Log ALL actions: tool executions, AI queries, scope changes,
//   login/logout, configuration changes
// - Rotate logs daily, retain for CONFIG.AUDIT_RETENTION_DAYS
// - Provide export function for compliance reports

export interface AuditEntry {
  id: string;
  timestamp: string; // ISO 8601
  sessionId: string;
  action:
    | "tool_execute"
    | "tool_complete"
    | "tool_cancel"
    | "ai_query"
    | "ai_tool_call"
    | "scope_check"
    | "scope_change"
    | "session_start"
    | "session_end";
  tool?: string;
  target?: string;
  params?: Record<string, unknown>;
  scopeResult?: "allowed" | "denied";
  result?: "success" | "failure" | "timeout" | "cancelled";
  details?: string;
  prevHash: string; // SHA-256 of previous entry
}

export class AuditLogger {
  constructor(logPath: string);

  async log(
    entry: Omit<AuditEntry, "id" | "timestamp" | "prevHash">,
  ): Promise<void>;

  // Verify hash chain integrity
  async verify(): Promise<{ valid: boolean; brokenAt?: number }>;

  // Export entries for a date range
  async export(startDate: string, endDate: string): Promise<AuditEntry[]>;
}
```

#### 4.2.10 WebSocket Handler (`api/ws-handler.ts`)

```typescript
// Requirements:
// - Accept WebSocket connections on port 9901
// - Authenticate via session token (simple shared secret for Phase 1)
// - Message types from client → server:
//   - tool.execute: { toolId, params } → start tool, stream results back
//   - tool.cancel: { jobId } → kill running tool
//   - tool.list: {} → return list of available tools
//   - ai.message: { text, graphContext } → send to AI operator, stream response
//   - ai.approve: { jobId } → approve a pending tool execution from AI
//   - ai.reject: { jobId } → reject a pending tool execution
//   - scope.get: {} → return current scope config
//   - scope.validate: { target } → check if target is in scope
// - Message types from server → client:
//   - tool.started: { jobId, toolId, target }
//   - tool.output: { jobId, chunk, stream } — real-time terminal output
//   - tool.structured: { jobId, discoveries[] } — parsed results for 3D
//   - tool.completed: { jobId, exitCode }
//   - tool.error: { jobId, error }
//   - ai.chunk: { sessionId, chunk } — streaming AI response
//   - ai.tool_call: { sessionId, toolName, input, requiresApproval }
//   - ai.complete: { sessionId }
//   - scope.config: { scopeConfig }
//   - toast: { type, title, body } — notification for the UI
//
// All messages are JSON (not MessagePack) for simplicity in Phase 1.
// Phase 2: switch to MessagePack for bandwidth efficiency.

export interface WsMessage {
  type: string;
  payload: Record<string, unknown>;
  requestId?: string; // For request-response correlation
}
```

### 4.3 Web Client — Phase 1 Scope

#### 4.3.1 Project Setup

```json
// web-client/package.json
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
    "3d-force-graph": "^1.77.0",
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

#### 4.3.2 State Manager (`network/state-manager.ts`)

```typescript
// Requirements:
// - Single source of truth for ALL client-side state via Zustand
// - Slices:
//   1. Graph state: nodes, edges, particles (from capture agent)
//   2. Tool state: running jobs, completed jobs, structured results
//   3. AI state: conversation history, pending approvals
//   4. UI state: selected node, hovered node, active panel, filters
//   5. Scope state: current scope config, validation cache
// - Apply capture agent snapshot/delta frames
// - Apply orchestrator tool events (started, output, structured, completed)
// - Computed properties: sorted node list, filtered edges, protocol counts
// - Emit typed events for 3D scene updates

import { create } from "zustand";

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
  discoveries: Map<string, Discovery[]>; // targetIp → discoveries
  subNodes: Map<string, SubNode[]>; // targetIp → visual sub-nodes

  // ── AI state ──
  aiMessages: AIMessage[];
  pendingApprovals: PendingApproval[];

  // ── UI state ──
  selectedNodeId: string | null;
  hoveredNodeId: string | null;
  protocolFilters: Record<string, boolean>;
  activeTab: "terminal" | "traffic" | "packets";
  commandPaletteOpen: boolean;
  radialMenuOpen: boolean;
  radialMenuPosition: { x: number; y: number } | null;

  // ── Scope ──
  scope: ScopeConfig | null;

  // ── Actions ──
  applySnapshot(frame: SnapshotFrame): void;
  applyDelta(frame: DeltaFrame): void;
  addJob(job: ToolJob): void;
  updateJob(jobId: string, update: Partial<ToolJob>): void;
  addDiscoveries(targetIp: string, discoveries: Discovery[]): void;
  selectNode(nodeId: string | null): void;
  addAIMessage(message: AIMessage): void;
  toggleProtocol(protocol: string): void;
}

export interface ClientNode {
  id: string;
  ip: string;
  hostname: string | null;
  nodeType: "local" | "gateway" | "dns" | "cdn" | "remote" | "target";
  position: { x: number; y: number; z: number } | null;
  totalBytesIn: number;
  totalBytesOut: number;
  activeConnections: number;
  packetsPerSec: number;
  lastSeen: number;
  staleness: number;
  // Cyberdeck additions:
  os?: string;
  ports?: PortInfo[];
  vulnCount?: number;
  scanned: boolean;
  scanJobs: string[]; // Job IDs of scans run against this node
}

export interface PortInfo {
  port: number;
  protocol: "tcp" | "udp";
  state: "open" | "filtered" | "closed";
  service?: string;
  version?: string;
  vulnSeverity?: "critical" | "high" | "medium" | "low" | "info";
  vulnId?: string;
}

export interface SubNode {
  id: string;
  parentIp: string;
  type: "port" | "service" | "vulnerability" | "directory";
  label: string;
  severity?: string;
  orbitAngle: number;
  orbitRadius: number;
}

export interface AIMessage {
  id: string;
  role: "user" | "assistant";
  content: string; // May contain HTML for tool calls/code blocks
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
```

#### 4.3.3 Sub-Node Renderer (`scene/subnode-renderer.ts`)

```typescript
// Requirements:
// - When tool results (port scans, vuln scans) are received, create 3D sub-nodes
//   that orbit the parent host node
// - Sub-node visual encoding:
//
//   | Type | Geometry | Color Logic |
//   |------|----------|-------------|
//   | Port (open, no vuln) | SphereGeometry(0.5, 8, 8) | #00b0ff (info blue) |
//   | Port (critical vuln) | SphereGeometry(1.0, 8, 8) | #ff0040 (neon red) |
//   | Port (high vuln) | SphereGeometry(0.8, 8, 8) | #ff6600 (neon orange) |
//   | Port (medium vuln) | SphereGeometry(0.6, 8, 8) | #ffe600 (neon yellow) |
//   | Port (low vuln) | SphereGeometry(0.5, 8, 8) | #39ff14 (neon green) |
//   | Directory | BoxGeometry(0.4) | #aa88ff (purple) |
//   | Credential | DiamondGeometry(0.6) | #ff00c8 (magenta) |
//
// - Orbit behavior:
//   - Sub-nodes orbit their parent at radius = parent_radius * 2.5
//   - Evenly spaced around the orbit circle
//   - Slow rotation: 0.15 rad/sec
//   - Connected to parent by a thin line (same color as sub-node, opacity 0.15)
//
// - Animation:
//   - On creation: scale from 0 → 1 with elastic easing over 500ms
//   - Critical vulns: pulse emissive intensity (0.8 + sin(t*3)*0.4)
//   - On hover: show tooltip with port number, service name, CVE ID
//
// - Performance:
//   - Use InstancedMesh when >20 sub-nodes per host (Phase 2)
//   - Max 100 sub-nodes per host (aggregate remaining as "X more")
//   - Max 500 total sub-nodes in scene

export class SubNodeRenderer {
  constructor(scene: THREE.Scene, camera: THREE.Camera);

  // Add sub-nodes for a host based on discoveries
  addDiscoveries(
    hostIp: string,
    hostPosition: THREE.Vector3,
    discoveries: Discovery[],
  ): void;

  // Remove all sub-nodes for a host
  removeSubNodes(hostIp: string): void;

  // Update positions (called each frame for orbit animation)
  update(deltaTime: number, hostPositions: Map<string, THREE.Vector3>): void;

  // Dispose all sub-nodes
  dispose(): void;
}
```

#### 4.3.4 Radial Context Menu (`interaction/radial-menu.ts`)

```typescript
// Requirements:
// - Appears on right-click of a 3D node
// - Circular layout with 5-7 action buttons orbiting a center icon
// - Center shows the node's type icon
// - Actions are contextual based on node type and scan status:
//
//   Default actions (all nodes):
//   | Position | Icon | Label | Action | Risk |
//   |----------|------|-------|--------|------|
//   | 12 o'clock | 🔍 | SCAN | Port scan (nmap) | active |
//   | 2 o'clock | 📋 | ENUM | Service enumeration | active |
//   | 4 o'clock | 🛡 | VULN | Vulnerability scan (nuclei) | active |
//   | 6 o'clock | ⚡ | EXPLOIT | Exploit search/execution | invasive |
//   | 8 o'clock | 🔗 | TRACE | Traceroute | active |
//   | 10 o'clock | 🤖 | AI PLAN | Ask AI to plan attack | passive |
//
//   Additional actions for scanned nodes:
//   | Icon | Label | Action |
//   |------|-------|--------|
//   | 🕷 | WEB | Web app scan (gobuster/nikto) |
//   | 🔓 | AUTH | Auth testing (hydra) |
//
// - Orbit radius: 75px from center
// - Each button: 70x70px rounded square with dark background
// - Hover effect: scale 1.1x, cyan border glow
// - Click triggers: (1) hide menu, (2) validate scope, (3) execute tool, (4) show toast
// - Position: centered on the right-click screen coordinates
// - Dismiss on: click outside, Escape key, any action click
//
// Implementation: HTML overlay positioned via CSS transform
// (NOT a 3D object — much simpler to handle interaction)

export class RadialMenu {
  constructor(container: HTMLElement);

  // Show the menu at screen position for a specific node
  show(x: number, y: number, node: ClientNode): void;

  // Hide the menu
  hide(): void;

  // Register action handler
  onAction(handler: (action: string, node: ClientNode) => void): void;

  get isVisible(): boolean;
}
```

#### 4.3.5 Terminal Manager (`terminal/terminal-manager.ts`)

```typescript
// Requirements:
// - Initialize xterm.js with WebGL addon for GPU-accelerated rendering
// - Terminal styling: JetBrains Mono font, cyberpunk color scheme
// - Two input modes:
//   1. Local commands: help, scope, targets, clear, ai <prompt>
//   2. Tool commands: nmap, nuclei, gobuster, etc. → sent to orchestrator
// - Command history (up/down arrows, persist to localStorage)
// - Tab completion for tool names and common flags
// - Real-time output streaming from orchestrator tool execution
// - Special rendering for tool output:
//   - Prompt: "cyberdeck@local →" in cyan
//   - Commands: bright white
//   - Success output: green
//   - Warnings: yellow
//   - Errors: red
//   - Info: cyan
//   - Comments: dim italic
// - Support ANSI escape codes from tool output (nmap colors, progress bars)
// - Link detection: clickable IPs and URLs in output
//
// xterm.js configuration:
// {
//   fontFamily: 'JetBrains Mono, Share Tech Mono, monospace',
//   fontSize: 12,
//   theme: {
//     background: '#06060c',
//     foreground: '#c0d0e0',
//     cursor: '#00f0ff',
//     cursorAccent: '#06060c',
//     selectionBackground: '#00f0ff44',
//     black: '#0a0a0f',
//     red: '#ff3344',
//     green: '#00ff88',
//     yellow: '#f0ff00',
//     blue: '#00f0ff',
//     magenta: '#ff00c8',
//     cyan: '#00f0ff',
//     white: '#c0d0e0',
//   },
//   cursorBlink: true,
//   cursorStyle: 'bar',
//   scrollback: 10000,
// }

export class TerminalManager {
  constructor(container: HTMLElement);

  // Write formatted output to terminal
  writeLine(
    text: string,
    style?:
      | "prompt"
      | "cmd"
      | "output"
      | "success"
      | "error"
      | "warn"
      | "info"
      | "comment",
  ): void;

  // Write raw ANSI output (from tool execution)
  writeRaw(data: string): void;

  // Clear terminal
  clear(): void;

  // Register command handler
  onCommand(handler: (command: string) => void): void;

  // Focus the terminal input
  focus(): void;
}
```

#### 4.3.6 Command Palette (`ui/command-palette.ts`)

```typescript
// Requirements:
// - Triggered by Cmd+K (Mac) / Ctrl+K (Windows)
// - Centered overlay with frosted glass background
// - Input field with live fuzzy search
// - Results grouped by category:
//   - TOOLS: All registered security tools
//   - TARGETS: Active nodes in the graph (searchable by IP/hostname)
//   - ACTIONS: UI actions (toggle grid, reset camera, etc.)
//   - AI: LLM-related actions (ask AI, generate script)
// - Each result shows: icon, name, optional shortcut, description
// - Keyboard navigation: arrow keys, Enter to select
// - Selected item executes immediately (tool runs, camera flies to target, etc.)
// - ESC or click outside to dismiss
// - Recently used items appear at top
//
// Item sources:
// - Static: all ToolDefinition entries from tool-definitions.ts
// - Dynamic: current graph nodes (refreshed on open)
// - Static: UI actions with keyboard shortcuts
//
// Search algorithm: substring match on name + description, case-insensitive
// (Replace with Fuse.js for better fuzzy matching in Phase 2)

export class CommandPalette {
  constructor(container: HTMLElement);

  show(): void;
  hide(): void;
  toggle(): void;

  // Register action handler for when an item is selected
  onSelect(handler: (item: CommandPaletteItem) => void): void;

  get isVisible(): boolean;
}

export interface CommandPaletteItem {
  id: string;
  icon: string;
  name: string;
  description?: string;
  category: "tools" | "targets" | "actions" | "ai";
  shortcut?: string;
  action: () => void;
}
```

#### 4.3.7 AI Chat Renderer (`ai/chat-renderer.ts`)

````typescript
// Requirements:
// - Render AI conversation in the right panel below the detail card
// - Message types:
//   1. User messages: right-aligned, cyan-tinted bubble
//   2. Assistant messages: left-aligned, dark bubble
//   3. Tool call blocks: special rendering with tool name, command, status indicator
//   4. Code blocks: monospace with copy button, syntax highlighting (basic)
//   5. Tool results: collapsible dark terminal-style output
//   6. Pending approvals: yellow-bordered block with Approve/Reject buttons
//
// - Streaming: assistant messages render character-by-character as chunks arrive
// - Tool call rendering:
//   ```
//   ┌─────────────────────────────────┐
//   │ ⚡ nmap_scan                     │
//   │ nmap -sV -sC 10.10.11.234      │
//   │ ⟳ Executing...  [■■■□□□]       │
//   └─────────────────────────────────┘
//   ```
// - Approval rendering:
//   ```
//   ┌─────────────────────────────────┐
//   │ ⚠ APPROVAL REQUIRED             │
//   │ Tool: exploit/apache_path_rce   │
//   │ Target: 10.10.11.234            │
//   │ Risk: INVASIVE                  │
//   │                                 │
//   │ [✓ Approve]    [✗ Reject]       │
//   └─────────────────────────────────┘
//   ```
// - Auto-scroll to bottom on new messages
// - Max 100 messages in view (older messages removed from DOM, kept in state)
// - Input area: auto-resizing textarea with send button
//   - Enter sends, Shift+Enter for newline
//   - Placeholder: "Ask AI or type a command..."
//   - Model indicator: "claude-sonnet-4-5" badge in header

export class ChatRenderer {
  constructor(container: HTMLElement);

  addUserMessage(text: string): void;
  startAssistantMessage(): string; // Returns message ID
  appendToMessage(messageId: string, chunk: string): void;
  addToolCallBlock(messageId: string, toolCall: ToolCallBlock): void;
  addApprovalRequest(approval: PendingApproval): void;
  addCodeBlock(messageId: string, language: string, code: string): void;
  addToolResult(messageId: string, output: string, isError?: boolean): void;

  onSend(handler: (text: string) => void): void;
  onApprove(handler: (approvalId: string) => void): void;
  onReject(handler: (approvalId: string) => void): void;
}
````

### 4.4 Phase 1 Definition of Done

- [ ] Rust capture agent compiles and runs with `sudo ./cyberspace-capture`
- [ ] Capture agent emits MessagePack frames over WebSocket port 9900
- [ ] Orchestrator starts with `pnpm dev`, serves WebSocket on port 9901
- [ ] Docker tool image builds successfully with `docker build -t cyberdeck-tools .`
- [ ] Browser connects to both WebSocket endpoints
- [ ] 3D force graph renders live network traffic with cyberpunk aesthetics
- [ ] Right-click any node → radial context menu appears with 6 actions
- [ ] "Scan" action executes nmap in Docker container, output streams to terminal
- [ ] Scan results spawn orbiting sub-nodes colored by vulnerability severity
- [ ] Terminal accepts typed commands (nmap, nuclei, help, scope, targets)
- [ ] AI chat accepts natural language, routes to Claude API, streams response
- [ ] AI can invoke tools via tool_use, results appear in chat and terminal
- [ ] Command palette (Cmd+K) shows all tools, targets, and actions
- [ ] Scope validation blocks out-of-scope targets with clear error
- [ ] All tool executions logged to audit trail
- [ ] `?mock=true` works without capture agent or Docker
- [ ] 60fps with 200 nodes / 500 edges / 50 sub-nodes

---

## 5. Phase 2 — "The Matrix Takes Shape"

**Timeline:** 1–2 months after Phase 1

### 5.1 Additions

**Orchestrator:**

- Migrate from Fastify to Rust + Axum for performance
- Firecracker microVM support for LLM-generated scripts (stronger isolation)
- Metasploit RPC API integration (module search, exploit execution, session management)
- API integrations: Shodan, VirusTotal, Censys, SecurityTrails
- Persistent investigation database (SQLite) for cross-session history
- Multi-session support with separate conversation/audit per engagement

**Web Client:**

- Graduate from `3d-force-graph` to direct Three.js + InstancedMesh
- Web Worker force layout (ngraph.forcelayout3d)
- xterm.js with WebGL addon replacing the simple terminal
- Full node-pty → WebSocket PTY bridge (direct container shell access)
- Semantic zoom (LOD): 4 levels from AS clusters → individual ports
- BGP topology overlay from RIPE RIS Live WebSocket
- GeoIP positioning (MaxMind GeoLite2) for geographic view mode
- Investigation graph persistence (IndexedDB)
- ICE visualization: translucent polyhedra around firewalled hosts
- Custom GLSL/WGSL shaders: particle trails, chromatic aberration, film grain
- React migration with Zustand store
- `assistant-ui` for production-grade AI chat component
- `cmdk` for production command palette
- Search box (find by IP/hostname, camera flies to node)
- CVSS color-coded vulnerability detail panel
- Attack path visualization (shortest path between two nodes)

### 5.2 Phase 2 Definition of Done

- [ ] InstancedMesh handles 5,000+ nodes at 60fps
- [ ] xterm.js with WebGL provides full PTY terminal to tool containers
- [ ] Shodan/VirusTotal enrichment data appears on node hover
- [ ] BGP AS clusters visible in "AS Clusters" view mode
- [ ] GeoIP positions nodes geographically in "Geographic" view mode
- [ ] Semantic zoom transitions smoothly between 4 LOD levels
- [ ] Investigation graph persists across browser sessions
- [ ] Metasploit module search and execution works via AI operator
- [ ] Search finds nodes by IP/hostname/service

---

## 6. Phase 3 — "Jacking In"

**Timeline:** 3–6 months after Phase 2

### 6.1 Features

- WebGPU compute shaders for force-directed layout (50K+ nodes at 60fps)
- GPU-side particle system (zero CPU cost)
- WebXR/VR support (Quest 2/3, teleport navigation, hand controllers, spatial audio)
- Autonomous agent mode: LLM plans and executes multi-step assessments with human gates
  - Follows PTES methodology: recon → scanning → vulnerability analysis → exploitation
  - Maintains a Pentesting Task Tree (PTT) like PentestGPT
  - Graphiti-style temporal knowledge graph for cross-engagement learning
- PCAP file replay with time-travel controls
- Session recording and replay (IndexedDB + optional S3 export)
- Anomaly detection overlays (port scans, DDoS, DNS tunneling)
- Sonification (pitch = bandwidth, rhythm = packet rate, spatial audio)
- Electron desktop app (capture agent + orchestrator + browser bundled)
- Docker Compose distributed deployment (multiple capture agents → one browser)
- Collaborative mode: multiple operators share the same investigation graph
- Report generation: auto-generate pentest report from audit log + findings

---

## 7. Data Models

### 7.1 Capture Agent Wire Protocol (MessagePack)

**Identical to v1.0 spec.** See CYBERSPACE_PRODUCT_SPEC.md §6.1 for complete TypeScript and Rust type definitions.

Key types: `SnapshotFrame`, `DeltaFrame`, `NodeData`, `EdgeData`, `NodeUpdate`, `EdgeUpdate`, `PacketEvent`.

### 7.2 Orchestrator Wire Protocol (JSON over WebSocket)

```typescript
// ── Client → Orchestrator messages ──

interface ToolExecuteMsg {
  type: "tool.execute";
  requestId: string;
  payload: {
    toolId: string; // From tool-registry.ts
    params: Record<string, unknown>;
  };
}

interface ToolCancelMsg {
  type: "tool.cancel";
  payload: { jobId: string };
}

interface ToolListMsg {
  type: "tool.list";
  requestId: string;
}

interface AIMessageMsg {
  type: "ai.message";
  requestId: string;
  payload: {
    text: string;
    graphContext: {
      selectedNode?: {
        ip: string;
        hostname?: string;
        os?: string;
        ports?: PortInfo[];
        vulns?: number;
      };
      recentJobs?: {
        id: string;
        toolId: string;
        target: string;
        status: string;
      }[];
      nodeCount: number;
      edgeCount: number;
    };
  };
}

interface AIApproveMsg {
  type: "ai.approve";
  payload: { approvalId: string };
}

interface AIRejectMsg {
  type: "ai.reject";
  payload: { approvalId: string };
}

interface ScopeGetMsg {
  type: "scope.get";
  requestId: string;
}

interface ScopeValidateMsg {
  type: "scope.validate";
  requestId: string;
  payload: { target: string };
}

// ── Orchestrator → Client messages ──

interface ToolStartedMsg {
  type: "tool.started";
  payload: {
    jobId: string;
    toolId: string;
    target: string;
    command: string;
    estimatedDuration: number;
  };
}

interface ToolOutputMsg {
  type: "tool.output";
  payload: {
    jobId: string;
    chunk: string; // Raw terminal output (may contain ANSI)
    stream: "stdout" | "stderr";
  };
}

interface ToolStructuredMsg {
  type: "tool.structured";
  payload: {
    jobId: string;
    toolId: string;
    targetIp: string;
    discoveries: Discovery[]; // Parsed results for 3D visualization
  };
}

interface ToolCompletedMsg {
  type: "tool.completed";
  payload: {
    jobId: string;
    exitCode: number;
    durationSec: number;
    discoveryCount: number;
  };
}

interface ToolErrorMsg {
  type: "tool.error";
  payload: {
    jobId: string;
    error: string;
  };
}

interface AIChunkMsg {
  type: "ai.chunk";
  payload: {
    sessionId: string;
    chunk: AIResponseChunk;
  };
}

interface AIToolCallMsg {
  type: "ai.tool_call";
  payload: {
    sessionId: string;
    approvalId: string;
    toolName: string;
    target: string;
    command: string;
    riskLevel: "passive" | "active" | "invasive";
    requiresApproval: boolean; // true if riskLevel === 'invasive'
  };
}

interface AICompleteMsg {
  type: "ai.complete";
  payload: { sessionId: string };
}

interface ScopeConfigMsg {
  type: "scope.config";
  payload: ScopeConfig;
}

interface ToastMsg {
  type: "toast";
  payload: {
    level: "info" | "success" | "warning" | "error";
    title: string;
    body: string;
  };
}

interface ScopeValidateResultMsg {
  type: "scope.validate.result";
  requestId: string;
  payload: ValidationResult;
}
```

### 7.3 Investigation Discovery Types

```typescript
// Normalized discovery types that map from tool results to 3D sub-nodes.
// These are the atoms of the investigation graph.

interface Discovery {
  id: string; // nanoid
  type:
    | "port"
    | "service"
    | "vulnerability"
    | "directory"
    | "credential"
    | "domain"
    | "hostname";
  targetIp: string; // Parent host IP
  jobId: string; // Tool job that produced this
  timestamp: number;

  // Port discovery
  port?: number;
  transportProtocol?: "tcp" | "udp";
  portState?: "open" | "filtered" | "closed";

  // Service
  serviceName?: string; // e.g., 'ssh', 'http', 'mysql'
  serviceVersion?: string; // e.g., 'OpenSSH 8.2p1', 'Apache 2.4.41'
  serviceProduct?: string; // e.g., 'OpenSSH', 'Apache httpd'
  banner?: string;

  // Vulnerability
  vulnId?: string; // CVE-XXXX-XXXXX or nuclei template ID
  vulnSeverity?: "critical" | "high" | "medium" | "low" | "info";
  vulnTitle?: string;
  vulnDescription?: string;
  cvssScore?: number;
  exploitAvailable?: boolean;

  // Web directory
  path?: string;
  httpStatusCode?: number;
  contentLength?: number;

  // Domain/hostname
  domain?: string;
  resolvedIps?: string[];

  // Raw output reference
  rawOutput?: string;
}
```

---

## 8. WebSocket Protocols

### 8.1 Dual WebSocket Architecture

The browser maintains **two simultaneous WebSocket connections**:

| Connection      | Port | Protocol             | Purpose                                    |
| --------------- | ---- | -------------------- | ------------------------------------------ |
| Capture WS      | 9900 | Binary (MessagePack) | Network topology deltas from capture agent |
| Orchestrator WS | 9901 | JSON                 | Tool execution, AI chat, scope management  |

This separation keeps the capture agent simple and privilege-isolated. The capture agent doesn't know about tools, AI, or scope — it just captures packets.

### 8.2 Connection Lifecycle

**Capture WS (port 9900):**

```
Client                           Capture Agent
  |  ──── WS Connect ───────────▶  |
  |  ◀──── Snapshot Frame ──────── |
  |  ◀──── Delta Frame ─────────── |  (every 500ms)
  |  ◀──── Delta Frame ─────────── |
  |  ...                            |
```

**Orchestrator WS (port 9901):**

```
Client                           Orchestrator
  |  ──── WS Connect ───────────▶  |
  |  ◀──── scope.config ────────── |  (on connect)
  |                                 |
  |  ──── tool.execute ──────────▶ |
  |  ◀──── tool.started ────────── |
  |  ◀──── tool.output (chunk) ─── |  (streaming)
  |  ◀──── tool.output (chunk) ─── |
  |  ◀──── tool.structured ──────  |  (parsed results)
  |  ◀──── tool.completed ──────── |
  |                                 |
  |  ──── ai.message ────────────▶ |
  |  ◀──── ai.chunk (text) ─────── |  (streaming)
  |  ◀──── ai.tool_call ─────────  |  (AI wants to run a tool)
  |  ──── ai.approve ────────────▶ |  (human approves)
  |  ◀──── tool.started ────────── |
  |  ◀──── tool.output ──────────  |
  |  ◀──── ai.chunk (analysis) ─── |  (AI analyzes results)
  |  ◀──── ai.complete ──────────  |
```

### 8.3 Reconnection

Both connections use exponential backoff: 1s, 2s, 4s, 8s, max 30s. On reconnect to capture WS, the agent sends a fresh snapshot. On reconnect to orchestrator WS, client re-fetches scope config and active job states.

---

## 9. Tool Execution Engine

See §4.2.4–4.2.6 for detailed specifications. Summary:

**Execution flow:**

1. User triggers tool (radial menu, terminal, command palette, or AI)
2. Client sends `tool.execute` to orchestrator
3. Orchestrator validates scope (§4.2.8)
4. If scope valid: create Docker container from `cyberdeck-tools` image
5. Apply iptables rules restricting egress to scope CIDRs only
6. Execute command inside container via Docker exec API
7. Stream stdout/stderr to client via `tool.output` messages
8. When complete: parse structured output (XML/JSON) into Discovery objects
9. Send `tool.structured` with discoveries for 3D visualization
10. Send `tool.completed` with summary
11. Destroy container

**Container security:**

- Drop all capabilities, add only what the tool needs
- Memory limit: 2GB
- CPU limit: 2 cores
- PID limit: 256
- Timeout: 300 seconds
- Network namespace with iptables allowing only scope CIDRs
- Read-only root filesystem (except /tmp)
- No access to Docker socket or host filesystem

---

## 10. LLM Integration (AI Operator)

See §4.2.7 for detailed specification. Summary:

**Interaction modes:**

1. **Chat mode:** User types natural language in chat panel → routed to Claude
2. **Command mode:** User types `ai <prompt>` in terminal → routed to Claude
3. **Context action:** User clicks "AI PLAN" in radial menu → sends target context to Claude

**Agentic loop:**

```
User message + graph context
       ↓
Claude reasons about target
       ↓
Claude emits tool_use (e.g., run_nmap)
       ↓
Orchestrator validates scope
       ↓
If risk level is invasive → send approval request to user
If risk level is passive/active → execute immediately
       ↓
Tool executes in Docker container
       ↓
Results returned to Claude as tool_result
       ↓
Claude analyzes results, suggests next steps
       ↓
Claude may emit another tool_use (loop continues)
       ↓
Claude provides final analysis to user
```

**Script generation safety:**

1. Claude generates script via `generate_script` tool
2. Script content displayed in chat with syntax highlighting
3. Static analysis: check for dangerous patterns (os.system, eval, hardcoded creds)
4. User reviews and approves (always required for custom scripts)
5. Script written to container's /tmp and executed
6. Output streamed back to chat and terminal

---

## 11. 3D Scene Specification

### 11.1 Node Visual Encoding

| Node Type | Geometry                    | Base Color        | Size (radius) | Icon |
| --------- | --------------------------- | ----------------- | ------------- | ---- |
| Target    | IcosahedronGeometry(3.5, 2) | #ff3344 (red)     | 3.5           | 🎯   |
| Local     | IcosahedronGeometry(2, 1)   | #00ff88 (green)   | 2             | 💻   |
| Gateway   | OctahedronGeometry(3, 0)    | #00f0ff (cyan)    | 3             | 📡   |
| DNS       | TetrahedronGeometry(2, 0)   | #f0ff00 (yellow)  | 2             | 📖   |
| CDN       | BoxGeometry(2.5)            | #ff8844 (orange)  | 2.5           | ☁    |
| Remote    | IcosahedronGeometry(1.2, 1) | #ff00c8 (magenta) | 1.2           | 🌐   |

**Target nodes are visually distinct** — larger, red, more detailed geometry. They represent in-scope hosts actively being assessed.

**Dynamic sizing:** Base radius × `clamp(log2(pps + 1) / 4, 0.5, 3.0)`.

**Material:** `MeshStandardMaterial` with emissive matching color, emissiveIntensity pulses on activity, metalness 0.8, roughness 0.2.

**Selection ring:** Hidden `RingGeometry` child, becomes visible (opacity 0.4, pulsing) when node is selected.

### 11.2 Sub-Node Visual Encoding

See §4.3.3 for detailed specification. Sub-nodes orbit parent hosts:

| Severity | Color   | Size | Pulse Speed   |
| -------- | ------- | ---- | ------------- |
| Critical | #ff0040 | 1.0  | Fast (3 Hz)   |
| High     | #ff6600 | 0.8  | Medium (2 Hz) |
| Medium   | #ffe600 | 0.6  | Slow (1 Hz)   |
| Low      | #39ff14 | 0.5  | None          |
| Info     | #00b0ff | 0.5  | None          |

### 11.3 Edge, Particle, Camera, and Postprocessing

**Identical to v1.0 spec** sections §8.2–8.5. See CYBERSPACE_PRODUCT_SPEC.md for complete details.

---

## 12. Spatial Interaction System

### 12.1 Interaction Modes

| Input                    | Handler         | Result                                                           |
| ------------------------ | --------------- | ---------------------------------------------------------------- |
| Left-click node          | Select          | Detail panel updates, selection ring appears, camera orbits node |
| Right-click node         | Radial menu     | Circular context menu with tool actions                          |
| Left-click background    | Deselect        | Clear selection, hide detail panel actions                       |
| Hover node               | Tooltip         | IP, hostname, status, connection count                           |
| Hover sub-node           | Sub-tooltip     | Port number, service, CVE ID, severity                           |
| Mouse wheel              | Zoom            | OrbitControls zoom, update zoom indicator                        |
| Click node in left panel | Select + focus  | Camera flies to node, selects it                                 |
| Cmd+K                    | Command palette | Search tools, targets, actions                                   |
| Right-click background   | No action       | Dismiss any open radial menu                                     |

### 12.2 How Tool Results Map to 3D Space

This is the core cyberdeck innovation — tool execution has spatial consequences.

**Port scan (nmap) → Sub-nodes:**

```
Before scan:                After scan:
    ┌───┐                      ●22 SSH
    │ 🎯 │                   ● 80 HTTP ─── ┌───┐ ─── ●443 HTTPS
    └───┘                      │ 🎯 │
                                └───┘ ─── ●3306 MySQL
                              ●8080 Proxy
                                ●6379 Redis
```

Each open port becomes a sub-node orbiting the host. Size and color encode vulnerability severity.

**Vulnerability scan (nuclei) → Sub-node upgrades:**
Existing port sub-nodes change color to reflect discovered vulnerabilities. New vulnerability-specific sub-nodes may be added. Critical vulnerabilities pulse with oscillating emissive intensity.

**Directory brute force (gobuster) → Sub-nodes on web ports:**
Discovered directories become sub-sub-nodes orbiting the relevant port sub-node (e.g., `/admin` orbits the port 80 sub-node).

**DNS enumeration → New main nodes:**
Discovered hostnames and their resolved IPs become new main nodes in the graph, connected by DNS resolution edges.

---

## 13. UI/UX Specification

### 13.1 Layout

```
┌──────────────────────────────────────────────────────────────────┐
│  TOPBAR: Logo | Scope Badge | Divider | Running Tools | Stats   │
│          | Cmd+K Hint                                            │
├─────────┬───────────────────────────────────────┬────────────────┤
│         │                                       │ DETAIL CARD    │
│ TOOLBOX │         3D VIEWPORT                   │ (selected node)│
│         │         (force-directed graph          │ ─────────────  │
│ PROTOCOL│          with sub-nodes,              │ AI CHAT        │
│ FILTERS │          particles, bloom)            │ (messages,     │
│         │                                       │  tool calls,   │
│ TARGET  │                                       │  approvals,    │
│ LIST    │                                       │  code blocks)  │
│         ├───────────────────────────────────────│                │
│         │ TERMINAL (xterm.js)                   │                │
│         │ Tab: Terminal | Traffic | Packets      │                │
└─────────┴───────────────────────────────────────┴────────────────┘
```

Grid: `grid-template-columns: 260px 1fr 340px; grid-template-rows: 48px 1fr 220px;`

### 13.2 Keyboard Shortcuts

| Key                | Action                                      |
| ------------------ | ------------------------------------------- |
| `Cmd+K` / `Ctrl+K` | Open command palette                        |
| `Escape`           | Close palette / radial menu / deselect node |
| `Space`            | Toggle auto-rotate                          |
| `R`                | Reset camera to default position            |
| `F`                | Focus camera on selected node               |
| `/`                | Focus terminal input                        |
| `G`                | Toggle grid visibility                      |
| `B`                | Toggle bloom on/off                         |
| `1-4`              | Switch view modes                           |
| `Ctrl+C`           | Cancel running tool (when terminal focused) |

### 13.3 Component Specifications

See §4.3.4–4.3.7 for detailed component specs:

- Radial context menu (§4.3.4)
- Terminal manager (§4.3.5)
- Command palette (§4.3.6)
- AI chat renderer (§4.3.7)

---

## 14. Command Interface Layer

### 14.1 Terminal Commands

| Command                   | Description                         | Example                                  |
| ------------------------- | ----------------------------------- | ---------------------------------------- |
| `help` or `?`             | Show available commands             | `help`                                   |
| `scope`                   | Display current engagement scope    | `scope`                                  |
| `targets`                 | List active target nodes            | `targets`                                |
| `nmap <target> [flags]`   | Run port scan                       | `nmap 10.10.11.234 -sV -sC`              |
| `nuclei <target> [flags]` | Run vulnerability scan              | `nuclei 10.10.11.234 -severity critical` |
| `gobuster <url> [flags]`  | Directory brute force               | `gobuster http://10.10.11.234`           |
| `whois <target>`          | WHOIS lookup                        | `whois 10.10.11.234`                     |
| `dig <domain> [type]`     | DNS lookup                          | `dig example.com ANY`                    |
| `traceroute <target>`     | Trace network path                  | `traceroute 10.10.11.234`                |
| `ai <prompt>`             | Send query to AI operator           | `ai suggest next steps for 10.10.11.234` |
| `jobs`                    | List running/completed tool jobs    | `jobs`                                   |
| `cancel <jobId>`          | Cancel a running tool               | `cancel abc123`                          |
| `clear`                   | Clear terminal output               | `clear`                                  |
| `export <format>`         | Export investigation data (Phase 2) | `export json`                            |

### 14.2 AI Chat Commands

Type in the AI chat input or prefix with `ai` in terminal:

| Pattern                       | AI Behavior                                         |
| ----------------------------- | --------------------------------------------------- |
| `scan <target>`               | Plans and executes port scan                        |
| `enumerate <target>`          | Runs service enumeration suite                      |
| `find vulns on <target>`      | Runs vulnerability scan, analyzes results           |
| `create a script to <task>`   | Generates custom Python/Bash script                 |
| `what should I try next?`     | Analyzes current discoveries, suggests next actions |
| `explain CVE-XXXX-XXXXX`      | Provides CVE details and exploitation context       |
| `how do I exploit <service>?` | Suggests exploitation approaches (with scope check) |
| `summarize findings`          | Generates summary of all discoveries for the target |

---

## 15. Visual Design System

### 15.1 Color Palette

```css
:root {
  /* Primary */
  --cyan: #00f0ff;
  --cyan-dim: #00f0ff44;
  --cyan-dark: #00f0ff15;
  --magenta: #ff00c8;
  --magenta-dim: #ff00c844;
  --yellow: #f0ff00;
  --green: #00ff88;
  --green-dim: #00ff8844;
  --red: #ff3344;
  --red-dim: #ff334444;
  --orange: #ff8844;
  --purple: #aa88ff;

  /* Vulnerability severity */
  --vuln-critical: #ff0040;
  --vuln-high: #ff6600;
  --vuln-medium: #ffe600;
  --vuln-low: #39ff14;
  --vuln-info: #00b0ff;

  /* Backgrounds */
  --bg: #0a0a0f;
  --bg-elevated: #0e0e18;
  --panel: #0d0d1acc;
  --panel-solid: #0d0d1a;
  --panel-border: #00f0ff18;

  /* Text */
  --text: #c0d0e0;
  --text-dim: #506070;
  --text-bright: #e8f0ff;
}
```

### 15.2 Protocol Colors

| Protocol | Color   | Hex     |
| -------- | ------- | ------- |
| TCP      | Cyan    | #00f0ff |
| UDP      | Magenta | #ff00c8 |
| DNS      | Yellow  | #f0ff00 |
| TLS      | Green   | #00ff88 |
| HTTP     | Orange  | #ff8844 |
| QUIC     | Purple  | #aa88ff |
| ICMP     | Red     | #ff3344 |

### 15.3 Typography

| Use                       | Font            | Weight    | Size       |
| ------------------------- | --------------- | --------- | ---------- |
| Logo, section titles      | Orbitron        | 900 / 400 | 14px / 8px |
| Code, terminal, IPs, data | JetBrains Mono  | 300-700   | 10-14px    |
| Monospace fallback        | Share Tech Mono | 400       | 10-14px    |
| UI labels, buttons, body  | Rajdhani        | 300-700   | 11-16px    |

### 15.4 Panel Styling

- Background: `#0d0d1acc` with `backdrop-filter: blur(20px)`
- Border: 1px solid `#00f0ff18`
- Scrollbars: 4px wide, `#00f0ff44` thumb
- All panels: frosted glass over 3D viewport

---

## 16. Safety & Scope Architecture

### 16.1 Scope Configuration (scope.yaml)

```yaml
engagement:
  name: "Lab Network Assessment"
  startDate: "2026-02-26T00:00:00Z"
  endDate: "2026-03-26T23:59:59Z"
  authorizedBy: "admin@lab.internal"

allowedCidrs:
  - "10.10.11.0/24"

allowedDomains:
  - "*.lab.internal"

restrictions:
  allowActiveScanning: true
  allowExploitation: false # Set to true only with written authorization
  allowBruteForce: false
  allowDoS: false
  maxConcurrentScans: 5

# blockedCidrs are always applied (127.0.0.0/8, 169.254.0.0/16, etc.)
```

### 16.2 Enforcement Layers

1. **Application layer:** ScopeValidator checks every tool.execute request
2. **Container layer:** iptables rules in container's network namespace block out-of-scope IPs
3. **DNS guard:** Hostnames resolved and verified before execution; re-checked for DNS rebinding
4. **Audit layer:** All actions logged regardless of scope validation result
5. **UI layer:** Scope badge always visible, scope violations show red toast

### 16.3 Risk Levels and Approval Gates

| Risk Level | Examples                                  | Approval Required             |
| ---------- | ----------------------------------------- | ----------------------------- |
| Passive    | WHOIS, DNS lookup, Shodan API             | None                          |
| Active     | Port scan, service enum, vuln scan        | None (within scope)           |
| Invasive   | Exploitation, brute force, custom scripts | Always (human clicks Approve) |

### 16.4 Legal First-Run Flow

On first launch, display a consent screen requiring the user to:

1. Acknowledge that all tools must only be used against authorized targets
2. Confirm they have written authorization for the defined scope
3. Accept the audit logging policy
4. Enter their name for audit attribution

---

## 17. Performance Budgets

### 17.1 Rendering Targets

| Metric         | Phase 1 | Phase 2 | Phase 3  |
| -------------- | ------- | ------- | -------- |
| Target FPS     | 60      | 60      | 60       |
| Max main nodes | 500     | 5,000   | 50,000+  |
| Max edges      | 1,000   | 15,000  | 100,000+ |
| Max sub-nodes  | 500     | 5,000   | 50,000+  |
| Max particles  | 2,000   | 10,000  | 100,000+ |
| Draw calls     | <100    | <20     | <10      |

### 17.2 Network Budget

| Metric                      | Budget            |
| --------------------------- | ----------------- |
| Capture WS frame size       | 1–10 KB           |
| Capture WS bandwidth        | <600 KB/sec       |
| Orchestrator WS tool output | <1 MB/sec per job |
| AI response streaming       | <100 KB/sec       |

### 17.3 Tool Execution Budget

| Metric                    | Budget      |
| ------------------------- | ----------- |
| Container startup time    | <2 seconds  |
| Output streaming latency  | <100ms      |
| Max concurrent containers | 5           |
| Container memory          | 2GB max     |
| Container timeout         | 300 seconds |

---

## 18. Testing Strategy

### 18.1 Capture Agent (Rust)

Unit tests for: parser (5-tuple extraction), flow (creation/update/expiration), graph (delta computation), protocol (MessagePack round-trip). **Identical to v1.0 spec.**

### 18.2 Orchestrator (Node.js)

| Test                      | What it validates                                            |
| ------------------------- | ------------------------------------------------------------ |
| `tool-runner.test.ts`     | Container lifecycle, output streaming, timeout, cancellation |
| `scope-validator.test.ts` | CIDR matching, DNS resolution, blocklist, time window        |
| `result-parser.test.ts`   | nmap XML parsing, nuclei JSON parsing, edge cases            |
| `ai-operator.test.ts`     | Claude tool_use handling, agentic loop, error recovery       |
| `audit-logger.test.ts`    | Hash chain integrity, entry formatting, rotation             |

### 18.3 Web Client (TypeScript)

| Test                        | What it validates                                        |
| --------------------------- | -------------------------------------------------------- |
| `state-manager.test.ts`     | Apply snapshot/delta, add discoveries, sub-node creation |
| `result-visualizer.test.ts` | Discovery → 3D sub-node mapping, severity colors         |
| `prompt-detector.test.ts`   | Natural language vs command detection                    |
| `scope-validator.test.ts`   | Client-side scope display and validation cache           |

### 18.4 Integration Tests

| Scenario          | Steps                                                                                      |
| ----------------- | ------------------------------------------------------------------------------------------ |
| End-to-end scan   | Start all services → trigger nmap from UI → verify terminal output + sub-nodes + audit log |
| AI tool execution | Send AI message → Claude returns tool_use → verify tool executes and results render        |
| Scope rejection   | Configure scope → attempt out-of-scope scan → verify rejection in UI and audit log         |
| Container timeout | Run tool that exceeds timeout → verify container killed and error reported                 |
| Reconnection      | Kill capture agent → verify reconnection and state recovery                                |

### 18.5 Manual Test Scenarios

1. **Cold start:** All services start clean, first WebSocket connections, initial graph renders
2. **High traffic:** `iperf3` or `hping3` flood → verify 60fps maintained
3. **Scan storm:** Run 5 concurrent nmap scans → verify container management
4. **AI multi-step:** Ask AI to enumerate a target → verify it chains multiple tools
5. **Scope violation:** Attempt to scan 8.8.8.8 with scope restricted to 10.x → verify blocked
6. **Mock mode:** `?mock=true` → verify full UI works without any backend services

---

## 19. Deployment

### 19.1 Development

```bash
# Terminal 1: Start capture agent
cd capture-agent
cargo build --release
sudo ./target/release/cyberspace-capture -i en0

# Terminal 2: Build and start tool Docker image
cd orchestrator/docker
docker build -t cyberdeck-tools -f Dockerfile.tools .

# Terminal 3: Start orchestrator
cd orchestrator
cp .env.example .env              # Set ANTHROPIC_API_KEY
pnpm install
pnpm dev

# Terminal 4: Start web client
cd web-client
pnpm install
pnpm dev
# Opens http://localhost:5173

# OR: Development without any backend
# http://localhost:5173?mock=true
```

### 19.2 Docker Compose (Full Stack)

```yaml
# docker-compose.yml
version: "3.8"
services:
  capture-agent:
    build: ./capture-agent
    network_mode: host
    cap_add:
      - NET_RAW
      - NET_ADMIN
    environment:
      - INTERFACE=eth0
      - WS_PORT=9900

  orchestrator:
    build: ./orchestrator
    ports:
      - "9901:9901"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock # Docker-in-Docker
      - ./scope.yaml:/app/scope.yaml
      - ./audit:/app/audit
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - CAPTURE_WS_URL=ws://host.docker.internal:9900

  web-client:
    build: ./web-client
    ports:
      - "8080:80"
    environment:
      - VITE_CAPTURE_WS=ws://localhost:9900
      - VITE_ORCHESTRATOR_WS=ws://localhost:9901
```

### 19.3 Security Notes

- Capture agent requires CAP_NET_RAW or root. Prefer `setcap cap_net_raw=eip` over root.
- Orchestrator needs Docker socket access — run it with appropriate permissions.
- WebSocket ports (9900, 9901) should be bound to 127.0.0.1 for local-only deployment.
- ANTHROPIC_API_KEY must be set in environment, never committed to repo.
- Audit logs should be backed up to WORM storage for compliance.
- The Docker tool image should be rebuilt weekly for latest vulnerability templates.

---

## Appendix A: Build Order

### Week 1: Capture Agent + Orchestrator Shell

1. `capture-agent/` — Identical to v1.0 Week 1. Captures packets, emits MessagePack over WS.
2. `orchestrator/src/index.ts` — Fastify server, WebSocket handler, basic message routing
3. `orchestrator/src/config.ts` — Configuration constants
4. `orchestrator/src/scope/scope-validator.ts` — CIDR validation
5. `orchestrator/src/scope/audit-logger.ts` — Append-only JSON log
6. `orchestrator/docker/Dockerfile.tools` — Build Kali tool image

**Test:** Capture agent emits packets. Orchestrator starts and accepts WS connections. Scope validation works.

### Week 2: Tool Execution Engine

1. `orchestrator/src/tools/tool-registry.ts` — All tool definitions
2. `orchestrator/src/tools/tool-runner.ts` — Docker container management + output streaming
3. `orchestrator/src/tools/result-parser.ts` — nmap XML + nuclei JSON parsers
4. `orchestrator/src/tools/job-manager.ts` — Job lifecycle, status tracking
5. `orchestrator/src/api/ws-handler.ts` — Full message routing (tool.execute → tool.output → tool.completed)

**Test:** Send `tool.execute` via WebSocket → nmap runs in Docker → output streams back → structured results parsed.

### Week 3: Web Client Core

1. Vite + TypeScript project setup
2. `web-client/src/types.ts` — All shared types
3. `web-client/src/network/capture-client.ts` — Connect to capture agent
4. `web-client/src/network/orchestrator-client.ts` — Connect to orchestrator
5. `web-client/src/network/state-manager.ts` — Zustand store with all slices
6. `web-client/src/network/mock-data.ts` — Simulated data (?mock=true)
7. `web-client/src/scene/scene-manager.ts` — 3d-force-graph with cyberpunk styling
8. `web-client/src/scene/postprocessing.ts` — Bloom
9. `web-client/src/scene/grid.ts` — Tron ground grid
10. `web-client/src/scene/subnode-renderer.ts` — Orbiting port/vuln sub-nodes

**Test:** `?mock=true` shows 3D graph. Real capture agent shows live traffic. Sub-nodes appear after mock scan.

### Week 4: Interaction + Terminal

1. `web-client/src/interaction/selection.ts` — Raycasting click/right-click
2. `web-client/src/interaction/radial-menu.ts` — Circular context menu
3. `web-client/src/terminal/terminal-manager.ts` — Terminal with command handling
4. `web-client/src/tools/tool-dispatcher.ts` — Route actions to orchestrator
5. `web-client/src/tools/result-visualizer.ts` — Map discoveries to 3D sub-nodes

**Test:** Right-click node → radial menu → "Scan" → terminal shows nmap output → sub-nodes appear in 3D.

### Week 5: AI Integration + Command Palette

1. `orchestrator/src/llm/ai-operator.ts` — Claude API integration with tool schemas
2. `orchestrator/src/llm/tool-schemas.ts` — Tool definitions for Claude
3. `orchestrator/src/llm/context-builder.ts` — Build target context from graph
4. `web-client/src/ai/chat-manager.ts` — Conversation state
5. `web-client/src/ai/chat-renderer.ts` — Chat UI with tool call rendering
6. `web-client/src/ui/command-palette.ts` — Cmd+K fuzzy search

**Test:** Type in AI chat → Claude responds → Claude suggests scan → tool executes → results in chat + 3D.

### Week 6: Polish + UI Panels

1. All UI panels (top bar, left panel, right panel detail card, bottom panel tabs)
2. Toast notifications
3. HUD overlays
4. Loading screen with consent flow
5. Scope badge and configuration
6. Keyboard shortcuts
7. Reconnection handling
8. Performance profiling
9. Edge cases (no Docker, no API key, scope violation, container timeout)

**Test:** Full end-to-end workflow. All Definition of Done items checked.

---

## Appendix B: Reference Commands

```bash
# Build the tool Docker image
cd orchestrator/docker
docker build -t cyberdeck-tools -f Dockerfile.tools .

# Test the tool image manually
docker run --rm -it cyberdeck-tools nmap --version
docker run --rm -it cyberdeck-tools nuclei --version

# Generate sample PCAP
sudo tcpdump -i en0 -c 1000 -w fixtures/sample.pcap

# Test scope validation
curl -X POST http://localhost:9901/api/scope/validate \
  -H 'Content-Type: application/json' \
  -d '{"target": "10.10.11.234"}'

# Test tool execution directly
wscat -c ws://localhost:9901 \
  -x '{"type":"tool.execute","requestId":"test1","payload":{"toolId":"nmap-scan","params":{"target":"10.10.11.234"}}}'

# Test RIPE RIS Live (Phase 2)
wscat -c wss://ris-live.ripe.net/v1/ws/ \
  -x '{"type":"ris_subscribe","data":{"type":"UPDATE"}}'

# Team Cymru ASN lookup
dig +short TXT 8.8.8.8.origin.asn.cymru.com
```

---

_End of specification. Build the cyberdeck._
