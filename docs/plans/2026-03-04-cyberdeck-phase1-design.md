# CYBERDECK Phase 1 MVP — Implementation Design

**Date:** 2026-03-04
**Spec:** `spec.md` (v2.0, 2663 lines)
**Mock:** `mock.html` (3010 lines, working Three.js prototype)

---

## Decisions & Deviations from Spec

| Decision | Spec says | We chose | Rationale |
|----------|-----------|----------|-----------|
| 3D rendering | 3d-force-graph (Phase 1) | Raw Three.js | More control, matches mock.html, avoids Phase 2 rewrite |
| Force layout | 3d-force-graph built-in | Custom `force-layout.ts` | ~200 lines, O(n²) fine for 200 nodes, upgradeable |
| Terminal | Simple HTML terminal (Phase 1) | xterm.js + WebGL addon | Handles ANSI/PTY properly, no rewrite later |
| PTY bridge | Phase 2 | Phase 1 (Week 2) | Required for xterm.js to receive real tool output |
| Framework | No React (Phase 1) | Vanilla TS + Zustand | Per spec — React deferred to Phase 2 |

Everything else follows the spec verbatim.

---

## Architecture Overview

Three independent layers connected via WebSocket:

```
┌─────────────────────┐
│  Capture Agent       │  Rust binary (runs as root)
│  Port 9900 (MsgPack) │  libpcap → etherparse → petgraph → WS
└──────────┬──────────┘
           │
┌──────────┴──────────┐
│  Orchestrator        │  Node.js + Fastify v5
│  Port 9901 (JSON)    │  Docker tool exec, Claude AI, scope validation
└──────────┬──────────┘
           │
┌──────────┴──────────┐
│  Web Client          │  TypeScript + Vite + Three.js
│  Browser             │  3D viz, terminal, AI chat, interaction
└─────────────────────┘
```

---

## Project Structure

```
cyberdeck/
├── pnpm-workspace.yaml
├── package.json                    # Root workspace
├── spec.md
├── mock.html
│
├── capture-agent/                  # Rust binary
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs                 # CLI, privilege check, startup
│       ├── capture.rs              # libpcap async packet stream
│       ├── parser.rs               # etherparse zero-copy 5-tuple
│       ├── flow.rs                 # HashMap<FlowKey, FlowState>, 30s timeout
│       ├── graph.rs                # petgraph, delta computation (500ms)
│       ├── enrichment.rs           # Reverse DNS, GeoIP, RFC1918
│       ├── websocket.rs            # tokio-tungstenite, port 9900
│       ├── protocol.rs             # SnapshotFrame, DeltaFrame types
│       └── config.rs               # Constants
│
├── orchestrator/                   # Node.js
│   ├── package.json
│   ├── tsconfig.json
│   └── src/
│       ├── index.ts                # Fastify bootstrap
│       ├── config.ts               # All constants
│       ├── tools/
│       │   ├── tool-registry.ts    # 7 tool defs with Zod schemas
│       │   ├── tool-runner.ts      # Docker container lifecycle
│       │   ├── result-parser.ts    # nmap XML, nuclei JSON → Discovery[]
│       │   ├── job-manager.ts      # Queue, status, rate limiting
│       │   ├── pty-bridge.ts       # node-pty → WebSocket
│       │   └── output-streamer.ts  # Dual stream: raw + structured
│       ├── llm/
│       │   ├── ai-operator.ts      # Claude API, conversation mgmt
│       │   ├── tool-schemas.ts     # Claude tool_use definitions
│       │   ├── context-builder.ts  # Graph context for system prompt
│       │   └── safety-gate.ts      # Human approval for invasive tools
│       ├── scope/
│       │   ├── scope-validator.ts  # CIDR allowlist, DNS rebind guard
│       │   ├── scope-config.ts     # Zod schema, hot-reload
│       │   └── audit-logger.ts     # JSONL + SHA-256 hash chain
│       └── api/
│           ├── ws-handler.ts       # tool.*, ai.*, scope.* routing
│           ├── routes.ts           # REST (health, scope validate)
│           └── middleware.ts       # CORS, rate limiting
│
├── web-client/                     # Browser frontend
│   ├── package.json
│   ├── tsconfig.json
│   ├── vite.config.ts
│   ├── index.html
│   └── src/
│       ├── main.ts                 # Entry point
│       ├── types.ts                # All shared TypeScript types
│       ├── config.ts               # Constants
│       ├── network/
│       │   ├── capture-client.ts   # WS port 9900, MessagePack decode
│       │   ├── orchestrator-client.ts  # WS port 9901, JSON
│       │   ├── state-manager.ts    # Zustand: graph, tools, AI, UI, scope
│       │   └── mock-data.ts        # Simulated data (?mock=true)
│       ├── scene/
│       │   ├── scene-manager.ts    # Three.js scene, camera, renderer
│       │   ├── node-renderer.ts    # Per-node meshes (geometry by type)
│       │   ├── subnode-renderer.ts # Orbiting port/vuln spheres
│       │   ├── edge-renderer.ts    # Protocol-colored lines
│       │   ├── particle-system.ts  # Packet flow animation
│       │   ├── grid.ts             # Tron ground grid
│       │   ├── postprocessing.ts   # Bloom, OutputPass
│       │   └── force-layout.ts     # Custom force-directed (NEW)
│       ├── interaction/
│       │   ├── selection.ts        # Raycasting click/right-click
│       │   ├── radial-menu.ts      # Circular HTML overlay
│       │   ├── camera-controller.ts # OrbitControls + fly-to
│       │   └── keyboard.ts         # Shortcuts
│       ├── terminal/
│       │   ├── terminal-manager.ts # xterm.js + WebGL addon
│       │   └── command-handler.ts  # Local vs tool command routing
│       ├── ai/
│       │   ├── chat-manager.ts     # Conversation state
│       │   └── chat-renderer.ts    # Bubbles, tool calls, approvals
│       ├── tools/
│       │   ├── tool-dispatcher.ts  # → orchestrator tool.execute
│       │   ├── tool-definitions.ts # Client-side icons/colors
│       │   └── result-visualizer.ts # Discovery[] → 3D sub-nodes
│       ├── ui/
│       │   ├── panels/
│       │   │   ├── top-bar.ts
│       │   │   ├── left-panel.ts
│       │   │   ├── right-panel.ts
│       │   │   └── bottom-panel.ts
│       │   ├── command-palette.ts  # Cmd+K fuzzy search
│       │   ├── hud.ts             # Crosshair, brackets, zoom
│       │   └── toast.ts           # Notifications
│       └── utils/
│           ├── color.ts            # Protocol/severity → color
│           ├── format.ts           # Byte/IP/time formatting
│           └── performance.ts      # FPS counter
│
└── docs/
    └── plans/
        └── 2026-03-04-cyberdeck-phase1-design.md  # This document
```

---

## Data Flow

### Flow 1: Live Network Visualization
```
Packets → libpcap → etherparse → flow aggregator → petgraph
→ DeltaFrame (MessagePack) → WS port 9900
→ capture-client.ts → state-manager.ts → node-renderer.ts → Three.js
```

### Flow 2: Tool Execution (e.g., nmap)
```
Right-click node → radial-menu → tool-dispatcher.ts
→ WS 9901: tool.execute {toolId, params}
→ scope-validator (CIDR check) → audit-logger
→ tool-runner → Docker container (nmap)
→ stdout: tool.output → xterm.js terminal
→ completion: result-parser → tool.structured {discoveries[]}
→ result-visualizer → subnode-renderer (orbiting spheres)
```

### Flow 3: AI Chat
```
User types → chat-manager.ts
→ WS 9901: ai.message {text, graphContext}
→ ai-operator → Claude API (streaming + tool_use)
→ ai.chunk → chat-renderer (streaming text)
→ Claude calls tool → safety-gate (risk check)
→ passive/active: auto-execute
→ invasive: approval UI → user approves → execute
→ results fed back to Claude for analysis
```

### Flow 4: Mock Mode (?mock=true)
```
mock-data.ts generates hosts/edges/traffic
→ state-manager populated directly
→ simulated tool results after delay
→ full UI functional without backends
```

---

## Build Sequence

### Week 1: Capture Agent + Orchestrator Shell
- Rust capture agent (all modules)
- Orchestrator: Fastify server, config, scope-validator, audit-logger
- Docker Dockerfile.tools (Kali image with security tools)
- **Test:** Capture agent emits MsgPack over WS. Orchestrator accepts connections. Scope validation works.

### Week 2: Tool Execution Engine
- tool-registry, tool-runner, result-parser, job-manager
- pty-bridge (node-pty → WS), output-streamer
- Full ws-handler message routing
- **Test:** tool.execute → nmap in Docker → stdout streams → structured results parsed.

### Week 3: Web Client Core
- Vite project setup, types, config
- capture-client, orchestrator-client, state-manager, mock-data
- scene-manager, node-renderer, edge-renderer, particle-system
- grid, postprocessing, force-layout, subnode-renderer
- **Test:** ?mock=true shows 3D graph. Live capture shows real traffic. Sub-nodes appear.

### Week 4: Interaction + Terminal
- selection (raycasting), radial-menu, camera-controller, keyboard
- terminal-manager (xterm.js + WebGL), command-handler
- tool-dispatcher, result-visualizer
- **Test:** Right-click → radial menu → Scan → terminal output → sub-nodes orbit host.

### Week 5: AI Integration + Command Palette
- ai-operator, tool-schemas, context-builder, safety-gate
- chat-manager, chat-renderer
- command-palette (Cmd+K)
- **Test:** AI chat → Claude responds → tool executes → results in chat + terminal + 3D.

### Week 6: Polish + UI Panels
- All UI panels (top-bar, left-panel, right-panel, bottom-panel)
- Toast notifications, HUD overlays
- Loading screen with consent flow
- Reconnection handling, performance profiling
- **Test:** Full end-to-end. All Phase 1 Definition of Done items pass.

---

## Phase 1 Definition of Done

- [ ] Rust capture agent runs with `sudo ./cyberspace-capture`
- [ ] Capture agent emits MessagePack frames over WS port 9900
- [ ] Orchestrator starts with `pnpm dev`, WebSocket on port 9901
- [ ] Docker tool image builds with `docker build -t cyberdeck-tools .`
- [ ] Browser connects to both WebSocket endpoints
- [ ] 3D force graph renders live traffic with cyberpunk aesthetics
- [ ] Right-click node → radial menu with 6 actions
- [ ] "Scan" executes nmap in Docker, streams to terminal
- [ ] Scan results spawn orbiting sub-nodes by severity
- [ ] Terminal accepts commands (nmap, nuclei, help, scope, targets)
- [ ] AI chat → Claude API → streaming response
- [ ] AI invokes tools via tool_use, results in chat + terminal
- [ ] Command palette (Cmd+K) shows tools, targets, actions
- [ ] Scope validation blocks out-of-scope targets
- [ ] All tool executions logged to audit trail
- [ ] `?mock=true` works without capture agent or Docker
- [ ] 60fps with 200 nodes / 500 edges / 50 sub-nodes
