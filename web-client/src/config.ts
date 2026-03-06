export const CONFIG = {
  CAPTURE_WS_URL: "ws://localhost:9900",
  ORCHESTRATOR_WS_URL: "ws://localhost:9901/ws",
  MOCK_MODE: new URLSearchParams(window.location.search).has("mock"),
} as const;

// Protocol color mapping (matches capture agent wire format)
export const PROTOCOL_COLORS: Record<string, string> = {
  TCP: "#00f0ff",
  UDP: "#ff00c8",
  DNS: "#f0ff00",
  TLS: "#00ff88",
  HTTP: "#ff8844",
  QUIC: "#aa88ff",
};

// Node type → visual properties
export const NODE_COLORS: Record<string, number> = {
  target: 0xff3344,
  router: 0x00f0ff,
  local: 0x00ff88,
  dns: 0xf0ff00,
  cdn: 0xff8844,
  remote: 0xff00c8,
};

export const NODE_ICONS: Record<string, string> = {
  target: "\u{1F3AF}", // 🎯
  router: "\u{1F4E1}", // 📡
  local: "\u{1F4BB}",  // 💻
  dns: "\u{1F4D6}",    // 📖
  cdn: "\u{2601}",     // ☁
  remote: "\u{1F310}", // 🌐
};

// Vulnerability severity → color
export const VULN_COLORS: Record<string, number> = {
  critical: 0xff0040,
  high: 0xff6600,
  medium: 0xffe600,
  low: 0x39ff14,
  info: 0x00b0ff,
};

// Vulnerability severity → sub-node radius
export const VULN_SIZES: Record<string, number> = {
  critical: 1.0,
  high: 0.8,
  medium: 0.6,
  low: 0.5,
  info: 0.5,
};
