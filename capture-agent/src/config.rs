/// Capture agent configuration constants
pub const WS_PORT: u16 = 9900;
pub const DELTA_INTERVAL_MS: u64 = 500;
pub const FLOW_TIMEOUT_SEC: u64 = 30;
pub const MAX_FLOWS: usize = 100_000;
pub const MAX_NODES: usize = 10_000;
pub const CAPTURE_BUFFER_SIZE: i32 = 16 * 1024 * 1024; // 16MB
pub const SNAPLEN: i32 = 96; // Enough for headers
