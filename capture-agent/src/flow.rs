use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config;
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
    pub bytes_forward: u64, // lower_ip -> upper_ip
    pub bytes_reverse: u64, // upper_ip -> lower_ip
    pub first_seen: u64,
    pub last_seen: u64,
}

#[derive(Default)]
pub struct FlowAggregator {
    flows: HashMap<FlowKey, FlowState>,
}

impl FlowAggregator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn process_packet(&mut self, pkt: &ParsedPacket) {
        let key = FlowKey::from_packet(pkt);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_millis() as u64;

        // Enforce MAX_FLOWS: evict stale flows if at capacity
        if !self.flows.contains_key(&key) && self.flows.len() >= config::MAX_FLOWS {
            self.evict_stale(config::FLOW_TIMEOUT_SEC * 1000);
            if self.flows.len() >= config::MAX_FLOWS {
                tracing::warn!("MAX_FLOWS limit ({}) reached, dropping new flow", config::MAX_FLOWS);
                return;
            }
        }

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

    /// Remove flows older than timeout_ms
    pub fn evict_stale(&mut self, timeout_ms: u64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_millis() as u64;
        self.flows
            .retain(|_, flow| now.saturating_sub(flow.last_seen) < timeout_ms);
    }
}
