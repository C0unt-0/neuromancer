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
                    tracing::info!("Capture pipeline shutting down: receiver dropped");
                    break;
                }
            }
        }
    });

    Ok(())
}
