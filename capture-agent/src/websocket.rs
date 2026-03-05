use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;
use futures_util::{SinkExt, StreamExt};

use crate::config;
use crate::graph::GraphBuilder;

pub async fn start_ws_server(
    port: u16,
    graph: Arc<RwLock<GraphBuilder>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    tracing::info!("WebSocket server listening on port {}", port);

    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::error!("Failed to accept connection: {}", e);
                continue;
            }
        };
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

            // Send initial snapshot — extract data inside lock, serialize outside
            let snapshot = {
                let mut g = graph.write().await;
                g.snapshot()
            }; // lock dropped here
            let data = match rmp_serde::to_vec(&snapshot) {
                Ok(d) => d,
                Err(e) => {
                    tracing::error!("Failed to serialize snapshot: {}", e);
                    return;
                }
            };
            if write.send(Message::Binary(data)).await.is_err() {
                return;
            }

            // Send deltas at fixed interval
            let mut tick = interval(Duration::from_millis(config::DELTA_INTERVAL_MS));
            loop {
                tick.tick().await;

                // Extract delta inside lock, serialize outside
                let delta = {
                    let mut g = graph.write().await;
                    g.delta()
                }; // lock dropped here

                // Only send if there are actual changes
                if delta.nodes_added.is_empty()
                    && delta.nodes_updated.is_empty()
                    && delta.edges_added.is_empty()
                    && delta.edges_updated.is_empty()
                    && delta.packet_events.is_empty()
                {
                    continue;
                }

                let data = match rmp_serde::to_vec(&delta) {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::error!("Failed to serialize delta: {}", e);
                        continue;
                    }
                };
                if write.send(Message::Binary(data)).await.is_err() {
                    tracing::info!("Client {} disconnected", addr);
                    break;
                }
            }
        });
    }
}
