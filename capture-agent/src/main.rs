use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use clap::Parser;

mod config;
mod capture;
mod parser;
mod flow;
mod graph;
mod protocol;
mod websocket;

#[derive(Parser, Debug)]
#[command(name = "cyberspace-capture", about = "Cyberdeck network capture agent")]
struct Args {
    #[arg(short, long, default_value = "en0")]
    interface: String,
    #[arg(short, long, default_value_t = 9900)]
    port: u16,
    #[arg(short, long, default_value = "")]
    filter: String,
}

fn main() {
    let args = Args::parse();
    tracing_subscriber::fmt::init();
    tracing::info!("Cyberdeck capture agent v0.1.0");

    if !nix_check_root() {
        tracing::error!("Requires root privileges. Run with sudo.");
        std::process::exit(1);
    }

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async move {
        let graph = Arc::new(RwLock::new(graph::GraphBuilder::new()));
        let (tx, mut rx) = mpsc::channel::<parser::ParsedPacket>(10_000);

        // Start packet capture
        let iface = args.interface.clone();
        let filter = args.filter.clone();
        capture::start_capture(&iface, &filter, tx)
            .await
            .expect("Failed to start capture");

        // Process packets -> graph
        let graph_writer = graph.clone();
        tokio::spawn(async move {
            while let Some(pkt) = rx.recv().await {
                let mut g = graph_writer.write().await;
                g.process_packet(&pkt);
            }
        });

        // Start WebSocket server (blocks)
        websocket::start_ws_server(args.port, graph)
            .await
            .expect("WebSocket server failed");
    });
}

fn nix_check_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}
