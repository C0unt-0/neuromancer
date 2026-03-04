use clap::Parser;

mod config;
mod flow;
mod parser;
mod protocol;

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
    tracing::info!("Cyberdeck capture agent starting on interface {}", args.interface);

    if !nix_check_root() {
        tracing::error!("Capture agent requires root privileges. Run with sudo.");
        std::process::exit(1);
    }

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        tracing::info!("WebSocket server will listen on port {}", args.port);
    });
}

fn nix_check_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}
