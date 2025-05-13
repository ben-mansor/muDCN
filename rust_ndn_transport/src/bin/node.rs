//
// μDCN Node: Main entry point for the Rust NDN transport layer
//
// This binary implements a stand-alone NDN node with QUIC-based transport.
//

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use structopt::StructOpt;
use tokio::signal;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

use udcn_transport::{Config, UdcnTransport};
use udcn_transport::cache::ContentStore;
use udcn_transport::name::Name;
use udcn_transport::ndn::{Data, Interest};

/// μDCN Node: High-performance NDN transport with QUIC
#[derive(StructOpt, Debug)]
#[structopt(name = "udcn-node")]
struct Opt {
    /// Address to listen on
    #[structopt(short, long, default_value = "0.0.0.0:6363")]
    address: String,
    
    /// Content store capacity
    #[structopt(short, long, default_value = "10000")]
    cache_size: usize,
    
    /// MTU size in bytes
    #[structopt(short, long, default_value = "1400")]
    mtu: usize,
    
    /// Metrics port
    #[structopt(short, long, default_value = "9090")]
    metrics_port: u16,
    
    /// Enable debug logging
    #[structopt(short, long)]
    debug: bool,
    
    /// Path to certificate file
    #[structopt(long)]
    cert: Option<PathBuf>,
    
    /// Path to private key file
    #[structopt(long)]
    key: Option<PathBuf>,
}

/// Main entry point
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let opt = Opt::from_args();
    
    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(if opt.debug { Level::DEBUG } else { Level::INFO })
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set tracing subscriber");
    
    info!("μDCN Node starting up");
    
    // Create configuration
    let config = Config {
        mtu: opt.mtu,
        cache_capacity: opt.cache_size,
        idle_timeout: 30,
        bind_address: opt.address.clone(),
        enable_metrics: true,
        metrics_port: opt.metrics_port,
    };
    
    info!("Configuration: {:?}", config);
    
    // Initialize the transport layer
    let transport = UdcnTransport::new(config).await?;
    
    // Register a sample prefix for testing
    transport.register_prefix(
        Name::from("/udcn/test"),
        Box::new(|interest| {
            // Simple echo handler
            let name = interest.name().clone();
            let content = format!("Echo for {}", name);
            Ok(Data::new(name, content.into_bytes()))
        }),
    ).await?;
    
    // Start the transport layer
    transport.start().await?;
    
    info!("μDCN Node running on {}", opt.address);
    info!("Press Ctrl+C to exit");
    
    // Wait for Ctrl+C
    match signal::ctrl_c().await {
        Ok(()) => {
            info!("Shutting down μDCN Node");
            transport.shutdown().await?;
        }
        Err(e) => {
            error!("Failed to listen for Ctrl+C: {}", e);
        }
    }
    
    Ok(())
}
