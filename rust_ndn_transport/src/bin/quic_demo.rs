use std::sync::Arc;
use std::time::Duration;

use tokio::time;
use tracing::{info, Level};
use rust_ndn_transport::error::Result;
use rust_ndn_transport::ndn::{Data, Interest};
use rust_ndn_transport::name::Name;
use rust_ndn_transport::quic_transport::QuicTransport;
use clap::Parser;

#[derive(Debug, Parser)]
#[clap(name = "quic-demo", about = "Demonstrate QUIC transport for NDN")]
enum Opt {
    /// Run as a server
    #[clap(name = "server")]
    Server {
        /// Bind address
        #[clap(short, long, default_value = "127.0.0.1")]
        addr: String,
        
        /// Port to listen on
        #[clap(short, long, default_value = "6363")]
        port: u16,
    },
    
    /// Run as a client
    #[clap(name = "client")]
    Client {
        /// Server address
        #[clap(short, long, default_value = "127.0.0.1")]
        addr: String,
        
        /// Server port
        #[clap(short, long, default_value = "6363")]
        port: u16,
        
        /// NDN name to request
        #[clap(short, long, default_value = "/example/data")]
        name: String,
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();
    
    // Parse command line arguments
    let opt = Opt::from_args();
    
    match opt {
        Opt::Server { addr, port } => {
            run_server(&addr, port).await?;
        },
        Opt::Client { addr, port, name } => {
            run_client(&addr, port, &name).await?;
        }
    }
    
    Ok(())
}

async fn run_server(addr: &str, port: u16) -> Result<()> {
    info!("Starting QUIC server on {}:{}", addr, port);
    
    // Create QUIC transport
    let mut transport = QuicTransport::new(addr, port, 30, 65535).await?;
    
    // Register handler for example prefix
    let example_prefix = Name::from_uri("/example")?;
    
    transport.register_handler(example_prefix, move |interest| {
        info!("Received Interest: {}", interest.name());
        
        // Prepare response data
        let data_content = format!("Hello from QUIC server! You requested: {}", interest.name());
        
        // Create Data packet
        let mut data = Data::new(interest.name().clone());
        data.set_content(data_content.as_bytes().to_vec());
        data.set_content_type(0); // Content type: BLOB
        data.set_freshness_period_ms(10000); // 10 seconds
        
        Ok(data)
    }).await?;
    
    // Start the server
    transport.start_server().await?;
    
    info!("Server running. Press Ctrl+C to stop.");
    
    // Keep the server running
    tokio::signal::ctrl_c().await?;
    
    // Shutdown
    info!("Shutting down server...");
    transport.shutdown().await?;
    
    Ok(())
}

async fn run_client(addr: &str, port: u16, name_str: &str) -> Result<()> {
    info!("Starting QUIC client to connect to {}:{}", addr, port);
    
    // Create QUIC transport
    // Use a different port for the client
    let transport = QuicTransport::new("0.0.0.0", 0, 30, 65535).await?;
    
    // Connect to the server
    let remote_addr = format!("{}:{}", addr, port).parse()?;
    let conn_tracker = transport.connect(addr, port).await?;
    
    info!("Connected to server. Sending Interest...");
    
    // Prepare Interest packet
    let name = Name::from_uri(name_str)?;
    let mut interest = Interest::new(name);
    interest.set_can_be_prefix(false);
    interest.set_must_be_fresh(true);
    interest.set_lifetime_ms(4000); // 4 seconds
    
    // Send Interest and wait for Data
    let start = std::time::Instant::now();
    let data = transport.send_interest(remote_addr, interest).await?;
    let rtt = start.elapsed().as_millis();
    
    // Display result
    info!("Received Data:");
    info!("  Name: {}", data.name());
    info!("  Content Type: {}", data.content_type());
    info!("  Freshness: {}ms", data.freshness_period_ms());
    
    let content = String::from_utf8_lossy(&data.content());
    info!("  Content: {}", content);
    info!("  RTT: {}ms", rtt);
    
    // Get connection stats
    if let Some(stats) = transport.get_connection_stats(remote_addr).await {
        info!("Connection Statistics:");
        info!("  RTT: {}ms", stats.rtt_ms);
        info!("  Data Received: {}", stats.data_received);
        info!("  Avg Data Size: {} bytes", stats.avg_data_size);
    }
    
    // Close connection
    transport.close_connection(remote_addr).await?;
    
    Ok(())
}
