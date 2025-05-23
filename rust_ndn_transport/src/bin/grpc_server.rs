use std::sync::Arc;
use std::net::SocketAddr;
use tonic::transport::Server;
use udcn_transport::UdcnTransport;
use udcn_transport::grpc::{udcn::udcn_control_server::UdcnControlServer, UdcnControlService};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "udcn-grpc-server", about = "gRPC server for µDCN transport")]
struct Opt {
    /// Listen address
    #[structopt(short, long, default_value = "127.0.0.1")]
    address: String,
    
    /// Listen port
    #[structopt(short, long, default_value = "50051")]
    port: u16,
    
    /// Enable debug logging
    #[structopt(short, long)]
    debug: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let opt = Opt::from_args();
    
    // Setup logging
    if opt.debug {
        std::env::set_var("RUST_LOG", "debug");
    } else {
        std::env::set_var("RUST_LOG", "info");
    }
    tracing_subscriber::fmt::init();
    
    // Log startup information
    tracing::info!("Starting µDCN gRPC server on {}:{}", opt.address, opt.port);
    
    // Create the transport instance
    let transport = Arc::new(UdcnTransport::new().await?);
    
    // Create server instance
    let service = UdcnControlService::new(transport);
    
    // Create socket address
    let addr = format!("{}:{}", opt.address, opt.port).parse::<SocketAddr>()?;
    
    // Start the server
    Server::builder()
        .add_service(UdcnControlServer::new(service))
        .serve(addr)
        .await?;
    
    Ok(())
}
