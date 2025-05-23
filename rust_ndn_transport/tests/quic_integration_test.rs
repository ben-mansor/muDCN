use std::net::SocketAddr;
use std::time::Duration;

use tokio::time::sleep;
use tonic::transport::Server;

use rust_ndn_transport::error::Result;
use rust_ndn_transport::grpc::udcn::{
    DataPacketResponse, InterestPacketRequest, QuicConnectionRequest, UdcnControlServer,
};
use rust_ndn_transport::grpc::{run_grpc_server, UdcnControlService};
use rust_ndn_transport::grpc_quic_integration::GrpcQuicAdapter;
use rust_ndn_transport::name::Name;
use rust_ndn_transport::ndn::{Data, Interest};
use rust_ndn_transport::quic_transport::QuicTransport;

// Integration test that demonstrates QUIC transport and gRPC working together
#[tokio::test(flavor = "multi_thread")]
async fn test_quic_and_grpc_integration() -> Result<()> {
    // Initialize logging for test
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .try_init();

    // Set up test server
    let server_port = 14300;
    let server_bind_addr = "127.0.0.1";
    let server_addr = format!("{}:{}", server_bind_addr, server_port);

    // Start QUIC server in the background 
    let quic_server = QuicTransport::new(server_bind_addr, server_port, 30, 65535).await?;
    let mut server_clone = quic_server.clone();
    server_clone.start_server().await?;
    
    // Register interest handler for testing
    let test_prefix = Name::from_uri("/test/quic/integration")?;
    server_clone.register_handler(test_prefix.clone(), move |interest| {
        println!("Server received interest: {}", interest.name());
        
        // Create response data
        let mut data = Data::new(interest.name().clone());
        let response_content = format!("QUIC integration test response for {}", interest.name());
        data.set_content(response_content.as_bytes().to_vec());
        data.set_content_type(0); // BLOB
        data.set_freshness_period_ms(1000);
        
        Ok(data)
    }).await?;
    
    // Give server time to initialize
    sleep(Duration::from_millis(100)).await;
    
    // Create QUIC client
    let client_bind_addr = "127.0.0.1";
    let client_port = 14301;
    let client = QuicTransport::new(client_bind_addr, client_port, 30, 65535).await?;
    
    // Connect to server
    let server_socket_addr: SocketAddr = server_addr.parse()?;
    let conn = client.connect(server_bind_addr, server_port).await?;
    
    // Create interest
    let interest_name = Name::from_uri("/test/quic/integration/request1")?;
    let mut interest = Interest::new(interest_name);
    interest.set_can_be_prefix(false);
    interest.set_must_be_fresh(true);
    interest.set_lifetime_ms(4000);
    
    // Send interest and receive data
    let data = client.send_interest(server_socket_addr, interest).await?;
    println!("Received data: name={}, content={:?}", 
             data.name(), 
             String::from_utf8_lossy(data.content()));
    
    // Verify data
    assert!(data.name().to_string().contains("/test/quic/integration/request1"));
    assert!(String::from_utf8_lossy(data.content()).contains("QUIC integration test response"));
    
    // Test gRPC + QUIC integration
    // Start a gRPC server with QUIC adapter
    let grpc_port = 50051;
    let grpc_addr = format!("{}:{}", server_bind_addr, grpc_port).parse()?;
    
    // Create QUIC adapter for gRPC
    let quic_adapter = GrpcQuicAdapter::new(client_bind_addr, client_port + 1).await?;
    
    // Start gRPC server in a background task
    let quic_adapter_clone = std::sync::Arc::new(quic_adapter);
    
    let grpc_task = tokio::spawn(async move {
        // Dummy transport for the test
        let dummy_transport = std::sync::Arc::new(());
        let service = UdcnControlService::new_with_quic(
            dummy_transport,
            quic_adapter_clone,
        );
        
        println!("Starting gRPC server on {}", grpc_addr);
        Server::builder()
            .add_service(UdcnControlServer::new(service))
            .serve(grpc_addr)
            .await
            .unwrap();
    });
    
    // Give gRPC server time to start
    sleep(Duration::from_millis(100)).await;
    
    // Connect to gRPC server as a client
    let grpc_client = rust_ndn_transport::grpc::udcn::udcn_control_client::UdcnControlClient::connect(
        format!("http://{}:{}", server_bind_addr, grpc_port)
    ).await?;
    
    let mut client = grpc_client;
    
    // Create a QUIC connection through gRPC
    let conn_request = tonic::Request::new(QuicConnectionRequest {
        peer_address: server_bind_addr.to_string(),
        port: server_port as u32,
        options: std::collections::HashMap::new(),
    });
    
    let conn_response = client.create_quic_connection(conn_request).await?;
    let conn_id = conn_response.get_ref().connection_id.clone();
    
    println!("Created connection through gRPC: {}", conn_id);
    assert!(conn_response.get_ref().success);
    
    // Send an interest through gRPC
    let interest_request = tonic::Request::new(InterestPacketRequest {
        connection_id: conn_id,
        name: "/test/quic/integration/request2".to_string(),
        can_be_prefix: false,
        must_be_fresh: true,
        lifetime_ms: 4000,
        hop_limit: 255,
        application_parameters: vec![],
    });
    
    let data_response = client.send_interest(interest_request).await?;
    let data_packet = data_response.get_ref();
    
    println!("Received data through gRPC: name={}, content={:?}", 
             data_packet.name,
             String::from_utf8_lossy(&data_packet.content));
    
    // Verify data
    assert!(data_packet.success);
    assert!(data_packet.name.contains("/test/quic/integration/request2"));
    assert!(String::from_utf8_lossy(&data_packet.content).contains("QUIC integration test response"));
    
    // Shutdown servers
    client.shutdown().await?;
    server_clone.shutdown().await?;
    
    // Cancel the gRPC task
    grpc_task.abort();
    
    Ok(())
}
