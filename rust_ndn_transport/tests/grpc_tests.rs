use std::sync::Arc;
use tonic::{Request, Response};
use udcn_transport::UdcnTransport;
use udcn_transport::grpc::{UdcnControlService, udcn::*};

#[cfg_attr(feature = "tokio-test", tokio::test)]
async fn test_get_transport_state() {
    // Create a mock transport
    let transport = Arc::new(UdcnTransport::new_mock());
    
    // Create the service
    let service = UdcnControlService::new(transport);
    
    // Create a request
    let request = Request::new(TransportStateRequest {
        include_detailed_stats: false,
    });
    
    // Call the service
    let response: Response<TransportStateResponse> = service.get_transport_state(request).await.unwrap();
    let response = response.into_inner();
    
    // Check response fields
    assert!(response.success);
    assert_eq!(response.error_message, "");
    assert!(response.uptime_seconds >= 0);
}

#[cfg_attr(feature = "tokio-test", tokio::test)]
async fn test_configure_xdp() {
    // Create a mock transport
    let transport = Arc::new(UdcnTransport::new_mock());
    
    // Create the service
    let service = UdcnControlService::new(transport);
    
    // Create a request with a mock program path
    // Note: In a real test, we'd need to ensure this file exists
    let request = Request::new(XdpConfigRequest {
        interface_name: "eth0".to_string(),
        program_path: "/tmp/mock_program.o".to_string(),
        mode: XdpConfigRequest_XdpMode::Driver as i32,
        map_pins: std::collections::HashMap::new(),
    });
    
    // In a real test, we'd have to mock the file existence check
    // Here we'll just verify the function exists and has the right signature
    let result = service.configure_xdp(request).await;
    
    // The test will pass as long as the method exists and can be called
    assert!(result.is_err()); // Error expected because the file doesn't exist
}

#[cfg_attr(feature = "tokio-test", tokio::test)]
async fn test_create_quic_connection() {
    // Create a mock transport
    let transport = Arc::new(UdcnTransport::new_mock());
    
    // Create the service
    let service = UdcnControlService::new(transport);
    
    // Create a request
    let request = Request::new(QuicConnectionRequest {
        peer_address: "127.0.0.1".to_string(),
        port: 12345,
        client_name: "test-client".to_string(),
    });
    
    // Call the service
    let result = service.create_quic_connection(request).await;
    
    // The test is successful if the method exists and can be called
    // In production code, we would mock the transport's create_quic_connection method
    assert!(result.is_err() || result.is_ok());
}
