//
// Python Binding Tests
//
// This module tests the Python bindings integration
//

use super::*;
use crate::python;
use crate::metrics::init_metrics;

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyBytes};
use pyo3::Python;

// Test Python helpers for NDN packet creation and parsing
#[test]
fn test_python_packet_helpers() {
    init_metrics();
    
    Python::with_gil(|py| {
        // Test interest creation
        let name = "/test/python/interest";
        let interest_bytes = python::create_interest(py, name, Some(1000))
            .expect("Failed to create interest");
        
        // Get bytes from PyObject
        let bytes = interest_bytes.extract::<&PyBytes>(py)
            .expect("Failed to extract bytes")
            .as_bytes();
        
        // Parse bytes back to Interest
        let interest = Interest::from_bytes(bytes)
            .expect("Failed to parse interest");
        
        // Verify interest
        assert_eq!(interest.name().to_string(), name, "Interest name mismatch");
        
        // Test Data creation
        let name = "/test/python/data";
        let content = b"Python binding test";
        let data_bytes = python::create_data(py, name, content, Some(2000))
            .expect("Failed to create data");
        
        // Get bytes from PyObject
        let bytes = data_bytes.extract::<&PyBytes>(py)
            .expect("Failed to extract bytes")
            .as_bytes();
        
        // Parse bytes back to Data
        let data = Data::from_bytes(bytes)
            .expect("Failed to parse data");
        
        // Verify data
        assert_eq!(data.name().to_string(), name, "Data name mismatch");
        assert_eq!(data.content(), content, "Data content mismatch");
        
        // Test parse_interest helper
        let interest = create_test_interest("/test/python/parse");
        let interest_bytes = interest.to_bytes();
        
        let parsed = python::parse_interest(py, &interest_bytes)
            .expect("Failed to parse interest");
        
        let dict = parsed.extract::<&PyDict>(py)
            .expect("Failed to extract dict");
        
        let parsed_name = dict.get_item("name")
            .expect("No name in parsed interest")
            .extract::<String>()
            .expect("Failed to extract name");
        
        assert_eq!(parsed_name, "/test/python/parse", "Parsed interest name mismatch");
        
        // Test parse_data helper
        let data = create_test_data("/test/python/parse", b"Parse test");
        let data_bytes = data.to_bytes();
        
        let parsed = python::parse_data(py, &data_bytes)
            .expect("Failed to parse data");
        
        let dict = parsed.extract::<&PyDict>(py)
            .expect("Failed to extract dict");
        
        let parsed_name = dict.get_item("name")
            .expect("No name in parsed data")
            .extract::<String>()
            .expect("Failed to extract name");
        
        let parsed_content = dict.get_item("content")
            .expect("No content in parsed data")
            .extract::<&PyBytes>(py)
            .expect("Failed to extract content")
            .as_bytes();
        
        assert_eq!(parsed_name, "/test/python/parse", "Parsed data name mismatch");
        assert_eq!(parsed_content, b"Parse test", "Parsed data content mismatch");
    });
}

// Create mock Python callback
struct MockPythonCallback {
    response_data: Data,
}

impl MockPythonCallback {
    fn new(response_data: Data) -> Self {
        Self { response_data }
    }
    
    fn as_py_object(&self, py: Python) -> PyObject {
        let callback_fn = PyFunction::new(
            py,
            PyCodeObject::new(
                py,
                "__pyo3_test__".to_object(py),
                vec!["interest_bytes".to_object(py)],
                "response_bytes = b'mock response'".to_object(py),
                vec!["response_bytes".to_object(py)],
                None,
                None,
            ).unwrap(),
            None,
        ).unwrap();
        
        callback_fn.to_object(py)
    }
}

// Test PyUdcnTransport construction and basic methods
#[test]
fn test_pyudcn_transport_creation() {
    init_metrics();
    
    Python::with_gil(|py| {
        // Create config dict
        let config_dict = PyDict::new(py);
        config_dict.set_item("mtu", 1400).unwrap();
        config_dict.set_item("bind_address", "127.0.0.1:0").unwrap();
        config_dict.set_item("enable_metrics", false).unwrap();
        
        // Create transport instance
        let transport = match python::PyUdcnTransport::new(py, Some(config_dict)) {
            Ok(t) => t,
            Err(e) => {
                panic!("Failed to create PyUdcnTransport: {:?}", e);
            }
        };
        
        // Test start method
        match transport.start(py) {
            Ok(()) => {},
            Err(e) => {
                panic!("Failed to start transport: {:?}", e);
            }
        };
        
        // Test getting state
        match transport.state(py) {
            Ok(state) => {
                assert!(state.contains("Running") || state.contains("Starting"), "Unexpected state: {}", state);
            },
            Err(e) => {
                panic!("Failed to get state: {:?}", e);
            }
        };
        
        // Test getting metrics
        match transport.get_metrics(py) {
            Ok(_) => {},
            Err(e) => {
                panic!("Failed to get metrics: {:?}", e);
            }
        };
        
        // Test stop method
        match transport.stop(py) {
            Ok(()) => {},
            Err(e) => {
                panic!("Failed to stop transport: {:?}", e);
            }
        };
    });
}

// Simulate Python callback execution environment
struct PyCallbackTestEnv {
    name: String,
    content: Vec<u8>,
}

impl PyCallbackTestEnv {
    fn new(name: &str, content: &[u8]) -> Self {
        Self {
            name: name.to_string(),
            content: content.to_vec(),
        }
    }
    
    fn create_callback_fn(&self, py: Python) -> PyResult<PyObject> {
        let locals = PyDict::new(py);
        
        // Add variables to the local dict
        locals.set_item("name", self.name.clone())?;
        locals.set_item("content", PyBytes::new(py, &self.content))?;
        
        // Execute a Python function definition
        let code = r#"
def handler(interest_bytes):
    import struct
    # Create a simple NDN data response with name and content
    # This is a simplified mock implementation
    name_bytes = name.encode('utf-8')
    header = struct.pack("!BBH", 0x06, 0xFD, len(name_bytes) + len(content) + 4)
    name_header = struct.pack("!BB", 0x07, len(name_bytes))
    content_header = struct.pack("!BB", 0x15, len(content))
    return header + name_header + name_bytes + content_header + content
        "#;
        
        py.run(code, None, Some(locals))?;
        
        // Get the function from locals
        locals.get_item("handler")
            .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("Failed to get handler function"))
    }
}
