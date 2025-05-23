//
// μDCN Python Bindings
//
// This module implements Python bindings for the Rust transport layer,
// allowing seamless integration with the Python control plane.
//

use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
use pyo3::types::{PyDict, PyList, PyBytes};
use pyo3::exceptions::{PyRuntimeError, PyValueError};

use std::sync::Arc;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use tokio::runtime::Runtime;

use crate::{Config, Result, UdcnTransport, TransportState};
use crate::ndn::{Interest, Data};
use crate::name::Name;
use crate::metrics::MetricValue;

// Create a Tokio runtime to run async Rust code from Python
thread_local! {
    static RUNTIME: Runtime = Runtime::new().unwrap();
}

// Convert Rust errors to Python exceptions
fn convert_error(err: crate::Error) -> PyErr {
    PyRuntimeError::new_err(format!("μDCN Error: {}", err))
}

/// Python-friendly wrapper for UdcnTransport
#[pyclass(name = "UdcnTransport")]
struct PyUdcnTransport {
    transport: Arc<UdcnTransport>,
    runtime: Runtime,
}

#[pymethods]
impl PyUdcnTransport {
    /// Create a new transport instance
    #[new]
    fn new(py: Python, config_dict: Option<&PyDict>) -> PyResult<Self> {
        // Create a default configuration
        let mut config = Config::default();
        
        // Apply custom configuration if provided
        if let Some(cfg) = config_dict {
            if let Some(mtu) = cfg.get_item("mtu") {
                config.mtu = mtu.extract()?;
            }
            if let Some(cache_capacity) = cfg.get_item("cache_capacity") {
                config.cache_capacity = cache_capacity.extract()?;
            }
            if let Some(idle_timeout) = cfg.get_item("idle_timeout") {
                config.idle_timeout = idle_timeout.extract()?;
            }
            if let Some(bind_address) = cfg.get_item("bind_address") {
                config.bind_address = bind_address.extract()?;
            }
            if let Some(enable_metrics) = cfg.get_item("enable_metrics") {
                config.enable_metrics = enable_metrics.extract()?;
            }
            if let Some(metrics_port) = cfg.get_item("metrics_port") {
                config.metrics_port = metrics_port.extract()?;
            }
        }
        
        // Create a runtime for async operations
        let runtime = Runtime::new().map_err(|e| PyRuntimeError::new_err(format!("Failed to create Tokio runtime: {}", e)))?;
        
        // Create the transport
        let transport = py.allow_threads(|| {
            runtime.block_on(async {
                UdcnTransport::new(config).await.map_err(convert_error)
            })
        })?;
        
        Ok(Self {
            transport: Arc::new(transport),
            runtime,
        })
    }
    
    /// Start the transport
    fn start(&self, py: Python) -> PyResult<()> {
        let transport = self.transport.clone();
        
        py.allow_threads(|| {
            self.runtime.block_on(async {
                transport.start().await.map_err(convert_error)
            })
        })
    }
    
    /// Stop the transport
    fn stop(&self, py: Python) -> PyResult<()> {
        let transport = self.transport.clone();
        
        py.allow_threads(|| {
            self.runtime.block_on(async {
                transport.stop().await.map_err(convert_error)
            })
        })
    }
    
    /// Register a prefix for handling interests
    fn register_prefix(&self, py: Python, prefix: &str, callback: PyObject) -> PyResult<u64> {
        let transport = self.transport.clone();
        let prefix_str = prefix.to_string();
        
        py.allow_threads(|| {
            self.runtime.block_on(async {
                // Parse the prefix
                let name = Name::from_uri(&prefix_str).map_err(|e| PyValueError::new_err(format!("Invalid prefix: {}", e)))?;
                
                // Create a handler that calls back to Python
                let py_callback = PyObject::from(callback);
                let handler = Box::new(move |interest: Interest| -> Result<Data> {
                    // Convert Interest to Python
                    Python::with_gil(|py| {
                        let args = PyTuple::new(py, &[PyBytes::new(py, &interest.to_bytes())]);
                        
                        // Call the Python callback
                        let result = py_callback.call1(py, args)
                            .map_err(|e| crate::Error::Other(format!("Python callback error: {}", e)))?;
                        
                        // Convert result back to Data
                        let bytes = result.extract::<&[u8]>(py)
                            .map_err(|e| crate::Error::Other(format!("Failed to extract bytes from Python: {}", e)))?;
                        
                        Data::from_bytes(bytes)
                    })
                });
                
                // Register the handler
                transport.register_prefix(name, handler).await.map_err(convert_error)
            })
        })
    }
    
    /// Unregister a prefix
    fn unregister_prefix(&self, py: Python, registration_id: u64) -> PyResult<()> {
        let transport = self.transport.clone();
        
        py.allow_threads(|| {
            self.runtime.block_on(async {
                transport.unregister_prefix(registration_id).await.map_err(convert_error)
            })
        })
    }
    
    /// Send an interest and get data
    fn send_interest(&self, py: Python, name: &str) -> PyResult<PyObject> {
        let transport = self.transport.clone();
        let name_str = name.to_string();
        
        py.allow_threads(|| {
            self.runtime.block_on(async {
                // Parse the name
                let name = Name::from_uri(&name_str).map_err(|e| PyValueError::new_err(format!("Invalid name: {}", e)))?;
                
                // Create an interest
                let interest = Interest::new(name);
                
                // Send the interest
                let data = transport.send_interest(interest).await.map_err(convert_error)?;
                
                // Convert data to Python bytes
                Python::with_gil(|py| {
                    let bytes = PyBytes::new(py, &data.to_bytes());
                    Ok(bytes.into())
                })
            })
        })
    }
    
    /// Get current state
    fn state(&self, py: Python) -> PyResult<String> {
        let transport = self.transport.clone();
        
        py.allow_threads(|| {
            self.runtime.block_on(async {
                let state = transport.state().await;
                Ok(format!("{:?}", state))
            })
        })
    }
    
    /// Get metrics
    fn get_metrics(&self, py: Python) -> PyResult<PyObject> {
        let transport = self.transport.clone();
        
        py.allow_threads(|| {
            self.runtime.block_on(async {
                let metrics = transport.get_metrics().await;
                
                Python::with_gil(|py| {
                    let dict = PyDict::new(py);
                    
                    for (key, value) in metrics {
                        let py_value = match value {
                            MetricValue::Counter(c) => c.to_object(py),
                            MetricValue::Gauge(g) => g.to_object(py),
                            MetricValue::Histogram(h) => h.to_object(py),
                            MetricValue::Text(t) => t.to_object(py),
                        };
                        
                        dict.set_item(key, py_value)?;
                    }
                    
                    Ok(dict.into())
                })
            })
        })
    }
    
    /// Get detailed statistics
    fn get_detailed_statistics(&self, py: Python) -> PyResult<PyObject> {
        let transport = self.transport.clone();
        
        py.allow_threads(|| {
            self.runtime.block_on(async {
                let stats = transport.get_detailed_statistics().await;
                
                Python::with_gil(|py| {
                    let dict = PyDict::new(py);
                    
                    for (key, value) in stats {
                        dict.set_item(key, value)?;
                    }
                    
                    Ok(dict.into())
                })
            })
        })
    }
    
    /// Update MTU
    fn update_mtu(&self, py: Python, mtu: usize) -> PyResult<()> {
        let transport = self.transport.clone();
        
        py.allow_threads(|| {
            self.runtime.block_on(async {
                transport.update_mtu(mtu).await.map_err(convert_error)
            })
        })
    }
    
    /// Configure the transport
    fn configure(&self, py: Python, config_dict: &PyDict) -> PyResult<()> {
        let transport = self.transport.clone();
        
        // Create a new configuration
        let mut config = Config::default();
        
        // Apply custom configuration
        if let Some(mtu) = config_dict.get_item("mtu") {
            config.mtu = mtu.extract()?;
        }
        if let Some(cache_capacity) = config_dict.get_item("cache_capacity") {
            config.cache_capacity = cache_capacity.extract()?;
        }
        if let Some(idle_timeout) = config_dict.get_item("idle_timeout") {
            config.idle_timeout = idle_timeout.extract()?;
        }
        if let Some(bind_address) = config_dict.get_item("bind_address") {
            config.bind_address = config_dict.get_item("bind_address").unwrap().extract()?;
        }
        if let Some(enable_metrics) = config_dict.get_item("enable_metrics") {
            config.enable_metrics = enable_metrics.extract()?;
        }
        if let Some(metrics_port) = config_dict.get_item("metrics_port") {
            config.metrics_port = metrics_port.extract()?;
        }
        
        py.allow_threads(|| {
            self.runtime.block_on(async {
                transport.configure(config).await.map_err(convert_error)
            })
        })
    }
}

/// Helper function to parse an NDN Data packet
#[pyfunction]
fn parse_data(py: Python, data_bytes: &[u8]) -> PyResult<PyObject> {
    match Data::from_bytes(data_bytes) {
        Ok(data) => {
            let dict = PyDict::new(py);
            dict.set_item("name", data.name().to_string())?;
            dict.set_item("content", PyBytes::new(py, data.content()))?;
            dict.set_item("freshness_period", data.get_fresh_period().as_secs())?;
            Ok(dict.into())
        },
        Err(e) => Err(PyValueError::new_err(format!("Failed to parse Data: {}", e))),
    }
}

/// Helper function to parse an NDN Interest packet
#[pyfunction]
fn parse_interest(py: Python, interest_bytes: &[u8]) -> PyResult<PyObject> {
    match Interest::from_bytes(interest_bytes) {
        Ok(interest) => {
            let dict = PyDict::new(py);
            dict.set_item("name", interest.name().to_string())?;
            dict.set_item("lifetime", interest.get_lifetime().as_secs())?;
            dict.set_item("nonce", interest.nonce())?;
            Ok(dict.into())
        },
        Err(e) => Err(PyValueError::new_err(format!("Failed to parse Interest: {}", e))),
    }
}

/// Helper function to create an Interest packet
#[pyfunction]
fn create_interest(py: Python, name: &str, lifetime_sec: Option<u64>) -> PyResult<PyObject> {
    let name = Name::from_uri(name).map_err(|e| PyValueError::new_err(format!("Invalid name: {}", e)))?;
    
    let mut interest = Interest::new(name);
    
    if let Some(lifetime) = lifetime_sec {
        interest = interest.lifetime(std::time::Duration::from_secs(lifetime));
    }
    
    let bytes = interest.to_bytes();
    Ok(PyBytes::new(py, &bytes).into())
}

/// Helper function to create a Data packet
#[pyfunction]
fn create_data(py: Python, name: &str, content: &[u8], freshness_sec: Option<u64>) -> PyResult<PyObject> {
    let name = Name::from_uri(name).map_err(|e| PyValueError::new_err(format!("Invalid name: {}", e)))?;
    
    // Clone the content to create an owned copy that can be given to the Data object
    let content_owned = content.to_vec();
    let mut data = Data::new(name, content_owned);
    
    if let Some(freshness) = freshness_sec {
        data = data.fresh_period(std::time::Duration::from_secs(freshness));
    }
    
    let bytes = data.to_bytes();
    Ok(PyBytes::new(py, &bytes).into())
}

/// Python module definition
#[pymodule]
fn udcn_transport(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyUdcnTransport>()?;
    m.add_function(wrap_pyfunction!(parse_data, m)?)?;
    m.add_function(wrap_pyfunction!(parse_interest, m)?)?;
    m.add_function(wrap_pyfunction!(create_interest, m)?)?;
    m.add_function(wrap_pyfunction!(create_data, m)?)?;
    
    // Add version info
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add("__author__", env!("CARGO_PKG_AUTHORS"))?;
    
    Ok(())
}
