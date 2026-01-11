//! TCP Listener Collector
//!
//! Collects information about TCP ports in LISTEN state.
//! - Windows: Uses IP Helper API (GetExtendedTcpTable)
//! - Linux: Reads /proc/net/tcp

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::ResolvedValue;
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::commands::tcp_listener::check_port_listening;

/// Collector for TCP listener information
pub struct TcpListenerCollector {
    id: String,
}

impl TcpListenerCollector {
    pub fn new() -> Self {
        Self {
            id: "tcp_listener_collector".to_string(),
        }
    }

    /// Extract port from object
    fn extract_port(&self, object: &ExecutableObject) -> Result<u16, CollectionError> {
        for element in &object.elements {
            if let ExecutableObjectElement::Field { name, value, .. } = element {
                if name == "port" {
                    match value {
                        ResolvedValue::Integer(i) => {
                            if *i < 1 || *i > 65535 {
                                return Err(CollectionError::InvalidObjectConfiguration {
                                    object_id: object.identifier.clone(),
                                    reason: format!("Port {} out of range (1-65535)", i),
                                });
                            }
                            return Ok(*i as u16);
                        }
                        ResolvedValue::String(s) => {
                            let port: u16 = s.parse().map_err(|_| {
                                CollectionError::InvalidObjectConfiguration {
                                    object_id: object.identifier.clone(),
                                    reason: format!("Invalid port number: {}", s),
                                }
                            })?;
                            return Ok(port);
                        }
                        _ => {
                            return Err(CollectionError::InvalidObjectConfiguration {
                                object_id: object.identifier.clone(),
                                reason: format!("Port must be an integer, got {:?}", value),
                            });
                        }
                    }
                }
            }
        }

        Err(CollectionError::InvalidObjectConfiguration {
            object_id: object.identifier.clone(),
            reason: "Missing required field 'port'".to_string(),
        })
    }

    /// Extract optional host filter from object
    fn extract_host(&self, object: &ExecutableObject) -> Option<String> {
        for element in &object.elements {
            if let ExecutableObjectElement::Field { name, value, .. } = element {
                if name == "host" {
                    if let ResolvedValue::String(s) = value {
                        // "any" means no filtering
                        if s.to_lowercase() == "any" {
                            return None;
                        }
                        return Some(s.clone());
                    }
                }
            }
        }
        None
    }
}

impl Default for TcpListenerCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for TcpListenerCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        // Validate contract compatibility
        self.validate_ctn_compatibility(contract)?;

        // Extract port (required)
        let port = self.extract_port(object)?;

        // Extract host filter (optional)
        let host_filter = self.extract_host(object);

        // Check if port is listening using platform-native API
        let result = check_port_listening(port, host_filter.as_deref());

        // Handle collection errors
        if let Some(ref error) = result.error {
            return Err(CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: error.clone(),
            });
        }

        // Build collected data
        let mut data = CollectedData::new(
            object.identifier.clone(),
            "tcp_listener".to_string(),
            self.id.clone(),
        );

        // Set collection method for traceability
        #[cfg(windows)]
        let description = "Check TCP port listener state via Windows IP Helper API";
        #[cfg(not(windows))]
        let description = "Check TCP port listener state via /proc/net/tcp";

        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::SocketInspection)
            .description(description)
            .target(format!("tcp:{}", port))
            .input("port", port.to_string());

        if let Some(ref host) = host_filter {
            method_builder = method_builder.input("host_filter", host);
        }

        data.set_method(method_builder.build());

        data.add_field(
            "listening".to_string(),
            ResolvedValue::Boolean(result.listening),
        );

        if let Some(addr) = result.local_address {
            data.add_field("local_address".to_string(), ResolvedValue::String(addr));
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["tcp_listener".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "tcp_listener" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'tcp_listener', got '{}'",
                    contract.ctn_type
                ),
            });
        }
        Ok(())
    }

    fn collector_id(&self) -> &str {
        &self.id
    }

    fn supports_batch_collection(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collector_id() {
        let collector = TcpListenerCollector::new();
        assert_eq!(collector.collector_id(), "tcp_listener_collector");
    }

    #[test]
    fn test_supported_ctn_types() {
        let collector = TcpListenerCollector::new();
        assert_eq!(collector.supported_ctn_types(), vec!["tcp_listener"]);
    }
}
