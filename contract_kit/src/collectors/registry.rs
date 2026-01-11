//! Registry Collector
//!
//! Collects Windows Registry data via reg.exe or PowerShell.
//!
//! ## Collected Data Fields
//!
//! | Field | Type | Executor | Description |
//! |-------|------|----------|-------------|
//! | `exists` | boolean | Both | Whether key/value exists |
//! | `type` | string | reg only | Registry type (reg_sz, reg_dword, etc.) |
//! | `value` | string | Both | Raw string value |

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::ResolvedValue;
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::commands::powershell::{
    build_registry_value_args, create_powershell_executor, parse_powershell_output,
};
use crate::commands::reg::{
    create_reg_executor, normalize_reg_type, normalize_reg_value, parse_reg_output,
};

/// Collector for Windows Registry
#[derive(Clone)]
pub struct RegistryCollector {
    id: String,
    reg_executor: SystemCommandExecutor,
    powershell_executor: SystemCommandExecutor,
}

impl RegistryCollector {
    /// Create a new registry collector
    pub fn new() -> Self {
        Self {
            id: "windows_registry_collector".to_string(),
            reg_executor: create_reg_executor(),
            powershell_executor: create_powershell_executor(),
        }
    }

    /// Create collector with custom ID
    pub fn with_id(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            reg_executor: create_reg_executor(),
            powershell_executor: create_powershell_executor(),
        }
    }

    /// Extract required string field from object
    fn extract_required_string(
        &self,
        object: &ExecutableObject,
        field_name: &str,
    ) -> Result<String, CollectionError> {
        self.extract_string_field(object, field_name)?
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: format!("Missing required field '{}'", field_name),
            })
    }

    /// Extract optional string field from object
    fn extract_string_field(
        &self,
        object: &ExecutableObject,
        field_name: &str,
    ) -> Result<Option<String>, CollectionError> {
        for element in &object.elements {
            if let ExecutableObjectElement::Field { name, value, .. } = element {
                if name == field_name {
                    match value {
                        ResolvedValue::String(s) => return Ok(Some(s.clone())),
                        _ => {
                            return Err(CollectionError::InvalidObjectConfiguration {
                                object_id: object.identifier.clone(),
                                reason: format!("Field '{}' must be a string", field_name),
                            });
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    /// Normalize hive name to full form for reg.exe
    fn normalize_hive_for_reg(&self, hive: &str) -> String {
        match hive.to_uppercase().as_str() {
            "HKLM" | "HKEY_LOCAL_MACHINE" => "HKLM".to_string(),
            "HKCU" | "HKEY_CURRENT_USER" => "HKCU".to_string(),
            "HKCR" | "HKEY_CLASSES_ROOT" => "HKCR".to_string(),
            "HKU" | "HKEY_USERS" => "HKU".to_string(),
            "HKCC" | "HKEY_CURRENT_CONFIG" => "HKCC".to_string(),
            _ => hive.to_string(),
        }
    }

    /// Collect using reg.exe
    fn collect_via_reg(
        &self,
        object: &ExecutableObject,
        hive: &str,
        key: &str,
        name: &str,
    ) -> Result<CollectedData, CollectionError> {
        let normalized_hive = self.normalize_hive_for_reg(hive);
        let full_path = format!("{}\\{}", normalized_hive, key);

        // Build command string for traceability
        let command_str = format!("reg query \"{}\" /v \"{}\"", full_path, name);

        let args = ["query", &full_path, "/v", name];

        let output = self.reg_executor.execute("reg", &args, None).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("reg.exe execution failed: {}", e),
            }
        })?;

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "registry".to_string(),
            self.id.clone(),
        );

        // Set collection method for traceability
        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::RegistryQuery)
            .description("Query registry value via reg.exe")
            .target(&full_path)
            .command(&command_str)
            .input("hive", hive)
            .input("key", key)
            .input("name", name)
            .input("executor", "reg")
            .build();
        data.set_method(method);

        // Check exit code
        // Exit code 0 = success
        // Exit code 1 = key/value not found
        if output.exit_code == 1 {
            // Key or value doesn't exist
            data.add_field("exists".to_string(), ResolvedValue::Boolean(false));
            data.add_field("value".to_string(), ResolvedValue::String(String::new()));
            return Ok(data);
        }

        if output.exit_code != 0 {
            // Check for access denied
            if output.stderr.to_lowercase().contains("access")
                && output.stderr.to_lowercase().contains("denied")
            {
                return Err(CollectionError::AccessDenied {
                    object_id: object.identifier.clone(),
                    reason: format!("Access denied to registry key: {}", full_path),
                });
            }

            return Err(CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!(
                    "reg.exe failed with exit code {}: {}",
                    output.exit_code, output.stderr
                ),
            });
        }

        // Parse output
        match parse_reg_output(&output.stdout) {
            Some((reg_type, value)) => {
                data.add_field("exists".to_string(), ResolvedValue::Boolean(true));
                data.add_field(
                    "type".to_string(),
                    ResolvedValue::String(normalize_reg_type(&reg_type)),
                );
                // Normalize value (converts hex DWORD/QWORD to decimal)
                let normalized_value = normalize_reg_value(&reg_type, &value);
                data.add_field("value".to_string(), ResolvedValue::String(normalized_value));
            }
            None => {
                // Couldn't parse output - might be empty or unexpected format
                data.add_field("exists".to_string(), ResolvedValue::Boolean(false));
                data.add_field("value".to_string(), ResolvedValue::String(String::new()));
            }
        }

        Ok(data)
    }

    /// Collect using PowerShell Get-ItemPropertyValue
    fn collect_via_powershell(
        &self,
        object: &ExecutableObject,
        hive: &str,
        key: &str,
        name: &str,
    ) -> Result<CollectedData, CollectionError> {
        let args = build_registry_value_args(hive, key, name);
        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        // Build command string for traceability
        let command_str = format!("powershell {}", args.join(" "));

        let output = self
            .powershell_executor
            .execute("powershell", &args_refs, None)
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("PowerShell execution failed: {}", e),
            })?;

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "registry".to_string(),
            self.id.clone(),
        );

        // Set collection method for traceability
        let full_path = format!("{}\\{}", hive, key);
        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::RegistryQuery)
            .description("Query registry value via PowerShell Get-ItemPropertyValue")
            .target(&full_path)
            .command(&command_str)
            .input("hive", hive)
            .input("key", key)
            .input("name", name)
            .input("executor", "powershell")
            .build();
        data.set_method(method);

        // Check for errors
        if output.exit_code != 0 {
            let stderr_lower = output.stderr.to_lowercase();

            // Check for "not exist" errors
            if stderr_lower.contains("does not exist")
                || stderr_lower.contains("cannot find path")
                || stderr_lower.contains("property")
            {
                data.add_field("exists".to_string(), ResolvedValue::Boolean(false));
                data.add_field("value".to_string(), ResolvedValue::String(String::new()));
                return Ok(data);
            }

            // Check for access denied
            if stderr_lower.contains("access") && stderr_lower.contains("denied") {
                return Err(CollectionError::AccessDenied {
                    object_id: object.identifier.clone(),
                    reason: format!("Access denied to registry key: {}\\{}", hive, key),
                });
            }

            return Err(CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!(
                    "PowerShell failed with exit code {}: {}",
                    output.exit_code, output.stderr
                ),
            });
        }

        // Parse output (just trim)
        let value = parse_powershell_output(&output.stdout);

        data.add_field("exists".to_string(), ResolvedValue::Boolean(true));
        // Note: PowerShell doesn't return type info
        data.add_field("value".to_string(), ResolvedValue::String(value));

        Ok(data)
    }
}

impl Default for RegistryCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for RegistryCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        // Validate hints against contract
        contract.validate_behavior_hints(hints).map_err(|e| {
            CollectionError::CtnContractValidation {
                reason: e.to_string(),
            }
        })?;

        // Extract required fields
        let hive = self.extract_required_string(object, "hive")?;
        let key = self.extract_required_string(object, "key")?;
        let name = self.extract_required_string(object, "name")?;

        // Get executor from behavior (default: reg)
        let executor = hints.get_parameter("executor").unwrap_or("reg");

        // Dispatch to appropriate collector
        match executor {
            "reg" => self.collect_via_reg(object, &hive, &key, &name),
            "powershell" => self.collect_via_powershell(object, &hive, &key, &name),
            _ => Err(CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: format!(
                    "Invalid executor '{}'. Valid values: reg, powershell",
                    executor
                ),
            }),
        }
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["registry".to_string()]
    }

    fn collector_id(&self) -> &str {
        &self.id
    }

    fn supports_batch_collection(&self) -> bool {
        false
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "registry" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'registry', got '{}'",
                    contract.ctn_type
                ),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collector_creation() {
        let collector = RegistryCollector::new();
        assert_eq!(collector.collector_id(), "windows_registry_collector");
        assert!(collector
            .supported_ctn_types()
            .contains(&"registry".to_string()));
    }

    #[test]
    fn test_collector_with_custom_id() {
        let collector = RegistryCollector::with_id("custom_id");
        assert_eq!(collector.collector_id(), "custom_id");
    }

    #[test]
    fn test_normalize_hive() {
        let collector = RegistryCollector::new();
        assert_eq!(
            collector.normalize_hive_for_reg("HKEY_LOCAL_MACHINE"),
            "HKLM"
        );
        assert_eq!(collector.normalize_hive_for_reg("HKLM"), "HKLM");
        assert_eq!(
            collector.normalize_hive_for_reg("hkey_current_user"),
            "HKCU"
        );
    }

    #[test]
    fn test_supports_batch_collection() {
        let collector = RegistryCollector::new();
        assert!(!collector.supports_batch_collection());
    }
}
