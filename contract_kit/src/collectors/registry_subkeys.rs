//! Registry Subkeys Collector
//!
//! Collects Windows Registry subkey enumeration data via reg.exe or PowerShell.
//!
//! ## Collected Data Fields
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `exists` | boolean | Whether the key exists |
//! | `subkey_count` | int | Number of child subkeys |
//! | `subkeys` | string[] | List of subkey names |

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::ResolvedValue;
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::commands::powershell::create_powershell_executor;
use crate::commands::reg::create_reg_executor;

/// Collector for Windows Registry subkey enumeration
#[derive(Clone)]
pub struct RegistrySubkeysCollector {
    id: String,
    reg_executor: SystemCommandExecutor,
    powershell_executor: SystemCommandExecutor,
}

impl RegistrySubkeysCollector {
    /// Create a new registry subkeys collector
    pub fn new() -> Self {
        Self {
            id: "windows_registry_subkeys_collector".to_string(),
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

    /// Normalize hive name to short form for reg.exe
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

    /// Normalize hive name to PowerShell drive format
    fn normalize_hive_for_powershell(&self, hive: &str) -> &'static str {
        match hive.to_uppercase().as_str() {
            "HKEY_LOCAL_MACHINE" | "HKLM" => "HKLM",
            "HKEY_CURRENT_USER" | "HKCU" => "HKCU",
            "HKEY_CLASSES_ROOT" | "HKCR" => "HKCR",
            "HKEY_USERS" | "HKU" => "HKU",
            "HKEY_CURRENT_CONFIG" | "HKCC" => "HKCC",
            _ => "HKLM",
        }
    }

    /// Parse reg.exe output to extract subkey names
    ///
    /// reg query output for subkeys looks like:
    /// ```text
    /// HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Calais\Readers
    ///     (Default)    REG_SZ    (value not set)
    ///
    /// HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Calais\Readers\SubKey1
    ///
    /// HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Calais\Readers\SubKey2
    /// ```
    fn parse_reg_subkeys_output(&self, stdout: &str, parent_path: &str) -> Vec<String> {
        let mut subkeys = Vec::new();
        let parent_normalized = parent_path.to_uppercase();

        for line in stdout.lines() {
            let trimmed = line.trim();

            // Skip empty lines
            if trimmed.is_empty() {
                continue;
            }

            // Skip lines that are values (start with spaces in original, or contain REG_)
            if line.starts_with(' ') || line.starts_with('\t') || trimmed.contains("REG_") {
                continue;
            }

            // Check if this is a subkey path (starts with HKEY_ and contains parent path)
            if trimmed.to_uppercase().starts_with("HKEY_")
                || trimmed.to_uppercase().starts_with("HKLM")
                || trimmed.to_uppercase().starts_with("HKCU")
            {
                let trimmed_upper = trimmed.to_uppercase();

                // Skip if this is the parent key itself
                if trimmed_upper == parent_normalized {
                    continue;
                }

                // Check if this is a direct child (one level deeper)
                if trimmed_upper.starts_with(&parent_normalized) {
                    // Extract the subkey name (part after parent path + backslash)
                    let prefix = format!("{}\\", parent_normalized);
                    if let Some(suffix) = trimmed_upper.strip_prefix(&prefix) {
                        // Only include direct children (no additional backslashes)
                        if !suffix.contains('\\') && !suffix.is_empty() {
                            // Use original case from the line
                            let original_suffix = &trimmed[parent_path.len() + 1..];
                            subkeys.push(original_suffix.to_string());
                        }
                    }
                }
            }
        }

        subkeys
    }

    /// Parse PowerShell Get-ChildItem output
    ///
    /// Each line is a subkey name
    fn parse_powershell_subkeys_output(&self, stdout: &str) -> Vec<String> {
        stdout
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty())
            .map(|line| line.to_string())
            .collect()
    }

    /// Collect using reg.exe (subkey enumeration)
    fn collect_via_reg(
        &self,
        object: &ExecutableObject,
        hive: &str,
        key: &str,
    ) -> Result<CollectedData, CollectionError> {
        let normalized_hive = self.normalize_hive_for_reg(hive);
        let full_path = format!("{}\\{}", normalized_hive, key);

        // Build command string for traceability
        let command_str = format!("reg query \"{}\"", full_path);

        // Query without /v flag to enumerate subkeys
        let args = ["query", &full_path];

        let output = self.reg_executor.execute("reg", &args, None).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("reg.exe execution failed: {}", e),
            }
        })?;

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "registry_subkeys".to_string(),
            self.id.clone(),
        );

        // Set collection method for traceability
        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::RegistryQuery)
            .description("Enumerate registry subkeys via reg.exe")
            .target(&full_path)
            .command(&command_str)
            .input("hive", hive)
            .input("key", key)
            .input("executor", "reg")
            .build();
        data.set_method(method);

        // Exit code 1 = key not found
        if output.exit_code == 1 {
            data.add_field("exists".to_string(), ResolvedValue::Boolean(false));
            data.add_field("subkey_count".to_string(), ResolvedValue::Integer(0));
            data.add_field("subkeys".to_string(), ResolvedValue::String(String::new()));
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

        // Parse subkeys from output
        let subkeys = self.parse_reg_subkeys_output(&output.stdout, &full_path);
        let subkey_count = subkeys.len() as i64;

        data.add_field("exists".to_string(), ResolvedValue::Boolean(true));
        data.add_field(
            "subkey_count".to_string(),
            ResolvedValue::Integer(subkey_count),
        );
        // Store subkeys as comma-separated string for pattern matching
        data.add_field(
            "subkeys".to_string(),
            ResolvedValue::String(subkeys.join(",")),
        );

        Ok(data)
    }

    /// Collect using PowerShell Get-ChildItem
    fn collect_via_powershell(
        &self,
        object: &ExecutableObject,
        hive: &str,
        key: &str,
    ) -> Result<CollectedData, CollectionError> {
        let ps_hive = self.normalize_hive_for_powershell(hive);

        // Build PowerShell command to enumerate child keys
        let command = format!(
            "Get-ChildItem -Path '{}:\\{}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName",
            ps_hive, key
        );

        let args = ["-NoProfile", "-NonInteractive", "-Command", &command];

        let output = self
            .powershell_executor
            .execute("powershell", &args, None)
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("PowerShell execution failed: {}", e),
            })?;

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "registry_subkeys".to_string(),
            self.id.clone(),
        );

        // Set collection method for traceability
        let full_path = format!("{}:\\{}", ps_hive, key);
        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::RegistryQuery)
            .description("Enumerate registry subkeys via PowerShell Get-ChildItem")
            .target(&full_path)
            .command(format!(
                "powershell -NoProfile -NonInteractive -Command \"{}\"",
                command
            ))
            .input("hive", hive)
            .input("key", key)
            .input("executor", "powershell")
            .build();
        data.set_method(method);

        // Check for errors indicating key doesn't exist
        if output.exit_code != 0 {
            let stderr_lower = output.stderr.to_lowercase();

            if stderr_lower.contains("does not exist")
                || stderr_lower.contains("cannot find path")
                || stderr_lower.contains("itemnotfoundexception")
            {
                data.add_field("exists".to_string(), ResolvedValue::Boolean(false));
                data.add_field("subkey_count".to_string(), ResolvedValue::Integer(0));
                data.add_field("subkeys".to_string(), ResolvedValue::String(String::new()));
                return Ok(data);
            }

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

        // Parse subkeys from output
        let subkeys = self.parse_powershell_subkeys_output(&output.stdout);
        let subkey_count = subkeys.len() as i64;

        // Note: Empty output with exit code 0 means key exists but has no subkeys
        data.add_field("exists".to_string(), ResolvedValue::Boolean(true));
        data.add_field(
            "subkey_count".to_string(),
            ResolvedValue::Integer(subkey_count),
        );
        // Store subkeys as comma-separated string for pattern matching
        data.add_field(
            "subkeys".to_string(),
            ResolvedValue::String(subkeys.join(",")),
        );

        Ok(data)
    }
}

impl Default for RegistrySubkeysCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for RegistrySubkeysCollector {
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

        // Extract required fields (hive and key only - no name)
        let hive = self.extract_required_string(object, "hive")?;
        let key = self.extract_required_string(object, "key")?;

        // Get executor from behavior (default: reg)
        let executor = hints.get_parameter("executor").unwrap_or("reg");

        // Dispatch to appropriate collector
        match executor {
            "reg" => self.collect_via_reg(object, &hive, &key),
            "powershell" => self.collect_via_powershell(object, &hive, &key),
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
        vec!["registry_subkeys".to_string()]
    }

    fn collector_id(&self) -> &str {
        &self.id
    }

    fn supports_batch_collection(&self) -> bool {
        false
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "registry_subkeys" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'registry_subkeys', got '{}'",
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
        let collector = RegistrySubkeysCollector::new();
        assert_eq!(
            collector.collector_id(),
            "windows_registry_subkeys_collector"
        );
        assert!(collector
            .supported_ctn_types()
            .contains(&"registry_subkeys".to_string()));
    }

    #[test]
    fn test_collector_with_custom_id() {
        let collector = RegistrySubkeysCollector::with_id("custom_id");
        assert_eq!(collector.collector_id(), "custom_id");
    }

    #[test]
    fn test_normalize_hive() {
        let collector = RegistrySubkeysCollector::new();
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
    fn test_parse_reg_subkeys_output() {
        let collector = RegistrySubkeysCollector::new();

        let output = r#"
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Calais\Readers
    (Default)    REG_SZ    (value not set)

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Calais\Readers\SubKey1

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Calais\Readers\SubKey2
"#;

        // Use full hive name to match output
        let parent = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\Calais\\Readers";
        let subkeys = collector.parse_reg_subkeys_output(output, parent);

        assert_eq!(subkeys.len(), 2);
        assert!(subkeys.contains(&"SubKey1".to_string()));
        assert!(subkeys.contains(&"SubKey2".to_string()));
    }

    #[test]
    fn test_parse_reg_subkeys_empty() {
        let collector = RegistrySubkeysCollector::new();

        let output = r#"
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Calais\Readers
    SomeValue    REG_SZ    SomeData
"#;

        let parent = "HKLM\\SOFTWARE\\Microsoft\\Cryptography\\Calais\\Readers";
        let subkeys = collector.parse_reg_subkeys_output(output, parent);

        assert!(subkeys.is_empty());
    }

    #[test]
    fn test_parse_powershell_subkeys_output() {
        let collector = RegistrySubkeysCollector::new();

        let output = "SubKey1\nSubKey2\nSubKey3\n";
        let subkeys = collector.parse_powershell_subkeys_output(output);

        assert_eq!(subkeys.len(), 3);
        assert_eq!(subkeys.first(), Some(&"SubKey1".to_string()));
        assert_eq!(subkeys.get(1), Some(&"SubKey2".to_string()));
        assert_eq!(subkeys.get(2), Some(&"SubKey3".to_string()));
    }

    #[test]
    fn test_parse_powershell_subkeys_empty() {
        let collector = RegistrySubkeysCollector::new();

        let output = "";
        let subkeys = collector.parse_powershell_subkeys_output(output);

        assert!(subkeys.is_empty());
    }

    #[test]
    fn test_supports_batch_collection() {
        let collector = RegistrySubkeysCollector::new();
        assert!(!collector.supports_batch_collection());
    }
}
