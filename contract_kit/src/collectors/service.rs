//! Service Collector
//!
//! Collects Windows Service data via sc.exe or PowerShell.
//!
//! ## Collection Methods
//!
//! ### sc.exe (default)
//! - Runs `sc.exe query <n>` for runtime state
//! - Runs `sc.exe qc <n>` for configuration
//! - Provides all fields including `service_type`
//!
//! ### PowerShell
//! - Runs `Get-CimInstance -ClassName Win32_Service -Filter "Name='<n>'"`
//! - Can detect `DelayedAutoStart` property
//!
//! ## Collected Data Fields
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `exists` | boolean | Whether service exists |
//! | `state` | string | Runtime state (normalized) |
//! | `start_type` | string | Startup type (normalized) |
//! | `display_name` | string | Display name |
//! | `path` | string | Binary path |
//! | `service_type` | string | Service type (normalized) |

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::ResolvedValue;
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::commands::powershell::create_powershell_executor;
use crate::commands::sc::{
    create_sc_executor, is_access_denied, is_service_not_found, parse_sc_qc_output,
    parse_sc_query_output,
};

/// Collector for Windows Services
#[derive(Clone)]
pub struct ServiceCollector {
    id: String,
    sc_executor: SystemCommandExecutor,
    powershell_executor: SystemCommandExecutor,
}

impl ServiceCollector {
    /// Create a new service collector
    pub fn new() -> Self {
        Self {
            id: "windows_service_collector".to_string(),
            sc_executor: create_sc_executor(),
            powershell_executor: create_powershell_executor(),
        }
    }

    /// Create collector with custom ID
    pub fn with_id(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            sc_executor: create_sc_executor(),
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

    /// Collect service data using sc.exe
    ///
    /// Executes both `sc.exe query` and `sc.exe qc` to get full service information.
    fn collect_via_sc(
        &self,
        object: &ExecutableObject,
        service_name: &str,
    ) -> Result<CollectedData, CollectionError> {
        let mut data = CollectedData::new(
            object.identifier.clone(),
            "service".to_string(),
            self.id.clone(),
        );

        // Build command strings for traceability
        let query_command = format!("sc.exe query \"{}\"", service_name);
        let qc_command = format!("sc.exe qc \"{}\"", service_name);

        // Set collection method for traceability (combining both commands)
        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::Command)
            .description("Query Windows service state and configuration via sc.exe")
            .target(service_name)
            .command(format!("{}; {}", query_command, qc_command))
            .input("service_name", service_name)
            .input("executor", "sc")
            .build();
        data.set_method(method);

        // Step 1: Query runtime state with `sc.exe query`
        let query_args = ["query", service_name];
        let query_output = self
            .sc_executor
            .execute("sc.exe", &query_args, None)
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("sc.exe query execution failed: {}", e),
            })?;

        // Check for service not found
        if is_service_not_found(&query_output.stdout) || is_service_not_found(&query_output.stderr)
        {
            data.add_field("exists".to_string(), ResolvedValue::Boolean(false));
            data.add_field("state".to_string(), ResolvedValue::String(String::new()));
            data.add_field(
                "start_type".to_string(),
                ResolvedValue::String(String::new()),
            );
            return Ok(data);
        }

        // Check for access denied
        if is_access_denied(&query_output.stdout) || is_access_denied(&query_output.stderr) {
            return Err(CollectionError::AccessDenied {
                object_id: object.identifier.clone(),
                reason: format!("Access denied querying service: {}", service_name),
            });
        }

        // Check for other errors
        if query_output.exit_code != 0 {
            return Err(CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!(
                    "sc.exe query failed with exit code {}: {}",
                    query_output.exit_code, query_output.stderr
                ),
            });
        }

        // Parse query output for runtime state
        let query_info = parse_sc_query_output(&query_output.stdout).ok_or_else(|| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: "Failed to parse sc.exe query output".to_string(),
            }
        })?;

        // Step 2: Query configuration with `sc.exe qc`
        let qc_args = ["qc", service_name];
        let qc_output = self
            .sc_executor
            .execute("sc.exe", &qc_args, None)
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("sc.exe qc execution failed: {}", e),
            })?;

        // Check for errors on qc (shouldn't happen if query succeeded, but be safe)
        if is_service_not_found(&qc_output.stdout) || is_service_not_found(&qc_output.stderr) {
            // Unusual: query succeeded but qc failed - treat as not found
            data.add_field("exists".to_string(), ResolvedValue::Boolean(false));
            data.add_field("state".to_string(), ResolvedValue::String(String::new()));
            data.add_field(
                "start_type".to_string(),
                ResolvedValue::String(String::new()),
            );
            return Ok(data);
        }

        if is_access_denied(&qc_output.stdout) || is_access_denied(&qc_output.stderr) {
            return Err(CollectionError::AccessDenied {
                object_id: object.identifier.clone(),
                reason: format!(
                    "Access denied querying service configuration: {}",
                    service_name
                ),
            });
        }

        if qc_output.exit_code != 0 {
            return Err(CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!(
                    "sc.exe qc failed with exit code {}: {}",
                    qc_output.exit_code, qc_output.stderr
                ),
            });
        }

        // Parse qc output for configuration
        let qc_info = parse_sc_qc_output(&qc_output.stdout).ok_or_else(|| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: "Failed to parse sc.exe qc output".to_string(),
            }
        })?;

        // Build collected data
        data.add_field("exists".to_string(), ResolvedValue::Boolean(true));
        data.add_field("state".to_string(), ResolvedValue::String(query_info.state));
        data.add_field(
            "start_type".to_string(),
            ResolvedValue::String(qc_info.start_type),
        );
        data.add_field(
            "display_name".to_string(),
            ResolvedValue::String(qc_info.display_name),
        );
        data.add_field("path".to_string(), ResolvedValue::String(qc_info.path));
        data.add_field(
            "service_type".to_string(),
            ResolvedValue::String(qc_info.service_type),
        );

        Ok(data)
    }

    /// Collect service data using PowerShell Get-CimInstance
    fn collect_via_powershell(
        &self,
        object: &ExecutableObject,
        service_name: &str,
    ) -> Result<CollectedData, CollectionError> {
        let mut data = CollectedData::new(
            object.identifier.clone(),
            "service".to_string(),
            self.id.clone(),
        );

        // Build PowerShell command
        let command = format!(
            "Get-CimInstance -ClassName Win32_Service -Filter \"Name='{}'\" | Select-Object Name, State, StartMode, DisplayName, PathName, ServiceType, DelayedAutoStart | ConvertTo-Json",
            service_name.replace('\'', "''") // Escape single quotes
        );

        let args = ["-NoProfile", "-NonInteractive", "-Command", &command];

        // Build command string for traceability
        let command_str = format!(
            "powershell -NoProfile -NonInteractive -Command \"{}\"",
            command
        );

        // Set collection method for traceability
        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::WmiQuery)
            .description("Query Windows service via PowerShell Get-CimInstance (WMI)")
            .target(service_name)
            .command(&command_str)
            .input("service_name", service_name)
            .input("executor", "powershell")
            .input("wmi_class", "Win32_Service")
            .build();
        data.set_method(method);

        let output = self
            .powershell_executor
            .execute("powershell", &args, None)
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("PowerShell execution failed: {}", e),
            })?;

        // Check for errors
        if output.exit_code != 0 {
            let stderr_lower = output.stderr.to_lowercase();

            if stderr_lower.contains("access") && stderr_lower.contains("denied") {
                return Err(CollectionError::AccessDenied {
                    object_id: object.identifier.clone(),
                    reason: format!("Access denied querying service: {}", service_name),
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

        // Check for empty output (service not found)
        let stdout_trimmed = output.stdout.trim();
        if stdout_trimmed.is_empty() || stdout_trimmed == "null" {
            data.add_field("exists".to_string(), ResolvedValue::Boolean(false));
            data.add_field("state".to_string(), ResolvedValue::String(String::new()));
            data.add_field(
                "start_type".to_string(),
                ResolvedValue::String(String::new()),
            );
            return Ok(data);
        }

        // Parse JSON output
        let json: serde_json::Value = serde_json::from_str(stdout_trimmed).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to parse PowerShell JSON output: {}", e),
            }
        })?;

        // Extract and normalize fields
        let state = json
            .get("State")
            .and_then(|v| v.as_str())
            .map(normalize_powershell_state)
            .unwrap_or_else(|| "unknown".to_string());

        let start_mode = json
            .get("StartMode")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let delayed_auto_start = json
            .get("DelayedAutoStart")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let start_type = normalize_powershell_start_type(start_mode, delayed_auto_start);

        let display_name = json
            .get("DisplayName")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let path = json
            .get("PathName")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let service_type = json
            .get("ServiceType")
            .and_then(|v| v.as_str())
            .map(normalize_powershell_service_type)
            .unwrap_or_else(|| "unknown".to_string());

        // Build collected data
        data.add_field("exists".to_string(), ResolvedValue::Boolean(true));
        data.add_field("state".to_string(), ResolvedValue::String(state));
        data.add_field("start_type".to_string(), ResolvedValue::String(start_type));
        data.add_field(
            "display_name".to_string(),
            ResolvedValue::String(display_name),
        );
        data.add_field("path".to_string(), ResolvedValue::String(path));
        data.add_field(
            "service_type".to_string(),
            ResolvedValue::String(service_type),
        );

        Ok(data)
    }
}

impl Default for ServiceCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for ServiceCollector {
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

        // Extract required service name
        let service_name = self.extract_required_string(object, "name")?;

        // Get executor from behavior (default: sc)
        let executor = hints.get_parameter("executor").unwrap_or("sc");

        // Dispatch to appropriate collector
        match executor {
            "sc" => self.collect_via_sc(object, &service_name),
            "powershell" => self.collect_via_powershell(object, &service_name),
            _ => Err(CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: format!(
                    "Invalid executor '{}'. Valid values: sc, powershell",
                    executor
                ),
            }),
        }
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["service".to_string()]
    }

    fn collector_id(&self) -> &str {
        &self.id
    }

    fn supports_batch_collection(&self) -> bool {
        false // Each service requires separate queries
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "service" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'service', got '{}'",
                    contract.ctn_type
                ),
            });
        }
        Ok(())
    }
}

/// Normalize PowerShell State value to lowercase standard
///
/// | PowerShell | Normalized |
/// |------------|------------|
/// | Running | running |
/// | Stopped | stopped |
/// | Paused | paused |
/// | StartPending | start_pending |
/// | StopPending | stop_pending |
/// | ContinuePending | continue_pending |
/// | PausePending | pause_pending |
fn normalize_powershell_state(state: &str) -> String {
    match state {
        "Running" => "running".to_string(),
        "Stopped" => "stopped".to_string(),
        "Paused" => "paused".to_string(),
        "StartPending" => "start_pending".to_string(),
        "StopPending" => "stop_pending".to_string(),
        "ContinuePending" => "continue_pending".to_string(),
        "PausePending" => "pause_pending".to_string(),
        _ => "unknown".to_string(),
    }
}

/// Normalize PowerShell StartMode value to lowercase standard
///
/// | PowerShell StartMode | DelayedAutoStart | Normalized |
/// |----------------------|------------------|------------|
/// | Automatic | true | auto_delayed |
/// | Automatic | false | auto |
/// | Auto | true | auto_delayed |
/// | Auto | false | auto |
/// | Manual | - | manual |
/// | Disabled | - | disabled |
/// | Boot | - | boot |
/// | System | - | system |
fn normalize_powershell_start_type(start_mode: &str, delayed_auto_start: bool) -> String {
    match start_mode {
        "Automatic" | "Auto" => {
            if delayed_auto_start {
                "auto_delayed".to_string()
            } else {
                "auto".to_string()
            }
        }
        "Manual" => "manual".to_string(),
        "Disabled" => "disabled".to_string(),
        "Boot" => "boot".to_string(),
        "System" => "system".to_string(),
        _ => "unknown".to_string(),
    }
}

/// Normalize PowerShell ServiceType value to lowercase standard
///
/// | PowerShell | Normalized |
/// |------------|------------|
/// | Own Process | own_process |
/// | Share Process | share_process |
/// | Kernel Driver | kernel_driver |
/// | File System Driver | file_system_driver |
fn normalize_powershell_service_type(service_type: &str) -> String {
    match service_type {
        "Own Process" => "own_process".to_string(),
        "Share Process" => "share_process".to_string(),
        "Kernel Driver" => "kernel_driver".to_string(),
        "File System Driver" => "file_system_driver".to_string(),
        _ => {
            // Handle variations
            let lower = service_type.to_lowercase();
            if lower.contains("own") && lower.contains("process") {
                "own_process".to_string()
            } else if lower.contains("share") && lower.contains("process") {
                "share_process".to_string()
            } else if lower.contains("kernel") {
                "kernel_driver".to_string()
            } else if lower.contains("file") && lower.contains("system") {
                "file_system_driver".to_string()
            } else {
                "unknown".to_string()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collector_creation() {
        let collector = ServiceCollector::new();
        assert_eq!(collector.collector_id(), "windows_service_collector");
        assert!(collector
            .supported_ctn_types()
            .contains(&"service".to_string()));
    }

    #[test]
    fn test_collector_with_custom_id() {
        let collector = ServiceCollector::with_id("custom_id");
        assert_eq!(collector.collector_id(), "custom_id");
    }

    #[test]
    fn test_supports_batch_collection() {
        let collector = ServiceCollector::new();
        assert!(!collector.supports_batch_collection());
    }

    #[test]
    fn test_normalize_powershell_state() {
        assert_eq!(normalize_powershell_state("Running"), "running");
        assert_eq!(normalize_powershell_state("Stopped"), "stopped");
        assert_eq!(normalize_powershell_state("Paused"), "paused");
        assert_eq!(normalize_powershell_state("StartPending"), "start_pending");
        assert_eq!(normalize_powershell_state("StopPending"), "stop_pending");
        assert_eq!(normalize_powershell_state("Unknown"), "unknown");
    }

    #[test]
    fn test_normalize_powershell_start_type() {
        assert_eq!(normalize_powershell_start_type("Automatic", false), "auto");
        assert_eq!(
            normalize_powershell_start_type("Automatic", true),
            "auto_delayed"
        );
        assert_eq!(normalize_powershell_start_type("Auto", false), "auto");
        assert_eq!(
            normalize_powershell_start_type("Auto", true),
            "auto_delayed"
        );
        assert_eq!(normalize_powershell_start_type("Manual", false), "manual");
        assert_eq!(
            normalize_powershell_start_type("Disabled", false),
            "disabled"
        );
        assert_eq!(normalize_powershell_start_type("Boot", false), "boot");
        assert_eq!(normalize_powershell_start_type("System", false), "system");
    }

    #[test]
    fn test_normalize_powershell_service_type() {
        assert_eq!(
            normalize_powershell_service_type("Own Process"),
            "own_process"
        );
        assert_eq!(
            normalize_powershell_service_type("Share Process"),
            "share_process"
        );
        assert_eq!(
            normalize_powershell_service_type("Kernel Driver"),
            "kernel_driver"
        );
        assert_eq!(
            normalize_powershell_service_type("File System Driver"),
            "file_system_driver"
        );
    }

    #[test]
    fn test_ctn_compatibility() {
        let collector = ServiceCollector::new();

        // Valid contract
        let valid_contract = CtnContract::new("service".to_string());
        assert!(collector
            .validate_ctn_compatibility(&valid_contract)
            .is_ok());

        // Invalid contract
        let invalid_contract = CtnContract::new("registry".to_string());
        assert!(collector
            .validate_ctn_compatibility(&invalid_contract)
            .is_err());
    }
}
