//! sc.exe command executor
//!
//! Whitelisted command configuration for Windows Service queries via sc.exe.
//!
//! ## Usage
//!
//! ```ignore
//! let executor = create_sc_executor();
//!
//! // Query runtime state
//! let output = executor.execute("sc.exe", &["query", "W32Time"], None)?;
//! let state_info = parse_sc_query_output(&output.stdout)?;
//!
//! // Query configuration
//! let output = executor.execute("sc.exe", &["qc", "W32Time"], None)?;
//! let config_info = parse_sc_qc_output(&output.stdout)?;
//! ```
//!
//! ## Output Formats
//!
//! ### sc.exe query (runtime state)
//! ```text
//! SERVICE_NAME: W32Time
//!         TYPE               : 30  WIN32
//!         STATE              : 4  RUNNING
//!                                 (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
//!         WIN32_EXIT_CODE    : 0  (0x0)
//!         SERVICE_EXIT_CODE  : 0  (0x0)
//!         CHECKPOINT         : 0x0
//!         WAIT_HINT          : 0x0
//! ```
//!
//! ### sc.exe qc (configuration)
//! ```text
//! [SC] QueryServiceConfig SUCCESS
//! SERVICE_NAME: W32Time
//!         TYPE               : 20  WIN32_SHARE_PROCESS
//!         START_TYPE         : 3   DEMAND_START
//!         ERROR_CONTROL      : 1   NORMAL
//!         BINARY_PATH_NAME   : C:\windows\system32\svchost.exe -k LocalService
//!         LOAD_ORDER_GROUP   :
//!         TAG                : 0
//!         DISPLAY_NAME       : Windows Time
//!         DEPENDENCIES       :
//!         SERVICE_START_NAME : NT AUTHORITY\LocalService
//! ```

use execution_engine::strategies::SystemCommandExecutor;
use std::time::Duration;

/// Default timeout for sc.exe execution (30 seconds)
const DEFAULT_SC_TIMEOUT_SECS: u64 = 30;

/// Whitelisted sc.exe binary paths
pub const SC_PATHS: &[&str] = &["sc.exe", "C:\\Windows\\System32\\sc.exe"];

/// sc.exe error codes
pub const SC_ERROR_SERVICE_NOT_FOUND: i32 = 1060;
pub const SC_ERROR_ACCESS_DENIED: i32 = 5;

/// Parsed output from `sc.exe query`
#[derive(Debug, Clone, Default)]
pub struct ScQueryOutput {
    /// Service runtime state (normalized)
    pub state: String,
    /// Service type from query output (less detailed than qc)
    pub service_type: Option<String>,
}

/// Parsed output from `sc.exe qc`
#[derive(Debug, Clone, Default)]
pub struct ScQcOutput {
    /// Service type (normalized)
    pub service_type: String,
    /// Start type (normalized)
    pub start_type: String,
    /// Binary path
    pub path: String,
    /// Display name
    pub display_name: String,
}

/// Combined service information from both commands
#[derive(Debug, Clone, Default)]
pub struct ServiceInfo {
    pub exists: bool,
    pub state: String,
    pub start_type: String,
    pub display_name: String,
    pub path: String,
    pub service_type: String,
}

/// Create a command executor configured for sc.exe
pub fn create_sc_executor() -> SystemCommandExecutor {
    let mut executor =
        SystemCommandExecutor::with_timeout(Duration::from_secs(DEFAULT_SC_TIMEOUT_SECS));

    // Whitelist sc.exe binary paths
    for path in SC_PATHS {
        executor.allow_command(*path);
    }

    executor
}

/// Check if sc.exe output indicates the service was not found
pub fn is_service_not_found(output: &str) -> bool {
    output.contains("FAILED 1060:") || output.contains("does not exist as an installed service")
}

/// Check if sc.exe output indicates access denied
pub fn is_access_denied(output: &str) -> bool {
    output.contains("FAILED 5:") || output.to_lowercase().contains("access is denied")
}

/// Parse `sc.exe query` output to extract runtime state
///
/// Extracts the STATE line: `STATE              : 4  RUNNING`
pub fn parse_sc_query_output(output: &str) -> Option<ScQueryOutput> {
    let mut result = ScQueryOutput::default();

    for line in output.lines() {
        let trimmed = line.trim();

        // Parse STATE line
        if trimmed.starts_with("STATE") {
            if let Some(state) = parse_state_line(trimmed) {
                result.state = state;
            }
        }

        // Parse TYPE line (from query, less detailed)
        if trimmed.starts_with("TYPE") {
            if let Some(svc_type) = parse_type_line(trimmed) {
                result.service_type = Some(svc_type);
            }
        }
    }

    if result.state.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Parse `sc.exe qc` output to extract configuration
///
/// Extracts TYPE, START_TYPE, BINARY_PATH_NAME, DISPLAY_NAME
pub fn parse_sc_qc_output(output: &str) -> Option<ScQcOutput> {
    let mut result = ScQcOutput::default();

    for line in output.lines() {
        let trimmed = line.trim();

        // Parse TYPE line
        if trimmed.starts_with("TYPE") {
            if let Some(svc_type) = parse_type_line(trimmed) {
                result.service_type = svc_type;
            }
        }

        // Parse START_TYPE line
        if trimmed.starts_with("START_TYPE") {
            if let Some(start_type) = parse_start_type_line(trimmed) {
                result.start_type = start_type;
            }
        }

        // Parse BINARY_PATH_NAME line
        if trimmed.starts_with("BINARY_PATH_NAME") {
            if let Some(path) = parse_key_value_line(trimmed) {
                result.path = path;
            }
        }

        // Parse DISPLAY_NAME line
        if trimmed.starts_with("DISPLAY_NAME") {
            if let Some(name) = parse_key_value_line(trimmed) {
                result.display_name = name;
            }
        }
    }

    // Must have at least start_type to be valid
    if result.start_type.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Parse STATE line and normalize value
///
/// Input: `STATE              : 4  RUNNING`
/// Output: `running`
fn parse_state_line(line: &str) -> Option<String> {
    // Split on `:` and get the value part
    let value = line.split_once(':')?.1.trim();

    // Value format: "4  RUNNING" or "1  STOPPED"
    // We want the text part, normalized to lowercase
    let state_text = extract_text_after_number(value)?;
    Some(normalize_state(&state_text))
}

/// Parse TYPE line and normalize value
///
/// Input: `TYPE               : 20  WIN32_SHARE_PROCESS`
/// Input: `TYPE               : 110  WIN32_OWN_PROCESS (interactive)`
/// Output: `share_process`, `own_process_interactive`
fn parse_type_line(line: &str) -> Option<String> {
    let value = line.split_once(':')?.1.trim();

    let type_text = extract_text_after_number(value)?;
    Some(normalize_service_type(&type_text))
}

/// Parse START_TYPE line and normalize value
///
/// Input: `START_TYPE         : 3   DEMAND_START`
/// Input: `START_TYPE         : 2   AUTO_START  (DELAYED)`
/// Output: `manual`, `auto_delayed`
fn parse_start_type_line(line: &str) -> Option<String> {
    let value = line.split_once(':')?.1.trim();

    let start_text = extract_text_after_number(value)?;
    Some(normalize_start_type(&start_text))
}

/// Parse a simple key: value line
///
/// Input: `DISPLAY_NAME       : Windows Time`
/// Output: `Windows Time`
fn parse_key_value_line(line: &str) -> Option<String> {
    let value = line.split_once(':')?.1.trim();

    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

/// Extract text portion after the numeric code
///
/// Input: "4  RUNNING" -> "RUNNING"
/// Input: "20  WIN32_SHARE_PROCESS" -> "WIN32_SHARE_PROCESS"
/// Input: "110  WIN32_OWN_PROCESS (interactive)" -> "WIN32_OWN_PROCESS (interactive)"
fn extract_text_after_number(value: &str) -> Option<String> {
    // Find first non-digit, non-whitespace character
    let trimmed = value.trim();

    // Skip leading digits
    let text_start = trimmed
        .find(|c: char| !c.is_ascii_digit() && !c.is_whitespace())
        .unwrap_or(0);

    let text = trimmed.get(text_start..)?.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

/// Normalize runtime state to lowercase standard values
///
/// | sc.exe | Normalized |
/// |--------|------------|
/// | STOPPED | stopped |
/// | START_PENDING | start_pending |
/// | STOP_PENDING | stop_pending |
/// | RUNNING | running |
/// | CONTINUE_PENDING | continue_pending |
/// | PAUSE_PENDING | pause_pending |
/// | PAUSED | paused |
fn normalize_state(state: &str) -> String {
    match state.to_uppercase().as_str() {
        "STOPPED" => "stopped".to_string(),
        "START_PENDING" => "start_pending".to_string(),
        "STOP_PENDING" => "stop_pending".to_string(),
        "RUNNING" => "running".to_string(),
        "CONTINUE_PENDING" => "continue_pending".to_string(),
        "PAUSE_PENDING" => "pause_pending".to_string(),
        "PAUSED" => "paused".to_string(),
        _ => "unknown".to_string(),
    }
}

/// Normalize start type to lowercase standard values
///
/// | sc.exe | Normalized |
/// |--------|------------|
/// | BOOT_START | boot |
/// | SYSTEM_START | system |
/// | AUTO_START | auto |
/// | AUTO_START  (DELAYED) | auto_delayed |
/// | DEMAND_START | manual |
/// | DISABLED | disabled |
fn normalize_start_type(start_type: &str) -> String {
    let upper = start_type.to_uppercase();

    // Check for delayed auto-start first (contains both AUTO_START and DELAYED)
    if upper.contains("AUTO_START") && upper.contains("DELAYED") {
        return "auto_delayed".to_string();
    }

    // Match exact start types
    if upper.contains("BOOT_START") {
        "boot".to_string()
    } else if upper.contains("SYSTEM_START") {
        "system".to_string()
    } else if upper.contains("AUTO_START") {
        "auto".to_string()
    } else if upper.contains("DEMAND_START") {
        "manual".to_string()
    } else if upper.contains("DISABLED") {
        "disabled".to_string()
    } else {
        "unknown".to_string()
    }
}

/// Normalize service type to lowercase standard values
///
/// | sc.exe | Normalized |
/// |--------|------------|
/// | KERNEL_DRIVER | kernel_driver |
/// | FILE_SYSTEM_DRIVER | file_system_driver |
/// | WIN32_OWN_PROCESS | own_process |
/// | WIN32_OWN_PROCESS (interactive) | own_process_interactive |
/// | WIN32_SHARE_PROCESS | share_process |
/// | WIN32 | win32 (generic from query) |
fn normalize_service_type(svc_type: &str) -> String {
    let upper = svc_type.to_uppercase();

    // Check for interactive variant first
    if upper.contains("WIN32_OWN_PROCESS") && upper.contains("INTERACTIVE") {
        return "own_process_interactive".to_string();
    }

    if upper.contains("KERNEL_DRIVER") {
        "kernel_driver".to_string()
    } else if upper.contains("FILE_SYSTEM_DRIVER") {
        "file_system_driver".to_string()
    } else if upper.contains("WIN32_OWN_PROCESS") {
        "own_process".to_string()
    } else if upper.contains("WIN32_SHARE_PROCESS") {
        "share_process".to_string()
    } else if upper == "WIN32" {
        // Generic type from sc query (not qc)
        "win32".to_string()
    } else {
        "unknown".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sc_query_running() {
        let output = r#"
SERVICE_NAME: W32Time
        TYPE               : 30  WIN32
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
"#;
        let result = parse_sc_query_output(output);
        assert!(result.is_some());
        assert_eq!(result.map(|r| r.state), Some("running".to_string()));
    }

    #[test]
    fn test_parse_sc_query_stopped() {
        let output = r#"
SERVICE_NAME: RemoteRegistry
        TYPE               : 20  WIN32_SHARE_PROCESS
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 1077  (0x435)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
"#;
        let result = parse_sc_query_output(output);
        assert!(result.is_some());
        assert_eq!(result.map(|r| r.state), Some("stopped".to_string()));
    }

    #[test]
    fn test_parse_sc_qc_demand_start() {
        let output = r#"
[SC] QueryServiceConfig SUCCESS
SERVICE_NAME: W32Time
        TYPE               : 20  WIN32_SHARE_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\windows\system32\svchost.exe -k LocalService
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Windows Time
        DEPENDENCIES       :
        SERVICE_START_NAME : NT AUTHORITY\LocalService
"#;
        let result = parse_sc_qc_output(output);
        assert!(result.is_some());
        let result = result.as_ref();
        assert_eq!(result.map(|r| r.start_type.as_str()), Some("manual"));
        assert_eq!(
            result.map(|r| r.service_type.as_str()),
            Some("share_process")
        );
        assert_eq!(
            result.map(|r| r.display_name.as_str()),
            Some("Windows Time")
        );
        assert_eq!(
            result.map(|r| r.path.as_str()),
            Some(r"C:\windows\system32\svchost.exe -k LocalService")
        );
    }

    #[test]
    fn test_parse_sc_qc_auto_delayed() {
        let output = r#"
[SC] QueryServiceConfig SUCCESS
SERVICE_NAME: WSearch
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START  (DELAYED)
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\windows\system32\SearchIndexer.exe /Embedding
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Windows Search
        DEPENDENCIES       : RPCSS
                           : BrokerInfrastructure
        SERVICE_START_NAME : LocalSystem
"#;
        let result = parse_sc_qc_output(output);
        assert!(result.is_some());
        let result = result.as_ref();
        assert_eq!(result.map(|r| r.start_type.as_str()), Some("auto_delayed"));
        assert_eq!(result.map(|r| r.service_type.as_str()), Some("own_process"));
    }

    #[test]
    fn test_parse_sc_qc_disabled() {
        let output = r#"
[SC] QueryServiceConfig SUCCESS
SERVICE_NAME: RemoteRegistry
        TYPE               : 20  WIN32_SHARE_PROCESS
        START_TYPE         : 4   DISABLED
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\windows\system32\svchost.exe -k localService -p
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Remote Registry
        DEPENDENCIES       : RPCSS
        SERVICE_START_NAME : NT AUTHORITY\LocalService
"#;
        let result = parse_sc_qc_output(output);
        assert!(result.is_some());
        assert_eq!(result.map(|r| r.start_type), Some("disabled".to_string()));
    }

    #[test]
    fn test_parse_sc_qc_interactive() {
        let output = r#"
[SC] QueryServiceConfig SUCCESS
SERVICE_NAME: Spooler
        TYPE               : 110  WIN32_OWN_PROCESS (interactive)
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\windows\System32\spoolsv.exe
        LOAD_ORDER_GROUP   : SpoolerGroup
        TAG                : 0
        DISPLAY_NAME       : Print Spooler
        DEPENDENCIES       : RPCSS
                           : http
        SERVICE_START_NAME : LocalSystem
"#;
        let result = parse_sc_qc_output(output);
        assert!(result.is_some());
        let result = result.as_ref();
        assert_eq!(result.map(|r| r.start_type.as_str()), Some("auto"));
        assert_eq!(
            result.map(|r| r.service_type.as_str()),
            Some("own_process_interactive")
        );
        assert_eq!(
            result.map(|r| r.display_name.as_str()),
            Some("Print Spooler")
        );
    }

    #[test]
    fn test_parse_sc_qc_kernel_driver() {
        let output = r#"
[SC] QueryServiceConfig SUCCESS
SERVICE_NAME: Tcpip
        TYPE               : 1  KERNEL_DRIVER
        START_TYPE         : 0   BOOT_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : \SystemRoot\System32\drivers\tcpip.sys
        LOAD_ORDER_GROUP   : PNP_TDI
        TAG                : 3
        DISPLAY_NAME       : TCP/IP Protocol Driver
        DEPENDENCIES       :
        SERVICE_START_NAME :
"#;
        let result = parse_sc_qc_output(output);
        assert!(result.is_some());
        let result = result.as_ref();
        assert_eq!(result.map(|r| r.start_type.as_str()), Some("boot"));
        assert_eq!(
            result.map(|r| r.service_type.as_str()),
            Some("kernel_driver")
        );
        assert_eq!(
            result.map(|r| r.display_name.as_str()),
            Some("TCP/IP Protocol Driver")
        );
    }

    #[test]
    fn test_is_service_not_found() {
        let output = r#"[SC] EnumQueryServicesStatus:OpenService FAILED 1060:
The specified service does not exist as an installed service."#;
        assert!(is_service_not_found(output));
    }

    #[test]
    fn test_is_service_not_found_qc() {
        let output = r#"[SC] OpenService FAILED 1060:
The specified service does not exist as an installed service."#;
        assert!(is_service_not_found(output));
    }

    #[test]
    fn test_normalize_state() {
        assert_eq!(normalize_state("RUNNING"), "running");
        assert_eq!(normalize_state("STOPPED"), "stopped");
        assert_eq!(normalize_state("PAUSED"), "paused");
        assert_eq!(normalize_state("START_PENDING"), "start_pending");
        assert_eq!(normalize_state("STOP_PENDING"), "stop_pending");
        assert_eq!(normalize_state("UNKNOWN_STATE"), "unknown");
    }

    #[test]
    fn test_normalize_start_type() {
        assert_eq!(normalize_start_type("AUTO_START"), "auto");
        assert_eq!(
            normalize_start_type("AUTO_START  (DELAYED)"),
            "auto_delayed"
        );
        assert_eq!(normalize_start_type("DEMAND_START"), "manual");
        assert_eq!(normalize_start_type("DISABLED"), "disabled");
        assert_eq!(normalize_start_type("BOOT_START"), "boot");
        assert_eq!(normalize_start_type("SYSTEM_START"), "system");
    }

    #[test]
    fn test_normalize_service_type() {
        assert_eq!(normalize_service_type("WIN32_OWN_PROCESS"), "own_process");
        assert_eq!(
            normalize_service_type("WIN32_OWN_PROCESS (interactive)"),
            "own_process_interactive"
        );
        assert_eq!(
            normalize_service_type("WIN32_SHARE_PROCESS"),
            "share_process"
        );
        assert_eq!(normalize_service_type("KERNEL_DRIVER"), "kernel_driver");
        assert_eq!(
            normalize_service_type("FILE_SYSTEM_DRIVER"),
            "file_system_driver"
        );
    }
}
