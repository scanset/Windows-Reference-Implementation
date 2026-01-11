//! PowerShell command executor
//!
//! Whitelisted command configuration for PowerShell commands.
//!
//! ## Usage
//!
//! ```ignore
//! let executor = create_powershell_executor();
//! let output = executor.execute(
//!     "powershell",
//!     &["-NoProfile", "-Command", "Get-ItemPropertyValue ..."],
//!     None
//! )?;
//! ```
//!
//! ## Output Format
//!
//! Raw value string (trimmed):
//! ```text
//! 26100
//! ```

use execution_engine::strategies::SystemCommandExecutor;
use std::time::Duration;

/// Default timeout for PowerShell execution (30 seconds)
const DEFAULT_POWERSHELL_TIMEOUT_SECS: u64 = 30;

/// Whitelisted PowerShell binary paths
///
/// Note: We use PowerShell 5.1 (Windows PowerShell) which is always available.
/// PowerShell Core (pwsh.exe) is optional and not guaranteed to exist.
pub const POWERSHELL_PATHS: &[&str] = &[
    "powershell",
    "powershell.exe",
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
];

/// Create a command executor configured for PowerShell
pub fn create_powershell_executor() -> SystemCommandExecutor {
    let mut executor =
        SystemCommandExecutor::with_timeout(Duration::from_secs(DEFAULT_POWERSHELL_TIMEOUT_SECS));

    // Whitelist PowerShell binary paths
    for path in POWERSHELL_PATHS {
        executor.allow_command(*path);
    }

    executor
}

/// Build PowerShell arguments for Get-ItemPropertyValue
///
/// Returns arguments array for: powershell -NoProfile -Command "Get-ItemPropertyValue ..."
pub fn build_registry_value_args(hive: &str, key: &str, name: &str) -> Vec<String> {
    // Normalize hive to PowerShell format (HKLM:, HKCU:, etc.)
    let ps_hive = normalize_hive_for_powershell(hive);

    // Build the PowerShell command
    let command = format!(
        "Get-ItemPropertyValue -Path '{}:\\{}' -Name '{}'",
        ps_hive, key, name
    );

    vec![
        "-NoProfile".to_string(),
        "-NonInteractive".to_string(),
        "-Command".to_string(),
        command,
    ]
}

/// Normalize registry hive name to PowerShell drive format
///
/// Converts:
/// - "HKEY_LOCAL_MACHINE" -> "HKLM"
/// - "HKEY_CURRENT_USER" -> "HKCU"
/// - "HKLM" -> "HKLM" (already short form)
fn normalize_hive_for_powershell(hive: &str) -> &'static str {
    match hive.to_uppercase().as_str() {
        "HKEY_LOCAL_MACHINE" | "HKLM" => "HKLM",
        "HKEY_CURRENT_USER" | "HKCU" => "HKCU",
        "HKEY_CLASSES_ROOT" | "HKCR" => "HKCR",
        "HKEY_USERS" | "HKU" => "HKU",
        "HKEY_CURRENT_CONFIG" | "HKCC" => "HKCC",
        _ => "HKLM", // Default fallback
    }
}

/// Parse PowerShell output (simple trim)
///
/// PowerShell Get-ItemPropertyValue returns just the value, so we only need to trim.
pub fn parse_powershell_output(output: &str) -> String {
    output.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_hive_full_names() {
        assert_eq!(normalize_hive_for_powershell("HKEY_LOCAL_MACHINE"), "HKLM");
        assert_eq!(normalize_hive_for_powershell("HKEY_CURRENT_USER"), "HKCU");
        assert_eq!(normalize_hive_for_powershell("HKEY_CLASSES_ROOT"), "HKCR");
        assert_eq!(normalize_hive_for_powershell("HKEY_USERS"), "HKU");
        assert_eq!(normalize_hive_for_powershell("HKEY_CURRENT_CONFIG"), "HKCC");
    }

    #[test]
    fn test_normalize_hive_short_names() {
        assert_eq!(normalize_hive_for_powershell("HKLM"), "HKLM");
        assert_eq!(normalize_hive_for_powershell("HKCU"), "HKCU");
        assert_eq!(normalize_hive_for_powershell("hklm"), "HKLM"); // lowercase
    }

    #[test]
    fn test_build_registry_value_args() {
        let args = build_registry_value_args(
            "HKEY_LOCAL_MACHINE",
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            "CurrentBuildNumber",
        );

        assert_eq!(args.first(), Some(&"-NoProfile".to_string()));
        assert_eq!(args.get(1), Some(&"-NonInteractive".to_string()));
        assert_eq!(args.get(2), Some(&"-Command".to_string()));
        assert!(args
            .get(3)
            .map(|s| s.contains("Get-ItemPropertyValue"))
            .unwrap_or(false));
        assert!(args.get(3).map(|s| s.contains("HKLM:")).unwrap_or(false));
        assert!(args
            .get(3)
            .map(|s| s.contains("CurrentBuildNumber"))
            .unwrap_or(false));
    }

    #[test]
    fn test_parse_powershell_output() {
        assert_eq!(parse_powershell_output("26100\n"), "26100");
        assert_eq!(parse_powershell_output("  26100  "), "26100");
        assert_eq!(parse_powershell_output("Windows 11 Pro"), "Windows 11 Pro");
    }
}
