//! reg.exe command executor
//!
//! Whitelisted command configuration for Windows Registry queries via reg.exe.
//!
//! ## Usage
//!
//! ```ignore
//! let executor = create_reg_executor();
//! let output = executor.execute("reg", &["query", "HKLM\\...", "/v", "ValueName"], None)?;
//! ```
//!
//! ## Output Format
//!
//! ```text
//! HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion
//!     CurrentBuildNumber    REG_SZ    26100
//! ```

use execution_engine::strategies::SystemCommandExecutor;
use std::time::Duration;

/// Default timeout for reg.exe execution (30 seconds)
const DEFAULT_REG_TIMEOUT_SECS: u64 = 30;

/// Whitelisted reg.exe binary paths
pub const REG_PATHS: &[&str] = &["reg", "reg.exe", "C:\\Windows\\System32\\reg.exe"];

/// Create a command executor configured for reg.exe
pub fn create_reg_executor() -> SystemCommandExecutor {
    let mut executor =
        SystemCommandExecutor::with_timeout(Duration::from_secs(DEFAULT_REG_TIMEOUT_SECS));

    // Whitelist reg.exe binary paths
    for path in REG_PATHS {
        executor.allow_command(*path);
    }

    executor
}

/// Parse reg.exe query output to extract type and value
///
/// Input format:
/// ```text
/// HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion
///     CurrentBuildNumber    REG_SZ    26100
/// ```
///
/// Returns (type, value) tuple, e.g., ("REG_SZ", "26100")
pub fn parse_reg_output(output: &str) -> Option<(String, String)> {
    for line in output.lines() {
        let trimmed = line.trim();
        // Skip empty lines and the key path line
        if trimmed.is_empty() || trimmed.starts_with("HKEY_") {
            continue;
        }

        // Parse: "    ValueName    REG_TYPE    Value"
        // Split on whitespace, but value may contain spaces
        let parts: Vec<&str> = trimmed.splitn(3, "    ").collect();
        if parts.len() >= 3 {
            // parts[0] = ValueName
            // parts[1] = REG_TYPE (may have leading/trailing spaces)
            // parts[2] = Value
            let reg_type = parts.get(1).map(|s| s.trim().to_string())?;
            let value = parts.get(2).map(|s| s.trim().to_string())?;
            return Some((reg_type, value));
        }

        // Alternative parsing: split on any whitespace
        let words: Vec<&str> = trimmed.split_whitespace().collect();
        if words.len() >= 3 {
            // Find the REG_ type token
            for (i, word) in words.iter().enumerate() {
                if word.starts_with("REG_") {
                    let reg_type = word.to_string();
                    // Everything after REG_TYPE is the value
                    let value = words.get(i + 1..).map(|s| s.join(" ")).unwrap_or_default();
                    return Some((reg_type, value));
                }
            }
        }
    }
    None
}

/// Normalize registry type to lowercase
///
/// Converts "REG_SZ" -> "reg_sz" for consistency with OVAL states
pub fn normalize_reg_type(reg_type: &str) -> String {
    reg_type.to_lowercase()
}

/// Normalize registry value based on type
///
/// For DWORD/QWORD: Converts hex format "0x1" to decimal "1"
/// For other types: Returns value as-is
pub fn normalize_reg_value(reg_type: &str, value: &str) -> String {
    let type_upper = reg_type.to_uppercase();

    // DWORD and QWORD values from reg.exe are in hex format (0x...)
    if type_upper == "REG_DWORD"
        || type_upper == "REG_QWORD"
        || type_upper == "REG_DWORD_BIG_ENDIAN"
    {
        if let Some(hex_str) = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
        {
            // Parse hex and convert to decimal string
            if let Ok(num) = u64::from_str_radix(hex_str, 16) {
                return num.to_string();
            }
        }
        // Try parsing as plain number (already decimal)
        if value.parse::<u64>().is_ok() {
            return value.to_string();
        }
    }

    // Return as-is for string types
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_reg_output_string() {
        let output = r#"
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion
    CurrentBuildNumber    REG_SZ    26100
"#;
        let result = parse_reg_output(output);
        assert!(result.is_some(), "Expected valid parse result");
        let (reg_type, value) = result.unwrap_or_default();
        assert_eq!(reg_type, "REG_SZ");
        assert_eq!(value, "26100");
    }

    #[test]
    fn test_parse_reg_output_dword() {
        let output = r#"
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection
    AllowTelemetry    REG_DWORD    0x2
"#;
        let result = parse_reg_output(output);
        assert!(result.is_some(), "Expected valid parse result");
        let (reg_type, value) = result.unwrap_or_default();
        assert_eq!(reg_type, "REG_DWORD");
        assert_eq!(value, "0x2");
    }

    #[test]
    fn test_parse_reg_output_with_spaces_in_value() {
        let output = r#"
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion
    ProductName    REG_SZ    Windows 11 Pro
"#;
        let result = parse_reg_output(output);
        assert!(result.is_some(), "Expected valid parse result");
        let (reg_type, value) = result.unwrap_or_default();
        assert_eq!(reg_type, "REG_SZ");
        assert_eq!(value, "Windows 11 Pro");
    }

    #[test]
    fn test_normalize_reg_type() {
        assert_eq!(normalize_reg_type("REG_SZ"), "reg_sz");
        assert_eq!(normalize_reg_type("REG_DWORD"), "reg_dword");
        assert_eq!(normalize_reg_type("REG_QWORD"), "reg_qword");
    }

    #[test]
    fn test_normalize_reg_value_dword_hex() {
        assert_eq!(normalize_reg_value("REG_DWORD", "0x1"), "1");
        assert_eq!(normalize_reg_value("REG_DWORD", "0x0"), "0");
        assert_eq!(normalize_reg_value("REG_DWORD", "0xff"), "255");
        assert_eq!(normalize_reg_value("REG_DWORD", "0xFF"), "255");
        assert_eq!(normalize_reg_value("REG_DWORD", "0x100"), "256");
    }

    #[test]
    fn test_normalize_reg_value_qword_hex() {
        assert_eq!(normalize_reg_value("REG_QWORD", "0x1"), "1");
        assert_eq!(normalize_reg_value("REG_QWORD", "0xffffffff"), "4294967295");
    }

    #[test]
    fn test_normalize_reg_value_string_unchanged() {
        assert_eq!(normalize_reg_value("REG_SZ", "hello"), "hello");
        assert_eq!(
            normalize_reg_value("REG_SZ", "Windows 11 Pro"),
            "Windows 11 Pro"
        );
        assert_eq!(normalize_reg_value("REG_EXPAND_SZ", "%PATH%"), "%PATH%");
    }

    #[test]
    fn test_normalize_reg_value_decimal_passthrough() {
        // Already decimal values should pass through
        assert_eq!(normalize_reg_value("REG_DWORD", "42"), "42");
    }
}
