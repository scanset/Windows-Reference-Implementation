//! Windows native TCP listener operations
//!
//! Uses the IP Helper API (iphlpapi) to query TCP listening ports.
//!
//! ## Usage
//!
//! ```ignore
//! let result = check_port_listening(22, None)?;
//! if result.listening {
//!     println!("Port 22 is listening on {}", result.local_address.unwrap());
//! }
//! ```
//!
//! ## Platform Support
//!
//! - **Windows**: Full support using GetExtendedTcpTable
//! - **Linux**: Stub for cross-compilation (use /proc/net/tcp directly)

/// Result of checking a TCP port
#[derive(Debug, Clone, Default)]
pub struct TcpListenerResult {
    /// Whether the port is in LISTEN state
    pub listening: bool,

    /// Local address:port if listening (e.g., "0.0.0.0:22")
    pub local_address: Option<String>,

    /// Error message if collection failed
    pub error: Option<String>,
}

/// Error type for TCP listener operations
#[derive(Debug)]
pub enum TcpListenerError {
    /// API call failed
    ApiError(String, u32),

    /// Invalid port
    InvalidPort(u16),
}

impl std::fmt::Display for TcpListenerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiError(msg, code) => write!(f, "{} (error {})", msg, code),
            Self::InvalidPort(port) => write!(f, "Invalid port: {}", port),
        }
    }
}

impl std::error::Error for TcpListenerError {}

/// Result type for TCP listener operations
pub type TcpListenerApiResult<T> = Result<T, TcpListenerError>;

// ============================================================================
// Windows Implementation
// ============================================================================

#[cfg(windows)]
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_TCP_STATE_LISTEN,
    TCP_TABLE_OWNER_PID_LISTENER,
};
#[cfg(windows)]
use windows::Win32::Networking::WinSock::AF_INET;

/// Check if a TCP port is listening
///
/// # Arguments
///
/// * `port` - TCP port number (1-65535)
/// * `host_filter` - Optional bind address filter (e.g., "127.0.0.1")
///
/// # Returns
///
/// `TcpListenerResult` with listening status and local address if found.
#[cfg(windows)]
pub fn check_port_listening(port: u16, host_filter: Option<&str>) -> TcpListenerResult {
    if port == 0 {
        return TcpListenerResult {
            listening: false,
            local_address: None,
            error: Some("Invalid port: 0".to_string()),
        };
    }

    // Get the TCP table
    let table = match get_tcp_table() {
        Ok(t) => t,
        Err(e) => {
            return TcpListenerResult {
                listening: false,
                local_address: None,
                error: Some(e.to_string()),
            };
        }
    };

    // Search for matching listener
    for entry in table {
        // Check if port matches (convert from network byte order)
        let entry_port = u16::from_be(entry.dwLocalPort as u16);
        if entry_port != port {
            continue;
        }

        // Check if in LISTEN state
        if entry.dwState != MIB_TCP_STATE_LISTEN.0 as u32 {
            continue;
        }

        // Convert IP address from network byte order
        let ip_bytes = entry.dwLocalAddr.to_ne_bytes();
        let local_ip = format!(
            "{}.{}.{}.{}",
            ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]
        );

        // If host filter specified, check if it matches
        if let Some(filter) = host_filter {
            if local_ip != filter && local_ip != "0.0.0.0" {
                continue;
            }
        }

        // Found a matching listener
        return TcpListenerResult {
            listening: true,
            local_address: Some(format!("{}:{}", local_ip, port)),
            error: None,
        };
    }

    // Port not found listening
    TcpListenerResult {
        listening: false,
        local_address: None,
        error: None,
    }
}

/// Get the TCP table from Windows
#[cfg(windows)]
fn get_tcp_table() -> TcpListenerApiResult<Vec<MIB_TCPROW_OWNER_PID>> {
    unsafe {
        // First call to get required buffer size
        let mut size: u32 = 0;
        let result = GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        );

        // ERROR_INSUFFICIENT_BUFFER (122) is expected on first call
        if result != 122 && result != 0 {
            return Err(TcpListenerError::ApiError(
                "GetExtendedTcpTable size query failed".to_string(),
                result,
            ));
        }

        if size == 0 {
            // No listeners
            return Ok(Vec::new());
        }

        // Allocate buffer
        let mut buffer: Vec<u8> = vec![0; size as usize];

        // Second call to get actual data
        let result = GetExtendedTcpTable(
            Some(buffer.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        );

        if result != 0 {
            return Err(TcpListenerError::ApiError(
                "GetExtendedTcpTable failed".to_string(),
                result,
            ));
        }

        // Parse the table
        let table = &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let num_entries = table.dwNumEntries as usize;

        if num_entries == 0 {
            return Ok(Vec::new());
        }

        // Copy entries to vector
        let entries_ptr = table.table.as_ptr();
        let entries = std::slice::from_raw_parts(entries_ptr, num_entries);

        Ok(entries.to_vec())
    }
}

/// Get all listening ports
///
/// Returns a list of all TCP ports currently in LISTEN state.
#[cfg(windows)]
pub fn get_all_listening_ports() -> TcpListenerApiResult<Vec<(String, u16)>> {
    let table = get_tcp_table()?;
    let mut listeners = Vec::new();

    for entry in table {
        if entry.dwState != MIB_TCP_STATE_LISTEN.0 as u32 {
            continue;
        }

        let port = u16::from_be(entry.dwLocalPort as u16);
        let ip_bytes = entry.dwLocalAddr.to_ne_bytes();
        let local_ip = format!(
            "{}.{}.{}.{}",
            ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]
        );

        listeners.push((local_ip, port));
    }

    Ok(listeners)
}

// ============================================================================
// Non-Windows Stubs (for cross-compilation)
// ============================================================================

/// Check if a TCP port is listening - non-Windows stub
///
/// On Linux, use /proc/net/tcp directly instead.
#[cfg(not(windows))]
pub fn check_port_listening(port: u16, host_filter: Option<&str>) -> TcpListenerResult {
    // Read /proc/net/tcp on Linux
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    if port == 0 {
        return TcpListenerResult {
            listening: false,
            local_address: None,
            error: Some("Invalid port: 0".to_string()),
        };
    }

    let port_hex = format!("{:04X}", port);

    let file = match File::open("/proc/net/tcp") {
        Ok(f) => f,
        Err(e) => {
            return TcpListenerResult {
                listening: false,
                local_address: None,
                error: Some(format!("Cannot open /proc/net/tcp: {}", e)),
            };
        }
    };

    let reader = BufReader::new(file);

    for line in reader.lines().skip(1) {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };

        if let Some(result) = parse_proc_tcp_line(&line, &port_hex, host_filter) {
            return result;
        }
    }

    TcpListenerResult {
        listening: false,
        local_address: None,
        error: None,
    }
}

/// Parse a line from /proc/net/tcp
#[cfg(not(windows))]
fn parse_proc_tcp_line(
    line: &str,
    port_hex: &str,
    host_filter: Option<&str>,
) -> Option<TcpListenerResult> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }

    let local_addr = parts.get(1)?;
    let addr_parts: Vec<&str> = local_addr.split(':').collect();
    if addr_parts.len() != 2 {
        return None;
    }

    let local_ip_hex = addr_parts.first()?;
    let local_port_hex = addr_parts.get(1)?;

    if *local_port_hex != port_hex {
        return None;
    }

    // State 0A = LISTEN
    let state = parts.get(3)?;
    if *state != "0A" {
        return None;
    }

    let local_ip = hex_to_ipv4(local_ip_hex);

    if let Some(filter) = host_filter {
        if local_ip != filter && local_ip != "0.0.0.0" {
            return None;
        }
    }

    let port = u16::from_str_radix(local_port_hex, 16).unwrap_or(0);
    Some(TcpListenerResult {
        listening: true,
        local_address: Some(format!("{}:{}", local_ip, port)),
        error: None,
    })
}

/// Convert hex IP (little-endian) to dotted decimal
#[cfg(not(windows))]
fn hex_to_ipv4(hex: &str) -> String {
    if hex.len() != 8 {
        return "invalid".to_string();
    }

    let bytes: Vec<u8> = (0..4)
        .filter_map(|i| {
            hex.get(i * 2..i * 2 + 2)
                .and_then(|s| u8::from_str_radix(s, 16).ok())
        })
        .collect();

    if bytes.len() != 4 {
        return "invalid".to_string();
    }

    // /proc/net/tcp stores in little-endian
    format!(
        "{}.{}.{}.{}",
        bytes.get(3).copied().unwrap_or(0),
        bytes.get(2).copied().unwrap_or(0),
        bytes.get(1).copied().unwrap_or(0),
        bytes.first().copied().unwrap_or(0)
    )
}

/// Get all listening ports - non-Windows stub
#[cfg(not(windows))]
pub fn get_all_listening_ports() -> TcpListenerApiResult<Vec<(String, u16)>> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let file = File::open("/proc/net/tcp")
        .map_err(|e| TcpListenerError::ApiError(format!("Cannot open /proc/net/tcp: {}", e), 0))?;

    let reader = BufReader::new(file);
    let mut listeners = Vec::new();

    for line in reader.lines().skip(1) {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }

        // Check state 0A = LISTEN
        if parts.get(3) != Some(&"0A") {
            continue;
        }

        if let Some(local_addr) = parts.get(1) {
            let addr_parts: Vec<&str> = local_addr.split(':').collect();
            if addr_parts.len() == 2 {
                let ip = hex_to_ipv4(addr_parts[0]);
                if let Ok(port) = u16::from_str_radix(addr_parts[1], 16) {
                    listeners.push((ip, port));
                }
            }
        }
    }

    Ok(listeners)
}

// ============================================================================
// Tests
// ============================================================================

#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_port() {
        let result = check_port_listening(0, None);
        assert!(!result.listening);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_unlikely_port_not_listening() {
        // Port 65432 is unlikely to be in use
        let result = check_port_listening(65432, None);
        assert!(!result.listening);
        assert!(result.error.is_none());
    }

    #[cfg(windows)]
    mod windows_tests {
        use super::*;

        #[test]
        fn test_get_all_listening_ports() {
            // Should not error even if no ports are listening
            let result = get_all_listening_ports();
            assert!(result.is_ok());
        }
    }

    #[cfg(not(windows))]
    mod linux_tests {
        use super::*;

        #[test]
        fn test_hex_to_ipv4() {
            assert_eq!(hex_to_ipv4("00000000"), "0.0.0.0");
            assert_eq!(hex_to_ipv4("0100007F"), "127.0.0.1");
            assert_eq!(hex_to_ipv4("0000"), "invalid");
        }
    }
}
