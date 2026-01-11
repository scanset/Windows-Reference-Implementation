//! Command executors and native APIs for Windows system tools
//!
//! Provides:
//! - `filesystem` - Native file system API (Win32 on Windows, std on Linux)
//! - `tcp_listener` - Native TCP listener API (IP Helper on Windows, procfs on Linux)
//! - `reg.exe` - Windows Registry queries
//! - `powershell.exe` - PowerShell commands
//! - `sc.exe` - Windows Service Control

pub mod filesystem;
pub mod powershell;
pub mod reg;
pub mod sc;
pub mod tcp_listener;

pub use filesystem::{
    file_exists, get_file_metadata, read_file_content, FileMetadata, FileSystemError,
    FileSystemResult,
};
pub use powershell::create_powershell_executor;
pub use reg::create_reg_executor;
pub use sc::create_sc_executor;
pub use tcp_listener::{
    check_port_listening, get_all_listening_ports, TcpListenerError, TcpListenerResult,
};
