//! Windows native file system operations
//!
//! Uses Win32 API for file metadata collection without shelling out to commands.
//!
//! ## Usage
//!
//! ```ignore
//! let metadata = get_file_metadata(r"C:\Windows\System32\config\SAM")?;
//! println!("Owner: {}", metadata.file_owner);
//! println!("Size: {}", metadata.file_size);
//! ```
//!
//! ## Collected Fields
//!
//! ### Portable Fields (All Platforms)
//!
//! | Field | Description |
//! |-------|-------------|
//! | `exists` | Whether the file exists |
//! | `readable` | Whether the file can be read by current process |
//! | `writable` | Whether the file can be written by current process |
//! | `file_size` | File size in bytes |
//! | `is_directory` | Whether the path is a directory |
//! | `file_owner` | File owner (UID on Unix, SID or DOMAIN\User on Windows) |
//! | `file_group` | File group (GID on Unix, SID or DOMAIN\Group on Windows) |
//!
//! ### Linux/macOS Only
//!
//! | Field | Description |
//! |-------|-------------|
//! | `file_mode` | File permissions in 4-digit octal format (e.g., "0644") |
//!
//! ### Windows Only
//!
//! | Field | Description |
//! |-------|-------------|
//! | `is_readonly` | Whether the file has read-only attribute |
//! | `is_hidden` | Whether the file has hidden attribute |
//! | `is_system` | Whether the file has system attribute |

#[cfg(windows)]
use std::ffi::OsStr;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

#[cfg(windows)]
use windows::core::{PCWSTR, PWSTR};
#[cfg(windows)]
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, HANDLE, HLOCAL, WIN32_ERROR,
};
#[cfg(windows)]
use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
#[cfg(windows)]
use windows::Win32::Security::{
    LookupAccountSidW, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SID_NAME_USE,
};
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::{
    CreateFileW, GetFileAttributesExW, GetFileAttributesW, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_SYSTEM,
    FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, GET_FILEEX_INFO_LEVELS, INVALID_FILE_ATTRIBUTES,
    OPEN_EXISTING, WIN32_FILE_ATTRIBUTE_DATA,
};

/// File metadata collected from platform-native APIs
#[derive(Debug, Clone, Default)]
pub struct FileMetadata {
    // ========================================================================
    // Portable Fields (All Platforms)
    // ========================================================================
    /// Whether the file exists
    pub exists: bool,

    /// Whether the file is readable by current process
    pub readable: bool,

    /// Whether the file is writable by current process
    pub writable: bool,

    /// File size in bytes
    pub file_size: u64,

    /// Whether the path is a directory
    pub is_directory: bool,

    /// File owner identifier (UID on Unix, SID or DOMAIN\User on Windows)
    pub file_owner: String,

    /// File group identifier (GID on Unix, SID or DOMAIN\Group on Windows)
    pub file_group: String,

    // ========================================================================
    // Linux/macOS Only
    // ========================================================================
    /// File permissions in octal format (e.g., "0644")
    /// Returns empty string on Windows
    pub file_mode: String,

    // ========================================================================
    // Windows Only
    // ========================================================================
    /// Whether the file has read-only attribute (Windows only, false on Unix)
    pub is_readonly: bool,

    /// Whether the file has hidden attribute (Windows only, false on Unix)
    pub is_hidden: bool,

    /// Whether the file has system attribute (Windows only, false on Unix)
    pub is_system: bool,
}

/// Error type for file system operations
#[derive(Debug)]
pub enum FileSystemError {
    /// File not found
    NotFound(String),

    /// Access denied
    AccessDenied(String),

    /// Other Windows error
    WindowsError(String, u32),

    /// Invalid path
    #[allow(dead_code)]
    InvalidPath(String),
}

impl std::fmt::Display for FileSystemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(path) => write!(f, "File not found: {}", path),
            Self::AccessDenied(path) => write!(f, "Access denied: {}", path),
            Self::WindowsError(msg, code) => write!(f, "{} (error {})", msg, code),
            Self::InvalidPath(path) => write!(f, "Invalid path: {}", path),
        }
    }
}

impl std::error::Error for FileSystemError {}

/// Result type for file system operations
pub type FileSystemResult<T> = Result<T, FileSystemError>;

// ============================================================================
// Windows Implementation
// ============================================================================

/// Convert a Rust string to a null-terminated wide string
#[cfg(windows)]
fn to_wide_string(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Convert a SID to a string representation (DOMAIN\User or S-1-5-...)
#[cfg(windows)]
fn sid_to_string(sid: PSID) -> String {
    if sid.is_invalid() {
        return String::new();
    }

    unsafe {
        // First call to get buffer sizes
        let mut name_size: u32 = 0;
        let mut domain_size: u32 = 0;
        let mut sid_type = SID_NAME_USE::default();

        let _ = LookupAccountSidW(
            PCWSTR::null(),
            sid,
            PWSTR::null(),
            &mut name_size,
            PWSTR::null(),
            &mut domain_size,
            &mut sid_type,
        );

        if name_size == 0 {
            // Lookup failed, convert SID to string format
            return sid_to_string_format(sid);
        }

        // Allocate buffers
        let mut name_buf: Vec<u16> = vec![0; name_size as usize];
        let mut domain_buf: Vec<u16> = vec![0; domain_size as usize];

        // Second call to get actual values
        let result = LookupAccountSidW(
            PCWSTR::null(),
            sid,
            PWSTR(name_buf.as_mut_ptr()),
            &mut name_size,
            PWSTR(domain_buf.as_mut_ptr()),
            &mut domain_size,
            &mut sid_type,
        );

        if result.is_ok() {
            let name = name_buf
                .get(..name_size as usize)
                .map(String::from_utf16_lossy)
                .unwrap_or_default();
            let domain = domain_buf
                .get(..domain_size as usize)
                .map(String::from_utf16_lossy)
                .unwrap_or_default();

            if domain.is_empty() {
                name
            } else {
                format!("{}\\{}", domain, name)
            }
        } else {
            // Fallback to SID string format
            sid_to_string_format(sid)
        }
    }
}

/// Convert SID to S-1-5-... string format
#[cfg(windows)]
fn sid_to_string_format(sid: PSID) -> String {
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;

    unsafe {
        let mut string_sid = PWSTR::null();
        if ConvertSidToStringSidW(sid, &mut string_sid).is_ok() {
            let len = (0..).take_while(|&i| *string_sid.0.add(i) != 0).count();
            let slice = std::slice::from_raw_parts(string_sid.0, len);
            let result = String::from_utf16_lossy(slice);
            let _ = LocalFree(HLOCAL(string_sid.0 as *mut _));
            result
        } else {
            String::new()
        }
    }
}

/// Get file metadata using Windows API
///
/// # Arguments
///
/// * `path` - File path to query
///
/// # Returns
///
/// `FileMetadata` struct with all available fields populated.
/// If the file doesn't exist, returns metadata with `exists = false`.
#[cfg(windows)]
pub fn get_file_metadata(path: &str) -> FileSystemResult<FileMetadata> {
    let wide_path = to_wide_string(path);
    let mut metadata = FileMetadata::default();

    // Check if file exists and get attributes
    let attributes = unsafe { GetFileAttributesW(PCWSTR(wide_path.as_ptr())) };

    if attributes == INVALID_FILE_ATTRIBUTES {
        let error = unsafe { GetLastError() };
        if error == WIN32_ERROR(2) || error == WIN32_ERROR(3) {
            // ERROR_FILE_NOT_FOUND or ERROR_PATH_NOT_FOUND
            metadata.exists = false;
            return Ok(metadata);
        }
        return Err(FileSystemError::WindowsError(
            format!("GetFileAttributesW failed for {}", path),
            error.0,
        ));
    }

    metadata.exists = true;
    metadata.file_mode = String::new(); // Not applicable on Windows
    metadata.is_directory = (attributes & FILE_ATTRIBUTE_DIRECTORY.0) != 0;
    metadata.is_readonly = (attributes & FILE_ATTRIBUTE_READONLY.0) != 0;
    metadata.is_hidden = (attributes & FILE_ATTRIBUTE_HIDDEN.0) != 0;
    metadata.is_system = (attributes & FILE_ATTRIBUTE_SYSTEM.0) != 0;

    // Get file size
    let mut file_info = WIN32_FILE_ATTRIBUTE_DATA::default();
    let size_result = unsafe {
        GetFileAttributesExW(
            PCWSTR(wide_path.as_ptr()),
            GET_FILEEX_INFO_LEVELS(0), // GetFileExInfoStandard
            &mut file_info as *mut _ as *mut _,
        )
    };

    if size_result.is_ok() {
        metadata.file_size =
            ((file_info.nFileSizeHigh as u64) << 32) | (file_info.nFileSizeLow as u64);
    }

    // Check if readable
    metadata.readable = check_readable(path);

    // Check if writable
    metadata.writable = check_writable(path);

    // Get owner and group
    if let Ok((owner, group)) = get_file_security_info(path) {
        metadata.file_owner = owner;
        metadata.file_group = group;
    }

    Ok(metadata)
}

/// Check if file is readable by current process
#[cfg(windows)]
fn check_readable(path: &str) -> bool {
    let wide_path = to_wide_string(path);

    unsafe {
        let handle = CreateFileW(
            PCWSTR(wide_path.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            HANDLE::default(),
        );

        match handle {
            Ok(h) => {
                let _ = CloseHandle(h);
                true
            }
            Err(_) => false,
        }
    }
}

/// Check if file is writable by current process
#[cfg(windows)]
fn check_writable(path: &str) -> bool {
    let wide_path = to_wide_string(path);

    unsafe {
        let handle = CreateFileW(
            PCWSTR(wide_path.as_ptr()),
            FILE_GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            HANDLE::default(),
        );

        match handle {
            Ok(h) => {
                let _ = CloseHandle(h);
                true
            }
            Err(_) => false,
        }
    }
}

/// Get file owner and group using GetSecurityInfo
#[cfg(windows)]
fn get_file_security_info(path: &str) -> FileSystemResult<(String, String)> {
    let wide_path = to_wide_string(path);

    unsafe {
        // Open file handle for reading security info
        let handle = CreateFileW(
            PCWSTR(wide_path.as_ptr()),
            0, // No access needed, just for security query
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS, // Needed for directories
            HANDLE::default(),
        )
        .map_err(|e| {
            FileSystemError::AccessDenied(format!("Cannot open {} for security info: {}", path, e))
        })?;

        let mut owner_sid: PSID = PSID::default();
        let mut group_sid: PSID = PSID::default();
        let mut security_descriptor: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR::default();

        let result = GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION,
            Some(&mut owner_sid),
            Some(&mut group_sid),
            None,
            None,
            Some(&mut security_descriptor),
        );

        let _ = CloseHandle(handle);

        if result.is_err() {
            return Err(FileSystemError::WindowsError(
                format!("GetSecurityInfo failed for {}", path),
                result.0,
            ));
        }

        let owner = sid_to_string(owner_sid);
        let group = sid_to_string(group_sid);

        // Free the security descriptor
        if !security_descriptor.0.is_null() {
            let _ = LocalFree(HLOCAL(security_descriptor.0));
        }

        Ok((owner, group))
    }
}

/// Check if a file exists
#[cfg(windows)]
pub fn file_exists(path: &str) -> bool {
    let wide_path = to_wide_string(path);
    let attributes = unsafe { GetFileAttributesW(PCWSTR(wide_path.as_ptr())) };
    attributes != INVALID_FILE_ATTRIBUTES
}

/// Read file content as UTF-8 string
///
/// Uses standard Rust file I/O (works on all platforms)
pub fn read_file_content(path: &str) -> FileSystemResult<String> {
    #[cfg(windows)]
    {
        if !file_exists(path) {
            return Err(FileSystemError::NotFound(path.to_string()));
        }
    }

    #[cfg(not(windows))]
    {
        if !std::path::Path::new(path).exists() {
            return Err(FileSystemError::NotFound(path.to_string()));
        }
    }

    std::fs::read_to_string(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            FileSystemError::AccessDenied(path.to_string())
        } else {
            FileSystemError::WindowsError(format!("Failed to read {}: {}", path, e), 0)
        }
    })
}

// ============================================================================
// Non-Windows Implementation (Linux/macOS)
// ============================================================================

/// Get file metadata using standard Rust APIs (Unix)
///
/// This implementation is used on Linux/macOS platforms.
#[cfg(not(windows))]
pub fn get_file_metadata(path: &str) -> FileSystemResult<FileMetadata> {
    use std::fs;
    use std::path::Path;

    let path_obj = Path::new(path);
    let mut metadata = FileMetadata::default();

    if !path_obj.exists() {
        metadata.exists = false;
        return Ok(metadata);
    }

    metadata.exists = true;

    // Windows-specific fields default to false on Unix
    metadata.is_readonly = false;
    metadata.is_hidden = false;
    metadata.is_system = false;

    if let Ok(fs_meta) = fs::metadata(path) {
        metadata.file_size = fs_meta.len();
        metadata.is_directory = fs_meta.is_dir();

        // Check readable by attempting to open for read
        metadata.readable = fs::File::open(path).is_ok();

        // Check writable by attempting to open for write (without truncating)
        metadata.writable = std::fs::OpenOptions::new().write(true).open(path).is_ok();

        // Unix permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            metadata.file_mode = format!("{:04o}", fs_meta.permissions().mode() & 0o7777);
            metadata.file_owner = fs_meta.uid().to_string();
            metadata.file_group = fs_meta.gid().to_string();
        }

        #[cfg(not(unix))]
        {
            metadata.file_mode = String::new();
            metadata.file_owner = String::new();
            metadata.file_group = String::new();
        }
    }

    Ok(metadata)
}

/// Check if a file exists (Unix)
#[cfg(not(windows))]
pub fn file_exists(path: &str) -> bool {
    std::path::Path::new(path).exists()
}

// ============================================================================
// Tests
// ============================================================================

#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_not_exists() {
        let result = get_file_metadata("/nonexistent/path/file.txt");
        assert!(result.is_ok());
        let metadata = result.unwrap();
        assert!(!metadata.exists);
        assert!(!metadata.readable);
        assert!(!metadata.writable);
    }

    #[test]
    fn test_file_exists_function() {
        // Test with a path that definitely doesn't exist
        assert!(!file_exists("/definitely/nonexistent/path/12345.xyz"));
    }

    #[cfg(unix)]
    mod unix_tests {
        use super::*;
        use std::fs::{self, File};
        use std::io::Write;

        fn create_test_dir() -> std::path::PathBuf {
            let dir = std::env::temp_dir().join(format!("esp_test_{}", std::process::id()));
            let _ = fs::create_dir_all(&dir);
            dir
        }

        fn cleanup_test_dir(dir: &std::path::Path) {
            let _ = fs::remove_dir_all(dir);
        }

        #[test]
        fn test_get_metadata_readable_file() {
            let dir = create_test_dir();
            let file_path = dir.join("test.txt");
            let mut file = File::create(&file_path).unwrap();
            writeln!(file, "test content").unwrap();
            drop(file);

            let metadata = get_file_metadata(file_path.to_str().unwrap()).unwrap();

            assert!(metadata.exists);
            assert!(metadata.readable);
            assert!(metadata.writable);
            assert!(!metadata.is_directory);
            assert!(metadata.file_size > 0);
            assert!(!metadata.file_mode.is_empty());
            assert!(!metadata.file_owner.is_empty());

            cleanup_test_dir(&dir);
        }

        #[test]
        fn test_get_metadata_directory() {
            let dir = create_test_dir();
            let metadata = get_file_metadata(dir.to_str().unwrap()).unwrap();

            assert!(metadata.exists);
            assert!(metadata.is_directory);

            cleanup_test_dir(&dir);
        }

        #[test]
        fn test_windows_fields_false_on_unix() {
            let dir = create_test_dir();
            let metadata = get_file_metadata(dir.to_str().unwrap()).unwrap();

            assert!(!metadata.is_readonly);
            assert!(!metadata.is_hidden);
            assert!(!metadata.is_system);

            cleanup_test_dir(&dir);
        }
    }

    #[cfg(windows)]
    mod windows_tests {
        use super::*;

        #[test]
        fn test_file_exists_system32() {
            assert!(file_exists(r"C:\Windows\System32\kernel32.dll"));
        }

        #[test]
        fn test_get_metadata_kernel32() {
            let metadata = get_file_metadata(r"C:\Windows\System32\kernel32.dll")
                .expect("Should get metadata");

            assert!(metadata.exists);
            assert!(metadata.file_size > 0);
            assert!(!metadata.file_owner.is_empty());
            assert!(!metadata.is_directory);
            assert!(metadata.readable);
            // kernel32.dll should not be writable by normal users
            assert!(!metadata.writable);
        }

        #[test]
        fn test_get_metadata_windows_directory() {
            let metadata = get_file_metadata(r"C:\Windows").expect("Should get metadata");

            assert!(metadata.exists);
            assert!(metadata.is_directory);
            assert!(!metadata.file_owner.is_empty());
        }

        #[test]
        fn test_file_mode_empty_on_windows() {
            let metadata = get_file_metadata(r"C:\Windows\System32\kernel32.dll")
                .expect("Should get metadata");

            // file_mode should be empty on Windows (not applicable)
            assert!(metadata.file_mode.is_empty());
        }

        #[test]
        fn test_to_wide_string() {
            let wide = to_wide_string("test");
            assert_eq!(wide, vec![116, 101, 115, 116, 0]); // "test" + null terminator
        }
    }
}
