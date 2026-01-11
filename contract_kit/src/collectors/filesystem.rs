//! # File System Data Collector
//!
//! Collects file metadata and content.
//! On Windows, uses native Win32 APIs for metadata collection.
//! On other platforms, uses standard Rust APIs.
//!
//! ## Field Portability
//!
//! | Category | Fields |
//! |----------|--------|
//! | Portable | `exists`, `readable`, `writable`, `file_size`, `is_directory`, `file_owner`, `file_group` |
//! | Linux/macOS | `file_mode` (octal permissions) |
//! | Windows | `is_readonly`, `is_hidden`, `is_system` |

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CollectionMode, CtnContract, CtnDataCollector,
};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::path::Path;

use crate::commands::filesystem::{get_file_metadata, read_file_content, FileSystemError};

/// Collector for file system data
pub struct FileSystemCollector {
    id: String,
}

impl FileSystemCollector {
    pub fn new() -> Self {
        Self {
            id: "filesystem_collector".to_string(),
        }
    }

    /// Extract path from object, handling VAR resolution
    fn extract_path(&self, object: &ExecutableObject) -> Result<String, CollectionError> {
        for element in &object.elements {
            if let ExecutableObjectElement::Field { name, value, .. } = element {
                if name == "path" {
                    match value {
                        ResolvedValue::String(s) => return Ok(s.clone()),
                        _ => {
                            return Err(CollectionError::InvalidObjectConfiguration {
                                object_id: object.identifier.clone(),
                                reason: format!("'path' field must be a string, got {:?}", value),
                            })
                        }
                    }
                }
            }
        }

        Err(CollectionError::InvalidObjectConfiguration {
            object_id: object.identifier.clone(),
            reason: "Missing required 'path' field".to_string(),
        })
    }

    /// Collect metadata using platform-native API
    fn collect_metadata(
        &self,
        path: &str,
        object_id: &str,
    ) -> Result<CollectedData, CollectionError> {
        let mut data = CollectedData::new(
            object_id.to_string(),
            "file_metadata".to_string(),
            self.id.clone(),
        );

        // Set collection method for traceability
        #[cfg(windows)]
        let description = "Query file metadata via Windows API";
        #[cfg(not(windows))]
        let description = "Query file metadata via stat()";

        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::FileStat)
            .description(description)
            .target(path)
            .build();
        data.set_method(method);

        // Get metadata using platform-native API
        let metadata = get_file_metadata(path).map_err(|e| match e {
            FileSystemError::AccessDenied(p) => CollectionError::AccessDenied {
                object_id: object_id.to_string(),
                reason: format!("Permission denied: {}", p),
            },
            FileSystemError::NotFound(_) => CollectionError::ObjectNotFound {
                object_id: object_id.to_string(),
            },
            _ => CollectionError::CollectionFailed {
                object_id: object_id.to_string(),
                reason: e.to_string(),
            },
        })?;

        // ====================================================================
        // Portable Fields (All Platforms)
        // ====================================================================

        data.add_field(
            "exists".to_string(),
            ResolvedValue::Boolean(metadata.exists),
        );

        if !metadata.exists {
            // Early return for non-existent files with default values
            data.add_field("readable".to_string(), ResolvedValue::Boolean(false));
            data.add_field("writable".to_string(), ResolvedValue::Boolean(false));
            data.add_field("file_size".to_string(), ResolvedValue::Integer(0));
            data.add_field("is_directory".to_string(), ResolvedValue::Boolean(false));
            data.add_field(
                "file_owner".to_string(),
                ResolvedValue::String(String::new()),
            );
            data.add_field(
                "file_group".to_string(),
                ResolvedValue::String(String::new()),
            );
            // Platform-specific fields
            data.add_field(
                "file_mode".to_string(),
                ResolvedValue::String(String::new()),
            );
            data.add_field("is_readonly".to_string(), ResolvedValue::Boolean(false));
            data.add_field("is_hidden".to_string(), ResolvedValue::Boolean(false));
            data.add_field("is_system".to_string(), ResolvedValue::Boolean(false));
            return Ok(data);
        }

        data.add_field(
            "readable".to_string(),
            ResolvedValue::Boolean(metadata.readable),
        );
        data.add_field(
            "writable".to_string(),
            ResolvedValue::Boolean(metadata.writable),
        );
        data.add_field(
            "file_size".to_string(),
            ResolvedValue::Integer(metadata.file_size as i64),
        );
        data.add_field(
            "is_directory".to_string(),
            ResolvedValue::Boolean(metadata.is_directory),
        );
        data.add_field(
            "file_owner".to_string(),
            ResolvedValue::String(metadata.file_owner),
        );
        data.add_field(
            "file_group".to_string(),
            ResolvedValue::String(metadata.file_group),
        );

        // ====================================================================
        // Linux/macOS Only (empty string on Windows)
        // ====================================================================

        data.add_field(
            "file_mode".to_string(),
            ResolvedValue::String(metadata.file_mode),
        );

        // ====================================================================
        // Windows Only (false on Linux/macOS)
        // ====================================================================

        data.add_field(
            "is_readonly".to_string(),
            ResolvedValue::Boolean(metadata.is_readonly),
        );
        data.add_field(
            "is_hidden".to_string(),
            ResolvedValue::Boolean(metadata.is_hidden),
        );
        data.add_field(
            "is_system".to_string(),
            ResolvedValue::Boolean(metadata.is_system),
        );

        Ok(data)
    }

    /// Collect file content
    fn collect_content(
        &self,
        path: &str,
        object_id: &str,
    ) -> Result<CollectedData, CollectionError> {
        let mut data = CollectedData::new(
            object_id.to_string(),
            "file_content".to_string(),
            self.id.clone(),
        );

        // Set collection method for traceability
        let method = CollectionMethod::file_read(path).with_description("Read file contents");
        data.set_method(method);

        // Read file content
        let content = read_file_content(path).map_err(|e| match e {
            FileSystemError::AccessDenied(p) => CollectionError::AccessDenied {
                object_id: object_id.to_string(),
                reason: format!("Cannot read file: {}", p),
            },
            FileSystemError::NotFound(_) => CollectionError::ObjectNotFound {
                object_id: object_id.to_string(),
            },
            _ => CollectionError::CollectionFailed {
                object_id: object_id.to_string(),
                reason: e.to_string(),
            },
        })?;

        data.add_field("file_content".to_string(), ResolvedValue::String(content));

        Ok(data)
    }

    /// Collect JSON file as RecordData
    fn collect_json_record(
        &self,
        path: &str,
        object_id: &str,
    ) -> Result<CollectedData, CollectionError> {
        let mut data = CollectedData::new(
            object_id.to_string(),
            "json_record".to_string(),
            self.id.clone(),
        );

        // Set collection method for traceability
        let method = CollectionMethod::file_read(path).with_description("Read and parse JSON file");
        data.set_method(method);

        // Read and parse JSON
        let content = read_file_content(path).map_err(|e| CollectionError::CollectionFailed {
            object_id: object_id.to_string(),
            reason: e.to_string(),
        })?;

        let json_value: serde_json::Value =
            serde_json::from_str(&content).map_err(|e| CollectionError::CollectionFailed {
                object_id: object_id.to_string(),
                reason: format!("Failed to parse JSON: {}", e),
            })?;

        let record_data = RecordData::from_json_value(json_value);

        data.add_field(
            "json_data".to_string(),
            ResolvedValue::RecordData(Box::new(record_data)),
        );

        Ok(data)
    }

    /// Collect files recursively from a directory
    fn collect_recursive(
        &self,
        base_path: &str,
        object_id: &str,
        max_depth: i64,
        include_hidden: bool,
        follow_symlinks: bool,
    ) -> Result<CollectedData, CollectionError> {
        let mut data = CollectedData::new(
            object_id.to_string(),
            "file_content".to_string(),
            self.id.clone(),
        );

        // Set collection method for traceability
        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::FileRead)
            .description("Recursive directory scan")
            .target(base_path)
            .input("max_depth", max_depth.to_string())
            .input("include_hidden", include_hidden.to_string())
            .input("follow_symlinks", follow_symlinks.to_string())
            .build();
        data.set_method(method);

        let base = Path::new(base_path);

        // Check if base path exists
        if !base.exists() {
            return Err(CollectionError::ObjectNotFound {
                object_id: object_id.to_string(),
            });
        }

        // Collect files recursively
        let mut files = Vec::new();
        scan_directory_recursive(
            base,
            &mut files,
            0,
            max_depth,
            include_hidden,
            follow_symlinks,
        )?;

        // Collect content from all found files
        let mut all_content = String::new();
        let mut file_count = 0;

        for file_path in files {
            match std::fs::read_to_string(&file_path) {
                Ok(content) => {
                    all_content.push_str(&format!("=== {} ===\n", file_path.display()));
                    all_content.push_str(&content);
                    all_content.push_str("\n\n");
                    file_count += 1;
                }
                Err(_) => {
                    // Skip files we can't read (binary, permissions, etc.)
                    continue;
                }
            }
        }

        data.add_field(
            "file_content".to_string(),
            ResolvedValue::String(all_content),
        );
        data.add_field("file_count".to_string(), ResolvedValue::Integer(file_count));

        Ok(data)
    }
}

/// Recursively scan directory tree
fn scan_directory_recursive(
    dir: &Path,
    files: &mut Vec<std::path::PathBuf>,
    current_depth: i64,
    max_depth: i64,
    include_hidden: bool,
    follow_symlinks: bool,
) -> Result<(), CollectionError> {
    // Check depth limit
    if current_depth >= max_depth {
        return Ok(());
    }

    // Try to read directory
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => {
            // Skip directories we can't read
            return Ok(());
        }
    };

    for entry_result in entries {
        let entry = match entry_result {
            Ok(e) => e,
            Err(_) => continue, // Skip bad entries
        };

        let path = entry.path();

        // Get filename for hidden check
        let file_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };

        // Skip hidden files unless include_hidden is set
        if !include_hidden && file_name.starts_with('.') {
            continue;
        }

        // On Windows, also check hidden attribute
        #[cfg(windows)]
        if !include_hidden {
            if let Ok(metadata) = get_file_metadata(path.to_str().unwrap_or("")) {
                if metadata.is_hidden {
                    continue;
                }
            }
        }

        // Get metadata (respecting symlinks setting)
        let metadata = if follow_symlinks {
            match std::fs::metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            }
        } else {
            match std::fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            }
        };

        if metadata.is_file() {
            files.push(path);
        } else if metadata.is_dir() {
            // Recurse into subdirectory
            let _ = scan_directory_recursive(
                &path,
                files,
                current_depth + 1,
                max_depth,
                include_hidden,
                follow_symlinks,
            );
        }
    }

    Ok(())
}

impl CtnDataCollector for FileSystemCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        contract.validate_behavior_hints(hints).map_err(|e| {
            CollectionError::CtnContractValidation {
                reason: e.to_string(),
            }
        })?;

        let path = self.extract_path(object)?;

        match contract.collection_strategy.collection_mode {
            CollectionMode::Metadata => self.collect_metadata(&path, &object.identifier),
            CollectionMode::Content => {
                // Check if this is a JSON record request
                if contract.ctn_type == "json_record" {
                    return self.collect_json_record(&path, &object.identifier);
                }

                if hints.has_flag("recursive_scan") {
                    let max_depth = hints.get_parameter_as_int("max_depth").unwrap_or(3);
                    let include_hidden = hints.has_flag("include_hidden");
                    let follow_symlinks = hints.has_flag("follow_symlinks");

                    return self.collect_recursive(
                        &path,
                        &object.identifier,
                        max_depth,
                        include_hidden,
                        follow_symlinks,
                    );
                }

                // Default content collection
                self.collect_content(&path, &object.identifier)
            }
            _ => Err(CollectionError::UnsupportedCollectionMode {
                collector_id: self.id.clone(),
                mode: format!("{:?}", contract.collection_strategy.collection_mode),
            }),
        }
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec![
            "file_metadata".to_string(),
            "file_content".to_string(),
            "json_record".to_string(),
        ]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if !self.supported_ctn_types().contains(&contract.ctn_type) {
            return Err(CollectionError::CtnContractValidation {
                reason: format!("CTN type '{}' not supported", contract.ctn_type),
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

impl Default for FileSystemCollector {
    fn default() -> Self {
        Self::new()
    }
}
