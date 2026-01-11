//! # File System CTN Contracts
//!
//! Contracts for file metadata and content validation.
//!
//! ## Field Portability
//!
//! Fields are categorized by platform support:
//!
//! | Category | Fields | Notes |
//! |----------|--------|-------|
//! | Portable | `exists`, `readable`, `writable`, `size`, `is_directory`, `owner_id`, `group_id` | Work identically on all platforms |
//! | Linux/macOS | `permissions` | Octal mode string, empty on Windows |
//! | Windows | `is_readonly`, `is_hidden`, `is_system` | Windows attributes, `false` on Unix |

use execution_engine::strategies::{
    BehaviorParameter, BehaviorType, CollectionMode, CollectionStrategy, CtnContract,
    ObjectFieldSpec, PerformanceHints, StateFieldSpec, SupportedBehavior,
};
use execution_engine::types::common::{DataType, Operation};

/// Create contract for file_metadata CTN type
///
/// Fast metadata collection via stat() - permissions, owner, group, existence
///
/// ## Portable Fields
/// - `exists`, `readable`, `writable`, `size`, `is_directory`
/// - `owner_id` (UID on Unix, SID on Windows)
/// - `group_id` (GID on Unix, SID on Windows)
///
/// ## Platform-Specific Fields
/// - `permissions` - Linux/macOS only (octal string)
/// - `is_readonly`, `is_hidden`, `is_system` - Windows only
pub fn create_file_metadata_contract() -> CtnContract {
    let mut contract = CtnContract::new("file_metadata".to_string());

    // ========================================================================
    // Object Requirements
    // ========================================================================

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "path".to_string(),
            data_type: DataType::String,
            description: "File system path (absolute or relative)".to_string(),
            example_values: vec![
                "/etc/sudoers".to_string(),
                "C:\\Windows\\System32\\config\\SAM".to_string(),
            ],
            validation_notes: Some("Supports VAR resolution".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "type".to_string(),
            data_type: DataType::String,
            description: "Resource type indicator".to_string(),
            example_values: vec!["file".to_string()],
            validation_notes: Some("Informational only".to_string()),
        });

    // ========================================================================
    // State Requirements - Portable Fields
    // ========================================================================

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "exists".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether file exists".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: Some("Portable: works on all platforms".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "readable".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether file is readable by current process".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: Some("Portable: tests read permission".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "writable".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether file is writable by current process".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: Some("Portable: tests write permission".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "size".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::LessThan,
                Operation::GreaterThanOrEqual,
                Operation::LessThanOrEqual,
            ],
            description: "File size in bytes".to_string(),
            example_values: vec!["0".to_string(), "1024".to_string()],
            validation_notes: Some("Portable: integer bytes".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "is_directory".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether path is a directory".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: Some("Portable: works on all platforms".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "owner_id".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "File owner identifier (UID on Unix, SID on Windows)".to_string(),
            example_values: vec!["0".to_string(), "S-1-5-18".to_string()],
            validation_notes: Some(
                "Portable field, platform-specific values: UID string on Unix, SID on Windows"
                    .to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "group_id".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "File group identifier (GID on Unix, SID on Windows)".to_string(),
            example_values: vec!["0".to_string(), "S-1-5-32-544".to_string()],
            validation_notes: Some(
                "Portable field, platform-specific values: GID string on Unix, SID on Windows"
                    .to_string(),
            ),
        });

    // ========================================================================
    // State Requirements - Linux/macOS Only
    // ========================================================================

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "permissions".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "File permissions in octal format (Linux/macOS only)".to_string(),
            example_values: vec!["0440".to_string(), "0644".to_string(), "0755".to_string()],
            validation_notes: Some(
                "Linux/macOS only: 4-digit octal format. Returns empty string on Windows."
                    .to_string(),
            ),
        });

    // ========================================================================
    // State Requirements - Windows Only
    // ========================================================================

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "is_readonly".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether file has read-only attribute (Windows only)".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: Some("Windows only: always returns false on Linux/macOS".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "is_hidden".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether file has hidden attribute (Windows only)".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: Some("Windows only: always returns false on Linux/macOS".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "is_system".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether file has system attribute (Windows only)".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: Some("Windows only: always returns false on Linux/macOS".to_string()),
        });

    // ========================================================================
    // Field Mappings
    // ========================================================================

    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("path".to_string(), "target_path".to_string());

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec![
        // Portable fields
        "exists".to_string(),
        "readable".to_string(),
        "writable".to_string(),
        "file_size".to_string(),
        "is_directory".to_string(),
        "file_owner".to_string(),
        "file_group".to_string(),
        // Platform-specific (may be empty/false on some platforms)
        "file_mode".to_string(),
        "is_readonly".to_string(),
        "is_hidden".to_string(),
        "is_system".to_string(),
    ];

    // Portable mappings
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("exists".to_string(), "exists".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("readable".to_string(), "readable".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("writable".to_string(), "writable".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("size".to_string(), "file_size".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("is_directory".to_string(), "is_directory".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("owner_id".to_string(), "file_owner".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("group_id".to_string(), "file_group".to_string());

    // Linux/macOS only
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("permissions".to_string(), "file_mode".to_string());

    // Windows only
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("is_readonly".to_string(), "is_readonly".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("is_hidden".to_string(), "is_hidden".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("is_system".to_string(), "is_system".to_string());

    // ========================================================================
    // Collection Strategy
    // ========================================================================

    contract.collection_strategy = CollectionStrategy {
        collector_type: "filesystem".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["file_access".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(5),
            memory_usage_mb: Some(1),
            network_intensive: false,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}

/// Create contract for file_content CTN type
///
/// Full file content reading for string validation
pub fn create_file_content_contract() -> CtnContract {
    let mut contract = CtnContract::new("file_content".to_string());

    // Object requirements (same as metadata)
    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "path".to_string(),
            data_type: DataType::String,
            description: "File system path (absolute or relative)".to_string(),
            example_values: vec![
                "/etc/sudoers".to_string(),
                "C:\\ProgramData\\MyApp\\config.ini".to_string(),
            ],
            validation_notes: Some("Supports VAR resolution".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "type".to_string(),
            data_type: DataType::String,
            description: "Resource type indicator".to_string(),
            example_values: vec!["file".to_string()],
            validation_notes: Some("Informational only".to_string()),
        });

    // State requirements - content field with string operations
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "content".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::NotContains,
                Operation::StartsWith,
                Operation::EndsWith,
                Operation::PatternMatch,
            ],
            description: "File content as UTF-8 string".to_string(),
            example_values: vec!["logfile=".to_string(), "NOPASSWD".to_string()],
            validation_notes: Some("Binary files will error or return as binary".to_string()),
        });

    // Field mappings
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("path".to_string(), "target_path".to_string());

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["file_content".to_string()];

    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("content".to_string(), "file_content".to_string());

    // Collection strategy - more expensive
    contract.collection_strategy = CollectionStrategy {
        collector_type: "filesystem".to_string(),
        collection_mode: CollectionMode::Content,
        required_capabilities: vec!["file_access".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(50),
            memory_usage_mb: Some(10),
            network_intensive: false,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract.add_supported_behavior(SupportedBehavior {
        name: "recursive_scan".to_string(),
        behavior_type: BehaviorType::Flag,
        parameters: vec![BehaviorParameter {
            name: "max_depth".to_string(),
            data_type: DataType::Int,
            required: false,
            default_value: Some("3".to_string()),
            description: "Maximum directory depth for recursive scan".to_string(),
        }],
        description: "Recursively scan directories for matching files".to_string(),
        example: "BEHAVIOR recursive_scan max_depth 5".to_string(),
    });

    contract.add_supported_behavior(SupportedBehavior {
        name: "include_hidden".to_string(),
        behavior_type: BehaviorType::Flag,
        parameters: vec![],
        description: "Include hidden files (starting with .) in scan".to_string(),
        example: "BEHAVIOR include_hidden".to_string(),
    });

    contract.add_supported_behavior(SupportedBehavior {
        name: "binary_mode".to_string(),
        behavior_type: BehaviorType::Flag,
        parameters: vec![],
        description: "Collect binary files as base64-encoded data".to_string(),
        example: "BEHAVIOR binary_mode".to_string(),
    });

    contract.add_supported_behavior(SupportedBehavior {
        name: "follow_symlinks".to_string(),
        behavior_type: BehaviorType::Flag,
        parameters: vec![],
        description: "Follow symbolic links during collection".to_string(),
        example: "BEHAVIOR follow_symlinks".to_string(),
    });

    contract
}
