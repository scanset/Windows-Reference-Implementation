//! Registry CTN Contract
//!
//! Validates Windows Registry keys and values.
//!
//! ## OVAL Mapping
//!
//! | OVAL Element | ESP Equivalent |
//! |--------------|----------------|
//! | `registry_test` | CTN registry |
//! | `registry_object` | OBJECT block |
//! | `registry_state` | STATE block |
//! | `check_existence` | TEST existence_check |
//! | `check` | TEST item_check |
//!
//! ## Example ESP
//!
//! ```esp
//! OBJECT build_number
//!     hive `HKEY_LOCAL_MACHINE`
//!     key `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
//!     name `CurrentBuildNumber`
//! OBJECT_END
//!
//! STATE minimum_build
//!     type string = `reg_sz`
//!     value_version version >= `19045`
//! STATE_END
//!
//! CTN registry
//!     TEST at_least_one all
//!     STATE_REF minimum_build
//!     OBJECT_REF build_number
//! CTN_END
//! ```

use execution_engine::strategies::{
    BehaviorParameter, BehaviorType, CollectionMode, CollectionStrategy, CtnContract,
    ObjectFieldSpec, PerformanceHints, StateFieldSpec, SupportedBehavior,
};
use execution_engine::types::common::{DataType, Operation};

/// Valid registry hive names (full and abbreviated)
pub const VALID_HIVES: &[&str] = &[
    "HKEY_LOCAL_MACHINE",
    "HKEY_CURRENT_USER",
    "HKEY_CLASSES_ROOT",
    "HKEY_USERS",
    "HKEY_CURRENT_CONFIG",
    "HKLM",
    "HKCU",
    "HKCR",
    "HKU",
    "HKCC",
];

/// Registry value types (lowercase, matching OVAL convention)
pub const REGISTRY_TYPES: &[&str] = &[
    "reg_sz",
    "reg_expand_sz",
    "reg_binary",
    "reg_dword",
    "reg_dword_big_endian",
    "reg_link",
    "reg_multi_sz",
    "reg_resource_list",
    "reg_full_resource_descriptor",
    "reg_resource_requirements_list",
    "reg_qword",
    "reg_none",
];

/// Create the registry CTN contract
pub fn create_registry_contract() -> CtnContract {
    let mut contract = CtnContract::new("registry".to_string());

    // =========================================================================
    // Object Requirements (Input)
    // =========================================================================

    // Required: Registry hive
    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "hive".to_string(),
            data_type: DataType::String,
            description: "Registry hive (HKEY_LOCAL_MACHINE, HKLM, etc.)".to_string(),
            example_values: vec![
                "HKEY_LOCAL_MACHINE".to_string(),
                "HKLM".to_string(),
                "HKEY_CURRENT_USER".to_string(),
            ],
            validation_notes: Some(format!("Valid values: {}", VALID_HIVES.join(", "))),
        });

    // Required: Registry key path
    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "key".to_string(),
            data_type: DataType::String,
            description: "Registry key path (without hive prefix)".to_string(),
            example_values: vec![
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion".to_string(),
                "SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection".to_string(),
            ],
            validation_notes: Some("Use backslashes as path separators".to_string()),
        });

    // Required: Value name
    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "name".to_string(),
            data_type: DataType::String,
            description: "Registry value name".to_string(),
            example_values: vec![
                "CurrentBuildNumber".to_string(),
                "AllowTelemetry".to_string(),
                "EditionId".to_string(),
            ],
            validation_notes: None,
        });

    // =========================================================================
    // State Requirements (Validation)
    // =========================================================================

    // exists - Key/value existence
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "exists".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the registry key/value exists".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: None,
        });

    // type - Registry value type (reg only)
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "type".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::CaseInsensitiveEquals,
            ],
            description: "Registry value type (only available with reg executor)".to_string(),
            example_values: vec![
                "reg_sz".to_string(),
                "reg_dword".to_string(),
                "reg_qword".to_string(),
            ],
            validation_notes: Some(format!("Valid types: {}", REGISTRY_TYPES.join(", "))),
        });

    // value - String comparison
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "value".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::NotContains,
                Operation::StartsWith,
                Operation::EndsWith,
                Operation::PatternMatch,
                Operation::CaseInsensitiveEquals,
                Operation::CaseInsensitiveNotEqual,
            ],
            description: "Registry value as string".to_string(),
            example_values: vec!["EnterpriseS".to_string(), "26100".to_string()],
            validation_notes: Some("For string comparisons".to_string()),
        });

    // value_int - Integer comparison (for DWORD/QWORD)
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "value_int".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::LessThan,
                Operation::GreaterThanOrEqual,
                Operation::LessThanOrEqual,
            ],
            description: "Registry value as integer (for DWORD/QWORD)".to_string(),
            example_values: vec!["0".to_string(), "1".to_string(), "2".to_string()],
            validation_notes: Some("Parses string value to integer".to_string()),
        });

    // value_version - Version comparison
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "value_version".to_string(),
            data_type: DataType::Version,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::LessThan,
                Operation::GreaterThanOrEqual,
                Operation::LessThanOrEqual,
            ],
            description: "Registry value as version (semver comparison)".to_string(),
            example_values: vec!["6.3".to_string(), "19045".to_string(), "10240".to_string()],
            validation_notes: Some("Uses semantic version comparison rules".to_string()),
        });

    // =========================================================================
    // Field Mappings
    // =========================================================================

    // Object fields used for collection
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("hive".to_string(), "hive".to_string());
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("key".to_string(), "key".to_string());
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("name".to_string(), "name".to_string());

    // Required data fields from collector
    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["exists".to_string(), "value".to_string()];

    // Optional data fields from collector (type only available with reg executor)
    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec!["type".to_string()];

    // State field → collected data field
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("exists".to_string(), "exists".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("type".to_string(), "type".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("value".to_string(), "value".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("value_int".to_string(), "value".to_string()); // parsed from value
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("value_version".to_string(), "value".to_string()); // parsed from value

    // =========================================================================
    // Collection Strategy
    // =========================================================================

    contract.collection_strategy = CollectionStrategy {
        collector_type: "windows_registry".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["registry_read".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(100),
            memory_usage_mb: Some(1),
            network_intensive: false,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    // =========================================================================
    // Behaviors
    // =========================================================================

    // executor - Collection method selection
    contract.add_supported_behavior(SupportedBehavior {
        name: "executor".to_string(),
        behavior_type: BehaviorType::Parameter,
        parameters: vec![BehaviorParameter {
            name: "executor".to_string(),
            data_type: DataType::String,
            required: false,
            default_value: Some("reg".to_string()),
            description: "Collection method: reg (default) or powershell".to_string(),
        }],
        description: "Select the registry collection executor".to_string(),
        example: "behavior executor powershell".to_string(),
    });

    contract
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contract_creation() {
        let contract = create_registry_contract();
        assert_eq!(contract.ctn_type, "registry");
    }

    #[test]
    fn test_object_requirements() {
        let contract = create_registry_contract();
        assert_eq!(contract.object_requirements.required_fields.len(), 3);

        let field_names: Vec<&str> = contract
            .object_requirements
            .required_fields
            .iter()
            .map(|f| f.name.as_str())
            .collect();
        assert!(field_names.contains(&"hive"));
        assert!(field_names.contains(&"key"));
        assert!(field_names.contains(&"name"));
    }

    #[test]
    fn test_state_requirements() {
        let contract = create_registry_contract();
        assert_eq!(contract.state_requirements.optional_fields.len(), 5);

        let field_names: Vec<&str> = contract
            .state_requirements
            .optional_fields
            .iter()
            .map(|f| f.name.as_str())
            .collect();
        assert!(field_names.contains(&"exists"));
        assert!(field_names.contains(&"type"));
        assert!(field_names.contains(&"value"));
        assert!(field_names.contains(&"value_int"));
        assert!(field_names.contains(&"value_version"));
    }

    #[test]
    fn test_behaviors() {
        let contract = create_registry_contract();
        assert_eq!(contract.supported_behaviors.len(), 1);
        assert_eq!(
            contract
                .supported_behaviors
                .first()
                .map(|b| b.name.as_str()),
            Some("executor")
        );
    }
}
