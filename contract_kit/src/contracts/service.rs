//! Service CTN Contract
//!
//! Validates Windows Service configuration and runtime state.
//!
//! ## OVAL Mapping
//!
//! | OVAL Element | ESP Equivalent |
//! |--------------|----------------|
//! | `service_test` | CTN service |
//! | `service_object` | OBJECT block |
//! | `service_state` | STATE block |
//! | `check_existence` | TEST existence_check |
//! | `check` | TEST item_check |
//!
//! ## Example ESP
//!
//! ```esp
//! OBJECT time_service
//!     name `W32Time`
//! OBJECT_END
//!
//! STATE service_running
//!     exists boolean = true
//!     state string = `running`
//!     start_type string = `auto`
//! STATE_END
//!
//! CTN service
//!     TEST at_least_one all
//!     STATE_REF service_running
//!     OBJECT_REF time_service
//! CTN_END
//! ```

use execution_engine::strategies::{
    BehaviorParameter, BehaviorType, CollectionMode, CollectionStrategy, CtnContract,
    ObjectFieldSpec, PerformanceHints, StateFieldSpec, SupportedBehavior,
};
use execution_engine::types::common::{DataType, Operation};

/// Valid runtime state values (normalized)
pub const VALID_STATES: &[&str] = &[
    "running",
    "stopped",
    "paused",
    "start_pending",
    "stop_pending",
    "continue_pending",
    "pause_pending",
    "unknown",
];

/// Valid start type values (normalized)
pub const VALID_START_TYPES: &[&str] = &[
    "auto",
    "auto_delayed",
    "manual",
    "disabled",
    "boot",
    "system",
    "unknown",
];

/// Valid service type values (normalized)
pub const VALID_SERVICE_TYPES: &[&str] = &[
    "own_process",
    "own_process_interactive",
    "share_process",
    "kernel_driver",
    "file_system_driver",
    "win32",
    "unknown",
];

/// Create the service CTN contract
pub fn create_service_contract() -> CtnContract {
    let mut contract = CtnContract::new("service".to_string());

    // =========================================================================
    // Object Requirements (Input)
    // =========================================================================

    // Required: Service name
    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "name".to_string(),
            data_type: DataType::String,
            description: "Service name (not DisplayName)".to_string(),
            example_values: vec![
                "W32Time".to_string(),
                "Spooler".to_string(),
                "TermService".to_string(),
                "RemoteRegistry".to_string(),
            ],
            validation_notes: Some(
                "Use service name (e.g., 'W32Time') not display name (e.g., 'Windows Time')"
                    .to_string(),
            ),
        });

    // =========================================================================
    // State Requirements (Validation)
    // =========================================================================

    // exists - Service existence
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "exists".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the service exists".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: Some(
                "Use 'exists boolean = false' to ensure a service does NOT exist".to_string(),
            ),
        });

    // state - Runtime state
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "state".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::CaseInsensitiveEquals,
            ],
            description: "Service runtime state".to_string(),
            example_values: vec![
                "running".to_string(),
                "stopped".to_string(),
                "paused".to_string(),
            ],
            validation_notes: Some(format!("Valid values: {}", VALID_STATES.join(", "))),
        });

    // start_type - Startup type
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "start_type".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::CaseInsensitiveEquals,
            ],
            description: "Service startup type".to_string(),
            example_values: vec![
                "auto".to_string(),
                "auto_delayed".to_string(),
                "manual".to_string(),
                "disabled".to_string(),
            ],
            validation_notes: Some(format!("Valid values: {}", VALID_START_TYPES.join(", "))),
        });

    // display_name - Display name
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "display_name".to_string(),
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
            description: "Service display name".to_string(),
            example_values: vec![
                "Windows Time".to_string(),
                "Print Spooler".to_string(),
                "Remote Desktop Services".to_string(),
            ],
            validation_notes: None,
        });

    // path - Binary path
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "path".to_string(),
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
            description: "Service binary path".to_string(),
            example_values: vec![
                r"C:\windows\system32\svchost.exe -k LocalService".to_string(),
                r"C:\windows\System32\spoolsv.exe".to_string(),
            ],
            validation_notes: Some("Can be used to detect service binary tampering".to_string()),
        });

    // service_type - Service type
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "service_type".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::CaseInsensitiveEquals,
            ],
            description: "Service process type".to_string(),
            example_values: vec![
                "own_process".to_string(),
                "share_process".to_string(),
                "kernel_driver".to_string(),
            ],
            validation_notes: Some(format!("Valid values: {}", VALID_SERVICE_TYPES.join(", "))),
        });

    // =========================================================================
    // Field Mappings
    // =========================================================================

    // Object field -> collector parameter
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("name".to_string(), "name".to_string());

    // Required data fields from collector
    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec![
        "exists".to_string(),
        "state".to_string(),
        "start_type".to_string(),
    ];

    // Optional data fields from collector
    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "display_name".to_string(),
        "path".to_string(),
        "service_type".to_string(),
    ];

    // State field -> collected data field (1:1 mapping)
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("exists".to_string(), "exists".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("state".to_string(), "state".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("start_type".to_string(), "start_type".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("display_name".to_string(), "display_name".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("path".to_string(), "path".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("service_type".to_string(), "service_type".to_string());

    // =========================================================================
    // Collection Strategy
    // =========================================================================

    contract.collection_strategy = CollectionStrategy {
        collector_type: "windows_service".to_string(),
        collection_mode: CollectionMode::Status,
        required_capabilities: vec!["service_query".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(200), // Two sc.exe calls
            memory_usage_mb: Some(1),
            network_intensive: false,
            cpu_intensive: false,
            requires_elevated_privileges: false, // Most services queryable without elevation
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
            default_value: Some("sc".to_string()),
            description: "Collection method: sc (default) or powershell".to_string(),
        }],
        description: "Select the service collection executor".to_string(),
        example: "behavior executor powershell".to_string(),
    });

    contract
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contract_creation() {
        let contract = create_service_contract();
        assert_eq!(contract.ctn_type, "service");
    }

    #[test]
    fn test_object_requirements() {
        let contract = create_service_contract();
        assert_eq!(contract.object_requirements.required_fields.len(), 1);

        let field = contract.object_requirements.required_fields.first();
        assert!(field.is_some());
        assert_eq!(field.map(|f| f.name.as_str()), Some("name"));
        assert_eq!(field.map(|f| f.data_type), Some(DataType::String));
    }

    #[test]
    fn test_state_requirements() {
        let contract = create_service_contract();
        assert_eq!(contract.state_requirements.optional_fields.len(), 6);

        let field_names: Vec<&str> = contract
            .state_requirements
            .optional_fields
            .iter()
            .map(|f| f.name.as_str())
            .collect();

        assert!(field_names.contains(&"exists"));
        assert!(field_names.contains(&"state"));
        assert!(field_names.contains(&"start_type"));
        assert!(field_names.contains(&"display_name"));
        assert!(field_names.contains(&"path"));
        assert!(field_names.contains(&"service_type"));
    }

    #[test]
    fn test_state_operations() {
        let contract = create_service_contract();

        // Find the 'state' field
        let state_field = contract
            .state_requirements
            .optional_fields
            .iter()
            .find(|f| f.name == "state");

        assert!(state_field.is_some());
        assert!(state_field
            .map(|f| f.allowed_operations.contains(&Operation::Equals))
            .unwrap_or(false));
        assert!(state_field
            .map(|f| f.allowed_operations.contains(&Operation::NotEqual))
            .unwrap_or(false));
        assert!(state_field
            .map(|f| f
                .allowed_operations
                .contains(&Operation::CaseInsensitiveEquals))
            .unwrap_or(false));
    }

    #[test]
    fn test_path_operations() {
        let contract = create_service_contract();

        // Find the 'path' field - should have more operations for string matching
        let path_field = contract
            .state_requirements
            .optional_fields
            .iter()
            .find(|f| f.name == "path");

        assert!(path_field.is_some());
        assert!(path_field
            .map(|f| f.allowed_operations.contains(&Operation::Equals))
            .unwrap_or(false));
        assert!(path_field
            .map(|f| f.allowed_operations.contains(&Operation::Contains))
            .unwrap_or(false));
        assert!(path_field
            .map(|f| f.allowed_operations.contains(&Operation::StartsWith))
            .unwrap_or(false));
        assert!(path_field
            .map(|f| f.allowed_operations.contains(&Operation::PatternMatch))
            .unwrap_or(false));
    }

    #[test]
    fn test_field_mappings() {
        let contract = create_service_contract();

        // Check required data fields
        assert!(contract
            .field_mappings
            .collection_mappings
            .required_data_fields
            .contains(&"exists".to_string()));
        assert!(contract
            .field_mappings
            .collection_mappings
            .required_data_fields
            .contains(&"state".to_string()));
        assert!(contract
            .field_mappings
            .collection_mappings
            .required_data_fields
            .contains(&"start_type".to_string()));

        // Check optional data fields
        assert!(contract
            .field_mappings
            .collection_mappings
            .optional_data_fields
            .contains(&"display_name".to_string()));
        assert!(contract
            .field_mappings
            .collection_mappings
            .optional_data_fields
            .contains(&"path".to_string()));
        assert!(contract
            .field_mappings
            .collection_mappings
            .optional_data_fields
            .contains(&"service_type".to_string()));
    }

    #[test]
    fn test_behaviors() {
        let contract = create_service_contract();
        assert_eq!(contract.supported_behaviors.len(), 1);

        let executor_behavior = contract.supported_behaviors.first();
        assert!(executor_behavior.is_some());
        assert_eq!(executor_behavior.map(|b| b.name.as_str()), Some("executor"));
        assert_eq!(
            executor_behavior.map(|b| b.behavior_type.clone()),
            Some(BehaviorType::Parameter)
        );

        let param = executor_behavior.and_then(|b| b.parameters.first());
        assert!(param.is_some());
        assert_eq!(
            param
                .and_then(|p| p.default_value.as_ref())
                .map(|s| s.as_str()),
            Some("sc")
        );
    }

    #[test]
    fn test_collection_strategy() {
        let contract = create_service_contract();
        assert_eq!(
            contract.collection_strategy.collector_type,
            "windows_service"
        );
    }
}
