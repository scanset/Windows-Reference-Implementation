//! Service Executor
//!
//! Validates collected service data against STATE requirements.
//!
//! ## Validation Logic
//!
//! 1. **Existence Check**: Do the expected services exist?
//! 2. **State Validation**: Do services match expected state (state, start_type, etc.)?
//! 3. **Item Check**: How many objects must pass?
//!
//! ## Short-Circuit Behavior
//!
//! When `exists` is specified in STATE:
//! - `exists = true` + service missing -> FAIL immediately, skip other checks
//! - `exists = false` + service missing -> PASS immediately, skip other checks
//! - `exists = false` + service exists -> FAIL (service should not exist)

use common::results::Outcome;
use execution_engine::execution::{
    comparisons::string, evaluate_existence_check, evaluate_item_check, evaluate_state_operator,
};
use execution_engine::strategies::{
    CollectedData, CtnContract, CtnExecutionError, CtnExecutionResult, CtnExecutor,
    FieldValidationResult, StateValidationResult, TestPhase,
};
use execution_engine::types::common::{Operation, ResolvedValue};
use execution_engine::types::execution_context::ExecutableCriterion;
use std::collections::HashMap;

/// Executor for service CTN validation
pub struct ServiceExecutor {
    contract: CtnContract,
}

impl ServiceExecutor {
    /// Create a new service executor with the given contract
    pub fn new(contract: CtnContract) -> Self {
        Self { contract }
    }

    /// Compare two values based on the operation
    fn compare_values(
        &self,
        expected: &ResolvedValue,
        actual: &ResolvedValue,
        operation: Operation,
        _field_name: &str,
    ) -> bool {
        match (expected, actual) {
            // Boolean comparisons (exists)
            (ResolvedValue::Boolean(exp), ResolvedValue::Boolean(act)) => match operation {
                Operation::Equals => act == exp,
                Operation::NotEqual => act != exp,
                _ => false,
            },

            // String comparisons (state, start_type, display_name, path, service_type)
            (ResolvedValue::String(exp), ResolvedValue::String(act)) => {
                string::compare(act, exp, operation).unwrap_or(false)
            }

            // Type mismatch
            _ => false,
        }
    }

    /// Format operation for display
    fn format_operation(&self, op: Operation) -> &'static str {
        match op {
            Operation::Equals => "=",
            Operation::NotEqual => "!=",
            Operation::GreaterThan => ">",
            Operation::LessThan => "<",
            Operation::GreaterThanOrEqual => ">=",
            Operation::LessThanOrEqual => "<=",
            Operation::Contains => "contains",
            Operation::NotContains => "not_contains",
            Operation::StartsWith => "starts",
            Operation::EndsWith => "ends",
            Operation::NotStartsWith => "not_starts",
            Operation::NotEndsWith => "not_ends",
            Operation::PatternMatch => "pattern_match",
            Operation::CaseInsensitiveEquals => "ieq",
            Operation::CaseInsensitiveNotEqual => "ine",
            _ => "?",
        }
    }
}

impl CtnExecutor for ServiceExecutor {
    fn execute_with_contract(
        &self,
        criterion: &ExecutableCriterion,
        collected_data: HashMap<String, CollectedData>,
        _contract: &CtnContract,
    ) -> Result<CtnExecutionResult, CtnExecutionError> {
        let test_spec = &criterion.test;

        // =====================================================================
        // Phase 1: Existence Check
        // =====================================================================
        let objects_expected = criterion.expected_object_count();
        let objects_found = collected_data.len();

        let existence_passed =
            evaluate_existence_check(test_spec.existence_check, objects_found, objects_expected);

        if !existence_passed {
            return Ok(CtnExecutionResult::fail(
                criterion.criterion_type.clone(),
                format!(
                    "Existence check failed: expected {} service objects, found {}",
                    objects_expected, objects_found
                ),
            )
            .with_collected_data(collected_data));
        }

        // =====================================================================
        // Phase 2: State Validation
        // =====================================================================
        let mut state_results = Vec::new();
        let mut failure_messages = Vec::new();

        for (object_id, data) in &collected_data {
            let mut all_field_results = Vec::new();

            // Get actual existence status from collected data
            let actual_exists = data
                .get_field("exists")
                .map(|v| matches!(v, ResolvedValue::Boolean(true)))
                .unwrap_or(false);

            // Check if state specifies an exists requirement (for short-circuit logic)
            let exists_requirement = criterion.states.iter().find_map(|state| {
                state.fields.iter().find_map(|field| {
                    if field.name == "exists" {
                        if let ResolvedValue::Boolean(expected) = &field.value {
                            return Some((*expected, field.operation));
                        }
                    }
                    None
                })
            });

            // Short-circuit: Handle exists field specially
            if let Some((expected_exists, operation)) = exists_requirement {
                let exists_passed = self.compare_values(
                    &ResolvedValue::Boolean(expected_exists),
                    &ResolvedValue::Boolean(actual_exists),
                    operation,
                    "exists",
                );

                if !exists_passed {
                    // Record the exists check failure
                    let msg = if expected_exists && !actual_exists {
                        "Service does not exist".to_string()
                    } else if !expected_exists && actual_exists {
                        "Service exists but should not".to_string()
                    } else {
                        format!(
                            "exists check failed: got {}, expected {} {}",
                            actual_exists,
                            self.format_operation(operation),
                            expected_exists
                        )
                    };

                    all_field_results.push(FieldValidationResult {
                        field_name: "exists".to_string(),
                        expected_value: ResolvedValue::Boolean(expected_exists),
                        actual_value: ResolvedValue::Boolean(actual_exists),
                        operation,
                        passed: false,
                        message: msg.clone(),
                    });
                    failure_messages.push(format!("Service '{}': {}", object_id, msg));

                    // Short-circuit: Don't check other fields if existence check fails
                    state_results.push(StateValidationResult {
                        object_id: object_id.clone(),
                        state_results: all_field_results,
                        combined_result: false,
                        state_operator: test_spec.state_operator,
                        message: format!(
                            "Service '{}': failed ({})",
                            object_id,
                            if !actual_exists {
                                "service does not exist"
                            } else {
                                "service should not exist"
                            }
                        ),
                    });
                    continue; // Skip to next object
                }

                // exists check passed - record success
                all_field_results.push(FieldValidationResult {
                    field_name: "exists".to_string(),
                    expected_value: ResolvedValue::Boolean(expected_exists),
                    actual_value: ResolvedValue::Boolean(actual_exists),
                    operation,
                    passed: true,
                    message: "exists check passed".to_string(),
                });

                // Special case: if exists = false was expected and passed (service doesn't exist),
                // skip all other field validations
                if !expected_exists && !actual_exists {
                    state_results.push(StateValidationResult {
                        object_id: object_id.clone(),
                        state_results: all_field_results,
                        combined_result: true,
                        state_operator: test_spec.state_operator,
                        message: format!(
                            "Service '{}': passed (service correctly does not exist)",
                            object_id
                        ),
                    });
                    continue; // Skip to next object - no need to check other fields
                }
            }

            // Validate remaining state fields (skip exists, already handled)
            for state in &criterion.states {
                for field in &state.fields {
                    // Skip exists field - already handled above
                    if field.name == "exists" {
                        continue;
                    }

                    // Get the data field name from mapping
                    let data_field_name = self
                        .contract
                        .field_mappings
                        .validation_mappings
                        .state_to_data
                        .get(&field.name)
                        .cloned()
                        .unwrap_or_else(|| field.name.clone());

                    // Get actual value from collected data
                    let actual_value = match data.get_field(&data_field_name) {
                        Some(v) => v.clone(),
                        None => {
                            // Field not collected
                            if !actual_exists {
                                // Service doesn't exist, so fields can't be checked
                                let msg = format!(
                                    "Field '{}' not available (service does not exist)",
                                    field.name
                                );
                                all_field_results.push(FieldValidationResult {
                                    field_name: field.name.clone(),
                                    expected_value: field.value.clone(),
                                    actual_value: ResolvedValue::String("N/A".to_string()),
                                    operation: field.operation,
                                    passed: false,
                                    message: msg.clone(),
                                });
                                failure_messages.push(format!("Service '{}': {}", object_id, msg));
                                continue;
                            }

                            // Service exists but field not collected - unexpected
                            let msg = format!("Field '{}' not collected", field.name);
                            all_field_results.push(FieldValidationResult {
                                field_name: field.name.clone(),
                                expected_value: field.value.clone(),
                                actual_value: ResolvedValue::String("missing".to_string()),
                                operation: field.operation,
                                passed: false,
                                message: msg.clone(),
                            });
                            failure_messages.push(format!("Service '{}': {}", object_id, msg));
                            continue;
                        }
                    };

                    // Compare values
                    let passed = self.compare_values(
                        &field.value,
                        &actual_value,
                        field.operation,
                        &field.name,
                    );

                    let msg = if passed {
                        format!(
                            "{} check passed: {} {} {}",
                            field.name,
                            actual_value,
                            self.format_operation(field.operation),
                            field.value
                        )
                    } else {
                        format!(
                            "{} check failed: got {}, expected {} {}",
                            field.name,
                            actual_value,
                            self.format_operation(field.operation),
                            field.value
                        )
                    };

                    if !passed {
                        failure_messages.push(format!("Service '{}': {}", object_id, msg));
                    }

                    all_field_results.push(FieldValidationResult {
                        field_name: field.name.clone(),
                        expected_value: field.value.clone(),
                        actual_value,
                        operation: field.operation,
                        passed,
                        message: msg,
                    });
                }
            }

            // Combine field results using state operator
            let state_bools: Vec<bool> = all_field_results.iter().map(|r| r.passed).collect();
            let combined = if state_bools.is_empty() {
                true // No checks = pass
            } else {
                evaluate_state_operator(test_spec.state_operator, &state_bools)
            };

            state_results.push(StateValidationResult {
                object_id: object_id.clone(),
                state_results: all_field_results,
                combined_result: combined,
                state_operator: test_spec.state_operator,
                message: format!(
                    "Service '{}': {}",
                    object_id,
                    if combined { "passed" } else { "failed" }
                ),
            });
        }

        // =====================================================================
        // Phase 3: Item Check
        // =====================================================================
        let objects_passing = state_results.iter().filter(|r| r.combined_result).count();
        let item_passed =
            evaluate_item_check(test_spec.item_check, objects_passing, state_results.len());

        let final_status = if existence_passed && item_passed {
            Outcome::Pass
        } else {
            Outcome::Fail
        };

        let message = if final_status == Outcome::Pass {
            format!(
                "Service validation passed: {} of {} services compliant",
                objects_passing,
                state_results.len()
            )
        } else {
            format!(
                "Service validation failed:\n  - {}",
                failure_messages.join("\n  - ")
            )
        };

        Ok(CtnExecutionResult {
            ctn_type: criterion.criterion_type.clone(),
            status: final_status,
            test_phase: TestPhase::Complete,
            existence_result: None,
            state_results,
            item_check_result: None,
            message,
            details: serde_json::json!({
                "failures": failure_messages,
                "objects_passing": objects_passing,
                "objects_total": collected_data.len()
            }),
            execution_metadata: Default::default(),
            collected_data,
        })
    }

    fn get_ctn_contract(&self) -> CtnContract {
        self.contract.clone()
    }

    fn ctn_type(&self) -> &str {
        "service"
    }

    fn validate_collected_data(
        &self,
        collected_data: &HashMap<String, CollectedData>,
        _contract: &CtnContract,
    ) -> Result<(), CtnExecutionError> {
        for (object_id, data) in collected_data {
            // Check required field: exists
            if !data.has_field("exists") {
                return Err(CtnExecutionError::MissingDataField {
                    field: format!("exists (object: {})", object_id),
                });
            }

            // If service exists, check for required state fields
            let exists = data
                .get_field("exists")
                .map(|v| matches!(v, ResolvedValue::Boolean(true)))
                .unwrap_or(false);

            if exists {
                if !data.has_field("state") {
                    return Err(CtnExecutionError::MissingDataField {
                        field: format!("state (object: {})", object_id),
                    });
                }
                if !data.has_field("start_type") {
                    return Err(CtnExecutionError::MissingDataField {
                        field: format!("start_type (object: {})", object_id),
                    });
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::create_service_contract;

    #[test]
    fn test_executor_creation() {
        let contract = create_service_contract();
        let executor = ServiceExecutor::new(contract);
        assert_eq!(executor.ctn_type(), "service");
    }

    #[test]
    fn test_compare_booleans() {
        let contract = create_service_contract();
        let executor = ServiceExecutor::new(contract);

        // exists = true
        assert!(executor.compare_values(
            &ResolvedValue::Boolean(true),
            &ResolvedValue::Boolean(true),
            Operation::Equals,
            "exists"
        ));

        // exists != false
        assert!(executor.compare_values(
            &ResolvedValue::Boolean(false),
            &ResolvedValue::Boolean(true),
            Operation::NotEqual,
            "exists"
        ));

        // exists = false (both false)
        assert!(executor.compare_values(
            &ResolvedValue::Boolean(false),
            &ResolvedValue::Boolean(false),
            Operation::Equals,
            "exists"
        ));
    }

    #[test]
    fn test_compare_strings_equals() {
        let contract = create_service_contract();
        let executor = ServiceExecutor::new(contract);

        // state = "running"
        assert!(executor.compare_values(
            &ResolvedValue::String("running".to_string()),
            &ResolvedValue::String("running".to_string()),
            Operation::Equals,
            "state"
        ));

        // state != "stopped"
        assert!(executor.compare_values(
            &ResolvedValue::String("stopped".to_string()),
            &ResolvedValue::String("running".to_string()),
            Operation::NotEqual,
            "state"
        ));
    }

    #[test]
    fn test_compare_strings_case_insensitive() {
        let contract = create_service_contract();
        let executor = ServiceExecutor::new(contract);

        // state ieq "RUNNING"
        assert!(executor.compare_values(
            &ResolvedValue::String("RUNNING".to_string()),
            &ResolvedValue::String("running".to_string()),
            Operation::CaseInsensitiveEquals,
            "state"
        ));
    }

    #[test]
    fn test_compare_strings_contains() {
        let contract = create_service_contract();
        let executor = ServiceExecutor::new(contract);

        // path contains "svchost"
        assert!(executor.compare_values(
            &ResolvedValue::String("svchost".to_string()),
            &ResolvedValue::String(
                "C:\\windows\\system32\\svchost.exe -k LocalService".to_string()
            ),
            Operation::Contains,
            "path"
        ));
    }

    #[test]
    fn test_compare_strings_starts_with() {
        let contract = create_service_contract();
        let executor = ServiceExecutor::new(contract);

        // path starts "C:\\windows"
        assert!(executor.compare_values(
            &ResolvedValue::String("C:\\windows".to_string()),
            &ResolvedValue::String("C:\\windows\\system32\\svchost.exe".to_string()),
            Operation::StartsWith,
            "path"
        ));
    }

    #[test]
    fn test_compare_strings_ends_with() {
        let contract = create_service_contract();
        let executor = ServiceExecutor::new(contract);

        // path ends ".exe"
        assert!(executor.compare_values(
            &ResolvedValue::String(".exe".to_string()),
            &ResolvedValue::String("C:\\windows\\system32\\spoolsv.exe".to_string()),
            Operation::EndsWith,
            "path"
        ));
    }

    #[test]
    fn test_format_operation() {
        let contract = create_service_contract();
        let executor = ServiceExecutor::new(contract);

        assert_eq!(executor.format_operation(Operation::Equals), "=");
        assert_eq!(executor.format_operation(Operation::NotEqual), "!=");
        assert_eq!(executor.format_operation(Operation::Contains), "contains");
        assert_eq!(
            executor.format_operation(Operation::CaseInsensitiveEquals),
            "ieq"
        );
        assert_eq!(
            executor.format_operation(Operation::PatternMatch),
            "pattern_match"
        );
    }

    #[test]
    fn test_validate_collected_data_success() {
        let contract = create_service_contract();
        let executor = ServiceExecutor::new(contract.clone());

        let mut data = CollectedData::new(
            "test_service".to_string(),
            "service".to_string(),
            "test_collector".to_string(),
        );
        data.add_field("exists".to_string(), ResolvedValue::Boolean(true));
        data.add_field(
            "state".to_string(),
            ResolvedValue::String("running".to_string()),
        );
        data.add_field(
            "start_type".to_string(),
            ResolvedValue::String("auto".to_string()),
        );

        let mut collected = HashMap::new();
        collected.insert("test_service".to_string(), data);

        assert!(executor
            .validate_collected_data(&collected, &contract)
            .is_ok());
    }

    #[test]
    fn test_validate_collected_data_missing_exists() {
        let contract = create_service_contract();
        let executor = ServiceExecutor::new(contract.clone());

        let data = CollectedData::new(
            "test_service".to_string(),
            "service".to_string(),
            "test_collector".to_string(),
        );
        // Missing "exists" field

        let mut collected = HashMap::new();
        collected.insert("test_service".to_string(), data);

        assert!(executor
            .validate_collected_data(&collected, &contract)
            .is_err());
    }

    #[test]
    fn test_validate_collected_data_nonexistent_service() {
        let contract = create_service_contract();
        let executor = ServiceExecutor::new(contract.clone());

        let mut data = CollectedData::new(
            "test_service".to_string(),
            "service".to_string(),
            "test_collector".to_string(),
        );
        // Service doesn't exist - only needs exists field
        data.add_field("exists".to_string(), ResolvedValue::Boolean(false));

        let mut collected = HashMap::new();
        collected.insert("test_service".to_string(), data);

        // Should pass - non-existent services don't need state/start_type
        assert!(executor
            .validate_collected_data(&collected, &contract)
            .is_ok());
    }
}
