//! Registry Subkeys Executor
//!
//! Validates collected registry subkey data against STATE requirements.
//!
//! ## Validation Logic
//!
//! 1. **Existence Check**: Does the registry key exist?
//! 2. **State Validation**: Does subkey_count match? Are required subkeys present?
//! 3. **Item Check**: How many objects must pass?

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

/// Executor for registry_subkeys CTN validation
pub struct RegistrySubkeysExecutor {
    contract: CtnContract,
}

impl RegistrySubkeysExecutor {
    /// Create a new registry subkeys executor with the given contract
    pub fn new(contract: CtnContract) -> Self {
        Self { contract }
    }

    /// Compare two values based on the operation
    fn compare_values(
        &self,
        expected: &ResolvedValue,
        actual: &ResolvedValue,
        operation: Operation,
        field_name: &str,
    ) -> bool {
        match (expected, actual, field_name) {
            // Boolean comparisons (exists)
            (ResolvedValue::Boolean(exp), ResolvedValue::Boolean(act), _) => match operation {
                Operation::Equals => act == exp,
                Operation::NotEqual => act != exp,
                _ => false,
            },

            // Integer comparisons (subkey_count)
            (ResolvedValue::Integer(exp), ResolvedValue::Integer(act), _) => match operation {
                Operation::Equals => act == exp,
                Operation::NotEqual => act != exp,
                Operation::GreaterThan => act > exp,
                Operation::LessThan => act < exp,
                Operation::GreaterThanOrEqual => act >= exp,
                Operation::LessThanOrEqual => act <= exp,
                _ => false,
            },

            // subkeys field: actual is comma-separated string like "Reader1,Reader2,SmartCard"
            // Use string::compare for all string operations
            (ResolvedValue::String(exp), ResolvedValue::String(act), "subkeys") => {
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
            Operation::PatternMatch => "pattern_match",
            _ => "?",
        }
    }

    /// Format a ResolvedValue for display
    fn format_value(&self, value: &ResolvedValue) -> String {
        match value {
            ResolvedValue::Boolean(b) => b.to_string(),
            ResolvedValue::Integer(i) => i.to_string(),
            ResolvedValue::String(s) => {
                // For subkeys, show count if it looks like a comma-separated list
                if s.contains(',') {
                    let count = s.split(',').filter(|p| !p.is_empty()).count();
                    format!("[{} subkeys]", count)
                } else if s.is_empty() {
                    "[0 subkeys]".to_string()
                } else {
                    s.clone()
                }
            }
            _ => format!("{:?}", value),
        }
    }
}

impl CtnExecutor for RegistrySubkeysExecutor {
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
                    "Existence check failed: expected {} registry keys, found {}",
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

            // Short-circuit: If exists=true is required but key doesn't exist
            if let Some((expected_exists, operation)) = exists_requirement {
                let exists_passed = self.compare_values(
                    &ResolvedValue::Boolean(expected_exists),
                    &ResolvedValue::Boolean(actual_exists),
                    operation,
                    "exists",
                );

                if !exists_passed {
                    let msg = if expected_exists && !actual_exists {
                        "Registry key does not exist".to_string()
                    } else if !expected_exists && actual_exists {
                        "Registry key exists but should not".to_string()
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
                    failure_messages.push(format!("Registry '{}': {}", object_id, msg));

                    // Short-circuit: Don't check other fields if existence check fails
                    state_results.push(StateValidationResult {
                        object_id: object_id.clone(),
                        state_results: all_field_results,
                        combined_result: false,
                        state_operator: test_spec.state_operator,
                        message: format!("Registry '{}': failed (key does not exist)", object_id),
                    });
                    continue;
                }
            }

            // Validate each state
            for state in &criterion.states {
                for field in &state.fields {
                    // Skip exists field - already handled above
                    if field.name == "exists" {
                        all_field_results.push(FieldValidationResult {
                            field_name: "exists".to_string(),
                            expected_value: field.value.clone(),
                            actual_value: ResolvedValue::Boolean(actual_exists),
                            operation: field.operation,
                            passed: true,
                            message: "exists check passed".to_string(),
                        });
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
                            if !actual_exists {
                                let msg = format!(
                                    "Field '{}' not available (key does not exist)",
                                    field.name
                                );
                                all_field_results.push(FieldValidationResult {
                                    field_name: field.name.clone(),
                                    expected_value: field.value.clone(),
                                    actual_value: ResolvedValue::String("missing".to_string()),
                                    operation: field.operation,
                                    passed: false,
                                    message: msg.clone(),
                                });
                                failure_messages.push(format!("Registry '{}': {}", object_id, msg));
                                continue;
                            }

                            let msg = format!("Field '{}' not collected", field.name);
                            all_field_results.push(FieldValidationResult {
                                field_name: field.name.clone(),
                                expected_value: field.value.clone(),
                                actual_value: ResolvedValue::String("missing".to_string()),
                                operation: field.operation,
                                passed: false,
                                message: msg.clone(),
                            });
                            failure_messages.push(format!("Registry '{}': {}", object_id, msg));
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
                            self.format_value(&actual_value),
                            self.format_operation(field.operation),
                            self.format_value(&field.value)
                        )
                    } else {
                        format!(
                            "{} check failed: got {}, expected {} {}",
                            field.name,
                            self.format_value(&actual_value),
                            self.format_operation(field.operation),
                            self.format_value(&field.value)
                        )
                    };

                    if !passed {
                        failure_messages.push(format!("Registry '{}': {}", object_id, msg));
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
            let combined = evaluate_state_operator(test_spec.state_operator, &state_bools);

            state_results.push(StateValidationResult {
                object_id: object_id.clone(),
                state_results: all_field_results,
                combined_result: combined,
                state_operator: test_spec.state_operator,
                message: format!(
                    "Registry '{}': {}",
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
                "Registry subkeys validation passed: {} of {} objects compliant",
                objects_passing,
                state_results.len()
            )
        } else {
            format!(
                "Registry subkeys validation failed:\n  - {}",
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
        "registry_subkeys"
    }

    fn validate_collected_data(
        &self,
        collected_data: &HashMap<String, CollectedData>,
        _contract: &CtnContract,
    ) -> Result<(), CtnExecutionError> {
        for data in collected_data.values() {
            // Check required fields
            if !data.has_field("exists") {
                return Err(CtnExecutionError::MissingDataField {
                    field: "exists".to_string(),
                });
            }
            if !data.has_field("subkey_count") {
                return Err(CtnExecutionError::MissingDataField {
                    field: "subkey_count".to_string(),
                });
            }
            // Note: 'subkeys' is optional
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::create_registry_subkeys_contract;

    #[test]
    fn test_executor_creation() {
        let contract = create_registry_subkeys_contract();
        let executor = RegistrySubkeysExecutor::new(contract);
        assert_eq!(executor.ctn_type(), "registry_subkeys");
    }

    #[test]
    fn test_compare_booleans() {
        let contract = create_registry_subkeys_contract();
        let executor = RegistrySubkeysExecutor::new(contract);

        assert!(executor.compare_values(
            &ResolvedValue::Boolean(true),
            &ResolvedValue::Boolean(true),
            Operation::Equals,
            "exists"
        ));

        assert!(executor.compare_values(
            &ResolvedValue::Boolean(false),
            &ResolvedValue::Boolean(true),
            Operation::NotEqual,
            "exists"
        ));
    }

    #[test]
    fn test_compare_integers() {
        let contract = create_registry_subkeys_contract();
        let executor = RegistrySubkeysExecutor::new(contract);

        // subkey_count >= 1
        assert!(executor.compare_values(
            &ResolvedValue::Integer(1),
            &ResolvedValue::Integer(5),
            Operation::GreaterThanOrEqual,
            "subkey_count"
        ));

        // subkey_count = 0
        assert!(executor.compare_values(
            &ResolvedValue::Integer(0),
            &ResolvedValue::Integer(0),
            Operation::Equals,
            "subkey_count"
        ));

        // subkey_count > 0
        assert!(executor.compare_values(
            &ResolvedValue::Integer(0),
            &ResolvedValue::Integer(3),
            Operation::GreaterThan,
            "subkey_count"
        ));
    }

    #[test]
    fn test_compare_subkeys_contains() {
        let contract = create_registry_subkeys_contract();
        let executor = RegistrySubkeysExecutor::new(contract);

        // subkeys stored as comma-separated string
        let subkeys = ResolvedValue::String("Reader1,Reader2,SmartCardReader".to_string());

        // Contains "Reader1"
        assert!(executor.compare_values(
            &ResolvedValue::String("Reader1".to_string()),
            &subkeys,
            Operation::Contains,
            "subkeys"
        ));

        // Contains partial match
        assert!(executor.compare_values(
            &ResolvedValue::String("SmartCard".to_string()),
            &subkeys,
            Operation::Contains,
            "subkeys"
        ));

        // Does not contain
        assert!(!executor.compare_values(
            &ResolvedValue::String("NonExistent".to_string()),
            &subkeys,
            Operation::Contains,
            "subkeys"
        ));
    }
}
