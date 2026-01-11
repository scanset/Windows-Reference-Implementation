//! Registry Executor
//!
//! Validates collected registry data against STATE requirements.
//!
//! ## Validation Logic
//!
//! 1. **Existence Check**: Do the expected registry keys/values exist?
//! 2. **State Validation**: Do values match expected state (type, value, version)?
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

/// Executor for registry CTN validation
pub struct RegistryExecutor {
    contract: CtnContract,
}

impl RegistryExecutor {
    /// Create a new registry executor with the given contract
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

            // Version comparisons (value_version) - must come before generic string match
            (ResolvedValue::String(exp), ResolvedValue::String(act), "value_version") => {
                self.compare_versions(act, exp, operation)
            }

            // Version type with string actual
            (ResolvedValue::Version(exp), ResolvedValue::String(act), _) => {
                self.compare_versions(act, exp, operation)
            }

            // String comparisons (type, value) - generic catch-all for strings
            (ResolvedValue::String(exp), ResolvedValue::String(act), _) => {
                string::compare(act, exp, operation).unwrap_or(false)
            }

            // Integer comparisons (value_int)
            (ResolvedValue::Integer(exp), ResolvedValue::String(act), "value_int") => {
                // Parse actual string value to integer
                if let Ok(act_int) = act.parse::<i64>() {
                    match operation {
                        Operation::Equals => act_int == *exp,
                        Operation::NotEqual => act_int != *exp,
                        Operation::GreaterThan => act_int > *exp,
                        Operation::LessThan => act_int < *exp,
                        Operation::GreaterThanOrEqual => act_int >= *exp,
                        Operation::LessThanOrEqual => act_int <= *exp,
                        _ => false,
                    }
                } else {
                    false
                }
            }

            // Direct integer comparisons
            (ResolvedValue::Integer(exp), ResolvedValue::Integer(act), _) => match operation {
                Operation::Equals => act == exp,
                Operation::NotEqual => act != exp,
                Operation::GreaterThan => act > exp,
                Operation::LessThan => act < exp,
                Operation::GreaterThanOrEqual => act >= exp,
                Operation::LessThanOrEqual => act <= exp,
                _ => false,
            },

            // Type mismatch
            _ => false,
        }
    }

    /// Compare two version strings
    ///
    /// Parses versions as dot-separated numeric components.
    /// Examples: "6.3", "19045", "10240.0"
    fn compare_versions(&self, actual: &str, expected: &str, operation: Operation) -> bool {
        let parse_version = |s: &str| -> Vec<u64> {
            s.split('.')
                .filter_map(|part| part.parse::<u64>().ok())
                .collect()
        };

        let actual_parts = parse_version(actual);
        let expected_parts = parse_version(expected);

        // Compare component by component
        let cmp = actual_parts.cmp(&expected_parts);

        match operation {
            Operation::Equals => cmp == std::cmp::Ordering::Equal,
            Operation::NotEqual => cmp != std::cmp::Ordering::Equal,
            Operation::GreaterThan => cmp == std::cmp::Ordering::Greater,
            Operation::LessThan => cmp == std::cmp::Ordering::Less,
            Operation::GreaterThanOrEqual => cmp != std::cmp::Ordering::Less,
            Operation::LessThanOrEqual => cmp != std::cmp::Ordering::Greater,
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
            Operation::PatternMatch => "pattern_match",
            Operation::CaseInsensitiveEquals => "ieq",
            Operation::CaseInsensitiveNotEqual => "ine",
            _ => "?",
        }
    }
}

impl CtnExecutor for RegistryExecutor {
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
                    "Existence check failed: expected {} registry objects, found {}",
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
                    // Record the exists check failure
                    let msg = if expected_exists && !actual_exists {
                        "Registry key/value does not exist".to_string()
                    } else if !expected_exists && actual_exists {
                        "Registry key/value exists but should not".to_string()
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
                    continue; // Skip to next object
                }
            }

            // Validate each state
            for state in &criterion.states {
                for field in &state.fields {
                    // Skip exists field - already handled above
                    if field.name == "exists" {
                        // Record successful exists check if we got here
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
                            // Field not collected - but if key doesn't exist, this is expected
                            if !actual_exists {
                                // Key doesn't exist, so type/value can't be checked
                                // This should only happen if exists wasn't explicitly checked
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

                            // Key exists but field not collected - unexpected
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
                "Registry validation passed: {} of {} objects compliant",
                objects_passing,
                state_results.len()
            )
        } else {
            format!(
                "Registry validation failed:\n  - {}",
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
        "registry"
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
            if !data.has_field("value") {
                return Err(CtnExecutionError::MissingDataField {
                    field: "value".to_string(),
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::create_registry_contract;

    #[test]
    fn test_executor_creation() {
        let contract = create_registry_contract();
        let executor = RegistryExecutor::new(contract);
        assert_eq!(executor.ctn_type(), "registry");
    }

    #[test]
    fn test_compare_booleans() {
        let contract = create_registry_contract();
        let executor = RegistryExecutor::new(contract);

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
    }

    #[test]
    fn test_compare_strings() {
        let contract = create_registry_contract();
        let executor = RegistryExecutor::new(contract);

        // type = "reg_sz"
        assert!(executor.compare_values(
            &ResolvedValue::String("reg_sz".to_string()),
            &ResolvedValue::String("reg_sz".to_string()),
            Operation::Equals,
            "type"
        ));

        // value contains "Enterprise"
        assert!(executor.compare_values(
            &ResolvedValue::String("Enterprise".to_string()),
            &ResolvedValue::String("EnterpriseS".to_string()),
            Operation::Contains,
            "value"
        ));
    }

    #[test]
    fn test_compare_value_int() {
        let contract = create_registry_contract();
        let executor = RegistryExecutor::new(contract);

        // value_int >= 1 (actual is string "2")
        assert!(executor.compare_values(
            &ResolvedValue::Integer(1),
            &ResolvedValue::String("2".to_string()),
            Operation::GreaterThanOrEqual,
            "value_int"
        ));

        // value_int = 0 (actual is string "0")
        assert!(executor.compare_values(
            &ResolvedValue::Integer(0),
            &ResolvedValue::String("0".to_string()),
            Operation::Equals,
            "value_int"
        ));
    }

    #[test]
    fn test_compare_value_version() {
        let contract = create_registry_contract();
        let executor = RegistryExecutor::new(contract);

        // value_version >= "19045" (actual is "26100")
        assert!(executor.compare_values(
            &ResolvedValue::String("19045".to_string()),
            &ResolvedValue::String("26100".to_string()),
            Operation::GreaterThanOrEqual,
            "value_version"
        ));

        // value_version >= "6.3" (actual is "6.3")
        assert!(executor.compare_values(
            &ResolvedValue::String("6.3".to_string()),
            &ResolvedValue::String("6.3".to_string()),
            Operation::GreaterThanOrEqual,
            "value_version"
        ));
    }
}
