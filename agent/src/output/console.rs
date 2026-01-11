//! Console output formatting
//!
//! Provides formatted console output for scan results.

use contract_kit::execution_api::ScanResult;

/// Print scan results to console in a human-readable format
pub fn print_results(scan_results: &[ScanResult]) {
    if scan_results.is_empty() {
        return;
    }

    println!();
    println!("╔═══════════════════════════════════════════════════════════════════════════════╗");
    println!("║                              SCAN RESULTS                                     ║");
    println!("╚═══════════════════════════════════════════════════════════════════════════════╝");
    println!();

    for (index, result) in scan_results.iter().enumerate() {
        print_policy_result(index + 1, scan_results.len(), result);
    }

    print_summary_table(scan_results);
}

/// Print a single policy result
fn print_policy_result(num: usize, total: usize, result: &ScanResult) {
    let status_icon = if result.tree_passed { "✓" } else { "✗" };
    let status_text = if result.tree_passed { "PASS" } else { "FAIL" };
    let status_color = if result.tree_passed {
        "\x1b[32m"
    } else {
        "\x1b[31m"
    }; // Green or Red
    let reset = "\x1b[0m";

    println!("┌───────────────────────────────────────────────────────────────────────────────┐");
    println!("│ Policy {}/{}: {}", num, total, result.outcome.policy_id);
    println!("├───────────────────────────────────────────────────────────────────────────────┤");
    println!(
        "│ Status:      {}{} {}{}",
        status_color, status_icon, status_text, reset
    );
    println!("│ Platform:    {}", result.outcome.platform);
    println!("│ Criticality: {:?}", result.outcome.criticality);
    println!(
        "│ Criteria:    {}/{} passed",
        result.criteria_counts.passed, result.criteria_counts.total
    );

    // Print control mappings
    if !result.outcome.control_mappings.is_empty() {
        let mappings: Vec<String> = result
            .outcome
            .control_mappings
            .iter()
            .map(|m| format!("{}:{}", m.framework, m.control_id))
            .collect();
        println!("│ Controls:    {}", mappings.join(", "));
    }

    // Print findings if any
    if !result.findings.is_empty() {
        println!(
            "├───────────────────────────────────────────────────────────────────────────────┤"
        );
        println!("│ Findings ({}):", result.findings.len());
        for finding in &result.findings {
            println!(
                "│   • [{}] {}",
                finding.severity.to_string().to_uppercase(),
                finding.title
            );
            // Print description lines with proper indentation
            for line in finding.description.lines().take(3) {
                let truncated = if line.len() > 70 {
                    format!("{}...", &line[..67])
                } else {
                    line.to_string()
                };
                println!("│       {}", truncated);
            }
        }
    }

    println!("└───────────────────────────────────────────────────────────────────────────────┘");
    println!();
}

/// Print summary table
fn print_summary_table(scan_results: &[ScanResult]) {
    let total = scan_results.len();
    let passed = scan_results.iter().filter(|r| r.tree_passed).count();
    let failed = total - passed;

    // Calculate by criticality
    let mut critical_pass = 0;
    let mut critical_fail = 0;
    let mut high_pass = 0;
    let mut high_fail = 0;
    let mut medium_pass = 0;
    let mut medium_fail = 0;
    let mut low_pass = 0;
    let mut low_fail = 0;
    let mut info_pass = 0;
    let mut info_fail = 0;

    for result in scan_results {
        let passed = result.tree_passed;
        match result.outcome.criticality {
            common::results::Criticality::Critical => {
                if passed {
                    critical_pass += 1;
                } else {
                    critical_fail += 1;
                }
            }
            common::results::Criticality::High => {
                if passed {
                    high_pass += 1;
                } else {
                    high_fail += 1;
                }
            }
            common::results::Criticality::Medium => {
                if passed {
                    medium_pass += 1;
                } else {
                    medium_fail += 1;
                }
            }
            common::results::Criticality::Low => {
                if passed {
                    low_pass += 1;
                } else {
                    low_fail += 1;
                }
            }
            common::results::Criticality::Info => {
                if passed {
                    info_pass += 1;
                } else {
                    info_fail += 1;
                }
            }
        }
    }

    // Calculate posture score
    let total_weight: f32 = scan_results
        .iter()
        .map(|r| criticality_weight(r.outcome.criticality))
        .sum();
    let passed_weight: f32 = scan_results
        .iter()
        .filter(|r| r.tree_passed)
        .map(|r| criticality_weight(r.outcome.criticality))
        .sum();
    let posture_score = if total_weight > 0.0 {
        (passed_weight / total_weight) * 100.0
    } else {
        0.0
    };

    println!("╔═══════════════════════════════════════════════════════════════════════════════╗");
    println!("║                                 SUMMARY                                       ║");
    println!("╠═══════════════════════════════════════════════════════════════════════════════╣");
    println!("║                                                                               ║");
    println!(
        "║   Total Policies: {:3}                                                        ║",
        total
    );
    println!("║   \x1b[32mPassed:\x1b[0m          {:3}                                                        ║", passed);
    println!("║   \x1b[31mFailed:\x1b[0m          {:3}                                                        ║", failed);
    println!("║                                                                               ║");
    println!("╠═══════════════════════════════════════════════════════════════════════════════╣");
    println!(
        "║   Posture Score: {:5.1}%                                                      ║",
        posture_score
    );
    println!("╠═══════════════════════════════════════════════════════════════════════════════╣");
    println!("║                                                                               ║");
    println!("║   By Criticality:        Pass    Fail    Total                                ║");
    println!("║   ─────────────────────────────────────────                                   ║");

    if critical_pass + critical_fail > 0 {
        println!(
            "║   Critical               {:3}     {:3}      {:3}                                  ║",
            critical_pass,
            critical_fail,
            critical_pass + critical_fail
        );
    }
    if high_pass + high_fail > 0 {
        println!(
            "║   High                   {:3}     {:3}      {:3}                                  ║",
            high_pass,
            high_fail,
            high_pass + high_fail
        );
    }
    if medium_pass + medium_fail > 0 {
        println!(
            "║   Medium                 {:3}     {:3}      {:3}                                  ║",
            medium_pass,
            medium_fail,
            medium_pass + medium_fail
        );
    }
    if low_pass + low_fail > 0 {
        println!(
            "║   Low                    {:3}     {:3}      {:3}                                  ║",
            low_pass,
            low_fail,
            low_pass + low_fail
        );
    }
    if info_pass + info_fail > 0 {
        println!(
            "║   Info                   {:3}     {:3}      {:3}                                  ║",
            info_pass,
            info_fail,
            info_pass + info_fail
        );
    }

    println!("║                                                                               ║");
    println!("╚═══════════════════════════════════════════════════════════════════════════════╝");
    println!();
}

/// Get weight for criticality level
fn criticality_weight(criticality: common::results::Criticality) -> f32 {
    match criticality {
        common::results::Criticality::Critical => 1.0,
        common::results::Criticality::High => 0.8,
        common::results::Criticality::Medium => 0.5,
        common::results::Criticality::Low => 0.3,
        common::results::Criticality::Info => 0.1,
    }
}

/// Print a compact single-line result for progress output
pub fn print_progress_result(num: usize, total: usize, result: &ScanResult) {
    let status_icon = if result.tree_passed { "✓" } else { "✗" };
    let status_color = if result.tree_passed {
        "\x1b[32m"
    } else {
        "\x1b[31m"
    };
    let reset = "\x1b[0m";

    if result.tree_passed {
        println!(
            "[{}/{}] {}{}{} {} ({}/{} criteria)",
            num,
            total,
            status_color,
            status_icon,
            reset,
            result.outcome.policy_id,
            result.criteria_counts.passed,
            result.criteria_counts.total
        );
    } else {
        println!(
            "[{}/{}] {}{}{} {} ({} findings)",
            num,
            total,
            status_color,
            status_icon,
            reset,
            result.outcome.policy_id,
            result.findings.len()
        );
        for finding in &result.findings {
            println!("       └─ {}: {}", finding.finding_id, finding.title);
        }
    }
}
