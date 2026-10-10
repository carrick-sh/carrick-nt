//! Differential comparison between Carrick NT runtime observations and committed oracle receipts.
//!
//! Enforces exact byte-for-byte fidelity on stdout, stderr, and identical exit codes.

use crate::receipt::OracleReceipt;

/// Runtime observation captured from a Carrick execution run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionObservation {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl ExecutionObservation {
    pub fn new(exit_code: i32, stdout: impl Into<Vec<u8>>, stderr: impl Into<Vec<u8>>) -> Self {
        Self {
            exit_code,
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }
}

/// A specific divergence detected between an oracle receipt and runtime observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComparisonMismatch {
    InfrastructureFailure(String),
    ExitCodeMismatch { expected: i32, actual: i32 },
    StdoutMismatch { expected: Vec<u8>, actual: Vec<u8> },
    StderrMismatch { expected: Vec<u8>, actual: Vec<u8> },
    InvalidReceiptBase64(String),
}

impl std::fmt::Display for ComparisonMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComparisonMismatch::InfrastructureFailure(err) => {
                write!(
                    f,
                    "Oracle receipt records infrastructure failure rather than valid program execution: {err}"
                )
            }
            ComparisonMismatch::ExitCodeMismatch { expected, actual } => {
                write!(
                    f,
                    "Exit code mismatch: expected {expected} (oracle), got {actual} (carrick)"
                )
            }
            ComparisonMismatch::StdoutMismatch { expected, actual } => {
                let exp_lossy = String::from_utf8_lossy(expected);
                let act_lossy = String::from_utf8_lossy(actual);
                write!(
                    f,
                    "Stdout mismatch:\n  Expected (oracle, {} bytes): {:?}\n  Actual (carrick, {} bytes): {:?}",
                    expected.len(),
                    exp_lossy,
                    actual.len(),
                    act_lossy
                )
            }
            ComparisonMismatch::StderrMismatch { expected, actual } => {
                let exp_lossy = String::from_utf8_lossy(expected);
                let act_lossy = String::from_utf8_lossy(actual);
                write!(
                    f,
                    "Stderr mismatch:\n  Expected (oracle, {} bytes): {:?}\n  Actual (carrick, {} bytes): {:?}",
                    expected.len(),
                    exp_lossy,
                    actual.len(),
                    act_lossy
                )
            }
            ComparisonMismatch::InvalidReceiptBase64(err) => {
                write!(f, "Invalid base64 encoding in oracle receipt: {err}")
            }
        }
    }
}

/// Evaluator that differentials checks a Carrick execution against an OracleReceipt.
pub struct ReceiptComparator;

impl ReceiptComparator {
    /// Compares a Carrick observation against an oracle receipt, collecting all mismatches.
    pub fn compare(
        receipt: &OracleReceipt,
        actual: &ExecutionObservation,
    ) -> Result<(), Vec<ComparisonMismatch>> {
        if let Some(infra_err) = &receipt.execution.infra_error {
            return Err(vec![ComparisonMismatch::InfrastructureFailure(
                infra_err.clone(),
            )]);
        }

        if receipt.execution.exit_code == 125 {
            return Err(vec![ComparisonMismatch::InfrastructureFailure(
                "Receipt records container engine error (exit code 125)".to_string(),
            )]);
        }

        let mut mismatches = Vec::new();

        if actual.exit_code != receipt.execution.exit_code {
            mismatches.push(ComparisonMismatch::ExitCodeMismatch {
                expected: receipt.execution.exit_code,
                actual: actual.exit_code,
            });
        }

        match receipt.decode_stdout() {
            Ok(expected_stdout) => {
                if actual.stdout != expected_stdout {
                    mismatches.push(ComparisonMismatch::StdoutMismatch {
                        expected: expected_stdout,
                        actual: actual.stdout.clone(),
                    });
                }
            }
            Err(e) => {
                mismatches.push(ComparisonMismatch::InvalidReceiptBase64(format!(
                    "stdout: {e}"
                )));
            }
        }

        match receipt.decode_stderr() {
            Ok(expected_stderr) => {
                if actual.stderr != expected_stderr {
                    mismatches.push(ComparisonMismatch::StderrMismatch {
                        expected: expected_stderr,
                        actual: actual.stderr.clone(),
                    });
                }
            }
            Err(e) => {
                mismatches.push(ComparisonMismatch::InvalidReceiptBase64(format!(
                    "stderr: {e}"
                )));
            }
        }

        if mismatches.is_empty() {
            Ok(())
        } else {
            Err(mismatches)
        }
    }

    /// Asserts that a Carrick observation matches the oracle receipt, returning a detailed
    /// human-readable error report if any divergence is found.
    pub fn assert_matches(
        receipt: &OracleReceipt,
        actual: &ExecutionObservation,
    ) -> Result<(), String> {
        match Self::compare(receipt, actual) {
            Ok(()) => Ok(()),
            Err(mismatches) => {
                let mut report = format!(
                    "Differential conformance failure for test '{}' (target: {}):\n",
                    receipt.metadata.test_name, receipt.metadata.target_arch
                );
                for mismatch in mismatches {
                    report.push_str(&format!("  - {mismatch}\n"));
                }
                Err(report)
            }
        }
    }
}
