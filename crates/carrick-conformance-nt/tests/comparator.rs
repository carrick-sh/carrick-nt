//! Unit tests for ReceiptComparator differential checking.

use carrick_conformance_nt::comparator::{
    ComparisonMismatch, ExecutionObservation, ReceiptComparator,
};
use carrick_conformance_nt::receipt::{OracleHostInfo, OracleReceipt};

fn make_test_receipt(exit_code: i32, stdout: &[u8], stderr: &[u8]) -> OracleReceipt {
    OracleReceipt::new(
        "hello_console",
        "x86_64",
        OracleHostInfo {
            os: "Windows Server 2025 Datacenter".to_string(),
            build: "10.0.26100.1742".to_string(),
            container_image: "mcr.microsoft.com/windows/nanoserver:ltsc2025".to_string(),
        },
        None,
        b"fake-binary",
        "2026-10-10T22:00:00Z",
        vec!["hello_console.exe".to_string()],
        exit_code,
        stdout,
        stderr,
    )
}

#[test]
fn test_exact_match() {
    let receipt = make_test_receipt(0, b"Hello, Carrick NT!\r\n", b"");
    let obs = ExecutionObservation::new(0, b"Hello, Carrick NT!\r\n".to_vec(), Vec::new());

    assert!(ReceiptComparator::compare(&receipt, &obs).is_ok());
    assert!(ReceiptComparator::assert_matches(&receipt, &obs).is_ok());
}

#[test]
fn test_exit_code_mismatch() {
    let receipt = make_test_receipt(0, b"Hello, Carrick NT!\r\n", b"");
    let obs = ExecutionObservation::new(1, b"Hello, Carrick NT!\r\n".to_vec(), Vec::new());

    let res = ReceiptComparator::compare(&receipt, &obs);
    assert!(res.is_err());
    let errs = res.unwrap_err();
    assert_eq!(errs.len(), 1);
    assert_eq!(
        errs[0],
        ComparisonMismatch::ExitCodeMismatch {
            expected: 0,
            actual: 1
        }
    );

    let assert_res = ReceiptComparator::assert_matches(&receipt, &obs);
    assert!(assert_res.is_err());
    let msg = assert_res.unwrap_err();
    assert!(msg.contains("Exit code mismatch"));
}

#[test]
fn test_stdout_mismatch() {
    let receipt = make_test_receipt(0, b"Hello, Carrick NT!\r\n", b"");
    let obs = ExecutionObservation::new(0, b"Different output\r\n".to_vec(), Vec::new());

    let res = ReceiptComparator::compare(&receipt, &obs);
    assert!(res.is_err());
    let errs = res.unwrap_err();
    assert_eq!(errs.len(), 1);
    match &errs[0] {
        ComparisonMismatch::StdoutMismatch { expected, actual } => {
            assert_eq!(expected, b"Hello, Carrick NT!\r\n");
            assert_eq!(actual, b"Different output\r\n");
        }
        other => panic!("Unexpected mismatch: {other:?}"),
    }
}

#[test]
fn test_stderr_mismatch() {
    let receipt = make_test_receipt(0, b"Hello, Carrick NT!\r\n", b"");
    let obs = ExecutionObservation::new(
        0,
        b"Hello, Carrick NT!\r\n".to_vec(),
        b"warning: unexpected fault".to_vec(),
    );

    let res = ReceiptComparator::compare(&receipt, &obs);
    assert!(res.is_err());
    let errs = res.unwrap_err();
    assert_eq!(errs.len(), 1);
    match &errs[0] {
        ComparisonMismatch::StderrMismatch { expected, actual } => {
            assert_eq!(expected, b"");
            assert_eq!(actual, b"warning: unexpected fault");
        }
        other => panic!("Unexpected mismatch: {other:?}"),
    }
}

#[test]
fn test_multiple_mismatches() {
    let receipt = make_test_receipt(0, b"Hello, Carrick NT!\r\n", b"");
    let obs = ExecutionObservation::new(
        42,
        b"Failed\r\n".to_vec(),
        b"segfault at 0xdeadbeef".to_vec(),
    );

    let res = ReceiptComparator::compare(&receipt, &obs);
    assert!(res.is_err());
    let errs = res.unwrap_err();
    assert_eq!(errs.len(), 3);
}

#[test]
fn test_invalid_base64_in_receipt() {
    let mut receipt = make_test_receipt(0, b"test", b"");
    receipt.execution.stdout_base64 = "not-valid-base64!".to_string();

    let obs = ExecutionObservation::new(0, b"test".to_vec(), Vec::new());
    let res = ReceiptComparator::compare(&receipt, &obs);
    assert!(res.is_err());
    let errs = res.unwrap_err();
    assert!(matches!(
        errs[0],
        ComparisonMismatch::InvalidReceiptBase64(_)
    ));
}

#[test]
fn test_reject_receipt_with_infra_error() {
    let mut receipt = make_test_receipt(125, b"", b"hcs::System::CreateProcess Access is denied");
    receipt.execution.infra_error =
        Some("hcs::System::CreateProcess: Access is denied. (0x5)".to_string());

    assert!(receipt.is_infrastructure_failure());

    let obs = ExecutionObservation::new(0, b"Hello, Carrick NT!\r\n".to_vec(), Vec::new());
    let res = ReceiptComparator::compare(&receipt, &obs);
    assert!(res.is_err());
    let errs = res.unwrap_err();
    assert_eq!(errs.len(), 1);
    match &errs[0] {
        ComparisonMismatch::InfrastructureFailure(msg) => {
            assert!(msg.contains("Access is denied"));
        }
        other => panic!("Expected InfrastructureFailure, got {other:?}"),
    }

    let assert_res = ReceiptComparator::assert_matches(&receipt, &obs);
    assert!(assert_res.is_err());
    let report = assert_res.unwrap_err();
    assert!(report.contains("infrastructure failure"));
}

#[test]
fn test_reject_receipt_with_docker_exit_125() {
    let receipt = make_test_receipt(125, b"", b"docker: Error response from daemon");
    assert!(receipt.is_infrastructure_failure());

    let obs = ExecutionObservation::new(
        125,
        Vec::new(),
        b"docker: Error response from daemon".to_vec(),
    );
    let res = ReceiptComparator::compare(&receipt, &obs);
    assert!(res.is_err());
    let errs = res.unwrap_err();
    assert_eq!(errs.len(), 1);
    assert!(matches!(
        errs[0],
        ComparisonMismatch::InfrastructureFailure(_)
    ));
}

#[test]
fn test_classify_infrastructure_error_helper() {
    use carrick_conformance_nt::classify_infrastructure_error;

    // Access denied / HCS error
    let hcs_err = "docker: Error response from daemon: container 123 encountered an error during hcs::System::CreateProcess: C:\\app\\hello_console.exe: failure in a Windows system call: Access is denied. (0x5)";
    let classified = classify_infrastructure_error(125, hcs_err);
    assert!(classified.is_some());
    assert!(classified.unwrap().contains("Access is denied"));

    // Exit 125 with empty stderr
    let classified_125 = classify_infrastructure_error(125, "");
    assert!(classified_125.is_some());

    // Exit 0 with no error
    assert!(classify_infrastructure_error(0, "").is_none());

    // Normal program non-zero exit code (e.g. exit 1 with app error output)
    assert!(classify_infrastructure_error(1, "Usage: hello.exe [options]\n").is_none());
}
