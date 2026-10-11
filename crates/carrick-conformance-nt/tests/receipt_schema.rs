//! Unit tests for OracleReceipt serialization, schema adherence, and cryptographic integrity.

use carrick_conformance_nt::receipt::{
    compute_sha256, OracleHostInfo, OracleReceipt, ORACLE_RECEIPT_SCHEMA_V1,
};
use std::path::PathBuf;

const DOC_5_2_EXAMPLE_JSON: &str = r#"{
  "$schema": "https://carrick.dev/schemas/oracle-receipt-v1.json",
  "metadata": {
    "test_name": "hello_console",
    "lane": "nt",
    "target_arch": "x86_64",
    "oracle_host": {
      "os": "Windows Server 2025 Datacenter",
      "build": "10.0.26100.1742",
      "container_image": "mcr.microsoft.com/windows/nanoserver:ltsc2025"
    },
    "source_hash_sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
    "binary_hash_sha256": "8f3b2c1e7a6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f",
    "captured_at_utc": "2026-10-10T22:00:00Z"
  },
  "execution": {
    "command": ["hello_console.exe"],
    "exit_code": 0,
    "stdout_raw": "Hello, Carrick NT!\r\n",
    "stdout_base64": "SGVsbG8sIENhcnJpY2sgTlQhDQo=",
    "stderr_raw": "",
    "stderr_base64": ""
  }
}"#;

#[test]
fn test_deserialize_doc_example_receipt() {
    let receipt = OracleReceipt::from_json_str(DOC_5_2_EXAMPLE_JSON)
        .expect("Failed to deserialize design doc example receipt");

    assert_eq!(receipt.schema, ORACLE_RECEIPT_SCHEMA_V1);
    assert_eq!(receipt.metadata.test_name, "hello_console");
    assert_eq!(receipt.metadata.lane, "nt");
    assert_eq!(receipt.metadata.target_arch, "x86_64");
    assert_eq!(
        receipt.metadata.oracle_host.os,
        "Windows Server 2025 Datacenter"
    );
    assert_eq!(receipt.metadata.oracle_host.build, "10.0.26100.1742");
    assert_eq!(receipt.execution.exit_code, 0);

    let stdout_bytes = receipt.decode_stdout().expect("Failed to decode stdout");
    assert_eq!(stdout_bytes, b"Hello, Carrick NT!\r\n");

    let stderr_bytes = receipt.decode_stderr().expect("Failed to decode stderr");
    assert!(stderr_bytes.is_empty());
}

#[test]
fn test_roundtrip_serialization() {
    let host = OracleHostInfo {
        os: "Windows Server 2025 Datacenter".to_string(),
        build: "10.0.26100.1742".to_string(),
        container_image: "mcr.microsoft.com/windows/nanoserver:ltsc2025".to_string(),
    };

    let source = b"// source code";
    let binary = b"\x4d\x5a\x90\x00";
    let stdout = b"Hello, Carrick NT!\r\n";
    let stderr = b"";

    let receipt = OracleReceipt::new(
        "hello_console",
        "x86_64",
        host,
        Some(source),
        binary,
        "2026-10-10T22:15:00Z",
        vec!["hello_console.exe".to_string()],
        0,
        stdout,
        stderr,
    );

    let json_str = receipt
        .to_json_string_pretty()
        .expect("Failed to serialize");
    let deserialized =
        OracleReceipt::from_json_str(&json_str).expect("Failed to deserialize roundtrip");

    assert_eq!(receipt, deserialized);
    assert_eq!(receipt.metadata.binary_hash_sha256, compute_sha256(binary));
    assert_eq!(
        receipt.metadata.source_hash_sha256.as_deref(),
        Some(compute_sha256(source).as_str())
    );
}

#[test]
fn test_sha256_computation() {
    // Known test vector for empty string
    assert_eq!(
        compute_sha256(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    // Known test vector for "Hello, Carrick NT!\r\n"
    assert_eq!(
        compute_sha256(b"Hello, Carrick NT!\r\n"),
        "d19e0189a6d33db4fe308d5c1b988ef90b9216e7ddbeb9bde374e650c1e4e939"
    );
}

#[test]
fn test_committed_oracle_receipts() {
    let ws = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let receipts_dir = ws.join("tests/oracle/receipts");

    for file_name in &["hello_console.json", "echo_cmdline_env.json"] {
        let path = receipts_dir.join(file_name);
        assert!(path.exists(), "Receipt file must exist: {}", path.display());
        let data = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {e}", path.display()));
        let receipt = OracleReceipt::from_json_str(&data)
            .unwrap_or_else(|e| panic!("Failed to parse {}: {e}", path.display()));
        assert_eq!(receipt.schema, ORACLE_RECEIPT_SCHEMA_V1);
        assert_eq!(receipt.execution.exit_code, 0);
        assert!(receipt.decode_stdout().is_ok());
        assert!(receipt.decode_stderr().is_ok());
    }
}
