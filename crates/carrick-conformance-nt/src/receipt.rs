//! Oracle receipt data structures, serialization, and decoding.
//!
//! Conforms to schema defined in `docs/design/ntdll-bootstrap.md` Section 5.2:
//! `https://carrick.dev/schemas/oracle-receipt-v1.json`

use base64::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

pub const ORACLE_RECEIPT_SCHEMA_V1: &str = "https://carrick.dev/schemas/oracle-receipt-v1.json";

/// Root container for a committed or captured Windows container oracle observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleReceipt {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub metadata: ReceiptMetadata,
    pub execution: ReceiptExecution,
}

/// Metadata identifying test provenance, target architecture, host environment,
/// and source/binary cryptographic hashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptMetadata {
    pub test_name: String,
    pub lane: String,
    pub target_arch: String,
    pub oracle_host: OracleHostInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_hash_sha256: Option<String>,
    pub binary_hash_sha256: String,
    pub captured_at_utc: String,
}

/// Environmental details of the Windows oracle host and container runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleHostInfo {
    pub os: String,
    pub build: String,
    pub container_image: String,
}

/// Exact execution results captured from the Windows container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptExecution {
    pub command: Vec<String>,
    pub exit_code: i32,
    pub stdout_raw: String,
    pub stdout_base64: String,
    pub stderr_raw: String,
    pub stderr_base64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub infra_error: Option<String>,
}

impl OracleReceipt {
    /// Creates a new OracleReceipt with standard schema and encoded output streams.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        test_name: impl Into<String>,
        target_arch: impl Into<String>,
        oracle_host: OracleHostInfo,
        source_bytes: Option<&[u8]>,
        binary_bytes: &[u8],
        captured_at_utc: impl Into<String>,
        command: Vec<String>,
        exit_code: i32,
        stdout_bytes: &[u8],
        stderr_bytes: &[u8],
    ) -> Self {
        let source_hash_sha256 = source_bytes.map(compute_sha256);
        let binary_hash_sha256 = compute_sha256(binary_bytes);

        let stdout_base64 = BASE64_STANDARD.encode(stdout_bytes);
        let stderr_base64 = BASE64_STANDARD.encode(stderr_bytes);

        let stdout_raw = String::from_utf8_lossy(stdout_bytes).into_owned();
        let stderr_raw = String::from_utf8_lossy(stderr_bytes).into_owned();

        Self {
            schema: ORACLE_RECEIPT_SCHEMA_V1.to_string(),
            metadata: ReceiptMetadata {
                test_name: test_name.into(),
                lane: "nt".to_string(),
                target_arch: target_arch.into(),
                oracle_host,
                source_hash_sha256,
                binary_hash_sha256,
                captured_at_utc: captured_at_utc.into(),
            },
            execution: ReceiptExecution {
                command,
                exit_code,
                stdout_raw,
                stdout_base64,
                stderr_raw,
                stderr_base64,
                infra_error: None,
            },
        }
    }

    /// Checks if the receipt records an infrastructure or container engine failure rather
    /// than a valid target program execution result.
    pub fn is_infrastructure_failure(&self) -> bool {
        self.execution.infra_error.is_some() || self.execution.exit_code == 125
    }

    /// Deserializes a receipt from a JSON string.
    pub fn from_json_str(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serializes the receipt to a formatted JSON string.
    pub fn to_json_string_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Reads and deserializes a receipt from a file path.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, std::io::Error> {
        let content = fs::read_to_string(path)?;
        serde_json::from_str(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// Serializes and writes the receipt to a file path.
    pub fn write_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), std::io::Error> {
        let pretty = self
            .to_json_string_pretty()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, pretty.as_bytes())
    }

    /// Decodes the base64-encoded standard output bytes.
    pub fn decode_stdout(&self) -> Result<Vec<u8>, base64::DecodeError> {
        BASE64_STANDARD.decode(&self.execution.stdout_base64)
    }

    /// Decodes the base64-encoded standard error bytes.
    pub fn decode_stderr(&self) -> Result<Vec<u8>, base64::DecodeError> {
        BASE64_STANDARD.decode(&self.execution.stderr_base64)
    }
}

/// Computes lower-hex SHA-256 hash of a byte slice.
pub fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    format!("{result:x}")
}
