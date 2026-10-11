//! Differential black-box oracle harness, receipt verification, and clean-room PE validator.
//!
//! Subsystems:
//! - `receipt`: committed oracle observation schema (`oracle-receipt-v1.json`).
//! - `comparator`: differential conformance evaluator comparing Carrick runs against receipts.
//! - `pe`: clean-room PE32+ header, section, and import validator.
//! - `harness`: automated Windows container test capture harness.

pub mod census;
pub mod comparator;
pub mod harness;
pub mod pe;
pub mod receipt;

pub use census::{
    build_census_report, generate_markdown_report, parse_api_set_name, scan_binary_bytes,
    scan_binary_file, ApiSetContract, ApiSetGroup, CensusError, CensusReport, DiscoveredImport,
    FirstTargets, ProgramCensus, RankedImport,
};
pub use comparator::{ComparisonMismatch, ExecutionObservation, ReceiptComparator};
pub use harness::{
    classify_infrastructure_error, execute_capture, generate_execution_plan, CaptureConfig,
    ExecutionPlan, HarnessError, DEFAULT_PINNED_NANOSERVER_IMAGE,
};
pub use pe::{
    parse_pe, verify_hello_console_pe, PeImageInfo, PeParseError, PeVerificationError,
    SectionHeader,
};
pub use receipt::{
    compute_sha256, OracleHostInfo, OracleReceipt, ReceiptExecution, ReceiptMetadata,
    ORACLE_RECEIPT_SCHEMA_V1,
};
