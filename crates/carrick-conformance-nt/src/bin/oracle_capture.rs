//! Command-line interface for the Windows container oracle capture harness.
//!
//! Run by the director against the Windows Server 2025 oracle VM to execute
//! PE test executables inside a Windows container and generate committed oracle receipts.

use carrick_conformance_nt::harness::{
    execute_capture, generate_execution_plan, CaptureConfig, DEFAULT_PINNED_NANOSERVER_IMAGE,
};
use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "carrick-oracle-capture",
    about = "Captures oracle observations from Windows containers over SSH"
)]
struct Args {
    /// Remote Windows oracle SSH host (e.g. administrator@192.168.1.106 or oracle-vm)
    #[arg(short = 'H', long, default_value = "administrator@oracle-vm-106")]
    host: String,

    /// Path to the compiled PE executable to test
    #[arg(
        short = 'b',
        long,
        default_value = "tests/oracle/fixtures/hello_console.exe"
    )]
    binary: PathBuf,

    /// Optional path to test program source code (to capture source SHA-256)
    #[arg(short = 's', long)]
    source: Option<PathBuf>,

    /// Path where the captured JSON receipt will be saved
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,

    /// Test name (defaults to binary file stem)
    #[arg(short = 'n', long)]
    test_name: Option<String>,

    /// Pinned base container image tag or digest
    #[arg(short = 'i', long, default_value = DEFAULT_PINNED_NANOSERVER_IMAGE)]
    image: String,

    /// Execution timeout in seconds
    #[arg(short = 't', long, default_value_t = 30)]
    timeout: u64,

    /// SSH port
    #[arg(short = 'p', long, default_value_t = 22)]
    port: u16,

    /// Path to SSH private key
    #[arg(short = 'k', long)]
    key: Option<PathBuf>,

    /// Temporary working directory on the remote Windows host
    #[arg(long, default_value = "C:\\carrick-oracle")]
    remote_dir: String,

    /// Arguments to pass to the target executable inside the container
    #[arg(long)]
    app_args: Option<String>,

    /// Environment variables in KEY=VALUE format to set in the container
    #[arg(long = "env")]
    env_vars: Vec<String>,

    /// Print the commands and plan without connecting to the remote host
    #[arg(long)]
    dry_run: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let test_name = args.test_name.unwrap_or_else(|| {
        args.binary
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "test".to_string())
    });

    let mut config = CaptureConfig::new(test_name, args.binary, args.host);
    config.source_path = args.source;
    config.ssh_port = args.port;
    config.ssh_key = args.key;
    config.remote_temp_dir = args.remote_dir;
    config.container_image = args.image;
    config.timeout_seconds = args.timeout;
    config.output_receipt_path = args.output;
    config.app_args = args.app_args;
    config.env_vars = args.env_vars;

    if args.dry_run {
        let plan = generate_execution_plan(&config);
        println!("=== Oracle Capture Execution Plan (Dry Run) ===");
        println!("Target test:    {}", config.test_name);
        println!("Local binary:   {}", config.binary_path.display());
        println!("Pinned image:   {}", plan.pinned_image);
        println!("Image rationale: {}\n", plan.image_rationale);
        println!("1. Stage files to Windows host via SCP:");
        println!("   {}\n", plan.scp_command);
        println!("2. Run container and capture receipt over SSH:");
        println!("   {}\n", plan.ssh_command);
        if let Some(out) = &config.output_receipt_path {
            println!("3. Local receipt destination: {}", out.display());
        }
        return ExitCode::SUCCESS;
    }

    println!("Starting oracle capture for '{}'...", config.test_name);
    match execute_capture(&config) {
        Ok(receipt) => {
            println!("Successfully captured oracle observation!");
            println!("  Exit code:   {}", receipt.execution.exit_code);
            println!(
                "  Stdout len:  {} bytes",
                receipt.execution.stdout_raw.len()
            );
            println!("  Binary SHA:  {}", receipt.metadata.binary_hash_sha256);
            if let Some(out) = &config.output_receipt_path {
                println!("  Receipt written to: {}", out.display());
            } else {
                let json = receipt.to_json_string_pretty().unwrap();
                println!("\n{json}");
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("Oracle capture failed: {err}");
            ExitCode::FAILURE
        }
    }
}
