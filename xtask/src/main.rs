//! Automation task runner for carrick-nt: fixture builds and PE validation.

use carrick_conformance_nt::pe::verify_hello_console_pe;
use carrick_conformance_nt::receipt::compute_sha256;
use clap::{Parser, Subcommand};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

#[derive(Parser)]
#[command(name = "xtask", about = "carrick-nt build and verification xtask")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Compiles clean-room PE fixtures (hello_console) without Microsoft SDKs
    BuildFixtures {
        #[arg(long, default_value = "x86_64-pc-windows-msvc")]
        target: String,
    },
    /// Verifies the compiled PE fixture using clean-room parser and llvm-readobj
    VerifyPe {
        #[arg(long)]
        binary: Option<PathBuf>,
    },
    /// Builds all fixtures and executes PE verification
    All {
        #[arg(long, default_value = "x86_64-pc-windows-msvc")]
        target: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Commands::BuildFixtures { target } => match build_fixtures(&target) {
            Ok(path) => {
                println!("Fixture built successfully at: {}", path.display());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("Error building fixtures: {e}");
                ExitCode::FAILURE
            }
        },
        Commands::VerifyPe { binary } => match verify_pe_artifact(binary.as_deref()) {
            Ok(()) => {
                println!("PE verification passed!");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("PE verification failed: {e}");
                ExitCode::FAILURE
            }
        },
        Commands::All { target } => match build_fixtures(&target) {
            Ok(path) => match verify_pe_artifact(Some(&path)) {
                Ok(()) => {
                    println!("\nAll tasks passed (build + PE verification)!");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("PE verification failed: {e}");
                    ExitCode::FAILURE
                }
            },
            Err(e) => {
                eprintln!("Error building fixtures: {e}");
                ExitCode::FAILURE
            }
        },
    }
}

pub fn build_fixtures(target: &str) -> Result<PathBuf, String> {
    println!("Building clean-room fixture 'hello_console' for target '{target}'...");

    let manifest_path = "crates/carrick-conformance-nt/fixtures/hello_console/Cargo.toml";
    if !Path::new(manifest_path).exists() {
        return Err(format!("Fixture manifest not found: {manifest_path}"));
    }

    let rustflags = "-C panic=abort -C linker=lld -C link-args=/nodefaultlib -C link-args=/entry:mainCRTStartup -C link-args=/subsystem:console";

    let status = Command::new("cargo")
        .arg("build")
        .arg("--manifest-path")
        .arg(manifest_path)
        .arg("--target")
        .arg(target)
        .arg("--release")
        .env("RUSTFLAGS", rustflags)
        .status()
        .map_err(|e| format!("Failed to spawn cargo build: {e}"))?;

    if !status.success() {
        return Err(format!("cargo build exited with status {status}"));
    }

    // Locate the built binary. Cargo places it in the fixture crate's target directory
    // or workspace target if part of a workspace.
    let possible_paths = [
        format!("crates/carrick-conformance-nt/fixtures/hello_console/target/{target}/release/hello_console.exe"),
        format!("target/{target}/release/hello_console.exe"),
    ];

    let found_binary = possible_paths
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
        .ok_or_else(|| "Could not locate compiled hello_console.exe in target dirs".to_string())?;

    // Copy to tests/oracle/fixtures/hello_console.exe and crates/carrick-conformance-nt/fixtures/
    let destinations = [
        "tests/oracle/fixtures/hello_console.exe",
        "crates/carrick-conformance-nt/fixtures/hello_console.exe",
    ];

    for dest_str in &destinations {
        let dest = Path::new(dest_str);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        fs::copy(&found_binary, dest).map_err(|e| e.to_string())?;
    }

    let binary_bytes = fs::read(&found_binary).map_err(|e| e.to_string())?;
    let hash = compute_sha256(&binary_bytes);
    println!("Compiled binary SHA-256: {hash}");
    println!("Staged binary to: {}", destinations[0]);

    Ok(PathBuf::from(destinations[0]))
}

pub fn verify_pe_artifact(binary: Option<&Path>) -> Result<(), String> {
    let candidate = match binary {
        Some(p) => p.to_path_buf(),
        None => {
            let default_path = PathBuf::from("tests/oracle/fixtures/hello_console.exe");
            if !default_path.exists() {
                // Try to build if missing
                build_fixtures("x86_64-pc-windows-msvc")?
            } else {
                default_path
            }
        }
    };

    println!("Verifying PE image at '{}'...", candidate.display());
    let bytes =
        fs::read(&candidate).map_err(|e| format!("Failed to read {}: {e}", candidate.display()))?;

    // 1. In-process clean-room PE validator
    let info = verify_hello_console_pe(&bytes)
        .map_err(|e| format!("Clean-room PE validation failed: {e}"))?;

    println!("  Machine: AMD64 (0x{:04x}) - OK", info.machine);
    println!("  Subsystem: Windows CUI ({}) - OK", info.subsystem);
    println!("  Sections count: {} - OK", info.sections.len());
    println!("  Imports: {:?}", info.imports);

    // 2. Cross-check with llvm-readobj if available
    let which_readobj = Command::new("which").arg("llvm-readobj").output();
    if let Ok(out) = which_readobj {
        if out.status.success() {
            println!("Cross-checking with host llvm-readobj...");
            let readobj_out = Command::new("llvm-readobj")
                .arg("--coff-imports")
                .arg(&candidate)
                .output()
                .map_err(|e| format!("Failed to run llvm-readobj: {e}"))?;

            if !readobj_out.status.success() {
                return Err(format!(
                    "llvm-readobj exited with failure: {}",
                    String::from_utf8_lossy(&readobj_out.stderr)
                ));
            }
            let output_str = String::from_utf8_lossy(&readobj_out.stdout);
            if !output_str.contains("KERNEL32.dll") && !output_str.contains("kernel32.dll") {
                return Err("llvm-readobj output did not contain KERNEL32.dll".to_string());
            }
            println!("  llvm-readobj cross-check - OK");
        }
    }

    Ok(())
}
