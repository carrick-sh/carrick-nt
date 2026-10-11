//! CLI tool for scanning PE imports and generating NT import census documentation.

use carrick_conformance_nt::census::{
    build_census_report, generate_markdown_report, scan_binary_file, ProgramCensus,
};
use clap::Parser;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "carrick-import-census",
    about = "Generate NT import census from clean-room binaries and system32 tools"
)]
struct Args {
    /// Directory containing clean-room built PE binaries
    #[arg(long, default_value = "target/census-fixtures")]
    cleanroom_dir: PathBuf,

    /// Directory containing public Windows console tools (for black-box metadata reading only)
    #[arg(long, default_value = "/home/carrick/nt-census-inputs/system32")]
    system32_dir: PathBuf,

    /// Path to output JSON report
    #[arg(long, default_value = "docs/census/import-census.json")]
    output_json: PathBuf,

    /// Path to output Markdown report
    #[arg(long, default_value = "docs/census/import-census.md")]
    output_md: PathBuf,

    /// Re-run command to embed in generated documents
    #[arg(long, default_value = "cargo xtask import-census")]
    rerun_cmd: String,

    /// Number of top system32 imports to include in first targets
    #[arg(long, default_value = "30")]
    top_system32_n: usize,

    /// Go toolchain status
    #[arg(
        long,
        default_value = "Go compiler not installed on host (`which go` returned not found); Go hello omitted."
    )]
    go_status: String,
}

fn main() -> ExitCode {
    let args = Args::parse();

    println!("Starting PE Import Census (NT-014)...");

    let mut scanned_programs: Vec<ProgramCensus> = Vec::new();

    // 1. Scan clean-room built programs
    if args.cleanroom_dir.exists() {
        println!(
            "Scanning clean-room binaries in {}...",
            args.cleanroom_dir.display()
        );
        match scan_directory(&args.cleanroom_dir, "clean_room_built") {
            Ok(progs) => {
                println!("  Found {} clean-room binaries.", progs.len());
                scanned_programs.extend(progs);
            }
            Err(e) => {
                eprintln!("Error scanning cleanroom dir: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        println!(
            "Notice: clean-room binaries directory {} not found (will scan system32 only or existing fixtures)",
            args.cleanroom_dir.display()
        );
    }

    // Also include hello_console if it exists
    let hello_console = Path::new("tests/oracle/fixtures/hello_console.exe");
    if hello_console.exists()
        && !scanned_programs
            .iter()
            .any(|p| p.name == "hello_console.exe")
    {
        if let Ok(prog) = scan_binary_file(hello_console, "clean_room_built") {
            scanned_programs.push(prog);
        }
    }

    // 2. Scan system32 console tools (black-box observation of headers only)
    if args.system32_dir.exists() {
        println!(
            "Scanning System32 console tools in {}...",
            args.system32_dir.display()
        );
        match scan_directory(&args.system32_dir, "system32_console") {
            Ok(progs) => {
                println!("  Found {} System32 tools.", progs.len());
                scanned_programs.extend(progs);
            }
            Err(e) => {
                eprintln!("Error scanning system32 dir: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        eprintln!(
            "System32 directory not found at: {}",
            args.system32_dir.display()
        );
        return ExitCode::FAILURE;
    }

    if scanned_programs.is_empty() {
        eprintln!("No programs were scanned!");
        return ExitCode::FAILURE;
    }

    println!(
        "Aggregating census data for {} binaries...",
        scanned_programs.len()
    );
    let report = build_census_report(
        scanned_programs,
        &args.rerun_cmd,
        &args.go_status,
        args.top_system32_n,
    );

    // Ensure output directories exist
    if let Some(parent) = args.output_json.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            eprintln!("Failed to create output dir {}: {e}", parent.display());
            return ExitCode::FAILURE;
        }
    }
    if let Some(parent) = args.output_md.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            eprintln!("Failed to create output dir {}: {e}", parent.display());
            return ExitCode::FAILURE;
        }
    }

    // Write JSON
    let json_bytes = match serde_json::to_string_pretty(&report) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to serialize report to JSON: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = fs::write(&args.output_json, json_bytes) {
        eprintln!("Failed to write {}: {e}", args.output_json.display());
        return ExitCode::FAILURE;
    }
    println!("Wrote JSON census to: {}", args.output_json.display());

    // Write Markdown
    let md_content = generate_markdown_report(&report);
    if let Err(e) = fs::write(&args.output_md, md_content) {
        eprintln!("Failed to write {}: {e}", args.output_md.display());
        return ExitCode::FAILURE;
    }
    println!("Wrote Markdown census to: {}", args.output_md.display());

    println!("Census generation complete!");
    ExitCode::SUCCESS
}

fn scan_directory(dir: &Path, category: &str) -> Result<Vec<ProgramCensus>, String> {
    let mut entries = Vec::new();
    let read_dir = fs::read_dir(dir).map_err(|e| e.to_string())?;

    for entry_res in read_dir {
        let entry = entry_res.map_err(|e| e.to_string())?;
        let path = entry.path();
        if path.is_file() {
            let ext = path
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if ext == "exe" || ext == "com" {
                match scan_binary_file(&path, category) {
                    Ok(census) => entries.push(census),
                    Err(e) => eprintln!("Warning: failed to scan {}: {e}", path.display()),
                }
            }
        }
    }

    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}
