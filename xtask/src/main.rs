//! Automation task runner for carrick-nt: fixture builds, guest DLLs, and PE validation.

use carrick_conformance_nt::pe::verify_hello_console_pe;
use carrick_conformance_nt::receipt::compute_sha256;
use carrick_pe_loader::exports::{parse_export_directory, PeExportProvider};
use carrick_pe_loader::headers::{
    PeHeaders, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_FILE_DLL, IMAGE_FILE_MACHINE_AMD64,
};
use carrick_pe_loader::imports::parse_and_resolve_imports;
use carrick_pe_loader::mapper::PeLoader;
use carrick_pe_loader::plan::VirtualAddress;
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
    /// Compiles clean-room guest DLLs (ntdll.dll, kernel32.dll) without Microsoft SDKs
    BuildGuestDlls {
        #[arg(long, default_value = "x86_64-pc-windows-msvc")]
        target: String,
    },
    /// Verifies in-guest DLLs and resolves hello_console.exe imports against them
    VerifyGuestDlls {
        #[arg(long, default_value = "x86_64-pc-windows-msvc")]
        target: String,
    },
    /// Builds all fixtures and guest DLLs and executes PE verification
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
        Commands::BuildGuestDlls { target } => match build_guest_dlls(&target) {
            Ok((ntdll, kernel32)) => {
                println!("Guest DLLs built successfully:");
                println!("  ntdll.dll:    {}", ntdll.display());
                println!("  kernel32.dll: {}", kernel32.display());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("Error building guest DLLs: {e}");
                ExitCode::FAILURE
            }
        },
        Commands::VerifyGuestDlls { target } => match verify_guest_dlls(&target) {
            Ok(()) => {
                println!("Guest DLLs verification and import resolution passed!");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("Guest DLLs verification failed: {e}");
                ExitCode::FAILURE
            }
        },
        Commands::All { target } => {
            println!("=== Step 1: Building clean-room fixtures ===");
            let fixture_path = match build_fixtures(&target) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Error building fixtures: {e}");
                    return ExitCode::FAILURE;
                }
            };

            println!("\n=== Step 2: Verifying PE fixture ===");
            if let Err(e) = verify_pe_artifact(Some(&fixture_path)) {
                eprintln!("PE verification failed: {e}");
                return ExitCode::FAILURE;
            }

            println!("\n=== Step 3: Building guest DLLs ===");
            if let Err(e) = build_guest_dlls(&target) {
                eprintln!("Error building guest DLLs: {e}");
                return ExitCode::FAILURE;
            }

            println!("\n=== Step 4: Verifying guest DLLs and resolving imports ===");
            if let Err(e) = verify_guest_dlls(&target) {
                eprintln!("Guest DLLs verification failed: {e}");
                return ExitCode::FAILURE;
            }

            println!("\nAll tasks passed (build + PE verify + guest DLLs verify)!");
            ExitCode::SUCCESS
        }
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

    let possible_paths = [
        format!("crates/carrick-conformance-nt/fixtures/hello_console/target/{target}/release/hello_console.exe"),
        format!("target/{target}/release/hello_console.exe"),
    ];

    let found_binary = possible_paths
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
        .ok_or_else(|| "Could not locate compiled hello_console.exe in target dirs".to_string())?;

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

pub fn build_guest_dlls(target: &str) -> Result<(PathBuf, PathBuf), String> {
    println!("Building clean-room guest DLLs for target '{target}'...");

    // 1. Build ntdll.dll
    let ntdll_manifest = "crates/carrick-ntdll/Cargo.toml";
    if !Path::new(ntdll_manifest).exists() {
        return Err(format!("ntdll manifest not found: {ntdll_manifest}"));
    }

    let ntdll_rustflags = "-C panic=abort -C linker=lld -C link-args=/nodefaultlib -C link-args=/entry:DllMain -C link-args=/dll -C link-args=/subsystem:console";

    let status = Command::new("cargo")
        .arg("build")
        .arg("--manifest-path")
        .arg(ntdll_manifest)
        .arg("--target")
        .arg(target)
        .arg("--release")
        .env("RUSTFLAGS", ntdll_rustflags)
        .status()
        .map_err(|e| format!("Failed to spawn cargo build for ntdll: {e}"))?;

    if !status.success() {
        return Err(format!("ntdll cargo build exited with status {status}"));
    }

    let ntdll_binary = PathBuf::from(format!(
        "crates/carrick-ntdll/target/{target}/release/ntdll.dll"
    ));
    if !ntdll_binary.exists() {
        return Err("Could not locate compiled ntdll.dll".into());
    }

    // 2. Generate ntdll.lib from ntdll.def via llvm-dlltool
    let def_path = "crates/carrick-ntdll/ntdll.def";
    let lib_path = "crates/carrick-ntdll/ntdll.lib";
    let dlltool_status = Command::new("llvm-dlltool")
        .arg("-m")
        .arg("i386:x86-64")
        .arg("-d")
        .arg(def_path)
        .arg("-l")
        .arg(lib_path)
        .status()
        .map_err(|e| format!("Failed to spawn llvm-dlltool: {e}"))?;

    if !dlltool_status.success() {
        return Err(format!("llvm-dlltool exited with status {dlltool_status}"));
    }

    // 3. Build kernel32.dll
    let kernel32_manifest = "crates/carrick-kernel32/Cargo.toml";
    let ntdll_dir = fs::canonicalize("crates/carrick-ntdll").map_err(|e| e.to_string())?;
    let kernel32_rustflags = format!(
        "-C panic=abort -C linker=lld -C link-args=/nodefaultlib -C link-args=/entry:DllMain -C link-args=/dll -C link-args=/subsystem:console -C link-arg=/LIBPATH:{} -C link-arg=ntdll.lib",
        ntdll_dir.display()
    );

    let status = Command::new("cargo")
        .arg("build")
        .arg("--manifest-path")
        .arg(kernel32_manifest)
        .arg("--target")
        .arg(target)
        .arg("--release")
        .env("RUSTFLAGS", &kernel32_rustflags)
        .status()
        .map_err(|e| format!("Failed to spawn cargo build for kernel32: {e}"))?;

    if !status.success() {
        return Err(format!("kernel32 cargo build exited with status {status}"));
    }

    let kernel32_binary = PathBuf::from(format!(
        "crates/carrick-kernel32/target/{target}/release/kernel32.dll"
    ));
    if !kernel32_binary.exists() {
        return Err("Could not locate compiled kernel32.dll".into());
    }

    // 4. Stage artifacts
    let staging = [
        (&ntdll_binary, "tests/oracle/fixtures/ntdll.dll"),
        (
            &ntdll_binary,
            "crates/carrick-conformance-nt/fixtures/ntdll.dll",
        ),
        (&kernel32_binary, "tests/oracle/fixtures/kernel32.dll"),
        (
            &kernel32_binary,
            "crates/carrick-conformance-nt/fixtures/kernel32.dll",
        ),
    ];

    for (src, dest_str) in &staging {
        let dest = Path::new(dest_str);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        fs::copy(src, dest).map_err(|e| e.to_string())?;
    }

    let ntdll_bytes = fs::read(&ntdll_binary).map_err(|e| e.to_string())?;
    let kernel32_bytes = fs::read(&kernel32_binary).map_err(|e| e.to_string())?;
    println!("ntdll.dll SHA-256:    {}", compute_sha256(&ntdll_bytes));
    println!("kernel32.dll SHA-256: {}", compute_sha256(&kernel32_bytes));

    Ok((
        PathBuf::from("tests/oracle/fixtures/ntdll.dll"),
        PathBuf::from("tests/oracle/fixtures/kernel32.dll"),
    ))
}

pub fn verify_pe_artifact(binary: Option<&Path>) -> Result<(), String> {
    let candidate = match binary {
        Some(p) => p.to_path_buf(),
        None => {
            let default_path = PathBuf::from("tests/oracle/fixtures/hello_console.exe");
            if !default_path.exists() {
                build_fixtures("x86_64-pc-windows-msvc")?
            } else {
                default_path
            }
        }
    };

    println!("Verifying PE image at '{}'...", candidate.display());
    let bytes =
        fs::read(&candidate).map_err(|e| format!("Failed to read {}: {e}", candidate.display()))?;

    let info = verify_hello_console_pe(&bytes)
        .map_err(|e| format!("Clean-room PE validation failed: {e}"))?;

    println!("  Machine: AMD64 (0x{:04x}) - OK", info.machine);
    println!("  Subsystem: Windows CUI ({}) - OK", info.subsystem);
    println!("  Sections count: {} - OK", info.sections.len());
    println!("  Imports: {:?}", info.imports);

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

pub fn verify_guest_dlls(target: &str) -> Result<(), String> {
    let ntdll_path = PathBuf::from("tests/oracle/fixtures/ntdll.dll");
    let kernel32_path = PathBuf::from("tests/oracle/fixtures/kernel32.dll");
    let hello_path = PathBuf::from("tests/oracle/fixtures/hello_console.exe");

    if !ntdll_path.exists() || !kernel32_path.exists() {
        build_guest_dlls(target)?;
    }
    if !hello_path.exists() {
        build_fixtures(target)?;
    }

    println!("Verifying in-guest DLLs with carrick-pe-loader...");

    // 1. Verify ntdll.dll
    let ntdll_bytes = fs::read(&ntdll_path).map_err(|e| e.to_string())?;
    let ntdll_headers = PeHeaders::parse(&ntdll_bytes).map_err(|e| e.to_string())?;
    if ntdll_headers.coff.machine != IMAGE_FILE_MACHINE_AMD64 {
        return Err("ntdll.dll machine is not AMD64".into());
    }
    if ntdll_headers.coff.characteristics & IMAGE_FILE_DLL == 0 {
        return Err("ntdll.dll does not declare IMAGE_FILE_DLL".into());
    }
    let ntdll_import_dir = ntdll_headers.data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT);
    if let Some(dir) = ntdll_import_dir {
        if dir.is_present() && dir.size > 0 {
            return Err("ntdll.dll must have zero external imports".into());
        }
    }
    let ntdll_exports = parse_export_directory(&ntdll_headers, &ntdll_bytes)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "ntdll.dll has no export directory".to_string())?;
    for req in &[
        "NtWriteFile",
        "NtTerminateProcess",
        "NtClose",
        "RtlExitUserProcess",
        "carrick_process_start",
        "DllMain",
    ] {
        if ntdll_exports.find_by_name(req).is_none() {
            return Err(format!("ntdll.dll missing export {req}"));
        }
    }
    println!(
        "  ntdll.dll: AMD64, DLL, 0 imports, {} exports - OK",
        ntdll_exports.exports.len()
    );

    // 2. Verify kernel32.dll
    let kernel32_bytes = fs::read(&kernel32_path).map_err(|e| e.to_string())?;
    let kernel32_headers = PeHeaders::parse(&kernel32_bytes).map_err(|e| e.to_string())?;
    if kernel32_headers.coff.machine != IMAGE_FILE_MACHINE_AMD64 {
        return Err("kernel32.dll machine is not AMD64".into());
    }
    if kernel32_headers.coff.characteristics & IMAGE_FILE_DLL == 0 {
        return Err("kernel32.dll does not declare IMAGE_FILE_DLL".into());
    }
    let kernel32_exports = parse_export_directory(&kernel32_headers, &kernel32_bytes)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "kernel32.dll has no export directory".to_string())?;
    for req in &[
        "GetStdHandle",
        "WriteFile",
        "WriteConsoleA",
        "WriteConsoleW",
        "ExitProcess",
        "DllMain",
    ] {
        if kernel32_exports.find_by_name(req).is_none() {
            return Err(format!("kernel32.dll missing export {req}"));
        }
    }
    println!(
        "  kernel32.dll: AMD64, DLL, {} exports - OK",
        kernel32_exports.exports.len()
    );

    // 3. Verify kernel32 imports against ntdll
    let mut provider = PeExportProvider::new();
    let ntdll_base = VirtualAddress::new(0x0000_7FFF_1000_0000);
    provider.register_module("ntdll.dll", ntdll_base, ntdll_exports);

    let kernel32_base = VirtualAddress::new(0x0000_7FFF_2000_0000);
    let k32_bindings =
        parse_and_resolve_imports(&kernel32_headers, &kernel32_bytes, kernel32_base, &provider)
            .map_err(|e| format!("Failed to resolve kernel32 imports: {e}"))?;
    for b in &k32_bindings {
        if !b.dll_name.eq_ignore_ascii_case("ntdll.dll") {
            return Err(format!(
                "kernel32.dll imports forbidden DLL: {}",
                b.dll_name
            ));
        }
    }
    println!(
        "  kernel32.dll imports: {} bindings to ntdll.dll only - OK",
        k32_bindings.len()
    );

    // 4. Resolve hello_console.exe imports against these DLLs
    provider.register_module("kernel32.dll", kernel32_base, kernel32_exports);
    let hello_bytes = fs::read(&hello_path).map_err(|e| e.to_string())?;
    let loader = PeLoader::new(provider);
    let plan = loader
        .load(&hello_bytes)
        .map_err(|e| format!("Failed to load hello_console.exe: {e}"))?;

    if plan.import_bindings.len() != 3 {
        return Err(format!(
            "Expected 3 resolved imports in hello_console, found {}",
            plan.import_bindings.len()
        ));
    }
    for b in &plan.import_bindings {
        println!(
            "  Resolved import: {}!{} -> {}",
            b.dll_name, b.symbol, b.resolved_va
        );
    }

    Ok(())
}
