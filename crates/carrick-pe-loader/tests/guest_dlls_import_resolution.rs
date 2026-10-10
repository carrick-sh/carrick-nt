//! Integration test verifying clean-room in-guest ntdll.dll and kernel32.dll with carrick-pe-loader.
//!
//! Citations:
//! - AGENTS.md clean-room rules (no Wine, no ReactOS, no leaked Microsoft code).
//! - docs/design/ntdll-bootstrap.md Section 2.3, 3.5, 6.4 (Milestone M2, issues NT-008 and NT-009).
//! - Microsoft PE and COFF Specification (Rev 11.0) Sections 6.3 (.edata) and 6.4 (.idata).

use carrick_pe_loader::exports::{parse_export_directory, ExportTarget, PeExportProvider};
use carrick_pe_loader::headers::{
    PeHeaders, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_FILE_DLL, IMAGE_FILE_MACHINE_AMD64,
};
use carrick_pe_loader::imports::{parse_and_resolve_imports, ImportSymbol};
use carrick_pe_loader::mapper::PeLoader;
use carrick_pe_loader::plan::VirtualAddress;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

static BUILD_LOCK: Mutex<()> = Mutex::new(());

fn get_workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

struct GuestDlls {
    ntdll_path: PathBuf,
    kernel32_path: PathBuf,
    hello_console_path: PathBuf,
}

fn get_or_build_artifacts() -> GuestDlls {
    let _guard = BUILD_LOCK.lock().unwrap();
    let ws = get_workspace_root();

    let ntdll_dest = ws.join("tests/oracle/fixtures/ntdll.dll");
    let kernel32_dest = ws.join("tests/oracle/fixtures/kernel32.dll");
    let hello_dest = ws.join("tests/oracle/fixtures/hello_console.exe");

    let target = "x86_64-pc-windows-msvc";

    // 1. Build or locate ntdll.dll
    if !ntdll_dest.exists() {
        let manifest = ws.join("crates/carrick-ntdll/Cargo.toml");
        let rustflags = "-C panic=abort -C linker=lld -C link-args=/nodefaultlib -C link-args=/entry:DllMain -C link-args=/dll -C link-args=/subsystem:console";
        let status = Command::new("cargo")
            .current_dir(&ws)
            .arg("build")
            .arg("--manifest-path")
            .arg(&manifest)
            .arg("--target")
            .arg(target)
            .arg("--release")
            .env("RUSTFLAGS", rustflags)
            .status()
            .expect("Failed to build ntdll.dll");
        assert!(status.success(), "ntdll cargo build failed");

        let built_ntdll = ws.join(format!(
            "crates/carrick-ntdll/target/{target}/release/ntdll.dll"
        ));
        if let Some(parent) = ntdll_dest.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::copy(&built_ntdll, &ntdll_dest).unwrap();
    }

    // 2. Generate ntdll.lib for linking kernel32.dll
    let def_path = ws.join("crates/carrick-ntdll/ntdll.def");
    let lib_path = ws.join("crates/carrick-ntdll/ntdll.lib");
    if !lib_path.exists() {
        let dlltool_status = Command::new("llvm-dlltool")
            .arg("-m")
            .arg("i386:x86-64")
            .arg("-d")
            .arg(&def_path)
            .arg("-l")
            .arg(&lib_path)
            .status()
            .expect("Failed to run llvm-dlltool");
        assert!(dlltool_status.success(), "llvm-dlltool failed");
    }

    // 3. Build or locate kernel32.dll
    if !kernel32_dest.exists() {
        let manifest = ws.join("crates/carrick-kernel32/Cargo.toml");
        let ntdll_dir = ws.join("crates/carrick-ntdll");
        let rustflags = format!(
            "-C panic=abort -C linker=lld -C link-args=/nodefaultlib -C link-args=/entry:DllMain -C link-args=/dll -C link-args=/subsystem:console -C link-arg=/LIBPATH:{} -C link-arg=ntdll.lib",
            ntdll_dir.display()
        );
        let status = Command::new("cargo")
            .current_dir(&ws)
            .arg("build")
            .arg("--manifest-path")
            .arg(&manifest)
            .arg("--target")
            .arg(target)
            .arg("--release")
            .env("RUSTFLAGS", &rustflags)
            .status()
            .expect("Failed to build kernel32.dll");
        assert!(status.success(), "kernel32 cargo build failed");

        let built_kernel32 = ws.join(format!(
            "crates/carrick-kernel32/target/{target}/release/kernel32.dll"
        ));
        fs::copy(&built_kernel32, &kernel32_dest).unwrap();
    }

    // 4. Build or locate hello_console.exe
    if !hello_dest.exists() {
        let manifest = ws.join("crates/carrick-conformance-nt/fixtures/hello_console/Cargo.toml");
        let rustflags = "-C panic=abort -C linker=lld -C link-args=/nodefaultlib -C link-args=/entry:mainCRTStartup -C link-args=/subsystem:console";
        let status = Command::new("cargo")
            .current_dir(&ws)
            .arg("build")
            .arg("--manifest-path")
            .arg(&manifest)
            .arg("--target")
            .arg(target)
            .arg("--release")
            .env("RUSTFLAGS", rustflags)
            .status()
            .expect("Failed to build hello_console.exe");
        assert!(status.success(), "hello_console cargo build failed");

        let built_hello = ws.join(format!(
            "crates/carrick-conformance-nt/fixtures/hello_console/target/{target}/release/hello_console.exe"
        ));
        fs::copy(&built_hello, &hello_dest).unwrap();
    }

    GuestDlls {
        ntdll_path: ntdll_dest,
        kernel32_path: kernel32_dest,
        hello_console_path: hello_dest,
    }
}

#[test]
fn test_guest_dlls_architecture_and_exports() {
    let dlls = get_or_build_artifacts();

    // 1. Verify ntdll.dll
    let ntdll_bytes = fs::read(&dlls.ntdll_path).expect("failed to read ntdll.dll");
    let ntdll_headers = PeHeaders::parse(&ntdll_bytes).expect("failed to parse ntdll.dll headers");

    assert_eq!(ntdll_headers.coff.machine, IMAGE_FILE_MACHINE_AMD64);
    assert!(
        ntdll_headers.coff.characteristics & IMAGE_FILE_DLL != 0,
        "ntdll.dll must declare IMAGE_FILE_DLL"
    );

    // Verify ntdll has no imports (direct syscall boundary)
    let ntdll_import_dir = ntdll_headers.data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT);
    assert!(
        ntdll_import_dir.is_none() || !ntdll_import_dir.unwrap().is_present(),
        "ntdll.dll must have zero imports"
    );

    // Verify ntdll exports
    let ntdll_exports = parse_export_directory(&ntdll_headers, &ntdll_bytes)
        .expect("failed to parse ntdll exports")
        .expect("ntdll.dll missing export directory");

    assert_eq!(ntdll_exports.dll_name.to_ascii_lowercase(), "ntdll.dll");
    let required_ntdll_exports = [
        "NtWriteFile",
        "NtTerminateProcess",
        "NtClose",
        "RtlExitUserProcess",
        "carrick_process_start",
        "DllMain",
    ];
    for name in &required_ntdll_exports {
        assert!(
            ntdll_exports.find_by_name(name).is_some(),
            "ntdll.dll missing required export: {name}"
        );
    }

    // 2. Verify kernel32.dll
    let kernel32_bytes = fs::read(&dlls.kernel32_path).expect("failed to read kernel32.dll");
    let kernel32_headers =
        PeHeaders::parse(&kernel32_bytes).expect("failed to parse kernel32.dll headers");

    assert_eq!(kernel32_headers.coff.machine, IMAGE_FILE_MACHINE_AMD64);
    assert!(
        kernel32_headers.coff.characteristics & IMAGE_FILE_DLL != 0,
        "kernel32.dll must declare IMAGE_FILE_DLL"
    );

    // Verify kernel32 exports: documented public APIs that hello actually imports (plus WriteConsole/DllMain)
    let kernel32_exports = parse_export_directory(&kernel32_headers, &kernel32_bytes)
        .expect("failed to parse kernel32 exports")
        .expect("kernel32.dll missing export directory");

    assert_eq!(
        kernel32_exports.dll_name.to_ascii_lowercase(),
        "kernel32.dll"
    );
    let required_kernel32_exports = [
        "GetStdHandle",
        "WriteFile",
        "WriteConsoleA",
        "WriteConsoleW",
        "ExitProcess",
        "DllMain",
    ];
    for name in &required_kernel32_exports {
        assert!(
            kernel32_exports.find_by_name(name).is_some(),
            "kernel32.dll missing required export: {name}"
        );
    }

    // 3. Verify kernel32 import graph: must contain ONLY ntdll.dll
    let mut provider = PeExportProvider::new();
    let ntdll_base = VirtualAddress::new(0x0000_7FFF_1000_0000);
    provider.register_module("ntdll.dll", ntdll_base, ntdll_exports);

    let kernel32_base = VirtualAddress::new(0x0000_7FFF_2000_0000);
    let kernel32_bindings =
        parse_and_resolve_imports(&kernel32_headers, &kernel32_bytes, kernel32_base, &provider)
            .expect("failed to resolve kernel32.dll imports against ntdll.dll");

    assert!(
        !kernel32_bindings.is_empty(),
        "kernel32.dll must import from ntdll.dll"
    );
    for binding in &kernel32_bindings {
        assert_eq!(
            binding.dll_name.to_ascii_lowercase(),
            "ntdll.dll",
            "kernel32.dll must only import from ntdll.dll"
        );
        match &binding.symbol {
            ImportSymbol::Named(name) => {
                assert!(
                    name == "NtWriteFile" || name == "RtlExitUserProcess",
                    "unexpected import in kernel32.dll: {name}"
                );
            }
            ImportSymbol::Ordinal(ord) => panic!("unexpected ordinal import: #{ord}"),
        }
        assert!(binding.resolved_va > ntdll_base);
    }
}

#[test]
fn test_resolve_hello_console_against_guest_dlls() {
    let dlls = get_or_build_artifacts();

    let ntdll_bytes = fs::read(&dlls.ntdll_path).unwrap();
    let ntdll_headers = PeHeaders::parse(&ntdll_bytes).unwrap();
    let ntdll_exports = parse_export_directory(&ntdll_headers, &ntdll_bytes)
        .unwrap()
        .unwrap();

    let kernel32_bytes = fs::read(&dlls.kernel32_path).unwrap();
    let kernel32_headers = PeHeaders::parse(&kernel32_bytes).unwrap();
    let kernel32_exports = parse_export_directory(&kernel32_headers, &kernel32_bytes)
        .unwrap()
        .unwrap();

    // Set up PeExportProvider with in-guest DLLs
    let mut provider = PeExportProvider::new();
    let ntdll_base = VirtualAddress::new(0x0000_7FFF_1000_0000);
    let kernel32_base = VirtualAddress::new(0x0000_7FFF_2000_0000);

    provider.register_module("ntdll.dll", ntdll_base, ntdll_exports.clone());
    provider.register_module("kernel32.dll", kernel32_base, kernel32_exports.clone());

    // Load hello_console.exe and resolve its imports through the ExportProvider
    let hello_bytes = fs::read(&dlls.hello_console_path).unwrap();
    let loader = PeLoader::new(provider);
    let plan = loader
        .load(&hello_bytes)
        .expect("failed to load and resolve hello_console.exe");

    // Assert that every import in hello_console.exe resolved
    assert_eq!(plan.import_bindings.len(), 3);
    for binding in &plan.import_bindings {
        assert_eq!(binding.dll_name.to_ascii_lowercase(), "kernel32.dll");
        match &binding.symbol {
            ImportSymbol::Named(name) => {
                let entry = kernel32_exports
                    .find_by_name(name)
                    .unwrap_or_else(|| panic!("Symbol {name} not found in kernel32 exports"));
                match entry.target {
                    ExportTarget::Rva(rva) => {
                        let expected_va = kernel32_base.checked_add(rva as u64).unwrap();
                        assert_eq!(binding.resolved_va, expected_va);
                    }
                    ExportTarget::Forwarder(_) => {
                        panic!("Expected RVA target for {name}");
                    }
                }
            }
            ImportSymbol::Ordinal(ord) => panic!("Unexpected ordinal import: #{ord}"),
        }
    }

    // Apply the mapping plan to simulated guest memory and verify IAT content
    let mut guest_mem = vec![0u8; plan.total_virtual_size as usize];
    plan.apply_to_buffer(&hello_bytes, &mut guest_mem)
        .expect("apply_to_buffer failed for hello_console");

    for binding in &plan.import_bindings {
        let off = binding.iat_rva as usize;
        let written_va = u64::from_le_bytes(guest_mem[off..off + 8].try_into().unwrap());
        assert_eq!(written_va, binding.resolved_va.as_u64());
    }
}
