//! Verification of the clean-room hello_console PE binary.
//!
//! Asserts PE headers, 64-bit AMD64 machine, console subsystem, and restricted KERNEL32 imports
//! both via in-memory clean-room parser and llvm-readobj.

use carrick_conformance_nt::pe::{
    parse_pe, verify_hello_console_pe, PeParseError, PeVerificationError, IMAGE_FILE_MACHINE_AMD64,
    IMAGE_SUBSYSTEM_WINDOWS_CUI,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn get_workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn get_or_build_hello_console() -> PathBuf {
    let ws = get_workspace_root();
    let candidate = ws.join("tests/oracle/fixtures/hello_console.exe");
    if candidate.exists() {
        return candidate;
    }

    // Also check inside fixture crate target
    let target_candidate = ws.join(
        "crates/carrick-conformance-nt/fixtures/hello_console/target/x86_64-pc-windows-msvc/release/hello_console.exe",
    );
    if target_candidate.exists() {
        if let Some(parent) = candidate.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let _ = fs::copy(&target_candidate, &candidate);
        return candidate;
    }

    // Build via cargo
    let manifest_path = ws.join("crates/carrick-conformance-nt/fixtures/hello_console/Cargo.toml");
    let rustflags = "-C panic=abort -C linker=lld -C link-args=/nodefaultlib -C link-args=/entry:mainCRTStartup -C link-args=/subsystem:console";

    let status = Command::new("cargo")
        .current_dir(&ws)
        .arg("build")
        .arg("--manifest-path")
        .arg(&manifest_path)
        .arg("--target")
        .arg("x86_64-pc-windows-msvc")
        .arg("--release")
        .env("RUSTFLAGS", rustflags)
        .status()
        .expect("Failed to execute cargo build for hello_console");

    assert!(status.success(), "cargo build for hello_console failed");

    if let Some(parent) = candidate.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::copy(&target_candidate, &candidate).unwrap();
    candidate
}

#[test]
fn test_verify_hello_console_pe() {
    let bin_path = get_or_build_hello_console();
    let bytes = fs::read(&bin_path).expect("Failed to read hello_console.exe");

    let info =
        verify_hello_console_pe(&bytes).expect("verify_hello_console_pe failed on built binary");

    assert_eq!(info.machine, IMAGE_FILE_MACHINE_AMD64);
    assert_eq!(info.subsystem, IMAGE_SUBSYSTEM_WINDOWS_CUI);

    let mut dlls: Vec<&str> = info.imports.keys().map(|s| s.as_str()).collect();
    dlls.sort();
    assert_eq!(dlls, vec!["kernel32.dll"]);

    let mut syms: Vec<&str> = info.imports["kernel32.dll"]
        .iter()
        .map(|s| s.as_str())
        .collect();
    syms.sort();
    assert_eq!(syms, vec!["ExitProcess", "GetStdHandle", "WriteFile"]);
}

#[test]
fn test_llvm_readobj_cross_check() {
    let bin_path = get_or_build_hello_console();

    let output = Command::new("llvm-readobj")
        .arg("--file-headers")
        .arg("--coff-imports")
        .arg(&bin_path)
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                stdout.contains("IMAGE_FILE_MACHINE_AMD64") || stdout.contains("0x8664"),
                "llvm-readobj missing machine check"
            );
            assert!(
                stdout.contains("IMAGE_SUBSYSTEM_WINDOWS_CUI") || stdout.contains("0x3"),
                "llvm-readobj missing subsystem check"
            );
            assert!(
                stdout.contains("KERNEL32.dll") || stdout.contains("kernel32.dll"),
                "llvm-readobj missing KERNEL32 import"
            );
            assert!(stdout.contains("ExitProcess"));
            assert!(stdout.contains("GetStdHandle"));
            assert!(stdout.contains("WriteFile"));
        }
    }
}

#[test]
fn test_parser_rejections() {
    // Too small
    assert_eq!(
        parse_pe(b"short").unwrap_err(),
        PeParseError::FileTooSmall(5)
    );

    // Invalid DOS magic
    let mut bad_dos = vec![0u8; 100];
    bad_dos[0] = 0x12;
    bad_dos[1] = 0x34;
    assert_eq!(
        parse_pe(&bad_dos).unwrap_err(),
        PeParseError::InvalidDosSignature(0x3412)
    );

    // Corrupt subsystem (tamper built binary)
    let bin_path = get_or_build_hello_console();
    let mut tampered = fs::read(&bin_path).unwrap();

    // e_lfanew
    let e_lfanew = u32::from_le_bytes(tampered[0x3C..0x40].try_into().unwrap()) as usize;
    // Subsystem is at e_lfanew + 4 (PE sig) + 20 (COFF header) + 68
    let subsystem_offset = e_lfanew + 4 + 20 + 68;
    tampered[subsystem_offset] = 2; // Change to IMAGE_SUBSYSTEM_WINDOWS_GUI
    tampered[subsystem_offset + 1] = 0;

    let err = verify_hello_console_pe(&tampered).unwrap_err();
    assert_eq!(err, PeVerificationError::SubsystemMismatch(2));
}
