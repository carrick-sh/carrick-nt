//! Clean-room x86_64 Windows console fixture echoing CommandLine and environment variable.
//!
//! Conforms strictly to AGENTS.md clean-room rules:
//! - Freestanding Rust (`#![no_std]`, `#![no_main]`).
//! - No proprietary Microsoft SDK or MSVC runtime dependencies.
//! - Depends solely on `windows-sys` (MIT-licensed metadata).
//! - Resolves standard output via `GetStdHandle(STD_OUTPUT_HANDLE)`.
//! - Queries command line via `GetCommandLineW()`.
//! - Queries environment variable "CARRICK_TEST" via `GetEnvironmentVariableW()`.
//! - Emits CommandLine and variable value to stdout via `WriteFile`.
//! - Terminates with status 0 via `ExitProcess(0)`.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::WriteFile;
use windows_sys::Win32::System::Console::{GetStdHandle, STD_OUTPUT_HANDLE};
use windows_sys::Win32::System::Environment::{GetCommandLineW, GetEnvironmentVariableW};
use windows_sys::Win32::System::Threading::ExitProcess;

unsafe fn write_raw_bytes(stdout: HANDLE, bytes: &[u8]) {
    let mut written = 0u32;
    WriteFile(
        stdout,
        bytes.as_ptr(),
        bytes.len() as u32,
        &mut written,
        core::ptr::null_mut(),
    );
}

unsafe fn write_utf16_as_ascii(stdout: HANDLE, mut ptr: *const u16) {
    if ptr.is_null() {
        return;
    }
    while *ptr != 0 {
        let code = *ptr;
        let b = if code < 0x80 { code as u8 } else { b'?' };
        write_raw_bytes(stdout, &[b]);
        ptr = ptr.add(1);
    }
}

#[no_mangle]
pub extern "C" fn mainCRTStartup() -> ! {
    unsafe {
        let stdout = GetStdHandle(STD_OUTPUT_HANDLE);

        // Echo CommandLine
        write_raw_bytes(stdout, b"CommandLine: ");
        let cmd = GetCommandLineW();
        write_utf16_as_ascii(stdout, cmd);
        write_raw_bytes(stdout, b"\r\n");

        // Echo CARRICK_TEST environment variable
        write_raw_bytes(stdout, b"CARRICK_TEST: ");
        let var_name: [u16; 13] = [
            'C' as u16, 'A' as u16, 'R' as u16, 'R' as u16, 'I' as u16, 'C' as u16,
            'K' as u16, '_' as u16, 'T' as u16, 'E' as u16, 'S' as u16, 'T' as u16, 0,
        ];
        let mut val_buf = [0u16; 256];
        let len = GetEnvironmentVariableW(var_name.as_ptr(), val_buf.as_mut_ptr(), 256);
        if len > 0 {
            write_utf16_as_ascii(stdout, val_buf.as_ptr());
        } else {
            write_raw_bytes(stdout, b"<not set>");
        }
        write_raw_bytes(stdout, b"\r\n");

        ExitProcess(0);
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe { ExitProcess(1) }
}
