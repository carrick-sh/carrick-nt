//! Clean-room x86_64 Windows console "hello" test binary.
//!
//! Conforms strictly to AGENTS.md clean-room rules:
//! - Freestanding Rust (`#![no_std]`, `#![no_main]`).
//! - No proprietary Microsoft SDK or MSVC runtime dependencies.
//! - Depends solely on `windows-sys` (MIT-licensed metadata).
//! - Resolves standard output via `GetStdHandle(STD_OUTPUT_HANDLE)`.
//! - Emits "Hello, Carrick NT!\r\n" via `WriteFile`.
//! - Terminates with status 0 via `ExitProcess(0)`.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use windows_sys::Win32::Storage::FileSystem::WriteFile;
use windows_sys::Win32::System::Console::{GetStdHandle, STD_OUTPUT_HANDLE};
use windows_sys::Win32::System::Threading::ExitProcess;

#[no_mangle]
pub extern "C" fn mainCRTStartup() -> ! {
    let stdout = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    let msg = b"Hello, Carrick NT!\r\n";
    let mut written = 0u32;
    unsafe {
        WriteFile(
            stdout,
            msg.as_ptr(),
            msg.len() as u32,
            &mut written,
            core::ptr::null_mut(),
        );
        ExitProcess(0);
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe { ExitProcess(1) }
}
