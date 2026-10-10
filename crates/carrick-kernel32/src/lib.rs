//! Clean-room in-guest KERNEL32.dll for Carrick NT.
//!
//! Citations:
//! - docs/design/ntdll-bootstrap.md Section 2.3 & 3.8: Standard Handles & Console Initialization
//! - Microsoft Learn: Win32 Console & Process APIs (GetStdHandle, WriteFile, WriteConsole, ExitProcess)
//! - Microsoft Learn: winternl.h (PEB, RTL_USER_PROCESS_PARAMETERS)
//! - Clean-Room Rules: No Wine/ReactOS, no leaked Microsoft code.

#![no_std]

use carrick_nt_abi::{GuestVa, IoStatusBlock, NtHandle, NtStatus};
use core::panic::PanicInfo;

#[link(name = "ntdll")]
extern "system" {
    fn NtWriteFile(
        file_handle: NtHandle,
        event: NtHandle,
        apc_routine: GuestVa,
        apc_context: GuestVa,
        io_status_block: *mut IoStatusBlock,
        buffer: *const u8,
        length: u32,
        byte_offset: GuestVa,
        key: *const u32,
    ) -> NtStatus;

    fn RtlExitUserProcess(exit_status: u32) -> !;
}

/// DLL Entry Point for KERNEL32.dll.
///
/// # Safety
/// Called by the PE loader during DLL initialization or detachment.
#[no_mangle]
pub unsafe extern "system" fn DllMain(
    _hinst_dll: *mut core::ffi::c_void,
    _fdw_reason: u32,
    _lp_reserved: *mut core::ffi::c_void,
) -> i32 {
    1 // TRUE
}

/// Win32 Standard Handle IDs
pub const STD_INPUT_HANDLE: u32 = 0xFFFF_FFF6; // ((DWORD)-10)
pub const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5; // ((DWORD)-11)
pub const STD_ERROR_HANDLE: u32 = 0xFFFF_FFF4; // ((DWORD)-12)

/// Retrieves a handle to the specified standard device (standard input, output, or error).
///
/// Citations:
/// - Microsoft Learn: GetStdHandle function
/// - Microsoft Learn: winternl.h / PEB and RTL_USER_PROCESS_PARAMETERS
///
/// Implementation reads `PEB.ProcessParameters` via `GS:[0x60]` and returns the corresponding handle.
///
/// # Safety
/// Requires valid `GS` base pointer initialized to current thread's TEB.
#[no_mangle]
pub unsafe extern "system" fn GetStdHandle(n_std_handle: u32) -> NtHandle {
    // 1. Read PEB pointer from GS:[0x60] per Microsoft x64 software conventions
    let peb: *const u8;
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(pure, nomem, nostack));

    if peb.is_null() {
        return NtHandle::INVALID;
    }

    // 2. Read ProcessParameters pointer from PEB offset 0x20
    let proc_params_ptr = peb.add(0x20) as *const *const u8;
    let proc_params = *proc_params_ptr;
    if proc_params.is_null() {
        return NtHandle::INVALID;
    }

    // 3. Read handle from RTL_USER_PROCESS_PARAMETERS
    // Offset 0x20: StandardInput
    // Offset 0x28: StandardOutput
    // Offset 0x30: StandardError
    let handle_offset = match n_std_handle {
        STD_INPUT_HANDLE => 0x20,
        STD_OUTPUT_HANDLE => 0x28,
        STD_ERROR_HANDLE => 0x30,
        _ => return NtHandle::INVALID,
    };

    let handle_val = *(proc_params.add(handle_offset) as *const u64);
    NtHandle::from_raw(handle_val)
}

/// Writes data to the specified file or input/output (I/O) device.
///
/// Forwards directly to NTDLL `NtWriteFile`.
///
/// # Safety
/// `lp_buffer` must point to readable memory of at least `n_number_of_bytes_to_write` bytes.
/// `lp_number_of_bytes_written` must be writable if non-null.
#[no_mangle]
pub unsafe extern "system" fn WriteFile(
    h_file: NtHandle,
    lp_buffer: *const u8,
    n_number_of_bytes_to_write: u32,
    lp_number_of_bytes_written: *mut u32,
    _lp_overlapped: *mut core::ffi::c_void,
) -> i32 {
    let mut iosb = IoStatusBlock::default();

    let status = NtWriteFile(
        h_file,
        NtHandle::NULL,
        GuestVa::NULL,
        GuestVa::NULL,
        &mut iosb,
        lp_buffer,
        n_number_of_bytes_to_write,
        GuestVa::NULL,
        core::ptr::null(),
    );

    if !lp_number_of_bytes_written.is_null() {
        *lp_number_of_bytes_written = iosb.information as u32;
    }

    if status.is_success() {
        1 // TRUE
    } else {
        0 // FALSE
    }
}

/// Writes a character string to a console screen buffer beginning at the current cursor location.
///
/// # Safety
/// `lp_buffer` must point to readable bytes.
#[no_mangle]
pub unsafe extern "system" fn WriteConsoleA(
    h_console_output: NtHandle,
    lp_buffer: *const u8,
    n_number_of_chars_to_write: u32,
    lp_number_of_chars_written: *mut u32,
    lp_reserved: *mut core::ffi::c_void,
) -> i32 {
    WriteFile(
        h_console_output,
        lp_buffer,
        n_number_of_chars_to_write,
        lp_number_of_chars_written,
        lp_reserved,
    )
}

/// Writes a wide character string to a console screen buffer.
///
/// # Safety
/// `lp_buffer` must point to readable UTF-16 code units.
#[no_mangle]
pub unsafe extern "system" fn WriteConsoleW(
    h_console_output: NtHandle,
    lp_buffer: *const u16,
    n_number_of_chars_to_write: u32,
    lp_number_of_chars_written: *mut u32,
    lp_reserved: *mut core::ffi::c_void,
) -> i32 {
    let byte_count = n_number_of_chars_to_write.saturating_mul(2);
    let mut bytes_written = 0u32;

    let res = WriteFile(
        h_console_output,
        lp_buffer as *const u8,
        byte_count,
        &mut bytes_written,
        lp_reserved,
    );

    if !lp_number_of_chars_written.is_null() {
        *lp_number_of_chars_written = bytes_written / 2;
    }

    res
}

/// Ends the calling process and all its threads.
///
/// Forwards to NTDLL `RtlExitUserProcess`.
///
/// # Safety
/// Immediately terminates process execution and never returns.
#[no_mangle]
pub unsafe extern "system" fn ExitProcess(u_exit_code: u32) -> ! {
    RtlExitUserProcess(u_exit_code);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe {
        ExitProcess(1);
    }
}
