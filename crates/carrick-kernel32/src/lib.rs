//! Clean-room in-guest KERNEL32.dll for Carrick NT.
//!
//! Citations:
//! - docs/design/ntdll-bootstrap.md Section 2.3 & 3.8: Standard Handles & Console Initialization
//! - Microsoft Learn: Win32 Console & Process APIs (GetStdHandle, WriteFile, WriteConsole, ExitProcess)
//! - Microsoft Learn: winternl.h (PEB, RTL_USER_PROCESS_PARAMETERS)
//! - Clean-Room Rules: No Wine/ReactOS, no leaked Microsoft code.

#![no_std]

use carrick_nt_abi::{GuestVa, IoStatusBlock, NtHandle, NtStatus, Peb, RtlUserProcessParameters};
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
    let peb: *const Peb;
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(pure, nomem, nostack));

    if peb.is_null() {
        return NtHandle::INVALID;
    }

    // 2. Read ProcessParameters pointer from PEB
    let proc_params = (*peb).process_parameters.as_u64() as *const RtlUserProcessParameters;
    if proc_params.is_null() {
        return NtHandle::INVALID;
    }

    // 3. Read handle from typed RTL_USER_PROCESS_PARAMETERS struct
    match n_std_handle {
        STD_INPUT_HANDLE => (*proc_params).standard_input,
        STD_OUTPUT_HANDLE => (*proc_params).standard_output,
        STD_ERROR_HANDLE => (*proc_params).standard_error,
        _ => NtHandle::INVALID,
    }
}

/// Retrieves the command-line string for the current process.
///
/// Citations:
/// - Microsoft Learn: GetCommandLineW function
///   https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getcommandlinew
/// - winternl.h / Microsoft Learn: RTL_USER_PROCESS_PARAMETERS.CommandLine
///
/// Returns a pointer to the UTF-16 command-line string buffer in `PEB->ProcessParameters->CommandLine`.
///
/// # Safety
/// Requires valid `GS` base pointer initialized to current thread's TEB.
#[no_mangle]
pub unsafe extern "system" fn GetCommandLineW() -> *const u16 {
    let peb: *const Peb;
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(pure, nomem, nostack));
    if peb.is_null() {
        return core::ptr::null();
    }

    let proc_params = (*peb).process_parameters.as_u64() as *const RtlUserProcessParameters;
    if proc_params.is_null() {
        return core::ptr::null();
    }

    (*proc_params).command_line.buffer.as_u64() as *const u16
}

/// Retrieves the environment variables for the current process.
///
/// Citations:
/// - Microsoft Learn: GetEnvironmentStringsW function
///   https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getenvironmentstringsw
/// - winternl.h / Microsoft Learn: RTL_USER_PROCESS_PARAMETERS.Environment
///
/// Returns a pointer to the double-null-terminated UTF-16 environment block in `PEB->ProcessParameters->Environment`.
///
/// # Safety
/// Requires valid `GS` base pointer initialized to current thread's TEB.
#[no_mangle]
pub unsafe extern "system" fn GetEnvironmentStringsW() -> *const u16 {
    let peb: *const Peb;
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(pure, nomem, nostack));
    if peb.is_null() {
        return core::ptr::null();
    }

    let proc_params = (*peb).process_parameters.as_u64() as *const RtlUserProcessParameters;
    if proc_params.is_null() {
        return core::ptr::null();
    }

    (*proc_params).environment.as_u64() as *const u16
}

/// Frees a block of environment strings allocated by `GetEnvironmentStringsW`.
///
/// Citations:
/// - Microsoft Learn: FreeEnvironmentStringsW function
///   https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-freeenvironmentstringsw
///
/// # Safety
/// `penv` must point to an environment block returned by `GetEnvironmentStringsW`, or may be null.
#[no_mangle]
pub unsafe extern "system" fn FreeEnvironmentStringsW(_penv: *const u16) -> i32 {
    1 // TRUE
}

/// Retrieves the contents of the specified variable from the environment block of the calling process.
///
/// Citations:
/// - Microsoft Learn: GetEnvironmentVariableW function
///   https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getenvironmentvariablew
///
/// Behavior:
/// - Case-insensitive match on variable name.
/// - If `lp_name` is found:
///   - If `n_size` is greater than the value length: copies value + null terminator to `lp_buffer`,
///     and returns the number of characters stored (excluding terminating null).
///   - If `n_size` is not large enough (including `n_size == 0` when probing size):
///     returns required buffer size in characters (including terminating null).
/// - If `lp_name` is not found or null: returns 0.
///
/// # Safety
/// Caller must ensure `lp_name` is a valid null-terminated UTF-16 string and `lp_buffer` is writable
/// for at least `n_size` UTF-16 elements.
#[no_mangle]
pub unsafe extern "system" fn GetEnvironmentVariableW(
    lp_name: *const u16,
    lp_buffer: *mut u16,
    n_size: u32,
) -> u32 {
    if lp_name.is_null() {
        return 0;
    }

    let env_ptr = GetEnvironmentStringsW();
    if env_ptr.is_null() {
        return 0;
    }

    // Determine length of lp_name
    let mut name_len = 0;
    while *lp_name.add(name_len) != 0 {
        name_len += 1;
    }
    if name_len == 0 {
        return 0;
    }
    let name_slice = core::slice::from_raw_parts(lp_name, name_len);

    // Scan double-null terminated environment block
    let mut curr = env_ptr;
    while *curr != 0 {
        let mut entry_len = 0;
        while *curr.add(entry_len) != 0 {
            entry_len += 1;
        }

        let entry = core::slice::from_raw_parts(curr, entry_len);
        if let Some(eq_pos) = entry
            .iter()
            .enumerate()
            .position(|(i, &c)| i > 0 && c == b'=' as u16)
        {
            let var_name = &entry[..eq_pos];
            let var_val = &entry[eq_pos + 1..];

            if carrick_nt_abi::wire::eq_ignore_ascii_case_utf16(var_name, name_slice) {
                let val_len = var_val.len() as u32;
                if n_size > val_len {
                    if !lp_buffer.is_null() {
                        core::ptr::copy_nonoverlapping(var_val.as_ptr(), lp_buffer, var_val.len());
                        *lp_buffer.add(var_val.len()) = 0;
                    }
                    return val_len;
                } else {
                    return val_len + 1;
                }
            }
        }

        curr = curr.add(entry_len + 1);
    }

    0
}

/// Sets the value of an environment variable for the current process.
///
/// Citations:
/// - Microsoft Learn: SetEnvironmentVariableW function
///   https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-setenvironmentvariablew
///
/// # Safety
/// `lp_name` and `lp_value` must be valid null-terminated UTF-16 strings if non-null.
#[no_mangle]
pub unsafe extern "system" fn SetEnvironmentVariableW(
    _lp_name: *const u16,
    _lp_value: *const u16,
) -> i32 {
    1 // TRUE stub
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

/// Freestanding memcpy implementation for /nodefaultlib linking.
///
/// # Safety
/// `dest` and `src` must point to valid memory buffers of at least `n` bytes.
#[no_mangle]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        core::ptr::write_volatile(dest.add(i), core::ptr::read_volatile(src.add(i)));
        i += 1;
    }
    dest
}

/// Freestanding memset implementation for /nodefaultlib linking.
///
/// # Safety
/// `dest` must point to a valid writable buffer of at least `n` bytes.
#[no_mangle]
pub unsafe extern "C" fn memset(dest: *mut u8, c: i32, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        core::ptr::write_volatile(dest.add(i), c as u8);
        i += 1;
    }
    dest
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe {
        ExitProcess(1);
    }
}
