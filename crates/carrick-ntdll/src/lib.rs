//! Clean-room in-guest NTDLL.dll for Carrick NT.
//!
//! Citations:
//! - docs/design/ntdll-bootstrap.md Section 2.3: "The Carrick NT Hypercall / System Call Contract"
//! - Microsoft Learn: WDK Native APIs (NtWriteFile, NtTerminateProcess, NtClose)
//! - Microsoft Learn: Winternl.h (RtlExitUserProcess)
//! - Clean-Room Rules: No Wine/ReactOS, no leaked Microsoft code.

#![no_std]

use carrick_nt_abi::{GuestVa, IoStatusBlock, NtHandle, NtStatus};
use core::panic::PanicInfo;

/// DLL Entry Point for NTDLL.dll.
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

/// Issues Carrick NT syscall 2 (`NtWriteFile`).
///
/// On x86_64 Microsoft calling convention:
/// - `rcx`: `file_handle` -> moved to `r10` for `syscall`
/// - `rdx`: `event`
/// - `r8`: `apc_routine`
/// - `r9`: `apc_context`
/// - `[rsp + 0x28]`: `io_status_block`
/// - `[rsp + 0x30]`: `buffer`
/// - `[rsp + 0x38]`: `length`
/// - `[rsp + 0x40]`: `byte_offset`
/// - `[rsp + 0x48]`: `key`
/// - `eax`: holds Carrick `NtServiceId::NtWriteFile` (2)
///
/// # Safety
/// Caller must ensure guest memory pointers and buffer ranges are valid.
#[no_mangle]
#[unsafe(naked)]
pub unsafe extern "system" fn NtWriteFile(
    _file_handle: NtHandle,
    _event: NtHandle,
    _apc_routine: GuestVa,
    _apc_context: GuestVa,
    _io_status_block: *mut IoStatusBlock,
    _buffer: *const u8,
    _length: u32,
    _byte_offset: GuestVa,
    _key: *const u32,
) -> NtStatus {
    core::arch::naked_asm!(
        "mov r10, rcx",
        "mov eax, 2", // NtServiceId::NtWriteFile
        "syscall",
        "ret",
    );
}

/// Issues Carrick NT syscall 1 (`NtTerminateProcess`).
///
/// On x86_64 Microsoft calling convention:
/// - `rcx`: `process_handle` -> moved to `r10` for `syscall`
/// - `rdx`: `exit_status`
/// - `eax`: holds Carrick `NtServiceId::NtTerminateProcess` (1)
///
/// # Safety
/// Terminates execution of the target process.
#[no_mangle]
#[unsafe(naked)]
pub unsafe extern "system" fn NtTerminateProcess(
    _process_handle: NtHandle,
    _exit_status: NtStatus,
) -> NtStatus {
    core::arch::naked_asm!(
        "mov r10, rcx",
        "mov eax, 1", // NtServiceId::NtTerminateProcess
        "syscall",
        "ret",
    );
}

/// Issues Carrick NT syscall 3 (`NtClose`).
///
/// On x86_64 Microsoft calling convention:
/// - `rcx`: `handle` -> moved to `r10` for `syscall`
/// - `eax`: holds Carrick `NtServiceId::NtClose` (3)
///
/// # Safety
/// Closes the specified handle.
#[no_mangle]
#[unsafe(naked)]
pub unsafe extern "system" fn NtClose(_handle: NtHandle) -> NtStatus {
    core::arch::naked_asm!(
        "mov r10, rcx",
        "mov eax, 3", // NtServiceId::NtClose
        "syscall",
        "ret",
    );
}

/// Clean-room NT runtime process exit helper.
///
/// Invokes `NtTerminateProcess` on the current process and halts.
///
/// # Safety
/// Terminates the calling process and does not return.
#[no_mangle]
pub unsafe extern "system" fn RtlExitUserProcess(exit_status: u32) -> ! {
    let _ = NtTerminateProcess(NtHandle::CURRENT_PROCESS, NtStatus::from_raw(exit_status));
    loop {
        core::arch::asm!("pause", options(nomem, nostack));
    }
}

/// Carrick-specific process start entry point.
///
/// Entered by Carrick's NT personality kernel with the mapped PE image's
/// `AddressOfEntryPoint` and process parameter context. Calls the entry point
/// and forwards the return value to `RtlExitUserProcess`.
///
/// # Safety
/// Caller must ensure `entry_point` points to executable code or is None.
#[no_mangle]
pub unsafe extern "system" fn carrick_process_start(
    entry_point: Option<unsafe extern "system" fn() -> u32>,
    _context: usize,
) -> ! {
    let exit_code = if let Some(entry) = entry_point {
        entry()
    } else {
        0
    };
    RtlExitUserProcess(exit_code);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe {
        RtlExitUserProcess(1);
    }
}
