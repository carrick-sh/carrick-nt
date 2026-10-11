//! Clean-room Windows NT x64 system call argument decoder.
//!
//! Citations:
//! - docs/design/ntdll-bootstrap.md Section 2.3: "The Carrick NT Hypercall / System Call Contract"
//! - Microsoft Learn: "x64 Software Conventions" / Calling Convention
//!   https://learn.microsoft.com/en-us/cpp/build/x64-software-conventions
//! - Clean-Room Rules: No Wine/ReactOS, no leaked Microsoft code.

use carrick_core::personality::{CallContext, CallOrdinal, EntryDecodeError, ServiceError};
use carrick_guest_arch::{
    DefaultMmOwner, EntryArch, GuestIsa, MmuArch, NativeAbi, UserVa, X86Register, X86Registers,
};
use carrick_nt_abi::{GuestPtr, GuestVa, NtHandle, NtServiceId, UserLength};

use crate::call::NtCall;

/// Base stack offset for spilled x64 arguments in Windows NT calling convention.
///
/// When an application calls an NTDLL system call stub:
/// 1. The caller allocates 32 bytes of shadow space (`[rsp + 0x00..0x20]`).
/// 2. Spilled arguments (5th and above) begin at `[rsp + 0x20]`.
/// 3. The `call` instruction pushes the 8-byte return address, adjusting `rsp` down by 8.
/// 4. The NTDLL stub (`mov r10, rcx; mov eax, ID; syscall; ret`) does not push to the stack.
///
/// Therefore, at the `syscall` boundary, the 5th argument is located at `[rsp + 0x28]`,
/// the 6th at `[rsp + 0x30]`, the 7th at `[rsp + 0x38]`, and so on.
pub const NT_X64_STACK_ARG_BASE_OFFSET: u64 = 0x28;

/// Reads an argument for an NT x64 system call by index (0-indexed).
///
/// Parameter mapping:
/// - Index 0 (1st argument): passed in `rcx`, moved to `r10` for `syscall`
/// - Index 1 (2nd argument): passed in `rdx`
/// - Index 2 (3rd argument): passed in `r8`
/// - Index 3 (4th argument): passed in `r9`
/// - Index >= 4 (5th+ argument): spilled onto the user stack at `[rsp + 0x28 + (index - 4) * 8]`
pub fn read_nt_argument<A: EntryArch + MmuArch + DefaultMmOwner>(
    cx: &mut CallContext<'_, A>,
    arg_index: usize,
) -> Result<u64, EntryDecodeError>
where
    A::NativeFrame: X86Registers,
    EntryDecodeError: From<A::Error>,
    ServiceError: From<A::Error>,
{
    match arg_index {
        0 => {
            let snapshot = cx.snapshot()?;
            Ok(snapshot.frame.read(X86Register::R10))
        }
        1 => {
            let snapshot = cx.snapshot()?;
            Ok(snapshot.frame.read(X86Register::Rdx))
        }
        2 => {
            let snapshot = cx.snapshot()?;
            Ok(snapshot.frame.read(X86Register::R8))
        }
        3 => {
            let snapshot = cx.snapshot()?;
            Ok(snapshot.frame.read(X86Register::R9))
        }
        idx => {
            let sp = cx.user_stack_pointer()?;
            let stack_slot = (idx - 4) as u64;
            let offset = NT_X64_STACK_ARG_BASE_OFFSET
                .checked_add(
                    stack_slot
                        .checked_mul(8)
                        .ok_or(EntryDecodeError::OutOfBounds)?,
                )
                .ok_or(EntryDecodeError::OutOfBounds)?;
            let addr = sp
                .raw()
                .checked_add(offset)
                .ok_or(EntryDecodeError::Fault)?;
            let mut bytes = [0u8; 8];
            cx.user().copy_in(UserVa::new(addr), &mut bytes)?;
            Ok(u64::from_le_bytes(bytes))
        }
    }
}

/// Decodes an NT system call from the given entry frame `CallContext`.
///
/// Reads architectural snapshot and user stack pointer:
/// - Verifies ISA is x86_64 and ABI is x86_64 syscall.
/// - Reads `rax` (`NtServiceId` system service number).
/// - Reads register arguments `r10`, `rdx`, `r8`, `r9` from the architectural snapshot.
/// - Reads spilled arguments from user stack at `[rsp + 0x28 + 8*i]` via `cx.user().copy_in(...)`.
pub fn decode_nt_call<A: EntryArch + MmuArch + DefaultMmOwner>(
    cx: &mut CallContext<'_, A>,
) -> Result<NtCall, EntryDecodeError>
where
    A::NativeFrame: X86Registers,
    EntryDecodeError: From<A::Error>,
    ServiceError: From<A::Error>,
{
    let snapshot = cx.snapshot()?;
    if snapshot.isa != GuestIsa::X86_64 || snapshot.abi != NativeAbi::X86_64Syscall {
        return Err(EntryDecodeError::UnsupportedAbi);
    }

    let ordinal = CallOrdinal::from_raw(snapshot.frame.read(X86Register::Rax));
    let service = match NtServiceId::from_u32(ordinal.raw() as u32) {
        Some(s) => s,
        None => return Err(EntryDecodeError::UnsupportedAbi),
    };

    let r10 = snapshot.frame.read(X86Register::R10);
    let rdx = snapshot.frame.read(X86Register::Rdx);
    let r8 = snapshot.frame.read(X86Register::R8);
    let r9 = snapshot.frame.read(X86Register::R9);

    match service {
        NtServiceId::NtTerminateProcess => Ok(NtCall::TerminateProcess {
            process_handle: NtHandle::from_raw(r10),
            exit_status: carrick_nt_abi::NtStatus::from_raw(rdx as u32),
        }),
        NtServiceId::NtClose => Ok(NtCall::Close {
            handle: NtHandle::from_raw(r10),
        }),
        NtServiceId::NtWriteFile => {
            let sp = cx.user_stack_pointer()?;
            // Read 5 spilled stack arguments (args 5..9, 0-indexed 4..8) at sp + 0x28 + 8*i
            let mut stack_args = [0u64; 5];
            for (i, slot) in stack_args.iter_mut().enumerate() {
                let offset = NT_X64_STACK_ARG_BASE_OFFSET
                    .checked_add((i as u64).checked_mul(8).ok_or(EntryDecodeError::Fault)?)
                    .ok_or(EntryDecodeError::Fault)?;
                let addr = sp
                    .raw()
                    .checked_add(offset)
                    .ok_or(EntryDecodeError::Fault)?;
                let mut bytes = [0u8; 8];
                cx.user().copy_in(UserVa::new(addr), &mut bytes)?;
                *slot = u64::from_le_bytes(bytes);
            }

            Ok(NtCall::WriteFile {
                file_handle: NtHandle::from_raw(r10),
                event: NtHandle::from_raw(rdx),
                apc_routine: GuestVa::new(r8),
                apc_context: GuestVa::new(r9),
                io_status_block: GuestPtr::from_raw(stack_args[0]),
                buffer: GuestVa::new(stack_args[1]),
                length: UserLength::new(stack_args[2] as u32),
                byte_offset: GuestVa::new(stack_args[3]),
                key: GuestVa::new(stack_args[4]),
            })
        }
    }
}
