//! Clean-room Windows NT x64 system call argument decoder.
//!
//! Citations:
//! - docs/design/ntdll-bootstrap.md Section 2.3: "The Carrick NT Hypercall / System Call Contract"
//! - Microsoft Learn: "x64 Software Conventions" / Calling Convention
//!   https://learn.microsoft.com/en-us/cpp/build/x64-software-conventions
//! - Clean-Room Rules: No Wine/ReactOS, no leaked Microsoft code.

use carrick_core::personality::{CallContext, DecodedCall, EntryDecodeError, UserStackOffset};
use carrick_guest_arch::EntryArch;
use carrick_nt_abi::NtServiceId;

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
/// - Index 0 (1st argument): passed in `rcx`, moved to `r10` for `syscall` (`cx.register_argument(3)`)
/// - Index 1 (2nd argument): passed in `rdx` (`cx.register_argument(2)`)
/// - Index 2 (3rd argument): passed in `r8` (`cx.register_argument(4)`)
/// - Index 3 (4th argument): passed in `r9` (`cx.register_argument(5)`)
/// - Index >= 4 (5th+ argument): spilled onto the user stack at `[rsp + 0x28 + (index - 4) * 8]`
pub fn read_nt_argument<A: EntryArch>(
    cx: &mut CallContext<'_, A>,
    arg_index: usize,
) -> Result<u64, EntryDecodeError>
where
    EntryDecodeError: From<A::Error>,
{
    match arg_index {
        0 => cx.register_argument(3),
        1 => cx.register_argument(2),
        2 => cx.register_argument(4),
        3 => cx.register_argument(5),
        idx => {
            let stack_slot = (idx - 4) as u64;
            let offset = NT_X64_STACK_ARG_BASE_OFFSET
                .checked_add(
                    stack_slot
                        .checked_mul(8)
                        .ok_or(EntryDecodeError::OutOfBounds)?,
                )
                .ok_or(EntryDecodeError::OutOfBounds)?;
            cx.read_user_stack(UserStackOffset::new(offset))
        }
    }
}

/// Decodes an NT system call from the given entry frame `CallContext`.
///
/// Reads `eax` (`syscall_ordinal`), validates it against `NtServiceId`, and safely unpacks
/// register and stack arguments according to the NT x64 calling convention.
pub fn decode_nt_call<A: EntryArch>(
    cx: &mut CallContext<'_, A>,
) -> Result<DecodedCall, EntryDecodeError>
where
    EntryDecodeError: From<A::Error>,
{
    let ordinal = cx.syscall_ordinal()?;
    let stack = cx.user_stack_pointer()?;

    let service = match NtServiceId::from_u32(ordinal as u32) {
        Some(s) => s,
        None => return Err(EntryDecodeError::UnsupportedAbi),
    };

    let arg_count = match service {
        NtServiceId::NtTerminateProcess => 2,
        NtServiceId::NtClose => 1,
        NtServiceId::NtWriteFile => 9,
    };

    let mut args = [0u64; 16];
    for (i, slot) in args.iter_mut().take(arg_count).enumerate() {
        *slot = read_nt_argument(cx, i)?;
    }

    DecodedCall::with_args(ordinal, stack, &args[..arg_count])
}
