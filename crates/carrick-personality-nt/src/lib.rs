//! Clean-room Windows NT personality for Carrick.
//!
//! Citations:
//! - docs/design/ntdll-bootstrap.md Section 2.3 & 4.2
//! - Microsoft Learn: WDK Native APIs & x64 Software Conventions
//! - AGENTS.md clean-room rules: 100% clean-room, no Wine/ReactOS, no leaked Microsoft code.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

extern crate alloc;

pub mod call;
pub mod decode;
pub mod dispatch;
pub mod handle_table;
pub mod memory;

pub use call::NtCall;
pub use decode::{decode_nt_call, read_nt_argument, NT_X64_STACK_ARG_BASE_OFFSET};
#[cfg(feature = "std")]
pub use dispatch::StdOutputSink;
pub use dispatch::{encode_return, BufferOutputSink, ControlFlow, NtDispatcher, OutputSink};
pub use handle_table::{access_rights, HandleEntry, HandleObject, HandleTable};
pub use memory::{SimulatedUserMemory, UserMemory};

use carrick_core::personality::{CallContext, DecodedCall, EntryDecodeError};
use carrick_core::Personality;
use carrick_guest_arch::{EntryArch, ThreadPointerRegister};

/// Clean-room Windows NT operating system personality for Carrick.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NtPersonality;

impl NtPersonality {
    /// Creates a new `NtPersonality` instance.
    pub const fn new() -> Self {
        Self
    }
}

impl Personality for NtPersonality {
    fn name(&self) -> &'static str {
        "nt"
    }

    fn thread_pointer_register(&self) -> ThreadPointerRegister {
        #[cfg(target_arch = "x86_64")]
        {
            ThreadPointerRegister::GS
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            ThreadPointerRegister::GS
        }
    }

    fn decode<A: EntryArch>(
        &self,
        cx: &mut CallContext<'_, A>,
    ) -> Result<DecodedCall, EntryDecodeError>
    where
        EntryDecodeError: From<A::Error>,
    {
        decode_nt_call(cx)
    }
}
