//! Clean-room NT ABI wire types, status codes, and Carrick system call service IDs.
//!
//! Citations:
//! - docs/design/ntdll-bootstrap.md Section 2.3 & 6.4 (Milestone M2, Work Package NT-008)
//! - Microsoft Learn: NTSTATUS values, WDK headers
//! - Microsoft PE and COFF Specification (Rev 11.0)
//! - AGENTS.md clean-room rules: 100% clean-room, no Wine/ReactOS, no leaked Microsoft code.

#![no_std]

pub mod handle;
pub mod pointer;
pub mod service;
pub mod status;
pub mod wire;

// Re-export primary types for ease of use
pub use handle::NtHandle;
pub use pointer::{ByteCount, GuestPtr, GuestVa, UserLength};
pub use service::NtServiceId;
pub use status::NtStatus;
pub use wire::{ClientId, IoStatusBlock, ObjectAttributes, UnicodeString};

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn test_ntstatus_semantics() {
        assert!(NtStatus::STATUS_SUCCESS.is_success());
        assert!(!NtStatus::STATUS_SUCCESS.is_error());
        assert_eq!(NtStatus::STATUS_SUCCESS.as_u32(), 0);

        assert!(!NtStatus::STATUS_INVALID_HANDLE.is_success());
        assert!(NtStatus::STATUS_INVALID_HANDLE.is_error());
        assert_eq!(NtStatus::STATUS_INVALID_HANDLE.as_u32(), 0xC000_0008);

        assert!(!NtStatus::STATUS_END_OF_FILE.is_success());
        assert!(NtStatus::STATUS_END_OF_FILE.is_error());
        assert_eq!(NtStatus::STATUS_END_OF_FILE.as_u32(), 0xC000_0011);
    }

    #[test]
    fn test_nthandle_semantics() {
        assert!(NtHandle::NULL.is_null());
        assert!(NtHandle::NULL.is_invalid());
        assert!(NtHandle::INVALID.is_invalid());
        assert!(NtHandle::CURRENT_PROCESS.is_pseudo());
        assert!(NtHandle::CURRENT_THREAD.is_pseudo());
        assert!(NtHandle::STD_OUTPUT.is_pseudo());
        assert_eq!(NtHandle::CURRENT_PROCESS.as_u64(), 0xFFFF_FFFF_FFFF_FFFF);
        assert_eq!(NtHandle::STD_OUTPUT.as_u64(), 0xFFFF_FFFF_FFFF_FFF5);
    }

    #[test]
    fn test_nt_service_id_conversions() {
        assert_eq!(
            NtServiceId::from_u32(1),
            Some(NtServiceId::NtTerminateProcess)
        );
        assert_eq!(NtServiceId::from_u32(2), Some(NtServiceId::NtWriteFile));
        assert_eq!(NtServiceId::from_u32(3), Some(NtServiceId::NtClose));
        assert_eq!(NtServiceId::from_u32(0), None);
        assert_eq!(NtServiceId::from_u32(4), None);
    }

    #[test]
    fn test_wire_struct_layouts() {
        // Assert exact sizes and alignments matching x86_64 Windows NT standards
        assert_eq!(size_of::<IoStatusBlock>(), 16);
        assert_eq!(align_of::<IoStatusBlock>(), 8);
        assert_eq!(offset_of!(IoStatusBlock, status), 0);
        assert_eq!(offset_of!(IoStatusBlock, information), 8);

        assert_eq!(size_of::<UnicodeString>(), 16);
        assert_eq!(align_of::<UnicodeString>(), 8);
        assert_eq!(offset_of!(UnicodeString, length), 0);
        assert_eq!(offset_of!(UnicodeString, maximum_length), 2);
        assert_eq!(offset_of!(UnicodeString, buffer), 8);

        assert_eq!(size_of::<ObjectAttributes>(), 48);
        assert_eq!(align_of::<ObjectAttributes>(), 8);
        assert_eq!(offset_of!(ObjectAttributes, length), 0);
        assert_eq!(offset_of!(ObjectAttributes, root_directory), 8);
        assert_eq!(offset_of!(ObjectAttributes, object_name), 16);
        assert_eq!(offset_of!(ObjectAttributes, attributes), 24);
        assert_eq!(offset_of!(ObjectAttributes, security_descriptor), 32);
        assert_eq!(
            offset_of!(ObjectAttributes, security_quality_of_service),
            40
        );

        assert_eq!(size_of::<ClientId>(), 16);
        assert_eq!(align_of::<ClientId>(), 8);
        assert_eq!(offset_of!(ClientId, unique_process), 0);
        assert_eq!(offset_of!(ClientId, unique_thread), 8);
    }
}
