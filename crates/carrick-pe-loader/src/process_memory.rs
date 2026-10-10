//! Clean-room initialization and memory construction for TEB, PEB, and RTL_USER_PROCESS_PARAMETERS.
//!
//! Citations:
//! - winternl.h / Microsoft Learn: "TEB structure"
//!   https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-teb
//! - winternl.h / Microsoft Learn: "PEB structure"
//!   https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb
//! - winternl.h / Microsoft Learn: "RTL_USER_PROCESS_PARAMETERS structure"
//!   https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-rtl_user_process_parameters
//! - Microsoft Learn: "x64 Software Conventions" (GS segment base register)
//!   https://learn.microsoft.com/en-us/cpp/build/x64-software-conventions

use crate::plan::VirtualAddress;
use alloc::vec;
use alloc::vec::Vec;

// Standard Win32 pseudo handles
pub const STD_INPUT_HANDLE_VAL: u64 = 0xFFFF_FFFF_FFFF_FFF6; // ((DWORD)-10)
pub const STD_OUTPUT_HANDLE_VAL: u64 = 0xFFFF_FFFF_FFFF_FFF5; // ((DWORD)-11)
pub const STD_ERROR_HANDLE_VAL: u64 = 0xFFFF_FFFF_FFFF_FFF4; // ((DWORD)-12)

// TEB Structure Offsets (x86_64, winternl.h / Microsoft Learn)
pub const TEB_OFFSET_SELF: usize = 0x30;
pub const TEB_OFFSET_CLIENT_ID: usize = 0x40;
pub const TEB_OFFSET_CLIENT_ID_PID: usize = 0x40;
pub const TEB_OFFSET_CLIENT_ID_TID: usize = 0x48;
pub const TEB_OFFSET_PEB: usize = 0x60;
pub const TEB_OFFSET_TLS_SLOTS: usize = 0x1480;
pub const TEB_SIZE: usize = 0x1800;

// PEB Structure Offsets (x86_64, winternl.h / Microsoft Learn)
pub const PEB_OFFSET_BEING_DEBUGGED: usize = 0x02;
pub const PEB_OFFSET_IMAGE_BASE: usize = 0x10;
pub const PEB_OFFSET_LOADER_DATA: usize = 0x18;
pub const PEB_OFFSET_PROCESS_PARAMETERS: usize = 0x20;
pub const PEB_SIZE: usize = 0x1000;

// RTL_USER_PROCESS_PARAMETERS Structure Offsets (x86_64, winternl.h / Microsoft Learn)
pub const PROCESS_PARAMS_OFFSET_MAX_LEN: usize = 0x00;
pub const PROCESS_PARAMS_OFFSET_LEN: usize = 0x04;
pub const PROCESS_PARAMS_OFFSET_FLAGS: usize = 0x08;
pub const PROCESS_PARAMS_OFFSET_DEBUG_FLAGS: usize = 0x0C;
pub const PROCESS_PARAMS_OFFSET_CONSOLE_HANDLE: usize = 0x10;
pub const PROCESS_PARAMS_OFFSET_CONSOLE_FLAGS: usize = 0x18;
pub const PROCESS_PARAMS_OFFSET_STD_IN: usize = 0x20;
pub const PROCESS_PARAMS_OFFSET_STD_OUT: usize = 0x28;
pub const PROCESS_PARAMS_OFFSET_STD_ERR: usize = 0x30;
pub const PROCESS_PARAMS_OFFSET_CURRENT_DIR: usize = 0x38;
pub const PROCESS_PARAMS_OFFSET_IMAGE_PATH: usize = 0x60;
pub const PROCESS_PARAMS_OFFSET_COMMAND_LINE: usize = 0x70;
pub const PROCESS_PARAMS_HEADER_SIZE: usize = 0x80;

/// Builder for process and thread memory structures.
#[derive(Debug, Clone)]
pub struct ProcessMemoryConfig<'a> {
    pub teb_va: VirtualAddress,
    pub peb_va: VirtualAddress,
    pub process_parameters_va: VirtualAddress,
    pub image_base: VirtualAddress,
    pub image_path: &'a str,
    pub command_line: &'a str,
    pub stdin_handle: u64,
    pub stdout_handle: u64,
    pub stderr_handle: u64,
    pub process_id: u64,
    pub thread_id: u64,
}

impl<'a> Default for ProcessMemoryConfig<'a> {
    fn default() -> Self {
        Self {
            teb_va: VirtualAddress::new(0x0000_7FFE_0000_0000),
            peb_va: VirtualAddress::new(0x0000_7FFE_0001_0000),
            process_parameters_va: VirtualAddress::new(0x0000_7FFE_0002_0000),
            image_base: VirtualAddress::new(0x0000_0001_4000_0000),
            image_path: "C:\\hello_console.exe",
            command_line: "hello_console.exe",
            stdin_handle: STD_INPUT_HANDLE_VAL,
            stdout_handle: STD_OUTPUT_HANDLE_VAL,
            stderr_handle: STD_ERROR_HANDLE_VAL,
            process_id: 1000,
            thread_id: 1001,
        }
    }
}

/// The constructed memory images for TEB, PEB, and Process Parameters.
#[derive(Debug, Clone)]
pub struct ProcessMemoryImage {
    /// Raw byte buffer for the TEB.
    pub teb_bytes: Vec<u8>,
    /// Raw byte buffer for the PEB.
    pub peb_bytes: Vec<u8>,
    /// Raw byte buffer for RTL_USER_PROCESS_PARAMETERS.
    pub process_parameters_bytes: Vec<u8>,
    /// Virtual address assigned to the TEB.
    pub teb_va: VirtualAddress,
    /// Virtual address assigned to the PEB.
    pub peb_va: VirtualAddress,
    /// Virtual address assigned to RTL_USER_PROCESS_PARAMETERS.
    pub process_parameters_va: VirtualAddress,
}

impl ProcessMemoryImage {
    /// Constructs and initializes process memory structures according to Microsoft Learn specs.
    pub fn build(config: &ProcessMemoryConfig<'_>) -> Self {
        // 1. Build Process Parameters
        let mut params_bytes = vec![0u8; PROCESS_PARAMS_HEADER_SIZE];

        // Encode UTF-16 strings
        let image_path_utf16: Vec<u16> = config.image_path.encode_utf16().chain(Some(0)).collect();
        let cmd_line_utf16: Vec<u16> = config.command_line.encode_utf16().chain(Some(0)).collect();

        let image_path_bytes_len = ((image_path_utf16.len() - 1) * 2) as u16;
        let image_path_max_len = (image_path_utf16.len() * 2) as u16;

        let cmd_line_bytes_len = ((cmd_line_utf16.len() - 1) * 2) as u16;
        let cmd_line_max_len = (cmd_line_utf16.len() * 2) as u16;

        let image_path_offset = params_bytes.len();
        for &u in &image_path_utf16 {
            params_bytes.extend_from_slice(&u.to_le_bytes());
        }

        let cmd_line_offset = params_bytes.len();
        for &u in &cmd_line_utf16 {
            params_bytes.extend_from_slice(&u.to_le_bytes());
        }

        let total_params_len = params_bytes.len() as u32;

        // Write header fields
        params_bytes[PROCESS_PARAMS_OFFSET_MAX_LEN..PROCESS_PARAMS_OFFSET_MAX_LEN + 4]
            .copy_from_slice(&total_params_len.to_le_bytes());
        params_bytes[PROCESS_PARAMS_OFFSET_LEN..PROCESS_PARAMS_OFFSET_LEN + 4]
            .copy_from_slice(&total_params_len.to_le_bytes());
        params_bytes[PROCESS_PARAMS_OFFSET_STD_IN..PROCESS_PARAMS_OFFSET_STD_IN + 8]
            .copy_from_slice(&config.stdin_handle.to_le_bytes());
        params_bytes[PROCESS_PARAMS_OFFSET_STD_OUT..PROCESS_PARAMS_OFFSET_STD_OUT + 8]
            .copy_from_slice(&config.stdout_handle.to_le_bytes());
        params_bytes[PROCESS_PARAMS_OFFSET_STD_ERR..PROCESS_PARAMS_OFFSET_STD_ERR + 8]
            .copy_from_slice(&config.stderr_handle.to_le_bytes());

        // UNICODE_STRING ImagePathName at 0x60
        let image_path_va = config
            .process_parameters_va
            .checked_add(image_path_offset as u64)
            .unwrap();
        params_bytes[PROCESS_PARAMS_OFFSET_IMAGE_PATH..PROCESS_PARAMS_OFFSET_IMAGE_PATH + 2]
            .copy_from_slice(&image_path_bytes_len.to_le_bytes());
        params_bytes[PROCESS_PARAMS_OFFSET_IMAGE_PATH + 2..PROCESS_PARAMS_OFFSET_IMAGE_PATH + 4]
            .copy_from_slice(&image_path_max_len.to_le_bytes());
        params_bytes[PROCESS_PARAMS_OFFSET_IMAGE_PATH + 8..PROCESS_PARAMS_OFFSET_IMAGE_PATH + 16]
            .copy_from_slice(&image_path_va.as_u64().to_le_bytes());

        // UNICODE_STRING CommandLine at 0x70
        let cmd_line_va = config
            .process_parameters_va
            .checked_add(cmd_line_offset as u64)
            .unwrap();
        params_bytes[PROCESS_PARAMS_OFFSET_COMMAND_LINE..PROCESS_PARAMS_OFFSET_COMMAND_LINE + 2]
            .copy_from_slice(&cmd_line_bytes_len.to_le_bytes());
        params_bytes
            [PROCESS_PARAMS_OFFSET_COMMAND_LINE + 2..PROCESS_PARAMS_OFFSET_COMMAND_LINE + 4]
            .copy_from_slice(&cmd_line_max_len.to_le_bytes());
        params_bytes
            [PROCESS_PARAMS_OFFSET_COMMAND_LINE + 8..PROCESS_PARAMS_OFFSET_COMMAND_LINE + 16]
            .copy_from_slice(&cmd_line_va.as_u64().to_le_bytes());

        // 2. Build PEB
        let mut peb_bytes = vec![0u8; PEB_SIZE];
        peb_bytes[PEB_OFFSET_BEING_DEBUGGED] = 0;
        peb_bytes[PEB_OFFSET_IMAGE_BASE..PEB_OFFSET_IMAGE_BASE + 8]
            .copy_from_slice(&config.image_base.as_u64().to_le_bytes());
        peb_bytes[PEB_OFFSET_PROCESS_PARAMETERS..PEB_OFFSET_PROCESS_PARAMETERS + 8]
            .copy_from_slice(&config.process_parameters_va.as_u64().to_le_bytes());

        // 3. Build TEB
        let mut teb_bytes = vec![0u8; TEB_SIZE];
        // Self pointer at 0x30 points to TEB base
        teb_bytes[TEB_OFFSET_SELF..TEB_OFFSET_SELF + 8]
            .copy_from_slice(&config.teb_va.as_u64().to_le_bytes());
        // ClientId at 0x40 (PID, TID)
        teb_bytes[TEB_OFFSET_CLIENT_ID_PID..TEB_OFFSET_CLIENT_ID_PID + 8]
            .copy_from_slice(&config.process_id.to_le_bytes());
        teb_bytes[TEB_OFFSET_CLIENT_ID_TID..TEB_OFFSET_CLIENT_ID_TID + 8]
            .copy_from_slice(&config.thread_id.to_le_bytes());
        // Pointer to PEB at 0x60
        teb_bytes[TEB_OFFSET_PEB..TEB_OFFSET_PEB + 8]
            .copy_from_slice(&config.peb_va.as_u64().to_le_bytes());

        Self {
            teb_bytes,
            peb_bytes,
            process_parameters_bytes: params_bytes,
            teb_va: config.teb_va,
            peb_va: config.peb_va,
            process_parameters_va: config.process_parameters_va,
        }
    }

    /// Validates TEB Self pointer at GS:[0x30].
    pub fn read_teb_self(&self) -> u64 {
        u64::from_le_bytes(
            self.teb_bytes[TEB_OFFSET_SELF..TEB_OFFSET_SELF + 8]
                .try_into()
                .unwrap(),
        )
    }

    /// Validates TEB pointer to PEB at GS:[0x60].
    pub fn read_teb_peb(&self) -> u64 {
        u64::from_le_bytes(
            self.teb_bytes[TEB_OFFSET_PEB..TEB_OFFSET_PEB + 8]
                .try_into()
                .unwrap(),
        )
    }

    /// Validates PEB ImageBaseAddress at offset 0x10.
    pub fn read_peb_image_base(&self) -> u64 {
        u64::from_le_bytes(
            self.peb_bytes[PEB_OFFSET_IMAGE_BASE..PEB_OFFSET_IMAGE_BASE + 8]
                .try_into()
                .unwrap(),
        )
    }

    /// Validates PEB ProcessParameters pointer at offset 0x20.
    pub fn read_peb_process_parameters(&self) -> u64 {
        u64::from_le_bytes(
            self.peb_bytes[PEB_OFFSET_PROCESS_PARAMETERS..PEB_OFFSET_PROCESS_PARAMETERS + 8]
                .try_into()
                .unwrap(),
        )
    }

    /// Validates ProcessParameters StandardOutput at offset 0x28.
    pub fn read_standard_output_handle(&self) -> u64 {
        u64::from_le_bytes(
            self.process_parameters_bytes
                [PROCESS_PARAMS_OFFSET_STD_OUT..PROCESS_PARAMS_OFFSET_STD_OUT + 8]
                .try_into()
                .unwrap(),
        )
    }
}
