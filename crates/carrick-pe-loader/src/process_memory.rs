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
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use carrick_nt_abi::{
    ClientId, CurDir, GuestVa, NtHandle, Peb, RtlUserProcessParameters, Teb, UnicodeString,
};

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
pub const PROCESS_PARAMS_OFFSET_DLL_PATH: usize = 0x50;
pub const PROCESS_PARAMS_OFFSET_IMAGE_PATH: usize = 0x60;
pub const PROCESS_PARAMS_OFFSET_COMMAND_LINE: usize = 0x70;
pub const PROCESS_PARAMS_OFFSET_ENVIRONMENT: usize = 0x80;
pub const PROCESS_PARAMS_HEADER_SIZE: usize = 0x88;

/// Encodes a command-line string into UTF-16 code units with a terminating null character.
///
/// In Microsoft NT:
/// - `length` in `UNICODE_STRING` is in BYTES, excluding the terminating null code unit.
/// - `maximum_length` in `UNICODE_STRING` is in BYTES, including the terminating null code unit.
///
/// Returns `(length_bytes, max_length_bytes, utf16_bytes)`.
pub fn encode_command_line(cmd_line: &str) -> (u16, u16, Vec<u8>) {
    let utf16: Vec<u16> = cmd_line.encode_utf16().chain(Some(0)).collect();
    let length_bytes = ((utf16.len() - 1) * 2) as u16;
    let max_length_bytes = (utf16.len() * 2) as u16;

    let mut bytes = Vec::with_capacity(utf16.len() * 2);
    for u in &utf16 {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    (length_bytes, max_length_bytes, bytes)
}

/// Encodes key-value environment pairs into a double-null-terminated UTF-16 block.
///
/// In Windows NT, the environment block format is:
/// - Each variable is encoded as `Key=Value\0` in UTF-16 code units (2 bytes per char).
/// - The entire block is terminated with an additional null code unit (`\0`), making it double-null terminated.
/// - An empty environment block consists solely of two null UTF-16 characters (`\0\0`, 4 zero bytes).
pub fn encode_environment_block<K: AsRef<str>, V: AsRef<str>>(vars: &[(K, V)]) -> Vec<u8> {
    let mut utf16_units: Vec<u16> = Vec::new();
    let mut has_entries = false;

    for (k, v) in vars {
        has_entries = true;
        utf16_units.extend(k.as_ref().encode_utf16());
        utf16_units.push(b'=' as u16);
        utf16_units.extend(v.as_ref().encode_utf16());
        utf16_units.push(0); // Null terminator for this entry
    }

    if has_entries {
        utf16_units.push(0); // Additional null terminator for double-null termination of block
    } else {
        // An empty environment block is "\0\0" (2 null wchar_t code units)
        utf16_units.push(0);
        utf16_units.push(0);
    }

    let mut bytes = Vec::with_capacity(utf16_units.len() * 2);
    for u in utf16_units {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    bytes
}

/// Builder configuration for process and thread memory structures.
#[derive(Debug, Clone)]
pub struct ProcessMemoryConfig<'a> {
    pub teb_va: VirtualAddress,
    pub peb_va: VirtualAddress,
    pub process_parameters_va: VirtualAddress,
    pub image_base: VirtualAddress,
    pub image_path: &'a str,
    pub command_line: &'a str,
    pub environment: &'a [(&'a str, &'a str)],
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
            environment: &[],
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
    /// Constructs and initializes process memory structures according to Microsoft Learn specs
    /// using typed wire structs from `carrick-nt-abi`.
    pub fn build(config: &ProcessMemoryConfig<'_>) -> Self {
        // 1. Build Process Parameters
        let mut params_bytes = vec![0u8; PROCESS_PARAMS_HEADER_SIZE];

        // Encode UTF-16 strings and environment block
        let (image_path_bytes_len, image_path_max_len, image_path_bytes) =
            encode_command_line(config.image_path);
        let (cmd_line_bytes_len, cmd_line_max_len, cmd_line_bytes) =
            encode_command_line(config.command_line);
        let env_bytes = encode_environment_block(config.environment);

        // Align ImagePathName buffer to 8 bytes and append
        while !params_bytes.len().is_multiple_of(8) {
            params_bytes.push(0);
        }
        let image_path_offset = params_bytes.len();
        params_bytes.extend_from_slice(&image_path_bytes);

        // Align CommandLine buffer to 8 bytes and append
        while !params_bytes.len().is_multiple_of(8) {
            params_bytes.push(0);
        }
        let cmd_line_offset = params_bytes.len();
        params_bytes.extend_from_slice(&cmd_line_bytes);

        // Align Environment buffer to 8 bytes and append
        while !params_bytes.len().is_multiple_of(8) {
            params_bytes.push(0);
        }
        let env_offset = params_bytes.len();
        params_bytes.extend_from_slice(&env_bytes);

        let total_params_len = params_bytes.len() as u32;

        let image_path_va = config
            .process_parameters_va
            .checked_add(image_path_offset as u64)
            .unwrap();
        let cmd_line_va = config
            .process_parameters_va
            .checked_add(cmd_line_offset as u64)
            .unwrap();
        let env_va = config
            .process_parameters_va
            .checked_add(env_offset as u64)
            .unwrap();

        // Write typed RTL_USER_PROCESS_PARAMETERS wire struct header
        let params_header = RtlUserProcessParameters {
            maximum_length: total_params_len,
            length: total_params_len,
            flags: 0,
            debug_flags: 0,
            console_handle: NtHandle::NULL,
            console_flags: 0,
            standard_input: NtHandle::from_raw(config.stdin_handle),
            standard_output: NtHandle::from_raw(config.stdout_handle),
            standard_error: NtHandle::from_raw(config.stderr_handle),
            current_directory: CurDir::empty(),
            dll_path: UnicodeString::empty(),
            image_path_name: UnicodeString::new(
                image_path_bytes_len,
                image_path_max_len,
                GuestVa::new(image_path_va.as_u64()),
            ),
            command_line: UnicodeString::new(
                cmd_line_bytes_len,
                cmd_line_max_len,
                GuestVa::new(cmd_line_va.as_u64()),
            ),
            environment: GuestVa::new(env_va.as_u64()),
        };

        let header_slice = unsafe {
            core::slice::from_raw_parts(
                &params_header as *const _ as *const u8,
                core::mem::size_of::<RtlUserProcessParameters>(),
            )
        };
        params_bytes[..header_slice.len()].copy_from_slice(header_slice);

        // 2. Build PEB using typed wire struct
        let mut peb_bytes = vec![0u8; PEB_SIZE];
        let peb_header = Peb {
            reserved1: [0; 2],
            being_debugged: 0,
            reserved2: [0; 1],
            _padding: 0,
            mutant: GuestVa::NULL,
            image_base_address: GuestVa::new(config.image_base.as_u64()),
            loader_data: GuestVa::NULL,
            process_parameters: GuestVa::new(config.process_parameters_va.as_u64()),
        };
        let peb_slice = unsafe {
            core::slice::from_raw_parts(
                &peb_header as *const _ as *const u8,
                core::mem::size_of::<Peb>(),
            )
        };
        peb_bytes[..peb_slice.len()].copy_from_slice(peb_slice);

        // 3. Build TEB using typed wire struct
        let mut teb_bytes = vec![0u8; TEB_SIZE];
        let teb_header = Teb {
            reserved1: [GuestVa::NULL; 6],
            teb_self: GuestVa::new(config.teb_va.as_u64()),
            reserved_subsystem: GuestVa::NULL,
            client_id: ClientId::new(config.process_id, config.thread_id),
            reserved_rpc: GuestVa::NULL,
            reserved_tls: GuestVa::NULL,
            process_environment_block: GuestVa::new(config.peb_va.as_u64()),
        };
        let teb_slice = unsafe {
            core::slice::from_raw_parts(
                &teb_header as *const _ as *const u8,
                core::mem::size_of::<Teb>(),
            )
        };
        teb_bytes[..teb_slice.len()].copy_from_slice(teb_slice);

        Self {
            teb_bytes,
            peb_bytes,
            process_parameters_bytes: params_bytes,
            teb_va: config.teb_va,
            peb_va: config.peb_va,
            process_parameters_va: config.process_parameters_va,
        }
    }

    /// Access typed RTL_USER_PROCESS_PARAMETERS header.
    #[inline]
    pub fn parameters_header(&self) -> &RtlUserProcessParameters {
        assert!(
            self.process_parameters_bytes.len() >= core::mem::size_of::<RtlUserProcessParameters>()
        );
        unsafe { &*(self.process_parameters_bytes.as_ptr() as *const RtlUserProcessParameters) }
    }

    /// Access typed PEB header.
    #[inline]
    pub fn peb_header(&self) -> &Peb {
        assert!(self.peb_bytes.len() >= core::mem::size_of::<Peb>());
        unsafe { &*(self.peb_bytes.as_ptr() as *const Peb) }
    }

    /// Access typed TEB header prefix.
    #[inline]
    pub fn teb_header(&self) -> &Teb {
        assert!(self.teb_bytes.len() >= core::mem::size_of::<Teb>());
        unsafe { &*(self.teb_bytes.as_ptr() as *const Teb) }
    }

    /// Validates TEB Self pointer at GS:[0x30].
    pub fn read_teb_self(&self) -> u64 {
        self.teb_header().teb_self.as_u64()
    }

    /// Validates TEB pointer to PEB at GS:[0x60].
    pub fn read_teb_peb(&self) -> u64 {
        self.teb_header().process_environment_block.as_u64()
    }

    /// Validates PEB ImageBaseAddress at offset 0x10.
    pub fn read_peb_image_base(&self) -> u64 {
        self.peb_header().image_base_address.as_u64()
    }

    /// Validates PEB ProcessParameters pointer at offset 0x20.
    pub fn read_peb_process_parameters(&self) -> u64 {
        self.peb_header().process_parameters.as_u64()
    }

    /// Validates ProcessParameters StandardOutput at offset 0x28.
    pub fn read_standard_output_handle(&self) -> u64 {
        self.parameters_header().standard_output.as_u64()
    }

    /// Reads ProcessParameters Environment pointer at offset 0x80.
    pub fn read_environment_ptr(&self) -> u64 {
        self.parameters_header().environment.as_u64()
    }

    /// Reads CommandLine string from process parameter memory.
    pub fn read_command_line_str(&self) -> String {
        let cmd = self.parameters_header().command_line;
        if cmd.length == 0 || cmd.buffer.is_null() {
            return String::new();
        }
        let offset = (cmd.buffer.as_u64() - self.process_parameters_va.as_u64()) as usize;
        let char_count = (cmd.length / 2) as usize;
        let u16_slice: &[u16] = unsafe {
            core::slice::from_raw_parts(
                self.process_parameters_bytes[offset..].as_ptr() as *const u16,
                char_count,
            )
        };
        alloc::string::String::from_utf16_lossy(u16_slice)
    }
}
