//! Unit tests for NT-014 import census and API set analyzer.
//!
//! Tests:
//! 1. API set naming and contract resolution according to Microsoft Learn.
//! 2. Census scanning of real clean-room hello_console.exe fixture.
//! 3. Census scanning of synthetic PE containing delay-load imports.
//! 4. End-to-end report generation and ranking.

use carrick_conformance_nt::census::{
    build_census_report, generate_markdown_report, parse_api_set_name, scan_binary_bytes,
};
use carrick_pe_loader::headers::{
    PeHeaders, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, IMAGE_SCN_CNT_INITIALIZED_DATA,
    IMAGE_SCN_MEM_READ,
};
use carrick_pe_loader::imports::parse_all_imports;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

static BUILD_LOCK: Mutex<()> = Mutex::new(());

fn get_workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn get_or_build_hello_console() -> Vec<u8> {
    let _guard = BUILD_LOCK.lock().unwrap();
    let ws = get_workspace_root();
    let candidate = ws.join("tests/oracle/fixtures/hello_console.exe");
    if let Ok(b) = fs::read(&candidate) {
        return b;
    }

    let fixture_paths = [
        ws.join("crates/carrick-conformance-nt/fixtures/hello_console.exe"),
        ws.join("crates/carrick-conformance-nt/fixtures/hello_console/target/x86_64-pc-windows-msvc/release/hello_console.exe"),
        ws.join("target/x86_64-pc-windows-msvc/release/hello_console.exe"),
    ];

    for p in &fixture_paths {
        if let Ok(b) = fs::read(p) {
            let _ = fs::create_dir_all(candidate.parent().unwrap());
            let _ = fs::write(&candidate, &b);
            return b;
        }
    }

    // Build via cargo
    let manifest = ws.join("crates/carrick-conformance-nt/fixtures/hello_console/Cargo.toml");
    let rustflags = "-C panic=abort -C linker=lld -C link-args=/nodefaultlib -C link-args=/entry:mainCRTStartup -C link-args=/subsystem:console";

    let status = Command::new("cargo")
        .current_dir(&ws)
        .arg("build")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--target")
        .arg("x86_64-pc-windows-msvc")
        .arg("--release")
        .env("RUSTFLAGS", rustflags)
        .status()
        .expect("failed to spawn cargo build for hello_console");

    assert!(status.success(), "cargo build for hello_console failed");

    for p in &fixture_paths {
        if let Ok(b) = fs::read(p) {
            let _ = fs::create_dir_all(candidate.parent().unwrap());
            let _ = fs::write(&candidate, &b);
            return b;
        }
    }

    panic!("Could not find built hello_console.exe");
}

/// Constructs a valid PE binary with a synthetic .didat (delay-load) section.
fn create_synthetic_pe_with_delay_imports(base_bytes: &[u8]) -> Vec<u8> {
    let mut bytes = base_bytes.to_vec();

    // 1. Locate PE headers
    let e_lfanew = u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap()) as usize;
    let coff_offset = e_lfanew + 4;
    let num_sections =
        u16::from_le_bytes(bytes[coff_offset + 2..coff_offset + 4].try_into().unwrap());
    let size_of_opt = u16::from_le_bytes(
        bytes[coff_offset + 16..coff_offset + 18]
            .try_into()
            .unwrap(),
    ) as usize;
    let opt_offset = coff_offset + 20;

    let sec_table_offset = opt_offset + size_of_opt;
    let new_sec_offset = sec_table_offset + (num_sections as usize) * 40;

    // 2. Increment section count
    bytes[coff_offset + 2..coff_offset + 4].copy_from_slice(&(num_sections + 1).to_le_bytes());

    // 3. New section geometry: RVA 0x6000, file offset at end of current file
    let new_sec_rva = 0x6000u32;
    let raw_offset = bytes.len() as u32;
    let sec_size = 512u32;

    // 4. Construct .didat section payload:
    // Layout:
    // 0..32: IMAGE_DELAYLOAD_DESCRIPTOR (32 bytes)
    // 32..64: Null terminator descriptor (32 bytes)
    // 64..128: DLL name "ext-ms-win-ntuser-chartranslation-l1-1-0.dll\0"
    // 128..144: Import Address Table (IAT) - 2 thunks of 8 bytes (first 0, second 0)
    // 144..160: Import Name Table (INT) - 2 thunks of 8 bytes (first RVA to name, second 0)
    // 160..190: IMAGE_IMPORT_BY_NAME (2 bytes hint 0 + "CharToOemA\0")
    let mut sec_data = vec![0u8; sec_size as usize];

    let dll_name_rva = new_sec_rva + 64;
    let iat_rva = new_sec_rva + 128;
    let int_rva = new_sec_rva + 144;
    let ibn_rva = new_sec_rva + 160;

    // IMAGE_DELAYLOAD_DESCRIPTOR (32 bytes)
    sec_data[0..4].copy_from_slice(&1u32.to_le_bytes()); // Attributes = 1 (RVA-based)
    sec_data[4..8].copy_from_slice(&dll_name_rva.to_le_bytes()); // DllNameRVA
    sec_data[8..12].copy_from_slice(&(new_sec_rva + 60).to_le_bytes()); // ModuleHandleRVA
    sec_data[12..16].copy_from_slice(&iat_rva.to_le_bytes()); // ImportAddressTableRVA
    sec_data[16..20].copy_from_slice(&int_rva.to_le_bytes()); // ImportNameTableRVA
    sec_data[20..24].copy_from_slice(&0u32.to_le_bytes()); // BoundImportAddressTableRVA
    sec_data[24..28].copy_from_slice(&0u32.to_le_bytes()); // UnloadInformationTableRVA
    sec_data[28..32].copy_from_slice(&0u32.to_le_bytes()); // TimeDateStamp

    // Descriptor 2 (null terminator at 32..64 is already zeros)

    // DLL name string at 64
    let dll_name = b"ext-ms-win-ntuser-chartranslation-l1-1-0.dll\0";
    sec_data[64..64 + dll_name.len()].copy_from_slice(dll_name);

    // INT thunk at 144 pointing to ibn_rva (bit 63 clear = import by name)
    sec_data[144..152].copy_from_slice(&(ibn_rva as u64).to_le_bytes());
    // Thunk terminator at 152..160 is already 0

    // IMAGE_IMPORT_BY_NAME at 160
    // 2 bytes hint (0)
    sec_data[160..162].copy_from_slice(&0u16.to_le_bytes());
    // Symbol name string
    let sym_name = b"CharToOemA\0";
    sec_data[162..162 + sym_name.len()].copy_from_slice(sym_name);

    // 5. Write Section Header (40 bytes)
    let mut sec_header = [0u8; 40];
    sec_header[..6].copy_from_slice(b".didat");
    sec_header[8..12].copy_from_slice(&sec_size.to_le_bytes()); // VirtualSize
    sec_header[12..16].copy_from_slice(&new_sec_rva.to_le_bytes()); // VirtualAddress
    sec_header[16..20].copy_from_slice(&sec_size.to_le_bytes()); // SizeOfRawData
    sec_header[20..24].copy_from_slice(&raw_offset.to_le_bytes()); // PointerToRawData
    let chars = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
    sec_header[36..40].copy_from_slice(&chars.to_le_bytes());

    bytes[new_sec_offset..new_sec_offset + 40].copy_from_slice(&sec_header);

    // 6. Update SizeOfImage: 0x6000 + 0x1000 = 0x7000
    let new_image_size = 0x7000u32;
    bytes[opt_offset + 56..opt_offset + 60].copy_from_slice(&new_image_size.to_le_bytes());

    // 7. Update DataDirectory[13] (Delay Import Directory)
    let dir13_offset = opt_offset + 112 + IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT * 8;
    bytes[dir13_offset..dir13_offset + 4].copy_from_slice(&new_sec_rva.to_le_bytes());
    let dir13_size = 64u32; // 2 descriptors of 32 bytes
    bytes[dir13_offset + 4..dir13_offset + 8].copy_from_slice(&dir13_size.to_le_bytes());

    // 8. Append section data
    bytes.extend_from_slice(&sec_data);
    bytes
}

#[test]
fn test_api_set_parsing_and_resolution() {
    // 1. Core API set with version: resolves to kernelbase.dll / kernel32.dll with citation
    let core = parse_api_set_name("api-ms-win-core-synch-l1-2-0.dll").expect("should be api set");
    assert_eq!(core.contract_name, "api-ms-win-core-synch");
    assert_eq!(core.version.as_deref(), Some("l1-2-0"));
    assert_eq!(
        core.host_dll.as_deref(),
        Some("kernelbase.dll / kernel32.dll")
    );
    assert!(core
        .citation
        .unwrap()
        .contains("Microsoft Learn: Windows API sets"));

    // 2. CRT API set: resolves to ucrtbase.dll
    let crt = parse_api_set_name("api-ms-win-crt-stdio-l1-1-0.dll").expect("should be api set");
    assert_eq!(crt.contract_name, "api-ms-win-crt-stdio");
    assert_eq!(crt.version.as_deref(), Some("l1-1-0"));
    assert_eq!(crt.host_dll.as_deref(), Some("ucrtbase.dll"));
    assert!(crt.citation.unwrap().contains("Universal CRT deployment"));

    // 3. Security API set: resolves to advapi32.dll
    let sec = parse_api_set_name("api-ms-win-security-base-l1-1-0.dll").expect("should be api set");
    assert_eq!(sec.contract_name, "api-ms-win-security-base");
    assert_eq!(sec.host_dll.as_deref(), Some("advapi32.dll"));

    // 4. Extension API set: recognized as API set, contract parsed, host marked unresolved
    let ext = parse_api_set_name("ext-ms-win-ntuser-chartranslation-l1-1-0.dll")
        .expect("should be api set");
    assert_eq!(ext.contract_name, "ext-ms-win-ntuser-chartranslation");
    assert_eq!(ext.version.as_deref(), Some("l1-1-0"));
    assert_eq!(
        ext.host_dll, None,
        "extension API set without Learn citation must be unresolved"
    );
    assert_eq!(ext.citation, None);

    // 5. Traditional DLLs: not API sets
    assert!(parse_api_set_name("kernel32.dll").is_none());
    assert!(parse_api_set_name("ntdll.dll").is_none());
    assert!(parse_api_set_name("user32.dll").is_none());
}

#[test]
fn test_census_on_hello_fixture() {
    let bytes = get_or_build_hello_console();

    let census = scan_binary_bytes(
        &bytes,
        "hello_console.exe",
        "clean_room_built",
        "hello_console.exe",
    )
    .expect("failed to scan hello_console fixture");

    assert_eq!(census.name, "hello_console.exe");
    assert_eq!(census.category, "clean_room_built");
    assert_eq!(census.total_imports, 3);

    // Find kernel32 imports
    let k32_key = census
        .imports_by_module
        .keys()
        .find(|k| k.eq_ignore_ascii_case("kernel32.dll"))
        .expect("expected kernel32.dll in imports");

    let imports = &census.imports_by_module[k32_key];
    let symbol_names: Vec<&str> = imports.iter().map(|i| i.symbol.as_str()).collect();

    assert!(symbol_names.contains(&"ExitProcess"));
    assert!(symbol_names.contains(&"GetStdHandle"));
    assert!(symbol_names.contains(&"WriteFile"));

    for imp in imports {
        assert_eq!(imp.kind, "standard");
        assert!(!imp.is_ordinal);
        assert!(imp.api_set.is_none());
    }
}

#[test]
fn test_census_on_synthetic_pe_with_delay_load_imports() {
    let base_bytes = get_or_build_hello_console();
    let synthetic_pe = create_synthetic_pe_with_delay_imports(&base_bytes);

    // 1. Verify low-level PE headers detect delay-load data directory
    let headers = PeHeaders::parse(&synthetic_pe).expect("failed to parse synthetic PE headers");
    let delay_dir = headers
        .data_directory(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)
        .expect("delay directory must be present");
    assert!(delay_dir.is_present());
    assert_eq!(delay_dir.size, 64);

    // 2. Verify parse_all_imports returns both standard and delay-load imports
    let all_imports = parse_all_imports(&headers, &synthetic_pe)
        .expect("failed to parse all imports from synthetic PE");
    assert_eq!(
        all_imports.len(),
        4,
        "expected 3 standard + 1 delay-load import"
    );

    let delay_import = all_imports
        .iter()
        .find(|i| i.kind == carrick_pe_loader::imports::ImportKind::DelayLoad)
        .expect("missing delay load import");

    assert_eq!(
        delay_import.dll_name,
        "ext-ms-win-ntuser-chartranslation-l1-1-0.dll"
    );
    assert_eq!(
        delay_import.symbol,
        carrick_pe_loader::imports::ImportSymbol::Named("CharToOemA".to_string())
    );

    // 3. Verify high-level census tool scans and categorizes correctly
    let census = scan_binary_bytes(
        &synthetic_pe,
        "synthetic_delay.exe",
        "clean_room_built",
        "synthetic_delay.exe",
    )
    .expect("census scan failed on synthetic PE");

    assert_eq!(census.total_imports, 4);

    // Check delay import record in census
    let ext_module = census
        .imports_by_module
        .get("ext-ms-win-ntuser-chartranslation-l1-1-0.dll")
        .expect("missing delay import module");
    assert_eq!(ext_module.len(), 1);
    let ext_imp = &ext_module[0];
    assert_eq!(ext_imp.symbol, "CharToOemA");
    assert_eq!(ext_imp.kind, "delay-load");

    let api_set = ext_imp.api_set.as_ref().expect("must recognize as API set");
    assert_eq!(api_set.contract_name, "ext-ms-win-ntuser-chartranslation");
    assert_eq!(api_set.version.as_deref(), Some("l1-1-0"));
    assert_eq!(api_set.host_dll, None, "must be marked unresolved");

    // 4. Test report generation with synthetic program
    let report = build_census_report(
        vec![census],
        "cargo xtask import-census",
        "Go not installed",
        10,
    );

    assert_eq!(report.total_programs, 1);
    assert_eq!(report.clean_room_programs, 1);
    assert_eq!(report.first_targets.kernel32.len(), 3);
    assert!(report
        .first_targets
        .kernel32
        .contains(&"ExitProcess".to_string()));

    let md = generate_markdown_report(&report);
    assert!(md.contains("CharToOemA"));
    assert!(md.contains("ext-ms-win-ntuser-chartranslation"));
    assert!(md.contains("delay-load"));
}
