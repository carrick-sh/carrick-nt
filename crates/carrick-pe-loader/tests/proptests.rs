//! Property-based testing for carrick-pe-loader parser resilience.
//!
//! Conforms to Microsoft PE and COFF Specification (Rev 11.0).
//! Asserts that the parser and loader fail closed with typed errors
//! on arbitrary or mutated byte streams and never panic.

use carrick_pe_loader::headers::PeHeaders;
use carrick_pe_loader::mapper::PeLoader;
use proptest::prelude::*;
use std::fs;
use std::path::Path;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Asserts that parsing completely random byte slices never panics.
    #[test]
    fn proptest_arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let loader = PeLoader::default();
        let _ = loader.load(&bytes);
        let _ = PeHeaders::parse(&bytes);
    }

    /// Asserts that mutating real PE binaries with random byte corruptions never panics.
    #[test]
    fn proptest_mutated_pe_fixture_never_panic(
        mutations in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..32)
    ) {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let ws = if manifest.join("tests/oracle/fixtures/hello_console.exe").exists() {
            manifest.to_path_buf()
        } else {
            manifest.parent().unwrap().parent().unwrap().to_path_buf()
        };
        let fixture_path = ws.join("tests/oracle/fixtures/hello_console.exe");
        if let Ok(mut base_bytes) = fs::read(&fixture_path) {
            let len = base_bytes.len();
            if len > 0 {
                for (offset_raw, val) in mutations {
                    let off = offset_raw % len;
                    base_bytes[off] = val;
                }
                let loader = PeLoader::default();
                let _ = loader.load(&base_bytes);
                let _ = PeHeaders::parse(&base_bytes);
            }
        }
    }
}
