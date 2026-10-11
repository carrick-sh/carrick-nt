//! Import census scanner and API set analyzer for Carrick NT.
//!
//! Conforms strictly to:
//! - AGENTS.md clean-room rules (no decompiled code, no Wine/ReactOS, black-box observation only).
//! - Microsoft PE and COFF Specification (Rev 11.0) Sections 6.4 (.idata) and 6.6 (Delay-Load).
//! - Microsoft Learn: Windows API sets (<https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets>).
//! - Microsoft Learn: API set loader operation (<https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation>).
//! - Microsoft Learn: Windows umbrella libraries (<https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-umbrella-libraries>).
//! - Microsoft Learn: Universal CRT deployment (<https://learn.microsoft.com/en-us/cpp/windows/universal-crt-deployment>).

use carrick_pe_loader::headers::PeHeaders;
use carrick_pe_loader::imports::{parse_all_imports, ImportSymbol};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// Error types occurring during census scanning and aggregation.
#[derive(Debug, thiserror::Error)]
pub enum CensusError {
    #[error("I/O error accessing binary at '{path}': {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("PE parse error in '{path}': {source}")]
    Pe {
        path: PathBuf,
        source: carrick_pe_loader::error::PeError,
    },
    #[error("Import parse error in '{path}': {source}")]
    Import {
        path: PathBuf,
        source: carrick_pe_loader::error::ImportError,
    },
    #[error("Serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Detailed information on an identified API set contract.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ApiSetContract {
    /// Raw module name as declared in the import table (e.g. "api-ms-win-core-file-l1-1-0.dll").
    pub raw_name: String,
    /// Canonical contract identifier without version suffix (e.g. "api-ms-win-core-file").
    pub contract_name: String,
    /// Schema version string if present (e.g. "l1-1-0").
    pub version: Option<String>,
    /// Resolved host DLL according to public Microsoft Learn documentation, or None if unresolved.
    pub host_dll: Option<String>,
    /// Citation of the public Microsoft Learn documentation page stating the host DLL.
    pub citation: Option<String>,
}

/// Parses and recognizes an API set contract from a DLL name string.
///
/// Returns `Some(ApiSetContract)` if the name begins with `api-ms-win-` or `ext-ms-win-`
/// (or `api-` / `ext-`), otherwise `None`.
pub fn parse_api_set_name(name: &str) -> Option<ApiSetContract> {
    let raw = name.trim();
    let lower = raw.to_ascii_lowercase();
    let base = lower.strip_suffix(".dll").unwrap_or(&lower);

    if !base.starts_with("api-ms-win-") && !base.starts_with("ext-ms-win-") {
        return None;
    }

    // Versioned contract format: <prefix>-<contract>-l<schema>-<major>-<minor>
    // Example: api-ms-win-core-synch-l1-2-0
    let (contract_name, version) = match split_api_set_version(base) {
        Some((contract, ver)) => (contract.to_string(), Some(ver.to_string())),
        None => (base.to_string(), None),
    };

    // Public Microsoft Learn documentation resolutions:
    let (host_dll, citation) = if contract_name.starts_with("api-ms-win-core-") {
        (
            Some("kernelbase.dll / kernel32.dll".to_string()),
            Some(
                "Microsoft Learn: Windows API sets (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) \
                and API set loader operation (https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation): \
                core OS contracts hosted in kernelbase.dll and kernel32.dll."
                    .to_string(),
            ),
        )
    } else if contract_name.starts_with("api-ms-win-crt-") {
        (
            Some("ucrtbase.dll".to_string()),
            Some(
                "Microsoft Learn: Universal CRT deployment (https://learn.microsoft.com/en-us/cpp/windows/universal-crt-deployment) \
                and Upgrade your code to the Universal CRT (https://learn.microsoft.com/en-us/cpp/porting/upgrade-your-code-to-the-universal-crt): \
                api-ms-win-crt-* contracts resolve to ucrtbase.dll."
                    .to_string(),
            ),
        )
    } else if contract_name.starts_with("api-ms-win-security-") {
        (
            Some("advapi32.dll".to_string()),
            Some(
                "Microsoft Learn: Windows umbrella libraries (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-umbrella-libraries): \
                security contracts hosted in advapi32.dll."
                    .to_string(),
            ),
        )
    } else if contract_name.starts_with("api-ms-win-service-") {
        (
            Some("advapi32.dll / sechost.dll".to_string()),
            Some(
                "Microsoft Learn: Windows umbrella libraries (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-umbrella-libraries): \
                service management contracts hosted in advapi32.dll / sechost.dll."
                    .to_string(),
            ),
        )
    } else {
        // Any unlisted api-ms-win-* and all ext-ms-win-* are marked unresolved per AGENTS.md rules.
        (None, None)
    };

    Some(ApiSetContract {
        raw_name: raw.to_string(),
        contract_name,
        version,
        host_dll,
        citation,
    })
}

fn split_api_set_version(base: &str) -> Option<(&str, &str)> {
    // Pattern: -l<digit+>-<digit+>-<digit+>
    let mut parts = base.rsplitn(4, '-');
    let minor = parts.next()?;
    let major = parts.next()?;
    let schema = parts.next()?;

    if !schema.starts_with('l') && !schema.starts_with('L') {
        return None;
    }
    if !schema[1..].chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if !major.chars().all(|c| c.is_ascii_digit()) || !minor.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }

    let version_len = schema.len() + major.len() + minor.len() + 2; // two hyphens
    if base.len() <= version_len + 1 {
        return None;
    }
    let contract_len = base.len() - version_len - 1;
    let contract = &base[..contract_len];
    let version = &base[contract_len + 1..];
    Some((contract, version))
}

/// An individual import record associated with a program.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DiscoveredImport {
    /// Raw module name (e.g. "KERNEL32.dll" or "api-ms-win-core-file-l1-1-0.dll").
    pub module_name: String,
    /// Function name or ordinal.
    pub symbol: String,
    /// Whether the import was by ordinal.
    pub is_ordinal: bool,
    /// Mechanism: "standard" or "delay-load".
    pub kind: String,
    /// API set details if recognized as an API set.
    pub api_set: Option<ApiSetContract>,
}

/// Census summary for a single examined binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramCensus {
    pub name: String,
    pub path: String,
    pub category: String, // "clean_room_built" or "system32_console"
    pub total_imports: usize,
    pub imports_by_module: BTreeMap<String, Vec<DiscoveredImport>>,
}

/// A ranked entry across the entire corpus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RankedImport {
    pub rank: usize,
    pub symbol: String,
    pub module_or_contract: String,
    pub is_api_set: bool,
    pub contract_name: Option<String>,
    pub resolved_host_dll: Option<String>,
    pub citation: Option<String>,
    pub program_count: usize,
    pub programs: Vec<String>,
    pub mechanisms: BTreeSet<String>,
}

/// Grouped API set contract information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSetGroup {
    pub contract_name: String,
    pub versions_seen: BTreeSet<String>,
    pub resolved_host_dll: Option<String>,
    pub citation: Option<String>,
    pub symbols: BTreeSet<String>,
    pub program_count: usize,
    pub programs: Vec<String>,
}

/// Recommendations for the first exports required in Carrick guest DLLs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirstTargets {
    /// Required exports for ntdll.dll to satisfy clean-room programs and top system32 tools.
    pub ntdll: Vec<String>,
    /// Required exports for kernel32.dll to satisfy clean-room programs and top system32 tools.
    pub kernel32: Vec<String>,
    /// Required exports for kernelbase.dll (OneCore API set hosts).
    pub kernelbase: Vec<String>,
}

/// Complete census report suitable for JSON and Markdown emission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CensusReport {
    pub rerun_command: String,
    pub total_programs: usize,
    pub clean_room_programs: usize,
    pub system32_programs: usize,
    pub go_status: String,
    pub first_targets: FirstTargets,
    pub ranked_imports: Vec<RankedImport>,
    pub api_set_groups: Vec<ApiSetGroup>,
    pub per_program: BTreeMap<String, ProgramCensus>,
}

/// Scans a binary in-memory or from file bytes.
pub fn scan_binary_bytes(
    bytes: &[u8],
    program_name: &str,
    category: &str,
    path_display: &str,
) -> Result<ProgramCensus, carrick_pe_loader::error::PeError> {
    let headers = PeHeaders::parse(bytes)?;
    let raw_imports =
        parse_all_imports(&headers, bytes).map_err(carrick_pe_loader::error::PeError::Import)?;

    let mut imports_by_module: BTreeMap<String, Vec<DiscoveredImport>> = BTreeMap::new();
    let mut total_imports = 0;

    for raw in raw_imports {
        let (symbol_str, is_ordinal) = match &raw.symbol {
            ImportSymbol::Named(name) => (name.clone(), false),
            ImportSymbol::Ordinal(ord) => (format!("#{ord}"), true),
        };

        let api_set = parse_api_set_name(&raw.dll_name);
        let discovered = DiscoveredImport {
            module_name: raw.dll_name.clone(),
            symbol: symbol_str,
            is_ordinal,
            kind: raw.kind.to_string(),
            api_set,
        };

        imports_by_module
            .entry(raw.dll_name)
            .or_default()
            .push(discovered);
        total_imports += 1;
    }

    Ok(ProgramCensus {
        name: program_name.to_string(),
        path: path_display.to_string(),
        category: category.to_string(),
        total_imports,
        imports_by_module,
    })
}

/// Scans a binary file from disk.
pub fn scan_binary_file(path: &Path, category: &str) -> Result<ProgramCensus, CensusError> {
    let bytes = fs::read(path).map_err(|source| CensusError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let program_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    scan_binary_bytes(&bytes, program_name, category, &path.display().to_string()).map_err(
        |source| CensusError::Pe {
            path: path.to_path_buf(),
            source,
        },
    )
}

/// Builds the comprehensive census report from a list of scanned programs.
pub fn build_census_report(
    programs: Vec<ProgramCensus>,
    rerun_command: &str,
    go_status: &str,
    top_system32_n: usize,
) -> CensusReport {
    let mut clean_room_count = 0;
    let mut system32_count = 0;

    // Track imports: key = (effective_module_or_contract, symbol)
    #[derive(Hash, PartialEq, Eq, PartialOrd, Ord)]
    struct SymbolKey {
        module_or_contract: String,
        symbol: String,
    }

    struct SymbolStats {
        is_api_set: bool,
        contract_name: Option<String>,
        resolved_host_dll: Option<String>,
        citation: Option<String>,
        programs: BTreeSet<String>,
        mechanisms: BTreeSet<String>,
    }

    let mut symbol_map: BTreeMap<SymbolKey, SymbolStats> = BTreeMap::new();
    let mut api_groups: BTreeMap<String, ApiSetGroup> = BTreeMap::new();
    let mut per_program: BTreeMap<String, ProgramCensus> = BTreeMap::new();

    // Sets for first targets:
    let mut cleanroom_ntdll: BTreeSet<String> = BTreeSet::new();
    let mut cleanroom_kernel32: BTreeSet<String> = BTreeSet::new();
    let mut cleanroom_kernelbase: BTreeSet<String> = BTreeSet::new();

    // System32 tools frequency map
    let mut sys32_ntdll_freq: BTreeMap<String, usize> = BTreeMap::new();
    let mut sys32_kernel32_freq: BTreeMap<String, usize> = BTreeMap::new();
    let mut sys32_kernelbase_freq: BTreeMap<String, usize> = BTreeMap::new();

    for prog in programs {
        if prog.category == "clean_room_built" {
            clean_room_count += 1;
        } else {
            system32_count += 1;
        }

        let is_clean_room = prog.category == "clean_room_built";

        for (mod_name, imports) in &prog.imports_by_module {
            for imp in imports {
                let (target_module, is_api_set, contract, host, cite) = match &imp.api_set {
                    Some(set) => (
                        set.contract_name.clone(),
                        true,
                        Some(set.contract_name.clone()),
                        set.host_dll.clone(),
                        set.citation.clone(),
                    ),
                    None => (mod_name.to_ascii_lowercase(), false, None, None, None),
                };

                let key = SymbolKey {
                    module_or_contract: target_module.clone(),
                    symbol: imp.symbol.clone(),
                };

                let entry = symbol_map.entry(key).or_insert_with(|| SymbolStats {
                    is_api_set,
                    contract_name: contract.clone(),
                    resolved_host_dll: host.clone(),
                    citation: cite.clone(),
                    programs: BTreeSet::new(),
                    mechanisms: BTreeSet::new(),
                });

                entry.programs.insert(prog.name.clone());
                entry.mechanisms.insert(imp.kind.clone());

                if let Some(set) = &imp.api_set {
                    let group = api_groups
                        .entry(set.contract_name.clone())
                        .or_insert_with(|| ApiSetGroup {
                            contract_name: set.contract_name.clone(),
                            versions_seen: BTreeSet::new(),
                            resolved_host_dll: set.host_dll.clone(),
                            citation: set.citation.clone(),
                            symbols: BTreeSet::new(),
                            program_count: 0,
                            programs: Vec::new(),
                        });

                    if let Some(ver) = &set.version {
                        group.versions_seen.insert(ver.clone());
                    }
                    group.symbols.insert(imp.symbol.clone());
                }

                // Categorize for first targets
                let mod_lower = mod_name.to_ascii_lowercase();
                if is_clean_room {
                    if mod_lower == "ntdll.dll" {
                        cleanroom_ntdll.insert(imp.symbol.clone());
                    } else if mod_lower == "kernel32.dll" {
                        cleanroom_kernel32.insert(imp.symbol.clone());
                    } else if mod_lower == "kernelbase.dll" {
                        cleanroom_kernelbase.insert(imp.symbol.clone());
                    } else if let Some(h) = &host {
                        if h.contains("kernelbase") {
                            cleanroom_kernelbase.insert(imp.symbol.clone());
                        }
                        if h.contains("kernel32") {
                            cleanroom_kernel32.insert(imp.symbol.clone());
                        }
                    }
                } else if mod_lower == "ntdll.dll" {
                    *sys32_ntdll_freq.entry(imp.symbol.clone()).or_insert(0) += 1;
                } else if mod_lower == "kernel32.dll" {
                    *sys32_kernel32_freq.entry(imp.symbol.clone()).or_insert(0) += 1;
                } else if mod_lower == "kernelbase.dll" {
                    *sys32_kernelbase_freq.entry(imp.symbol.clone()).or_insert(0) += 1;
                } else if let Some(h) = &host {
                    if h.contains("kernelbase") {
                        *sys32_kernelbase_freq.entry(imp.symbol.clone()).or_insert(0) += 1;
                    }
                    if h.contains("kernel32") {
                        *sys32_kernel32_freq.entry(imp.symbol.clone()).or_insert(0) += 1;
                    }
                }
            }
        }

        per_program.insert(prog.name.clone(), prog);
    }

    // Rank symbols across all programs
    let mut ranked_items: Vec<(SymbolKey, SymbolStats)> = symbol_map.into_iter().collect();
    ranked_items.sort_by(|(k1, s1), (k2, s2)| {
        s2.programs
            .len()
            .cmp(&s1.programs.len())
            .then_with(|| k1.module_or_contract.cmp(&k2.module_or_contract))
            .then_with(|| k1.symbol.cmp(&k2.symbol))
    });

    let mut ranked_imports = Vec::new();
    for (idx, (k, stats)) in ranked_items.into_iter().enumerate() {
        ranked_imports.push(RankedImport {
            rank: idx + 1,
            symbol: k.symbol,
            module_or_contract: k.module_or_contract,
            is_api_set: stats.is_api_set,
            contract_name: stats.contract_name,
            resolved_host_dll: stats.resolved_host_dll,
            citation: stats.citation,
            program_count: stats.programs.len(),
            programs: stats.programs.into_iter().collect(),
            mechanisms: stats.mechanisms,
        });
    }

    // Update programs list for API set groups
    let mut api_set_groups: Vec<ApiSetGroup> = api_groups.into_values().collect();
    for group in &mut api_set_groups {
        let mut prog_set = BTreeSet::new();
        for prog in per_program.values() {
            for mod_name in prog.imports_by_module.keys() {
                if let Some(set) = parse_api_set_name(mod_name) {
                    if set.contract_name == group.contract_name {
                        prog_set.insert(prog.name.clone());
                    }
                }
            }
        }
        group.program_count = prog_set.len();
        group.programs = prog_set.into_iter().collect();
    }
    api_set_groups.sort_by(|a, b| {
        b.program_count
            .cmp(&a.program_count)
            .then_with(|| a.contract_name.cmp(&b.contract_name))
    });

    // Helper to get top N from a freq map
    let top_n_keys = |map: BTreeMap<String, usize>, n: usize| -> Vec<String> {
        let mut list: Vec<(String, usize)> = map.into_iter().collect();
        list.sort_by(|(s1, c1), (s2, c2)| c2.cmp(c1).then_with(|| s1.cmp(s2)));
        list.into_iter().take(n).map(|(s, _)| s).collect()
    };

    let top_sys32_ntdll = top_n_keys(sys32_ntdll_freq, top_system32_n);
    let top_sys32_kernel32 = top_n_keys(sys32_kernel32_freq, top_system32_n);
    let top_sys32_kernelbase = top_n_keys(sys32_kernelbase_freq, top_system32_n);

    // Merge clean-room and top system32 targets
    let mut first_ntdll = cleanroom_ntdll;
    first_ntdll.extend(top_sys32_ntdll);

    let mut first_kernel32 = cleanroom_kernel32;
    first_kernel32.extend(top_sys32_kernel32);

    let mut first_kernelbase = cleanroom_kernelbase;
    first_kernelbase.extend(top_sys32_kernelbase);

    let first_targets = FirstTargets {
        ntdll: first_ntdll.into_iter().collect(),
        kernel32: first_kernel32.into_iter().collect(),
        kernelbase: first_kernelbase.into_iter().collect(),
    };

    CensusReport {
        rerun_command: rerun_command.to_string(),
        total_programs: clean_room_count + system32_count,
        clean_room_programs: clean_room_count,
        system32_programs: system32_count,
        go_status: go_status.to_string(),
        first_targets,
        ranked_imports,
        api_set_groups,
        per_program,
    }
}

/// Generates formatted Markdown output for `docs/census/import-census.md`.
pub fn generate_markdown_report(report: &CensusReport) -> String {
    let mut md = String::new();

    md.push_str("# Carrick NT: PE Import Census (NT-014)\n\n");
    md.push_str(
        "Data-driven analysis of DLL and API set exports required by real Windows executables, ",
    );
    md.push_str("ranking export demand across clean-room built programs and standard Windows System32 console tools.\n\n");

    md.push_str("## Clean-Room Rules & Compliance\n\n");
    md.push_str("- Conforms strictly to repository `AGENTS.md`: no Wine/ReactOS source or test reuse, no leaked or decompiled Microsoft code.\n");
    md.push_str("- Public binaries were examined strictly via clean-room PE directory metadata (`carrick-pe-loader`); never disassembled or decompiled.\n");
    md.push_str("- Only derived import names, counts, and metadata are recorded; no bytes or binary images are committed.\n");
    md.push_str("- API set contracts and host DLL resolutions are learned exclusively from public Microsoft Learn documentation (cited below).\n\n");

    md.push_str("## Exact Re-Run Command\n\n");
    md.push_str("```bash\n");
    md.push_str(&format!("{}\n", report.rerun_command));
    md.push_str("```\n\n");

    md.push_str("## Corpus Summary\n\n");
    md.push_str(&format!(
        "- **Total Programs Scanned:** {}\n",
        report.total_programs
    ));
    md.push_str(&format!(
        "  - **Clean-Room Built Programs:** {}\n",
        report.clean_room_programs
    ));
    md.push_str(&format!(
        "  - **Windows System32 Console Tools:** {}\n",
        report.system32_programs
    ));
    md.push_str(&format!(
        "- **Go Toolchain Status:** {}\n\n",
        report.go_status
    ));

    md.push_str("## First Targets: Prioritized Guest DLL Exports\n\n");
    md.push_str("The following tables enumerate the mandatory exports needed from `ntdll.dll`, `kernel32.dll`, ");
    md.push_str("and `kernelbase.dll` to achieve complete coverage of all clean-room test programs plus the top-demanded exports ");
    md.push_str("across the Windows console utilities.\n\n");

    md.push_str("### 1. ntdll.dll First Targets\n\n");
    md.push_str("| Export Name | Source Demand |\n|---|---|\n");
    for sym in &report.first_targets.ntdll {
        md.push_str(&format!("| `{sym}` | Core demand |\n"));
    }
    md.push('\n');

    md.push_str("### 2. kernel32.dll First Targets\n\n");
    md.push_str("| Export Name | Source Demand |\n|---|---|\n");
    for sym in &report.first_targets.kernel32 {
        md.push_str(&format!("| `{sym}` | Core demand |\n"));
    }
    md.push('\n');

    md.push_str("### 3. kernelbase.dll First Targets (API Set Implementations)\n\n");
    md.push_str("| Export Name | Source Demand |\n|---|---|\n");
    for sym in &report.first_targets.kernelbase {
        md.push_str(&format!("| `{sym}` | OneCore API Set demand |\n"));
    }
    md.push('\n');

    md.push_str("## API Set Contract Catalog & Microsoft Learn Citations\n\n");
    md.push_str("| Contract Name | Versions Seen | Host DLL | Microsoft Learn Citation | Programs | Exports Count |\n");
    md.push_str("|---|---|---|---|---|---|\n");
    for group in &report.api_set_groups {
        let versions = if group.versions_seen.is_empty() {
            "alias (unversioned)".to_string()
        } else {
            group
                .versions_seen
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        };
        let host = group.resolved_host_dll.as_deref().unwrap_or("*Unresolved*");
        let cite = group.citation.as_deref().unwrap_or("None (unresolved)");
        md.push_str(&format!(
            "| `{}` | `{}` | {} | {} | {} | {} |\n",
            group.contract_name,
            versions,
            host,
            cite,
            group.program_count,
            group.symbols.len()
        ));
    }
    md.push('\n');

    md.push_str("## Ranked Table of Imports (Top 100)\n\n");
    md.push_str("| Rank | Export Symbol | DLL or API Set Contract | Type | Resolved Host DLL | Count | Programs |\n");
    md.push_str("|---|---|---|---|---|---|---|\n");
    for entry in report.ranked_imports.iter().take(100) {
        let is_api = if entry.is_api_set { "API Set" } else { "DLL" };
        let host = entry.resolved_host_dll.as_deref().unwrap_or("-");
        let prog_list = entry.programs.join(", ");
        md.push_str(&format!(
            "| {} | `{}` | `{}` | {} | {} | {} | {} |\n",
            entry.rank,
            entry.symbol,
            entry.module_or_contract,
            is_api,
            host,
            entry.program_count,
            prog_list
        ));
    }
    md.push('\n');

    md.push_str("## Per-Program Import Summaries\n\n");
    for (prog_name, prog) in &report.per_program {
        md.push_str(&format!("### {}\n\n", prog_name));
        md.push_str(&format!("- **Category:** {}\n", prog.category));
        md.push_str(&format!("- **Path:** `{}`\n", prog.path));
        md.push_str(&format!("- **Total Imports:** {}\n", prog.total_imports));
        md.push_str("- **Modules Imported:**\n\n");

        md.push_str("| Module / Contract | Mechanism | Symbols Count | Sample Symbols |\n");
        md.push_str("|---|---|---|---|\n");
        for (module, imps) in &prog.imports_by_module {
            let mechanism = if imps.iter().any(|i| i.kind == "delay-load") {
                if imps.iter().any(|i| i.kind == "standard") {
                    "standard + delay-load"
                } else {
                    "delay-load"
                }
            } else {
                "standard"
            };
            let sample = imps
                .iter()
                .take(3)
                .map(|i| i.symbol.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            let sample_str = if imps.len() > 3 {
                format!("{sample}, ...")
            } else {
                sample
            };
            md.push_str(&format!(
                "| `{}` | {} | {} | `{}` |\n",
                module,
                mechanism,
                imps.len(),
                sample_str
            ));
        }
        md.push('\n');
    }

    md
}
