# Clean-Room NTDLL Bootstrap and Console Execution Architecture

- **Status:** Proposed Design Document
- **Target Workload:** Unmodified x86_64 Windows PE console executable (`hello_console.exe`) invoking `WriteFile` or `WriteConsole` on `stdout` and terminating via `ExitProcess`.
- **Target Architecture:** x86_64 guest running under Carrick CPL0 shared kernel on Linux/KVM (and Hypervisor backends).
- **Repository:** `carrick-sh/carrick-nt`
- **Applicable Governance:** Clean-Room Rules in `AGENTS.md` (no Wine, no ReactOS, no leaked/decompiled code, no GPL/LGPL sources; public Microsoft documentation and black-box differential observation only).

---

## Table of Contents

1. [Executive Summary & Design Principles](#1-executive-summary--design-principles)
2. [Boundary Choice: Clean-Room In-Guest Userland vs. Kernel Seam](#2-boundary-choice-clean-room-in-guest-userland-vs-kernel-seam)
   - 2.1 [The NT System Call Volatility Problem](#21-the-nt-system-call-volatility-problem)
   - 2.2 [Evaluation of Alternative Architectural Boundaries](#22-evaluation-of-alternative-architectural-boundaries)
   - 2.3 [The Chosen Architecture: Clean-Room In-Guest DLLs with Carrick Hypercall Seam](#23-the-chosen-architecture-clean-room-in-guest-dlls-with-carrick-hypercall-seam)
   - 2.4 [Clean-Room Provenance & Legal Hygiene](#24-clean-room-provenance--legal-hygiene)
3. [PE/COFF Loader & Process Memory Initialization](#3-pecoff-loader--process-memory-initialization)
   - 3.1 [Specification Standards & Citation Registry](#31-specification-standards--citation-registry)
   - 3.2 [Header Hierarchy & Image Validation](#32-header-hierarchy--image-validation)
   - 3.3 [Virtual Address Space Allocation & Section Mapping](#33-virtual-address-space-allocation--section-mapping)
   - 3.4 [Base Relocations (.reloc)](#34-base-relocations-reloc)
   - 3.5 [Import Binding (.idata) & Export Forwarding](#35-import-binding-idata--export-forwarding)
   - 3.6 [Thread Local Storage (.tls) & Callbacks](#36-thread-local-storage-tls--callbacks)
   - 3.7 [Process & Thread Memory Structures (PEB, TEB, Process Parameters)](#37-process--thread-memory-structures-peb-teb-process-parameters)
   - 3.8 [Standard Handles & Console Initialization](#38-standard-handles--console-initialization)
4. [Crate Architecture & Carrick Seams](#4-crate-architecture--carrick-seams)
   - 4.1 [Repository Crate Layout (`carrick-nt`)](#41-repository-crate-layout-carrick-nt)
   - 4.2 [Carrick Core Seams Consumed](#42-carrick-core-seams-consumed)
   - 4.3 [Proposed Personality-Neutral Upstream Carrick Issues](#43-proposed-personality-neutral-upstream-carrick-issues)
5. [Differential Black-Box Testing & Oracle Toolchain](#5-differential-black-box-testing--oracle-toolchain)
   - 5.1 [Differential Oracle Harness (Windows Server 2025)](#51-differential-oracle-harness-windows-server-2025)
   - 5.2 [Committed Oracle Receipt Schema & Offline Verification](#52-committed-oracle-receipt-schema--offline-verification)
   - 5.3 [Clean-Room Test Program Toolchain (Zero Proprietary SDKs)](#53-clean-room-test-program-toolchain-zero-proprietary-sdks)
6. [Milestones, Acceptance Criteria & Issue Drafts](#6-milestones-acceptance-criteria--issue-drafts)
   - 6.1 [Roadmap Summary](#61-roadmap-summary)
   - 6.2 [Milestone M0: Oracle Harness & First Recorded Observation](#62-milestone-m0-oracle-harness--first-recorded-observation)
   - 6.3 [Milestone M1: PE/COFF Loader Maps the Hello Executable](#63-milestone-m1-pecoff-loader-maps-the-hello-executable)
   - 6.4 [Milestone M2: Hello Program Prints and Exits Under Carrick](#64-milestone-m2-hello-program-prints-and-exits-under-carrick)
   - 6.5 [Milestone M3: Widen to Argv, Environment & File I/O](#65-milestone-m3-widen-to-argv-environment--file-io)
7. [References & Citations](#7-references--citations)

---

## 1. Executive Summary & Design Principles

The objective of the NT personality for Carrick is to run unmodified 64-bit Windows portable executable (PE) binaries on Carrick's shared guest virtualization kernel. The first production milestone is the execution of an unmodified x86_64 Windows console "hello" program—a standard binary compiled by any mainstream compiler that resolves standard output, prints a string via `WriteFile` or `WriteConsole`, and terminates with a defined exit code via `ExitProcess`.

Achieving this while satisfying the project's strict clean-room governance requires resolving four fundamental architectural constraints:
1. **The System Call Volatility Boundary:** Unlike POSIX systems, Windows kernel system calls (invoked via the x86 `syscall` instruction) are undocumented, private, non-sequential, and change across OS builds. Standard Windows user programs never issue raw syscalls; they dynamically link against system subsystem libraries.
2. **The In-Guest Runtime Expectation:** Windows binaries expect standard user-space runtime structures to be pre-populated at fixed architectural coordinates before execution begins. In particular, the x86_64 `GS` segment base register must point to a valid Thread Environment Block (`TEB`), which links to the Process Environment Block (`PEB`) and `RTL_USER_PROCESS_PARAMETERS`.
3. **Clean-Room Subsystem Construction:** No Wine, ReactOS, leaked, or decompiled code may be consulted or used. All in-guest modules (`ntdll.dll`, `kernel32.dll`, `kernelbase.dll`) must be implemented clean-room in Rust, based solely on public Microsoft documentation, published specifications, and differential black-box observation of real Windows systems.
4. **Autonomous Conformance Verification:** Compatibility must be verified differentially against real Windows (specifically Windows Server 2025 containers running on Docker), generating immutable, committed oracle receipts that gate Carrick's CI without requiring a live Windows VM during routine test execution.

---

## 2. Boundary Choice: Clean-Room In-Guest Userland vs. Kernel Seam

### 2.1 The NT System Call Volatility Problem

On Linux, the kernel system call ABI is a first-class, strictly stabilized public interface. Syscall numbers (such as `sys_write = 1`, `sys_exit_group = 231` on x86_64) remain guaranteed across decades.

On Windows NT, the system call interface exposed by `ntoskrnl.exe` via `syscall` is deliberately **private, internal, and volatile**:
- Microsoft provides no documentation, guarantees, or SDK headers specifying System Service Numbers (SSNs).
- SSNs vary unpredictably between Windows versions, minor service updates, and monthly quality patches. For instance, `NtWriteFile` was service index `0x011f` in Windows 10 2004, `0x0120` in 20H2, and `0x0008` in earlier kernel generations.
- Standard Windows applications—including every compiler runtime (MSVC CRT, UCRT, MinGW, Rust `std`)—do not issue direct `syscall` instructions. They link dynamically against Win32 API DLLs (`kernel32.dll`, `kernelbase.dll`) or the C runtime (`ucrtbase.dll`, `msvcrt.dll`), which in turn route calls to `ntdll.dll`.
- `ntdll.dll` is the lowest user-mode library in the NT architecture. It transitions from user mode (CPL3) to kernel mode (CPL0) through stub functions that load the build-specific SSN into `eax` and execute `syscall`.

### 2.2 Evaluation of Alternative Architectural Boundaries

We evaluated three potential boundary designs for supporting unmodified Windows binaries:

| Boundary Approach | Description | Technical Deficiencies & Clean-Room Failure Modes | Verdict |
|---|---|---|---|
| **A. Trap & Emulate Raw Windows Syscalls at CPL0** | Hypervisor or guest kernel catches native `syscall` instructions issued by Microsoft's own `ntdll.dll`. | 1. **Fragility & Volatility:** Requires maintaining thousands of build-specific SSN lookup tables.<br>2. **Clean-Room Breach Risk:** Discovering SSN tables for each Microsoft build requires disassembling proprietary Microsoft DLLs or relying on reverse-engineered third-party tables (violating clean-room policy).<br>3. **Redistribution Violations:** Shipping proprietary Microsoft DLLs (`ntdll.dll`, `kernel32.dll`) inside Carrick guest images violates Microsoft copyright and redistribution licenses.<br>4. **In-Guest State Divergence:** Microsoft's native `ntdll.dll` performs undocumented internal handshakes with the kernel during process startup (e.g., `LdrpInitializeProcess`, complex activation contexts, undocumented LPC calls) that will fault immediately if the kernel does not implement every private internal interface. | **REJECTED** |
| **B. Trap at Win32 Subsystem Boundary (`kernel32.dll` Hypercalls)** | Implement `kernel32.dll` as a thin set of direct hypercalls into Carrick's kernel. | 1. **API Surface Explosion:** `kernel32.dll` exports thousands of convenience functions, many of which implement string parsing, console buffering, and path canonicalization. Implementing this entire surface in the kernel violates Carrick's principle of a minimal, orthogonal kernel core.<br>2. **Loss of NT Subsystem Layering:** Bypasses NT's native object architecture (handles, object directories, asynchronous I/O status blocks).<br>3. **Non-Native Native Executables:** Native NT utilities (which link only to `ntdll.dll` without Win32) cannot run. | **REJECTED** |
| **C. Clean-Room In-Guest Userland (`ntdll.dll` + Minimal Forwarders) with Carrick Hypercall Seam** | Clean-room `ntdll.dll` compiled for x86_64 Windows PE running in guest CPL3, backed by minimal `kernel32.dll`/`kernelbase.dll` export forwarders. `ntdll.dll` transitions into Carrick's NT personality via a Carrick-defined system call ABI. | 1. **100% Clean-Room Compliance:** We control the `ntdll` implementation and the system call contract completely; no Microsoft SSNs or binaries are required.<br>2. **Zero Proprietary Redistribution:** Guest images distribute only Carrick-authored, open-source PE binaries.<br>3. **Clean Architectural Layering:** Win32 APIs lower cleanly to documented NT native APIs (`NtWriteFile`, `NtTerminateProcess`, `NtClose`), which then invoke Carrick's NT personality.<br>4. **Unmodified User Binaries:** Real, off-the-shelf Windows console executables bind to standard DLL exports without modification. | **APPROVED** |

### 2.3 The Chosen Architecture: Clean-Room In-Guest DLLs with Carrick Hypercall Seam

The chosen architecture establishes a two-tier guest execution boundary:

```
+-------------------------------------------------------------------+
| Guest User Mode (CPL3)                                            |
|                                                                   |
|   +-------------------------------------------------------------+ |
|   | Unmodified Windows Console Binary (e.g. hello_console.exe)   | |
|   +-------------------------------------------------------------+ |
|               | calls WriteFile() / ExitProcess()                 |
|               v                                                   |
|   +-------------------------------------------------------------+ |
|   | KERNEL32.dll / KERNELBASE.dll (Clean-Room Forwarder DLLs)   | |
|   |   - WriteFile()        -> calls NtWriteFile()               | |
|   |   - WriteConsoleA/W()  -> translates/calls NtWriteFile()     | |
|   |   - GetStdHandle()     -> reads PEB.ProcessParameters        | |
|   |   - ExitProcess()      -> calls RtlExitUserProcess()         | |
|   +-------------------------------------------------------------+ |
|               | calls documented NT Native APIs                   |
|               v                                                   |
|   +-------------------------------------------------------------+ |
|   | NTDLL.dll (Clean-Room Native System Library)                |
|   |   - User-mode runtime: PEB/TEB init, minimal heap           |
|   |   - Native API stubs: NtWriteFile(), NtTerminateProcess()   |
|   |   - Syscall stub: loads Carrick NtServiceId into EAX        |
|   |                   executes `syscall`                        |
|   +-------------------------------------------------------------+ |
+-------------------------------------------------------------------+
                                |
                   Hardware `syscall` instruction
                                |
+-------------------------------------------------------------------+
| Carrick Shared Kernel / Guest CPL0                                |
|                                                                   |
|   +-------------------------------------------------------------+ |
|   | carrick-x86 (CPL0 Entry & Frame Snapshot)                   |
|   +-------------------------------------------------------------+ |
|               | invokes Personality::decode                       |
|               v                                                   |
|   +-------------------------------------------------------------+ |
|   | carrick-personality-nt (NT Personality Client)              |
|   |   - Decodes Carrick NtServiceId                             |
|   |   - Validates NT object handles & IO_STATUS_BLOCK           |
|   |   - Dispatches I/O to Carrick CoreServices                  |
|   +-------------------------------------------------------------+ |
|               | calls CoreServices::transfer / commit / enroll    |
|               v                                                   |
|   +-------------------------------------------------------------+ |
|   | carrick-core (Neutral Kernel Substrate: MMU, Sched, Wait)   |
|   +-------------------------------------------------------------+ |
+-------------------------------------------------------------------+
```

#### The Carrick NT Hypercall / System Call Contract
In our guest userland:
- `carrick-ntdll` defines stable, sequential service ordinals (`NtServiceId` in `carrick-nt-abi`).
- On x86_64, system call dispatch follows the Microsoft x64 calling convention:
  - `eax`: holds the `NtServiceId` (e.g., `0x0001` for `NtTerminateProcess`, `0x0002` for `NtWriteFile`).
  - `rcx`: 1st argument.
  - `rdx`: 2nd argument.
  - `r8`: 3rd argument.
  - `r9`: 4th argument.
  - `[rsp + 0x28]`, `[rsp + 0x30]`, ...: 5th and subsequent arguments passed on the user stack (accounting for the 32-byte shadow space and return address).
- Execution of `syscall` transitions control to Carrick's CPL0 entry point, where the x86 hardware frame is captured and passed to `Personality<X86_64Arch>::decode`.

### 2.4 Clean-Room Provenance & Legal Hygiene

In strict adherence to `AGENTS.md`:
1. **Zero Excluded Code:** No code, comments, structures, or test assets from Wine, ReactOS, or leaked/decompiled Microsoft code are consulted, referenced, or imported.
2. **Authorized Sources Only:**
   - **Microsoft Learn Documentation:** Official published documentation for Win32 functions, NT Native APIs, and the PE/COFF format.
   - **Microsoft PE and COFF Specification:** Published revision 11.0.
   - **Microsoft `win32metadata`:** Official MIT-licensed metadata project provided by Microsoft (`microsoft/win32metadata`) and the corresponding `windows-sys` crate for public types, constants, and signatures.
   - **Black-Box Differential Testing:** Observing and recording behavior on real, licensed Windows Server 2025 containers.
3. **No Proprietary Redistribution:** Carrick distributes zero Microsoft-authored binary files, import libraries (`.lib`), or proprietary C/C++ SDK headers (`windows.h`). All guest binaries are built from source using Rust or clean-room toolchains.

---

## 3. PE/COFF Loader & Process Memory Initialization

### 3.1 Specification Standards & Citation Registry

All loader operations, structures, and field offsets conform strictly to published Microsoft specifications and official documentation:

| Domain | Canonical Public Document | URL / Citation Key |
|---|---|---|
| **PE/COFF Image Format** | Microsoft PE and COFF Specification (Rev 11.0) | [Microsoft Learn: PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) |
| **x64 ABI Conventions** | x64 Software Conventions & Calling Conventions | [Microsoft Learn: x64 Software Conventions](https://learn.microsoft.com/en-us/cpp/build/x64-software-conventions) |
| **PEB Structure** | Winternl.h / Process Environment Block | [Microsoft Learn: PEB structure](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb) |
| **TEB Structure** | Winternl.h / Thread Environment Block | [Microsoft Learn: TEB structure](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-teb) |
| **Process Parameters** | Winternl.h / RTL_USER_PROCESS_PARAMETERS | [Microsoft Learn: RTL_USER_PROCESS_PARAMETERS](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-rtl_user_process_parameters) |
| **Native APIs** | Windows Driver Kit (WDK) Reference | [Microsoft Learn: NtWriteFile](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntwritefile) |

### 3.2 Header Hierarchy & Image Validation

The loader parses the PE binary in sequence:

```
+---------------------------------------------------------+
| MS-DOS 2.0 Compatible EXE Header (IMAGE_DOS_HEADER)     |
|   e_magic = 0x5A4D ("MZ")                               |
|   e_lfanew = Offset to NT Headers                       |
+---------------------------------------------------------+
                           |
                           v
+---------------------------------------------------------+
| NT Headers (IMAGE_NT_HEADERS64)                         |
|   Signature = 0x00004550 ("PE\0\0")                     |
|                                                         |
|   +---------------------------------------------------+ |
|   | COFF File Header (IMAGE_FILE_HEADER)              | |
|   |   Machine = 0x8664 (IMAGE_FILE_MACHINE_AMD64)     | |
|   |   NumberOfSections                                | |
|   |   SizeOfOptionalHeader                            | |
|   |   Characteristics (0x0022: EXECUTABLE, LAA)       | |
|   +---------------------------------------------------+ |
|                                                         |
|   +---------------------------------------------------+ |
|   | Optional Header (IMAGE_OPTIONAL_HEADER64)         | |
|   |   Magic = 0x020B (PE32+)                          | |
|   |   AddressOfEntryPoint (RVA of entry point)        | |
|   |   ImageBase (Preferred base VA)                   | |
|   |   SectionAlignment (typically 0x1000)             | |
|   |   FileAlignment (typically 0x200)                 | |
|   |   SizeOfImage (Total virtual span)                | |
|   |   SizeOfHeaders (Spanning DOS, NT, Sections)      | |
|   |   Subsystem (0x0003 = IMAGE_SUBSYSTEM_WINDOWS_CUI)| |
|   |   DllCharacteristics (NX_COMPAT, DYNAMIC_BASE)    | |
|   |   DataDirectory[16]:                              | |
|   |     [0] Export Table     [1] Import Table         | |
|   |     [3] Exception (.pdata) [5] Base Relocations   | |
|   |     [9] TLS Table        [10] Load Config         | |
|   +---------------------------------------------------+ |
+---------------------------------------------------------+
                           |
                           v
+---------------------------------------------------------+
| Section Table (Array of IMAGE_SECTION_HEADER)           |
|   [.text] VirtualSize, VirtualAddress, RawData, Chars   |
|   [.rdata] VirtualSize, VirtualAddress, RawData, Chars  |
|   [.data] VirtualSize, VirtualAddress, RawData, Chars   |
|   [.pdata] VirtualSize, VirtualAddress, RawData, Chars  |
|   [.reloc] VirtualSize, VirtualAddress, RawData, Chars  |
+---------------------------------------------------------+
```

#### Detailed Field Verification (PE Spec Sections 3.1 - 3.4)
1. **DOS Header:** Check `e_magic == 0x5A4D` (`MZ`). Validate `e_lfanew >= 0x40` and within file bounds.
2. **COFF File Header:** Check `Signature == 0x00004550` (`PE\0\0`). Verify `Machine == 0x8664` (`IMAGE_FILE_MACHINE_AMD64`). Assert `Characteristics` includes `IMAGE_FILE_EXECUTABLE_IMAGE` (0x0002).
3. **Optional Header (PE32+):** Verify `Magic == 0x020B`. Check that `SectionAlignment >= PageSize` (typically 4096 bytes / `0x1000`) and `FileAlignment` is a power of 2 between 512 and `SectionAlignment`.
4. **Subsystem Validation:** Verify `Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI` (3). GUI subsystems (2) fail closed with an explicit error during the console milestone.

### 3.3 Virtual Address Space Allocation & Section Mapping

Mapping follows Section 4 of the PE specification:

```
Virtual Memory Address Space
+----------------------------------+ ActualBase (Reserved SizeOfImage)
| PE Headers (DOS + NT + Sections) | Read-Only (0x1000 aligned)
+----------------------------------+ ActualBase + VirtualAddress(.text)
| .text section                    | Read + Execute
+----------------------------------+ ActualBase + VirtualAddress(.rdata)
| .rdata section (Imports, Readonly)| Read-Only
+----------------------------------+ ActualBase + VirtualAddress(.data)
| .data section                    | Read + Write
+----------------------------------+ ActualBase + VirtualAddress(.pdata)
| .pdata section (x64 Unwind info) | Read-Only
+----------------------------------+ ActualBase + VirtualAddress(.reloc)
| .reloc section (Base relocations)| Read-Only (Discardable)
+----------------------------------+
```

1. **Virtual Address Space Reservation:**
   - Query Carrick `CoreServices::reserve` for an address range of size `OptionalHeader.SizeOfImage` aligned to 64 KiB (the Windows allocation granularity).
   - If the preferred `OptionalHeader.ImageBase` is free and ASLR (`IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`) is disabled, reserve at `ImageBase`. Otherwise, allocate an arbitrary available 64 KiB aligned base (`ActualBase`).
2. **Header Mapping:**
   - Commit `OptionalHeader.SizeOfHeaders` bytes at `ActualBase` with `PageAccess::ReadOnly`.
   - Copy the headers verbatim from the binary image.
3. **Section Mapping:**
   - For each section in `IMAGE_SECTION_HEADER`:
     - Calculate target virtual address: `SecVA = ActualBase + SectionHeader.VirtualAddress`.
     - Calculate page-aligned span: `Span = align_up(SectionHeader.VirtualSize, SectionAlignment)`.
     - Translate `SectionHeader.Characteristics` to Carrick `PageAccess`:
       - `IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ` -> `PageAccess::ReadExecute`
       - `IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE` -> `PageAccess::ReadWrite`
       - `IMAGE_SCN_MEM_READ` -> `PageAccess::ReadOnly`
     - Commit pages via `CoreServices::commit_pages` for `Span` at `SecVA`.
     - Copy `SectionHeader.SizeOfRawData` bytes from `SectionHeader.PointerToRawData` to `SecVA`.
     - Zero the remainder of `Span` from `SizeOfRawData` to `VirtualSize` (uninitialized `.bss` data).

### 3.4 Base Relocations (.reloc)

Per Section 6.6 of the PE specification, if `ActualBase != OptionalHeader.ImageBase`, the base relocation table must be applied.
- The table is located at `DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]`.
- It consists of contiguous blocks starting with `IMAGE_BASE_RELOCATION`:
  ```rust
  #[repr(C)]
  struct ImageBaseRelocation {
      virtual_address: u32, // Page RVA
      size_of_block: u32,   // Total size in bytes including this header
  }
  ```
- Following each header is an array of 16-bit entries:
  - Top 4 bits: `RelocationType`.
  - Bottom 12 bits: `Offset` within the 4 KiB page.
- Handled relocation types:
  - `IMAGE_REL_BASED_ABSOLUTE` (0): Padding/no-op, skipped.
  - `IMAGE_REL_BASED_DIR64` (10): 64-bit VA fixup. The loader computes:
    $$\Delta = 	ext{ActualBase} - 	ext{OptionalHeader.ImageBase}$$
    $$	ext{TargetVA} = 	ext{ActualBase} + 	ext{virtual\_address} + 	ext{offset}$$
    $$*(	ext{u64}*)	ext{TargetVA} \mathrel{+}= \Delta$$
- Any unsupported relocation type fails image loading immediately.

### 3.5 Import Binding (.idata) & Export Forwarding

Per Section 6.4 of the PE specification, imported symbols are resolved through the Import Directory Table located at `DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]`:

1. **Import Directory Table Iteration:**
   - Array of `IMAGE_IMPORT_DESCRIPTOR` structures terminated by an all-zero structure:
     - `OriginalFirstThunk` (u32 RVA): Import Lookup Table (ILT).
     - `Name` (u32 RVA): RVA to null-terminated ASCII DLL name (e.g. `"KERNEL32.dll"`).
     - `FirstThunk` (u32 RVA): Import Address Table (IAT).
2. **DLL Resolution:**
   - Map imported DLL name case-insensitively (`KERNEL32.dll`, `KERNELBASE.dll`, `NTDLL.dll`) to the pre-loaded in-guest clean-room module instances.
3. **Symbol Lookup & IAT Fixup:**
   - Walk the ILT (array of 64-bit entries terminated by zero):
     - If bit 63 is set: Import by ordinal (bottom 16 bits).
     - If bit 63 is clear: Import by name. ILT points to `IMAGE_IMPORT_BY_NAME` (`Hint: u16`, `Name: [u8]`).
   - Look up the function in the target module's `IMAGE_EXPORT_DIRECTORY`:
     - Binary search in `AddressOfNames` array -> find name index.
     - Look up ordinal in `AddressOfNameOrdinals[name_index]`.
     - Read function RVA from `AddressOfFunctions[ordinal]`.
   - **Export Forwarding Check:** If the function RVA falls inside the export directory's virtual address span, it is a forwarder string (e.g., `"NTDLL.RtlExitUserProcess"`). The loader recursively resolves the forwarded DLL and symbol.
   - Write the resolved absolute function virtual address into the matching slot in the IAT (`FirstThunk`).

### 3.6 Thread Local Storage (.tls) & Callbacks

Per Section 6.7 of the PE specification, Thread Local Storage configuration is described by `IMAGE_TLS_DIRECTORY64` at `DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]`:
- `StartAddressOfRawData` (VA) & `EndAddressOfRawData` (VA): Template data.
- `AddressOfIndex` (VA): Location where the loader writes the assigned TLS slot index.
- `AddressOfCallBacks` (VA): Pointer to a null-terminated array of function pointers (`PIMAGE_TLS_CALLBACK`).
- **Loader Callback Execution:**
  - If `AddressOfCallBacks` is non-zero, the loader walks the array.
  - Before jumping to `AddressOfEntryPoint`, each callback is executed:
    `callback(ActualBase, DLL_PROCESS_ATTACH, NULL)`
  - Standard minimal console programs typically have an empty or null TLS callback list, but the loader must safely recognize and process the structure without faulting.

### 3.7 Process & Thread Memory Structures (PEB, TEB, Process Parameters)

Windows user mode relies on fixed data structures accessible via segment registers. On x86_64:
- The segment register `GS` has its base address set to the current thread's `TEB` per Microsoft x64 software conventions.
- The loader allocates, commits, and initializes the `TEB`, `PEB`, and `RTL_USER_PROCESS_PARAMETERS` in user virtual memory.

Every structure member listed below is cited directly to its official Microsoft Learn specification page (`winternl.h`). In accordance with our clean-room governance, **any member or offset not publicly named on Microsoft Learn is explicitly marked "to be observed via the oracle"**, and Carrick discovers and verifies its runtime presence and layout exclusively through black-box observation of real Windows Server 2025 containers.

```
                      x86_64 GS Segment
                             |
                             v
               +------------------------------------------+
               | Thread Environment Block (TEB)           |
               | Source: winternl.h / Microsoft Learn     |
               |                                          |
GS:[0x00] ---> | Reserved1[12] (PVOID[12])                |
               |   [internal fields: to be observed       |
               |    via the oracle]                       |
GS:[0x60] ---> | ProcessEnvironmentBlock (PPEB)           |----+
               | Reserved2[399] (PVOID[399])              |    |
               | Reserved3[1952] (BYTE[1952])             |    |
Offset 0x1480  | TlsSlots[64] (PVOID[64])                 |    |
               | Reserved4[8] (BYTE[8])                   |    |
               | Reserved5[26] (PVOID[26])                |    |
               | ReservedForOle (PVOID)                   |    |
               | Reserved6[4] (PVOID[4])                  |    |
               | TlsExpansionSlots (PVOID)                |    |
               +------------------------------------------+    |
                                                               |
                             +---------------------------------+
                             v
               +------------------------------------------+
               | Process Environment Block (PEB)          |
               | Source: winternl.h / Microsoft Learn     |
               |                                          |
Offset 0x00 -> | Reserved1[2] (BYTE[2])                   |
Offset 0x02 -> | BeingDebugged (BYTE)                     |
Offset 0x03 -> | Reserved2[21] (BYTE[21])                 |
               |   [internal fields: to be observed       |
               |    via the oracle]                       |
Offset 0x18 -> | LoaderData (PPEB_LDR_DATA)               |
Offset 0x20 -> | ProcessParameters                        |----+
               |   (PRTL_USER_PROCESS_PARAMETERS)         |    |
Offset 0x28 -> | Reserved3[520] (BYTE[520])               |    |
               |   [internal fields: to be observed       |
               |    via the oracle]                       |
               | PostProcessInitRoutine                   |    |
               | Reserved4[136] (BYTE[136])               |    |
               | SessionId (ULONG)                        |    |
               +------------------------------------------+    |
                                                               |
                             +---------------------------------+
                             v
               +------------------------------------------+
               | RTL_USER_PROCESS_PARAMETERS              |
               | Source: winternl.h / Microsoft Learn     |
               |                                          |
Offset 0x00 -> | Reserved1[16] (BYTE[16])                 |
Offset 0x10 -> | Reserved2[10] (PVOID[10])                |
               |   [internal fields: to be observed       |
               |    via the oracle]                       |
Offset 0x60 -> | ImagePathName (UNICODE_STRING)           |
Offset 0x70 -> | CommandLine (UNICODE_STRING)             |
               | [unlisted trailing fields: to be         |
               |  observed via the oracle]                |
               +------------------------------------------+
```

#### Detailed Structure Citations and Member Analysis

1. **TEB (Thread Environment Block):**
   - **Canonical Document:** [Microsoft Learn: TEB structure (winternl.h)](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-teb)
   - **Arch Anchor:** Base address loaded into `MSR_IA32_GS_BASE` (`0xC0000101`) per [Microsoft Learn: x64 Software Conventions](https://learn.microsoft.com/en-us/cpp/build/x64-software-conventions).
   - **Documented Members:**
     - `Reserved1[12]` (`PVOID[12]`): Offsets `0x00` through `0x5F` on x86_64.
       - *Internal fields:* Any specific sub-fields in this span (such as an exception registration pointer at `0x00`, stack limits, thread ID / process ID client identity at `0x40`, or a self-referential TEB pointer at `0x30`) are not publicly named in `winternl.h`; their exact presence, offsets, and required initialization values are **to be observed via the oracle**.
     - `ProcessEnvironmentBlock` (`PPEB`): Offset `0x60` on x86_64. Documented as: "A pointer to the PEB structure that contains information for the process as a whole."
     - `Reserved2[399]` (`PVOID[399]`): Reserved for internal OS use.
     - `Reserved3[1952]` (`BYTE[1952]`): Reserved for internal OS use.
     - `TlsSlots[64]` (`PVOID[64]`): Offset `0x1480` on x86_64. Documented as: "Data for Thread Local Storage. Call the TlsGetValue function to access it."
     - `Reserved4[8]` (`BYTE[8]`): Reserved for internal OS use.
     - `Reserved5[26]` (`PVOID[26]`): Reserved for internal OS use.
     - `ReservedForOle` (`PVOID`): Documented as: "Do not use. Call CoGetContextToken instead."
     - `Reserved6[4]` (`PVOID[4]`): Reserved for internal OS use.
     - `TlsExpansionSlots` (`PVOID`): Documented as: "Additional data for Thread Local Storage. Call the TlsGetValue function to access it."
   - Any member not explicitly listed above is **to be observed via the oracle**.

2. **PEB (Process Environment Block):**
   - **Canonical Document:** [Microsoft Learn: PEB structure (winternl.h)](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)
   - **Documented Members (64-bit Windows layout in Remarks):**
     - `Reserved1[2]` (`BYTE[2]`): Offsets `0x00` - `0x01`. Reserved for internal OS use.
     - `BeingDebugged` (`BYTE`): Offset `0x02`. Documented as: "Indicates whether the specified process is currently being debugged."
     - `Reserved2[21]` (`BYTE[21]`): Offsets `0x03` through `0x17`.
       - *Internal fields:* Fields within this span (such as an image base address pointer at offset `0x10`) are not named in `winternl.h`; their exact offset and necessity are **to be observed via the oracle**.
     - `LoaderData` (`PPEB_LDR_DATA`): Offset `0x18` on x86_64. Documented as: "A pointer to a PEB_LDR_DATA structure that contains information about the loaded modules for the process."
     - `ProcessParameters` (`PRTL_USER_PROCESS_PARAMETERS`): Offset `0x20` on x86_64. Documented as: "A pointer to an RTL_USER_PROCESS_PARAMETERS structure that contains process parameter information such as the command line."
     - `Reserved3[520]` (`BYTE[520]`): Offsets `0x28` through `0x22F`.
       - *Internal fields:* Fields within this span (such as a default process heap handle or processor count) are not named in `winternl.h`; their exact presence and offsets are **to be observed via the oracle**.
     - `PostProcessInitRoutine` (`PPS_POST_PROCESS_INIT_ROUTINE`): Documented as: "Not supported."
     - `Reserved4[136]` (`BYTE[136]`): Reserved for internal OS use.
     - `SessionId` (`ULONG`): Documented as: "The Terminal Services session identifier associated with the current process."
   - Any member not explicitly listed above is **to be observed via the oracle**.

3. **RTL_USER_PROCESS_PARAMETERS:**
   - **Canonical Document:** [Microsoft Learn: RTL_USER_PROCESS_PARAMETERS structure (winternl.h)](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-rtl_user_process_parameters)
   - **Documented Members:**
     - `Reserved1[16]` (`BYTE[16]`): Offsets `0x00` through `0x0F`. Reserved for internal OS use.
     - `Reserved2[10]` (`PVOID[10]`): Offsets `0x10` through `0x5F` on x86_64.
       - *Internal fields:* Console stream handle fields (standard input, standard output, standard error) and current directory strings are located in process parameter memory (traditionally placed within `Reserved2`), but are not explicitly named in `winternl.h`. Their exact structure offsets and handle representations are **to be observed via the oracle**.
     - `ImagePathName` (`UNICODE_STRING`): Offset `0x60` on x86_64. Documented as: "The path of the image file for the process."
     - `CommandLine` (`UNICODE_STRING`): Offset `0x70` on x86_64. Documented as: "The command-line string passed to the process."
     - *Unlisted trailing fields:* An environment variable block pointer is not named in `winternl.h`; its exact location and internal representation within process parameters are **to be observed via the oracle**.

### 3.8 Standard Handles & Console Initialization

Windows defines standard handle pseudo-constants in public Win32 headers:
- `STD_INPUT_HANDLE`: `((DWORD)-10)` (`0xFFFFFFF6`)
- `STD_OUTPUT_HANDLE`: `((DWORD)-11)` (`0xFFFFFFF5`)
- `STD_ERROR_HANDLE`: `((DWORD)-12)` (`0xFFFFFFF4`)

Per [Microsoft Learn: GetStdHandle function](https://learn.microsoft.com/en-us/windows/console/getstdhandle), calling `GetStdHandle(STD_OUTPUT_HANDLE)` returns the standard output device handle. In our clean-room userland:
- `carrick-kernel32` implements `GetStdHandle`: how standard handles are retrieved from process parameter memory or internal tables is verified and aligned with our black-box observations of real Windows containers.
- The returned handle points to a valid Carrick stream handle mapped to standard output.
- When `WriteFile` ([Microsoft Learn: WriteFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile)) or `WriteConsole` ([Microsoft Learn: WriteConsole](https://learn.microsoft.com/en-us/windows/console/writeconsole)) is called with this handle:
  - `WriteFile` forwards to documented native API `NtWriteFile(Handle, NULL, NULL, NULL, &IoStatusBlock, Buffer, Length, NULL, NULL)` ([Microsoft Learn: NtWriteFile](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntwritefile)).
  - In Carrick NT, `NtWriteFile` inspects the handle table, transfers the buffer to host stdout via `CoreServices::transfer`, and sets `IoStatusBlock.Information` to the transferred byte count with status `STATUS_SUCCESS` (`0x00000000`).

---

## 4. Crate Architecture & Carrick Seams

### 4.1 Repository Crate Layout (`carrick-nt`)

In accordance with `docs/superpowers/specs/2026-10-04-personality-core-split.md`, the NT personality lives in this dedicated repository (`carrick-sh/carrick-nt`), with dependencies pointing strictly **NT -> Carrick**.

```
carrick-nt/
├── Cargo.toml
├── AGENTS.md
├── docs/
│   └── design/
│       └── ntdll-bootstrap.md
├── crates/
│   ├── carrick-nt-abi/             # no_std: NT wire structs, NtStatus, NtServiceId
│   ├── carrick-personality-nt/     # Personality<X86_64Arch> implementation
│   ├── carrick-pe-loader/          # no_std PE/COFF parser, relocator, PEB/TEB builder
│   ├── carrick-ntdll/              # Guest CPL3 ntdll.dll implementation
│   ├── carrick-kernel32/           # Guest CPL3 kernel32.dll forwarders
│   ├── carrick-x86-cpl0-nt/        # Composition root: Carrick core + x86 + NT personality
│   └── carrick-conformance-nt/     # Oracle test runner & differential verification
└── tests/
    └── oracle/
        ├── fixtures/               # Clean-room test program sources
        └── receipts/               # Committed Windows Server 2025 oracle receipts
```

#### Detailed Crate Responsibilities
1. **`carrick-nt-abi` (`no_std`):**
   - NT status constants: `STATUS_SUCCESS (0x00000000)`, `STATUS_INVALID_HANDLE (0xC0000008)`, `STATUS_END_OF_FILE (0xC0000011)`.
   - NT wire types: `UNICODE_STRING`, `OBJECT_ATTRIBUTES`, `IO_STATUS_BLOCK`, `CLIENT_ID`.
   - Carrick NT system call identifiers: `NtServiceId` enumeration (`NtTerminateProcess`, `NtWriteFile`, `NtClose`, etc.).
2. **`carrick-personality-nt`:**
   - Implements `Personality<X86_64Arch>`.
   - Decodes `eax` (`NtServiceId`) and unpacks arguments from registers and guest user stack.
   - Manages handle table, process lifecycle, and status lowering.
3. **`carrick-pe-loader` (`no_std` + `alloc`):**
   - Standalone PE parser, section mapper, relocation calculator, import binder, and memory structure builder. Tested 100% VM-free in unit tests.
4. **`carrick-ntdll`:**
   - In-guest PE DLL exporting `NtWriteFile`, `NtTerminateProcess`, `NtClose`, `RtlExitUserProcess`.
   - Issues `syscall` with `NtServiceId` in `eax`.
5. **`carrick-kernel32`:**
   - In-guest PE DLL exporting `WriteFile`, `WriteConsoleA`, `WriteConsoleW`, `GetStdHandle`, `ExitProcess`.
   - Forwards calls to `carrick-ntdll`.
6. **`carrick-x86-cpl0-nt`:**
   - Image composition root crate. Compiles the bootable carrier image combining `carrick-core`, `carrick-x86`, and `carrick-personality-nt`.

### 4.2 Carrick Core Seams Consumed

The NT personality consumes the following neutral seams defined in Carrick's personality split specification:

1. **`Personality<A: EntryArch>` Trait:**
   ```rust
   impl Personality<X86_64Arch> for NtPersonality {
       type ProcessState = NtProcessState;
       type ThreadState = NtThreadState;
       type Call = NtCall;
       type Return = NtReturn;

       fn decode(&self, entry: &X86_64Frame, abi: GuestAbiProfile) -> Result<NtCall, EntryDecodeError>;
       fn dispatch(&mut self, call: NtCall, cx: &mut CallContext<'_, X86_64Arch>) -> ControlFlow<NtReturn>;
       fn resume(&mut self, continuation: ContinuationKey, cause: WakeCause, cx: &mut CallContext<'_, X86_64Arch>) -> ControlFlow<NtReturn>;
       fn fault(&mut self, fault: UserFault<X86_64Arch>, cx: &mut CallContext<'_, X86_64Arch>) -> ControlFlow<NtReturn>;
       fn encode_return(&self, value: NtReturn, frame: &mut X86_64Frame) -> Result<(), UserReturnError>;
   }
   ```
2. **`CoreServices<A: EntryArch>` Trait:**
   - `reserve(&mut self, mm, request)`: Reserves user virtual address space for PE images without backing frames.
   - `commit_pages(&mut self, reservation, range, backing, access)`: Commits memory pages with specific protection (`ReadExecute`, `ReadOnly`, `ReadWrite`).
   - `transfer(&mut self, permit, range)`: Safely writes PE headers, section bytes, and PEB/TEB data into guest memory.
   - `prepare_task` and `publish_task`: Manages task/thread birth and execution scheduling.

### 4.3 Proposed Personality-Neutral Upstream Carrick Issues

Nothing in Carrick may name NT or this repository. The following four seams are identified as missing or requiring extension upstream in `carrick`, drafted in strictly personality-neutral vocabulary:

---

#### Proposed Carrick Issue 1: Personality-Configurable Thread Pointer Base Register
- **Title:** `feat(core, arch): add personality-configurable thread base pointer register (FS/GS on x86_64, TPIDR/x18 on AArch64)`
- **Lane:** `arch`, `core`
- **Body:**
  - **Why:** Different operating system execution ABIs use different architectural registers for Thread Local Storage and thread environment context. Linux on x86_64 uses `FS_BASE` (`arch_prctl`), whereas alternative OS personalities require `GS_BASE` for user thread identity. On AArch64, some ABIs use `TPIDR_EL0`, while others reserve `x18`. Hard-coding the thread register prevents clean multi-personality support.
  - **What:** Extend `ThreadContext` and the `Personality` trait so that the registered personality specifies which architectural register serves as the thread context pointer. `carrick-x86` and `carrick-sched-core` must preserve, switch, and reload the chosen register during thread dispatch and context switching.
  - **Verified:** A VM-free test running two tasks with conflicting TLS register requirements (`FS_BASE` vs `GS_BASE`) verifies that each task preserves its respective register across preemption without clobbering.
- **Acceptance:**
  - Registered personalities can configure thread pointer base registers per task/thread.
  - x86_64 context switch restores `MSR_IA32_GS_BASE` and `MSR_IA32_FS_BASE` without leakage.
  - Zero personality-specific naming in `carrick-core` or `carrick-x86`.

---

#### Proposed Carrick Issue 2: Decouple Guest Image Packaging into Reusable Xtask Library
- **Title:** `refactor(build): export guest image packaging as a reusable xtask library supporting out-of-tree composition roots`
- **Lane:** `build`
- **Body:**
  - **Why:** `carrick-el1-image/build.rs` currently hard-codes relative filesystem paths (`../carrick-el1`) to package guest carrier images. Out-of-tree personality repositories cannot compose and package guest carrier images without duplicating complex image bundling logic.
  - **What:** Refactor guest image composition and packaging into a reusable xtask/library module in Carrick that accepts an arbitrary external composition root crate path and target architecture.
  - **Verified:** Build an example composition root from a detached path using the exported packaging library and verify the resulting carrier image boots under KVM.
- **Acceptance:**
  - Guest image build logic is callable as a library/xtask function from external workspaces.
  - No hard-coded directory assumptions or in-tree personality requirements.

---

#### Proposed Carrick Issue 3: Personality-Driven Stack Argument Decoding
- **Title:** `feat(core): support personality-driven stack argument decoding in entry frame decode`
- **Lane:** `core`
- **Body:**
  - **Why:** System call conventions for certain non-Linux ABIs pass more arguments than fit in the architectural register frame (e.g. more than 6 arguments). Arguments 7 through 11 are passed on the user stack. Currently, entry decoders only receive the CPU register snapshot and cannot safely access stack arguments.
  - **What:** Provide a bounded, fault-aware user stack reader helper within `CallContext` or `EntryArch` available during `Personality::decode`, allowing safe copyout of spilled arguments from guest user space before dispatch.
  - **Verified:** Unit test with a non-Linux test call taking 8 arguments confirms arguments 7 and 8 are correctly decoded from the stack, and unmapped stack addresses yield `EntryDecodeError::Fault` instead of kernel panics.
- **Acceptance:**
  - `Personality::decode` can safely inspect and copy stack-passed arguments.
  - Fault handling respects guest page protection and address boundaries.

---

#### Proposed Carrick Issue 4: Explicit Address-Space Reservation and Range Commit/Decommit Primitives
- **Title:** `feat(mmu-core): expose explicit address-space reservation and range commit/decommit primitives`
- **Lane:** `mmu-core`
- **Body:**
  - **Why:** Operating systems with two-stage virtual memory architectures (such as Win32 virtual memory) require reserving contiguous virtual address ranges upfront without allocating physical frames, followed by incremental committing and decommitting of pages within the reservation.
  - **What:** Expose explicit `reserve_range`, `commit_range`, and `decommit_range` operations on `PageTableManager` and `MmAuthority`.
  - **Verified:** Contract tests confirm that reserving 64 MiB consumes zero physical backing frames, committing a 4 KiB sub-range enables read/write access, and decommitting revokes access while retaining the reservation.
- **Acceptance:**
  - Two-stage reservation/commit semantics are exposed cleanly without POSIX/Linux assumptions.
  - Decommitted pages release physical frame custody while retaining VA bounds.

---

## 5. Differential Black-Box Testing & Oracle Toolchain

### 5.1 Differential Oracle Harness (Windows Server 2025)

In accordance with `AGENTS.md`, real Windows is the sole behavioral oracle. The oracle environment is hosted on willow VM 106 running Windows Server 2025 with Docker and Windows Containers enabled.

```
+-------------------------------------------------------------------------+
| Oracle Capture Phase (Runs on Willow VM 106 - Gated Director Run)        |
|                                                                         |
|  Clean-Room Test Program Source (tests/oracle/fixtures/hello_console.rs)|
|                               |                                         |
|                               v                                         |
|  Compiled Test Binary (hello_console.exe via x86_64-pc-windows-gnu)     |
|                               |                                         |
|                               v                                         |
|  Docker on Windows Server 2025 (mcr.microsoft.com/windows/nanoserver)    |
|   - Executes hello_console.exe                                          |
|   - Captures stdout, stderr, exit code, execution metadata              |
|                               |                                         |
|                               v                                         |
|  Committed Oracle Receipt (tests/oracle/receipts/hello_console.json)    |
+-------------------------------------------------------------------------+
                                |
                   Committed into Git Repository
                                |
+-------------------------------------------------------------------------+
| Conformance Verification Phase (Runs in Carrick CI / Offline Dev)        |
|                                                                         |
|  Carrick Host (Linux/KVM or macOS/HVF)                                  |
|   - Executes hello_console.exe under Carrick NT Carrier                 |
|   - Captures Carrick stdout, stderr, exit code                          |
|                               |                                         |
|                               v                                         |
|  Differential Evaluator (carrick-conformance-nt)                        |
|   - Compares Carrick observations against committed Oracle Receipt      |
|   - Asserts exact match (Byte-for-Byte stdout, identical exit code)     |
+-------------------------------------------------------------------------+
```

### 5.2 Committed Oracle Receipt Schema & Offline Verification

Oracle observations are recorded in structured, immutable JSON files committed under `tests/oracle/receipts/`. Routine CI runs perform 100% offline differential comparison against these receipts:

```json
{
  "$schema": "https://carrick.dev/schemas/oracle-receipt-v1.json",
  "metadata": {
    "test_name": "hello_console",
    "lane": "nt",
    "target_arch": "x86_64",
    "oracle_host": {
      "os": "Windows Server 2025 Datacenter",
      "build": "10.0.26100.1742",
      "container_image": "mcr.microsoft.com/windows/nanoserver:ltsc2025"
    },
    "source_hash_sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
    "binary_hash_sha256": "8f3b2c1e7a6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f",
    "captured_at_utc": "2026-10-10T22:00:00Z"
  },
  "execution": {
    "command": ["hello_console.exe"],
    "exit_code": 0,
    "stdout_raw": "Hello, Carrick NT!\r\n",
    "stdout_base64": "SGVsbG8sIENhcnJpY2sgTlQhDQo=",
    "stderr_raw": "",
    "stderr_base64": ""
  }
}
```

The conformance test harness (`carrick-conformance-nt`) parses the receipt, executes the identical binary on Carrick's NT carrier, and asserts:
1. `carrick.exit_code == oracle.execution.exit_code`
2. `carrick.stdout == base64_decode(oracle.execution.stdout_base64)`
3. `carrick.stderr == base64_decode(oracle.execution.stderr_base64)`

### 5.3 Clean-Room Test Program Toolchain (Zero Proprietary SDKs)

To prevent any intellectual property contamination or redistribution violations, test programs must be built without proprietary Microsoft Visual C++ headers (`windows.h`) or proprietary import libraries (`kernel32.lib`).

We specify two clean-room compilation paths:

#### Path 1: Pure Rust Clean-Room Toolchain (Primary)
- The test program is written in Rust targeting `x86_64-pc-windows-gnu` or `x86_64-pc-windows-msvc`.
- It depends strictly on `windows-sys` (generated directly from Microsoft's MIT-licensed `win32metadata` repository).
- Source for `hello_console.rs`:
  ```rust
  #![no_std]
  #![no_main]

  use core::panic::PanicInfo;
  use windows_sys::Win32::System::Console::{GetStdHandle, STD_OUTPUT_HANDLE};
  use windows_sys::Win32::Storage::FileSystem::WriteFile;
  use windows_sys::Win32::System::Threading::ExitProcess;

  #[no_mangle]
  pub extern "C" fn mainCRTStartup() -> ! {
      let stdout = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
      let msg = b"Hello, Carrick NT!\r\n";
      let mut written = 0u32;
      unsafe {
          WriteFile(
              stdout,
              msg.as_ptr(),
              msg.len() as u32,
              &mut written,
              core::ptr::null_mut(),
          );
          ExitProcess(0);
      }
  }

  #[panic_handler]
  fn panic(_info: &PanicInfo) -> ! {
      unsafe { ExitProcess(1) }
  }
  ```
- Built with standard `cargo build --target x86_64-pc-windows-gnu --release`. Zero proprietary Microsoft SDK files are involved.

#### Path 2: Freestanding LLVM/Clang Toolchain (Secondary C Option)
- Freestanding C compiled via Clang on Linux:
  `clang -target x86_64-pc-windows-gnu -nostdlib -ffreestanding -c hello.c -o hello.o`
- Linked using `lld-link` against an import library generated directly from clean-room `.def` files via `llvm-dlltool`:
  ```def
  LIBRARY KERNEL32.dll
  EXPORTS
      GetStdHandle
      WriteFile
      ExitProcess
  ```
- Both paths produce standard PE32+ console binaries with zero external proprietary dependencies.

---

## 6. Milestones, Acceptance Criteria & Issue Drafts

### 6.1 Roadmap Summary

```
+-----------------------------------------------------------------+
| M0: Oracle Harness & First Recorded Observation                 |
|   - Clean-room test builder + Windows container oracle capture  |
|   - hello_console.exe observation committed                     |
+-----------------------------------------------------------------+
                               |
                               v
+-----------------------------------------------------------------+
| M1: PE/COFF Loader Maps the Hello Executable                    |
|   - carrick-pe-loader parses PE, computes mappings, relocations |
|   - TEB, PEB, ProcessParameters initialized in guest memory      |
+-----------------------------------------------------------------+
                               |
                               v
+-----------------------------------------------------------------+
| M2: Hello Program Prints and Exits Under Carrick                |
|   - Clean-room ntdll.dll + kernel32.dll forwarders              |
|   - carrick-personality-nt dispatches NtWriteFile & Terminate   |
|   - End-to-end differential pass against M0 oracle              |
+-----------------------------------------------------------------+
                               |
                               v
+-----------------------------------------------------------------+
| M3: Widen to Argv, Environment & File I/O                       |
|   - Full CommandLine & Environment parsing in ProcessParameters |
|   - NtCreateFile, NtReadFile, NtClose support                   |
+-----------------------------------------------------------------+
```

---

### 6.2 Milestone M0: Oracle Harness & First Recorded Observation

#### Work Package NT-001: Clean-Room Console Test Program Builder
- **Issue Title:** `[NT-001] feat(test): clean-room console test program builder`
- **Lane:** `nt`
- **Body:**
  - **Why:** To verify NT personality execution differentially against real Windows, we require reproducible PE console test binaries compiled strictly without proprietary Microsoft SDK headers or import libraries.
  - **What:** Implement `crates/carrick-conformance-nt/fixtures/hello_console` in freestanding Rust targeting `x86_64-pc-windows-gnu`. The binary invokes `GetStdHandle(STD_OUTPUT_HANDLE)`, `WriteFile`, and `ExitProcess(0)`. Integrate build scripting in `xtask` to compile the fixture deterministically on Linux hosts.
  - **Verified:** Check that the compiled artifact is a valid 64-bit PE32+ console binary using `llvm-readobj` or `objdump`. Confirm zero link dependencies on proprietary MSVC libraries.
- **Acceptance Criteria:**
  - Clean-room `hello_console.exe` compiles reproducibly on Linux.
  - Binary header declares `IMAGE_FILE_MACHINE_AMD64` and `IMAGE_SUBSYSTEM_WINDOWS_CUI`.
  - Imports are restricted to `KERNEL32.dll` (`GetStdHandle`, `WriteFile`, `ExitProcess`).

#### Work Package NT-002: Windows Container Oracle Capture Harness
- **Issue Title:** `[NT-002] feat(oracle): windows container differential capture harness`
- **Lane:** `nt`
- **Body:**
  - **Why:** Differential testing requires executing test binaries in real Windows environments to capture authoritative stdout, stderr, and exit codes.
  - **What:** Create the automated oracle recording harness for willow VM 106. The harness deploys test binaries into a Windows container (`mcr.microsoft.com/windows/nanoserver:ltsc2025`), executes them, captures binary hashes, exit codes, and output streams, and generates structured JSON receipts adhering to `oracle-receipt-v1.json`.
  - **Verified:** Run the harness against `hello_console.exe` on willow VM 106; verify generated receipt captures exit code 0 and exact stdout bytes `"Hello, Carrick NT!\r\n"`.
- **Acceptance Criteria:**
  - Harness runs non-interactively via automated runner.
  - Generates valid `oracle-receipt-v1.json` files with SHA-256 hashes and base64 stream encodings.
  - Leaves zero persistent state or running containers on the oracle host.

#### Work Package NT-003: First Committed Oracle Receipt for Console Hello
- **Issue Title:** `[NT-003] test(oracle): commit baseline observation for hello_console`
- **Lane:** `nt`
- **Body:**
  - **Why:** Offline conformance testing requires committed oracle records in git so everyday CI can verify compatibility without accessing the Windows VM.
  - **What:** Check in `tests/oracle/receipts/hello_console.json` captured from Windows Server 2025. Add differential assertion test in `carrick-conformance-nt` verifying receipt schema and hash integrity.
  - **Verified:** `cargo test -p carrick-conformance-nt --test oracle_integrity` passes on Linux.
- **Acceptance Criteria:**
  - `tests/oracle/receipts/hello_console.json` committed to repository.
  - Integrity tests validate JSON schema and payload completeness.

---

### 6.3 Milestone M1: PE/COFF Loader Maps the Hello Executable

#### Work Package NT-004: Clean-Room PE/COFF Parser in `carrick-pe-loader`
- **Issue Title:** `[NT-004] feat(loader): clean-room pe/coff parser`
- **Lane:** `nt`
- **Body:**
  - **Why:** Carrick requires a `no_std` PE32+ parser to inspect Windows executables, validate headers, and calculate virtual memory layout according to the Microsoft PE/COFF specification.
  - **What:** Implement `PeImage` in `crates/carrick-pe-loader`. Parse DOS header, COFF header, Optional Header (PE32+), and Section Headers. Validate machine type (`AMD64`), subsystem (`WINDOWS_CUI`), and alignment constraints. Provide iterators for data directories and sections.
  - **Verified:** Unit tests in `carrick-pe-loader` parsing `hello_console.exe` verify section counts, entry point RVA, and image size match specification.
- **Acceptance Criteria:**
  - `no_std` + `alloc` implementation.
  - Fail-closed validation: rejects non-PE, 32-bit, or non-AMD64 binaries with typed errors.
  - 100% VM-free unit test coverage.

#### Work Package NT-005: Section Mapping & Memory Protection
- **Issue Title:** `[NT-005] feat(loader): section mapping and page protection integration`
- **Lane:** `nt`
- **Body:**
  - **Why:** The PE loader must map executable sections into guest address space with permissions matching PE section characteristics (`PAGE_EXECUTE_READ`, `PAGE_READONLY`, `PAGE_READWRITE`).
  - **What:** In `carrick-pe-loader`, implement `map_image_sections`. Consume `CoreServices::reserve` to reserve `SizeOfImage` and `CoreServices::commit_pages` to map headers and section data. Zero-fill uninitialized section space up to `VirtualSize`.
  - **Verified:** Test mapping against mock `CoreServices` memory tracking; verify pages have correct access flags and uninitialized data is zeroed.
- **Acceptance Criteria:**
  - Correct page access flags applied per section (`.text` RX, `.rdata` R, `.data` RW).
  - Headers mapped read-only at base.
  - BSS regions zero-filled.

#### Work Package NT-006: Base Relocation Engine
- **Issue Title:** `[NT-006] feat(loader): base relocation fixups for dynamic base images`
- **Lane:** `nt`
- **Body:**
  - **Why:** ASLR images or binaries mapped at an address other than their preferred `ImageBase` require base relocation fixups before execution.
  - **What:** Implement `apply_base_relocations` in `carrick-pe-loader`. Parse `IMAGE_BASE_RELOCATION` blocks from `.reloc`. Apply `IMAGE_REL_BASED_DIR64` fixups by adding the base address delta. Skip `IMAGE_REL_BASED_ABSOLUTE`.
  - **Verified:** Relocate `hello_console.exe` to an alternate base address; verify all 64-bit address references are correctly adjusted.
- **Acceptance Criteria:**
  - Handles `IMAGE_REL_BASED_DIR64` across page boundaries.
  - Rejects unknown relocation types.
  - Zero memory corruption on malformed relocation tables.

#### Work Package NT-007: PEB, TEB, and Process Parameters Memory Construction
- **Issue Title:** `[NT-007] feat(loader): peb, teb, and process parameters initialization`
- **Lane:** `nt`
- **Body:**
  - **Why:** Unmodified Windows binaries immediately fault if `GS:[0x30]` (`TEB.Self`) and `GS:[0x60]` (`PEB`) do not point to valid memory structures.
  - **What:** In `carrick-pe-loader`, build initial user-mode runtime memory images:
    - Layout `TEB` with `Self` pointer and `ClientId`.
    - Layout `PEB` with `ImageBaseAddress` and `ProcessParameters`.
    - Layout `RTL_USER_PROCESS_PARAMETERS` with standard handles and UTF-16 strings.
    - Write memory into guest address space and configure initial `GS_BASE`.
  - **Verified:** Unit test validates memory byte layout against Microsoft Learn `Winternl.h` structure offset definitions.
- **Acceptance Criteria:**
  - `TEB.Self` equals TEB guest virtual address.
  - `PEB` accurately reflects image base and process parameter pointers.
  - Standard handles point to valid initial handle descriptors.

---

### 6.4 Milestone M2: Hello Program Prints and Exits Under Carrick

#### Work Package NT-008: `carrick-nt-abi` Wire Types & System Call Enums
- **Issue Title:** `[NT-008] feat(abi): nt status codes, wire types, and service ids`
- **Lane:** `nt`
- **Body:**
  - **Why:** The NT personality and in-guest `ntdll` require shared, platform-neutral ABI definitions for status codes, wire structures, and system call numbers.
  - **What:** Implement `crates/carrick-nt-abi`:
    - `NtStatus` enum and constants (`STATUS_SUCCESS`, `STATUS_INVALID_HANDLE`, etc.).
    - Wire structs: `IO_STATUS_BLOCK`, `UNICODE_STRING`, `OBJECT_ATTRIBUTES`, `CLIENT_ID`.
    - Sequential `NtServiceId` enumeration (`NtTerminateProcess`, `NtWriteFile`, `NtClose`).
  - **Verified:** Ensure crate is `#![no_std]`, layout tests confirm `repr(C)` sizing.
- **Acceptance Criteria:**
  - `#![no_std]` without external dependencies.
  - Sizing and alignment match Windows x64 ABI standards.

#### Work Package NT-009: Clean-Room In-Guest `ntdll.dll` and `kernel32.dll`
- **Issue Title:** `[NT-009] feat(guest): clean-room ntdll and kernel32 forwarders`
- **Lane:** `nt`
- **Body:**
  - **Why:** Unmodified console binaries require dynamically importable `KERNEL32.dll` and `NTDLL.dll` PE shared libraries in guest user space.
  - **What:** Implement `crates/carrick-ntdll` and `crates/carrick-kernel32`:
    - `ntdll`: exports `NtWriteFile`, `NtTerminateProcess`, `NtClose`, `RtlExitUserProcess`. Emits x86_64 `syscall` stubs setting `eax = NtServiceId`.
    - `kernel32`: exports `WriteFile`, `WriteConsoleA`, `WriteConsoleW`, `GetStdHandle`, `ExitProcess`. Implements `GetStdHandle` by reading `PEB.ProcessParameters`. Forwards I/O and exit calls to `ntdll`.
  - **Verified:** Compile DLLs with `x86_64-pc-windows-gnu`. Verify exports with `llvm-readobj --coff-exports`.
- **Acceptance Criteria:**
  - DLLs export exact function names required by console binaries.
  - Clean-room Rust implementation with no external C runtime dependencies.

#### Work Package NT-010: NT Personality Implementation in `carrick-personality-nt`
- **Issue Title:** `[NT-010] feat(personality): nt personality call decoder and dispatch`
- **Lane:** `nt`
- **Body:**
  - **Why:** Carrick kernel needs an NT personality module to receive system calls from `carrick-ntdll` and execute them against Carrick core services.
  - **What:** Implement `Personality<X86_64Arch>` in `crates/carrick-personality-nt`:
    - Decode: map `eax` (`NtServiceId`) and register/stack parameters into `NtCall`.
    - Dispatch:
      - `NtTerminateProcess`: lower to `ControlFlow::Terminate`.
      - `NtWriteFile`: lookup handle, stream buffer to host stdout, update `IO_STATUS_BLOCK`.
    - Encode return: place `NtStatus` in `rax`.
  - **Verified:** Integration test using simulated `CallContext` executes `NtWriteFile` and `NtTerminateProcess` successfully.
- **Acceptance Criteria:**
  - Decodes register and stack arguments safely.
  - `NtWriteFile` updates `IO_STATUS_BLOCK.Information` with transferred bytes.
  - `NtTerminateProcess` terminates task with provided exit code.

#### Work Package NT-011: Composition Root & End-to-End Console Hello Execution
- **Issue Title:** `[NT-011] feat(carrier): compose nt carrier and execute hello_console`
- **Lane:** `nt`
- **Body:**
  - **Why:** Validate the full integration by running `hello_console.exe` under Carrick and matching the M0 oracle receipt.
  - **What:** Implement `carrick-x86-cpl0-nt` composition root. Wire `carrick-pe-loader`, `carrick-personality-nt`, and Carrick core. Execute `hello_console.exe` in `carrick-conformance-nt`.
  - **Verified:** Run `cargo test -p carrick-conformance-nt --test hello_console`. Verify stdout matches `"Hello, Carrick NT!\r\n"` and exit code is 0.
- **Acceptance Criteria:**
  - Unmodified `hello_console.exe` runs to completion.
  - Output and exit code match `tests/oracle/receipts/hello_console.json` byte-for-byte.
  - Zero unhandled faults or hypervisor crashes.

---

### 6.5 Milestone M3: Widen to Argv, Environment & File I/O

#### Work Package NT-012: Command Line & Environment Block Parsing
- **Issue Title:** `[NT-012] feat(loader): command line and environment block population`
- **Lane:** `nt`
- **Body:**
  - **Why:** Real console applications require command-line arguments (`GetCommandLineW`, `__argc`, `__argv`) and environment variables (`GetEnvironmentStringsW`).
  - **What:** Extend `carrick-pe-loader` to encode arbitrary command line strings and key-value environment pairs into `RTL_USER_PROCESS_PARAMETERS.CommandLine` and `Environment`. Implement parsing in `kernel32` forwarders.
  - **Verified:** Test binary echoing `CommandLine` and querying an environment variable matches committed oracle observation.
- **Acceptance Criteria:**
  - CommandLine properly formatted in UTF-16.
  - Double-null terminated UTF-16 environment block.
  - Differential oracle test passes.

#### Work Package NT-013: File System I/O Primitives
- **Issue Title:** `[NT-013] feat(personality): basic file io (ntcreatefile, ntreadfile)`
- **Lane:** `nt`
- **Body:**
  - **Why:** Console applications require reading configuration files and writing logs.
  - **What:** Implement `NtCreateFile`, `NtReadFile`, and `NtClose` in `carrick-personality-nt`. Lower NT paths (`\??\C:\path`) to Carrick VFS file operations. Wire corresponding Win32 APIs (`CreateFileW`, `ReadFile`, `CloseHandle`) in `carrick-kernel32`.
  - **Verified:** Test program creating, writing, and reading back a file verifies identical behavior against Windows container oracle.
- **Acceptance Criteria:**
  - NT handle table supports file objects with read/write access rights.
  - Status codes (`STATUS_OBJECT_NAME_NOT_FOUND`, `STATUS_END_OF_FILE`) match oracle.
  - Differential conformance tests pass.

---

## 7. References & Citations

1. **Microsoft Corporation**, *PE and COFF Specification*, Revision 11.0. Available at Microsoft Learn: `https://learn.microsoft.com/en-us/windows/win32/debug/pe-format`
   - Section 2: General Concepts
   - Section 3: MS-DOS Stub and COFF File Header
   - Section 3.4: Optional Header (Image Only)
   - Section 4: Section Table (Section Headers)
   - Section 6.4: The `.idata` Section (Import Directory Table)
   - Section 6.6: The `.reloc` Section (Base Relocations)
   - Section 6.7: The `.tls` Section (Thread Local Storage)
2. **Microsoft Corporation**, *x64 Software Conventions and ABI*. Available at Microsoft Learn: `https://learn.microsoft.com/en-us/cpp/build/x64-software-conventions`
3. **Microsoft Corporation**, *Winternl.h Header Documentation*:
   - `PEB` structure: `https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb`
   - `TEB` structure: `https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-teb`
   - `RTL_USER_PROCESS_PARAMETERS`: `https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-rtl_user_process_parameters`
4. **Microsoft Corporation**, *Windows Driver Kit (WDK) Native APIs*:
   - `NtWriteFile`: `https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntwritefile`
   - `NtTerminateProcess`: `https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntterminateprocess`
   - `NtClose`: `https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntclose`
5. **Microsoft Corporation**, *Win32 Console & Process APIs*:
   - `WriteFile`: `https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile`
   - `GetStdHandle`: `https://learn.microsoft.com/en-us/windows/console/getstdhandle`
   - `ExitProcess`: `https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitprocess`
6. **Microsoft Corporation**, *win32metadata Repository*, MIT License: `https://github.com/microsoft/win32metadata`
7. **Carrick Project Documentation**:
   - `AGENTS.md` (clean-room rules and commit standards)
   - `docs/superpowers/specs/2026-10-04-personality-core-split.md` (personality-neutral core split & seams)
   - `docs/personality-census.md` (architectural boundary classifications)
