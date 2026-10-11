# Carrick NT: PE Import Census (NT-014)

Data-driven analysis of DLL and API set exports required by real Windows executables, ranking export demand across clean-room built programs and standard Windows System32 console tools.

## Clean-Room Rules & Compliance

- Conforms strictly to repository `AGENTS.md`: no Wine/ReactOS source or test reuse, no leaked or decompiled Microsoft code.
- Public binaries were examined strictly via clean-room PE directory metadata (`carrick-pe-loader`); never disassembled or decompiled.
- Only derived import names, counts, and metadata are recorded; no bytes or binary images are committed.
- API set contracts and host DLL resolutions are learned exclusively from public Microsoft Learn documentation (cited below).

## Exact Re-Run Command

```bash
cargo xtask import-census
```

## Corpus Summary

- **Total Programs Scanned:** 27
  - **Clean-Room Built Programs:** 13
  - **Windows System32 Console Tools:** 14
- **Go Toolchain Status:** Go compiler not installed on host (`which go` returned not found); Go hello omitted.

## First Targets: Prioritized Guest DLL Exports

The following tables enumerate the mandatory exports needed from `ntdll.dll`, `kernel32.dll`, and `kernelbase.dll` to achieve complete coverage of all clean-room test programs plus the top-demanded exports across the Windows console utilities.

### 1. ntdll.dll First Targets

| Export Name | Source Demand |
|---|---|
| `DbgPrint` | Core demand |
| `NtCancelSynchronousIoFile` | Core demand |
| `NtClose` | Core demand |
| `NtCreateFile` | Core demand |
| `NtCreateNamedPipeFile` | Core demand |
| `NtFsControlFile` | Core demand |
| `NtOpenFile` | Core demand |
| `NtOpenProcessToken` | Core demand |
| `NtOpenThreadToken` | Core demand |
| `NtQueryDirectoryFile` | Core demand |
| `NtQueryEaFile` | Core demand |
| `NtQueryInformationFile` | Core demand |
| `NtQueryInformationProcess` | Core demand |
| `NtQueryInformationToken` | Core demand |
| `NtQuerySecurityObject` | Core demand |
| `NtQuerySystemInformationEx` | Core demand |
| `NtQuerySystemTime` | Core demand |
| `NtQueryVolumeInformationFile` | Core demand |
| `NtReadFile` | Core demand |
| `NtSetEaFile` | Core demand |
| `NtSetInformationFile` | Core demand |
| `NtSetInformationProcess` | Core demand |
| `NtWriteFile` | Core demand |
| `RtlAllocateHeap` | Core demand |
| `RtlCaptureContext` | Core demand |
| `RtlFreeHeap` | Core demand |
| `RtlFreeUnicodeString` | Core demand |
| `RtlLookupFunctionEntry` | Core demand |
| `RtlMultiByteToUnicodeN` | Core demand |
| `RtlNtStatusToDosError` | Core demand |
| `RtlUnicodeToOemN` | Core demand |
| `RtlVerifyVersionInfo` | Core demand |
| `RtlVirtualUnwind` | Core demand |
| `VerSetConditionMask` | Core demand |

### 2. kernel32.dll First Targets

| Export Name | Source Demand |
|---|---|
| `AddVectoredExceptionHandler` | Core demand |
| `CancelIo` | Core demand |
| `CloseHandle` | Core demand |
| `CompareStringOrdinal` | Core demand |
| `CompareStringW` | Core demand |
| `CopyFileExW` | Core demand |
| `CreateDirectoryW` | Core demand |
| `CreateEventW` | Core demand |
| `CreateFileMappingA` | Core demand |
| `CreateFileW` | Core demand |
| `CreateHardLinkW` | Core demand |
| `CreateMutexA` | Core demand |
| `CreatePipe` | Core demand |
| `CreateProcessW` | Core demand |
| `CreateSymbolicLinkW` | Core demand |
| `CreateThread` | Core demand |
| `CreateToolhelp32Snapshot` | Core demand |
| `CreateWaitableTimerExW` | Core demand |
| `DeleteCriticalSection` | Core demand |
| `DeleteFileW` | Core demand |
| `DeleteProcThreadAttributeList` | Core demand |
| `DeviceIoControl` | Core demand |
| `DuplicateHandle` | Core demand |
| `EnterCriticalSection` | Core demand |
| `ExitProcess` | Core demand |
| `FileTimeToSystemTime` | Core demand |
| `FindClose` | Core demand |
| `FindFirstFileExW` | Core demand |
| `FindNextFileW` | Core demand |
| `FlushFileBuffers` | Core demand |
| `FormatMessageW` | Core demand |
| `FreeEnvironmentStringsW` | Core demand |
| `GetCommandLineW` | Core demand |
| `GetConsoleMode` | Core demand |
| `GetConsoleOutputCP` | Core demand |
| `GetCurrentDirectoryW` | Core demand |
| `GetCurrentProcess` | Core demand |
| `GetCurrentProcessId` | Core demand |
| `GetCurrentThread` | Core demand |
| `GetCurrentThreadId` | Core demand |
| `GetEnvironmentStringsW` | Core demand |
| `GetEnvironmentVariableW` | Core demand |
| `GetExitCodeProcess` | Core demand |
| `GetFileAttributesW` | Core demand |
| `GetFileInformationByHandle` | Core demand |
| `GetFileInformationByHandleEx` | Core demand |
| `GetFileSizeEx` | Core demand |
| `GetFileType` | Core demand |
| `GetFinalPathNameByHandleW` | Core demand |
| `GetFullPathNameW` | Core demand |
| `GetLastError` | Core demand |
| `GetModuleFileNameW` | Core demand |
| `GetModuleHandleA` | Core demand |
| `GetModuleHandleW` | Core demand |
| `GetOverlappedResult` | Core demand |
| `GetProcAddress` | Core demand |
| `GetProcessHeap` | Core demand |
| `GetProcessId` | Core demand |
| `GetStartupInfoA` | Core demand |
| `GetStdHandle` | Core demand |
| `GetSystemDirectoryW` | Core demand |
| `GetSystemInfo` | Core demand |
| `GetSystemTimeAsFileTime` | Core demand |
| `GetSystemTimePreciseAsFileTime` | Core demand |
| `GetTempPathW` | Core demand |
| `GetTickCount` | Core demand |
| `GetTimeFormatW` | Core demand |
| `GetWindowsDirectoryW` | Core demand |
| `HeapAlloc` | Core demand |
| `HeapFree` | Core demand |
| `HeapReAlloc` | Core demand |
| `HeapSetInformation` | Core demand |
| `InitOnceBeginInitialize` | Core demand |
| `InitOnceComplete` | Core demand |
| `InitializeCriticalSection` | Core demand |
| `InitializeProcThreadAttributeList` | Core demand |
| `InitializeSListHead` | Core demand |
| `IsDebuggerPresent` | Core demand |
| `IsProcessorFeaturePresent` | Core demand |
| `LeaveCriticalSection` | Core demand |
| `LoadLibraryA` | Core demand |
| `LocalFree` | Core demand |
| `LockFileEx` | Core demand |
| `MapViewOfFile` | Core demand |
| `Module32FirstW` | Core demand |
| `Module32NextW` | Core demand |
| `MoveFileExW` | Core demand |
| `MultiByteToWideChar` | Core demand |
| `QueryPerformanceCounter` | Core demand |
| `QueryPerformanceFrequency` | Core demand |
| `RaiseException` | Core demand |
| `ReadConsoleW` | Core demand |
| `ReadFile` | Core demand |
| `ReadFileEx` | Core demand |
| `ReleaseMutex` | Core demand |
| `RemoveDirectoryW` | Core demand |
| `RtlCaptureContext` | Core demand |
| `RtlLookupFunctionEntry` | Core demand |
| `RtlUnwindEx` | Core demand |
| `RtlVirtualUnwind` | Core demand |
| `SetCurrentDirectoryW` | Core demand |
| `SetEnvironmentVariableW` | Core demand |
| `SetFileAttributesW` | Core demand |
| `SetFileInformationByHandle` | Core demand |
| `SetFilePointerEx` | Core demand |
| `SetFileTime` | Core demand |
| `SetHandleInformation` | Core demand |
| `SetLastError` | Core demand |
| `SetThreadStackGuarantee` | Core demand |
| `SetThreadUILanguage` | Core demand |
| `SetUnhandledExceptionFilter` | Core demand |
| `SetWaitableTimer` | Core demand |
| `Sleep` | Core demand |
| `SleepEx` | Core demand |
| `SwitchToThread` | Core demand |
| `TerminateProcess` | Core demand |
| `TlsAlloc` | Core demand |
| `TlsFree` | Core demand |
| `TlsGetValue` | Core demand |
| `TlsSetValue` | Core demand |
| `UnhandledExceptionFilter` | Core demand |
| `UnlockFile` | Core demand |
| `UnmapViewOfFile` | Core demand |
| `UpdateProcThreadAttribute` | Core demand |
| `VirtualProtect` | Core demand |
| `VirtualQuery` | Core demand |
| `WaitForMultipleObjects` | Core demand |
| `WaitForSingleObject` | Core demand |
| `WaitForSingleObjectEx` | Core demand |
| `WaitOnAddress` | Core demand |
| `WakeByAddressAll` | Core demand |
| `WakeByAddressSingle` | Core demand |
| `WideCharToMultiByte` | Core demand |
| `WriteConsoleW` | Core demand |
| `WriteFile` | Core demand |
| `WriteFileEx` | Core demand |
| `__C_specific_handler` | Core demand |
| `lstrlenW` | Core demand |

### 3. kernelbase.dll First Targets (API Set Implementations)

| Export Name | Source Demand |
|---|---|
| `AcquireSRWLockExclusive` | OneCore API Set demand |
| `ApiSetQueryApiSetPresence` | OneCore API Set demand |
| `FindClose` | OneCore API Set demand |
| `FormatMessageW` | OneCore API Set demand |
| `GetCommandLineW` | OneCore API Set demand |
| `GetConsoleMode` | OneCore API Set demand |
| `GetConsoleOutputCP` | OneCore API Set demand |
| `GetCurrentProcess` | OneCore API Set demand |
| `GetCurrentProcessId` | OneCore API Set demand |
| `GetCurrentThreadId` | OneCore API Set demand |
| `GetEnvironmentVariableW` | OneCore API Set demand |
| `GetFileType` | OneCore API Set demand |
| `GetLastError` | OneCore API Set demand |
| `GetModuleHandleW` | OneCore API Set demand |
| `GetSystemTimeAsFileTime` | OneCore API Set demand |
| `GetTickCount` | OneCore API Set demand |
| `HeapSetInformation` | OneCore API Set demand |
| `LocalFree` | OneCore API Set demand |
| `QueryPerformanceCounter` | OneCore API Set demand |
| `RegCloseKey` | OneCore API Set demand |
| `RegOpenKeyExW` | OneCore API Set demand |
| `RegQueryValueExW` | OneCore API Set demand |
| `RtlCaptureContext` | OneCore API Set demand |
| `RtlLookupFunctionEntry` | OneCore API Set demand |
| `RtlVirtualUnwind` | OneCore API Set demand |
| `SetUnhandledExceptionFilter` | OneCore API Set demand |
| `Sleep` | OneCore API Set demand |
| `TerminateProcess` | OneCore API Set demand |
| `UnhandledExceptionFilter` | OneCore API Set demand |
| `WaitOnAddress` | OneCore API Set demand |
| `WakeByAddressAll` | OneCore API Set demand |
| `WakeByAddressSingle` | OneCore API Set demand |
| `WideCharToMultiByte` | OneCore API Set demand |

## API Set Contract Catalog & Microsoft Learn Citations

| Contract Name | Versions Seen | Host DLL | Microsoft Learn Citation | Programs | Exports Count |
|---|---|---|---|---|---|
| `api-ms-win-core-synch` | `l1-1-0, l1-2-0` | kernelbase.dll / kernel32.dll | Microsoft Learn: Windows API sets (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) and API set loader operation (https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation): core OS contracts hosted in kernelbase.dll and kernel32.dll. | 15 | 25 |
| `api-ms-win-core-errorhandling` | `l1-1-0` | kernelbase.dll / kernel32.dll | Microsoft Learn: Windows API sets (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) and API set loader operation (https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation): core OS contracts hosted in kernelbase.dll and kernel32.dll. | 7 | 5 |
| `api-ms-win-core-libraryloader` | `l1-2-0` | kernelbase.dll / kernel32.dll | Microsoft Learn: Windows API sets (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) and API set loader operation (https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation): core OS contracts hosted in kernelbase.dll and kernel32.dll. | 7 | 8 |
| `api-ms-win-core-processthreads` | `l1-1-0, l1-1-1` | kernelbase.dll / kernel32.dll | Microsoft Learn: Windows API sets (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) and API set loader operation (https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation): core OS contracts hosted in kernelbase.dll and kernel32.dll. | 7 | 15 |
| `api-ms-win-core-profile` | `l1-1-0` | kernelbase.dll / kernel32.dll | Microsoft Learn: Windows API sets (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) and API set loader operation (https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation): core OS contracts hosted in kernelbase.dll and kernel32.dll. | 7 | 1 |
| `api-ms-win-core-sysinfo` | `l1-1-0` | kernelbase.dll / kernel32.dll | Microsoft Learn: Windows API sets (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) and API set loader operation (https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation): core OS contracts hosted in kernelbase.dll and kernel32.dll. | 7 | 8 |
| `api-ms-win-core-heap` | `l1-1-0, l2-1-0` | kernelbase.dll / kernel32.dll | Microsoft Learn: Windows API sets (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) and API set loader operation (https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation): core OS contracts hosted in kernelbase.dll and kernel32.dll. | 6 | 10 |
| `api-ms-win-core-processenvironment` | `l1-1-0, l1-2-0` | kernelbase.dll / kernel32.dll | Microsoft Learn: Windows API sets (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) and API set loader operation (https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation): core OS contracts hosted in kernelbase.dll and kernel32.dll. | 6 | 14 |
| `api-ms-win-core-console` | `l1-1-0, l2-1-0, l2-2-0, l3-2-0` | kernelbase.dll / kernel32.dll | Microsoft Learn: Windows API sets (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) and API set loader operation (https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation): core OS contracts hosted in kernelbase.dll and kernel32.dll. | 5 | 17 |
| `api-ms-win-core-file` | `l1-1-0, l1-2-2, l2-1-0, l2-1-2` | kernelbase.dll / kernel32.dll | Microsoft Learn: Windows API sets (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) and API set loader operation (https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation): core OS contracts hosted in kernelbase.dll and kernel32.dll. | 5 | 40 |
| `api-ms-win-core-localization` | `l1-2-0` | kernelbase.dll / kernel32.dll | Microsoft Learn: Windows API sets (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) and API set loader operation (https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation): core OS contracts hosted in kernelbase.dll and kernel32.dll. | 5 | 11 |
| `api-ms-win-crt-runtime` | `l1-1-0` | ucrtbase.dll | Microsoft Learn: Universal CRT deployment (https://learn.microsoft.com/en-us/cpp/windows/universal-crt-deployment) and Upgrade your code to the Universal CRT (https://learn.microsoft.com/en-us/cpp/porting/upgrade-your-code-to-the-universal-crt): api-ms-win-crt-* contracts resolve to ucrtbase.dll. | 5 | 18 |
| `api-ms-win-core-rtlsupport` | `l1-1-0` | kernelbase.dll / kernel32.dll | Microsoft Learn: Windows API sets (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) and API set loader operation (https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation): core OS contracts hosted in kernelbase.dll and kernel32.dll. | 4 | 3 |
| `api-ms-win-core-string` | `l1-1-0, l2-1-0` | kernelbase.dll / kernel32.dll | Microsoft Learn: Windows API sets (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) and API set loader operation (https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation): core OS contracts hosted in kernelbase.dll and kernel32.dll. | 4 | 5 |
| `api-ms-win-crt-heap` | `l1-1-0` | ucrtbase.dll | Microsoft Learn: Universal CRT deployment (https://learn.microsoft.com/en-us/cpp/windows/universal-crt-deployment) and Upgrade your code to the Universal CRT (https://learn.microsoft.com/en-us/cpp/porting/upgrade-your-code-to-the-universal-crt): api-ms-win-crt-* contracts resolve to ucrtbase.dll. | 4 | 2 |
| `api-ms-win-crt-locale` | `l1-1-0` | ucrtbase.dll | Microsoft Learn: Universal CRT deployment (https://learn.microsoft.com/en-us/cpp/windows/universal-crt-deployment) and Upgrade your code to the Universal CRT (https://learn.microsoft.com/en-us/cpp/porting/upgrade-your-code-to-the-universal-crt): api-ms-win-crt-* contracts resolve to ucrtbase.dll. | 4 | 1 |
| `api-ms-win-crt-math` | `l1-1-0` | ucrtbase.dll | Microsoft Learn: Universal CRT deployment (https://learn.microsoft.com/en-us/cpp/windows/universal-crt-deployment) and Upgrade your code to the Universal CRT (https://learn.microsoft.com/en-us/cpp/porting/upgrade-your-code-to-the-universal-crt): api-ms-win-crt-* contracts resolve to ucrtbase.dll. | 4 | 1 |
| `api-ms-win-crt-stdio` | `l1-1-0` | ucrtbase.dll | Microsoft Learn: Universal CRT deployment (https://learn.microsoft.com/en-us/cpp/windows/universal-crt-deployment) and Upgrade your code to the Universal CRT (https://learn.microsoft.com/en-us/cpp/porting/upgrade-your-code-to-the-universal-crt): api-ms-win-crt-* contracts resolve to ucrtbase.dll. | 4 | 2 |
| `api-ms-win-core-registry` | `l1-1-0` | kernelbase.dll / kernel32.dll | Microsoft Learn: Windows API sets (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) and API set loader operation (https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation): core OS contracts hosted in kernelbase.dll and kernel32.dll. | 3 | 9 |
| `api-ms-win-core-apiquery` | `l1-1-0` | kernelbase.dll / kernel32.dll | Microsoft Learn: Windows API sets (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) and API set loader operation (https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation): core OS contracts hosted in kernelbase.dll and kernel32.dll. | 2 | 1 |
| `api-ms-win-core-datetime` | `l1-1-0` | kernelbase.dll / kernel32.dll | Microsoft Learn: Windows API sets (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) and API set loader operation (https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation): core OS contracts hosted in kernelbase.dll and kernel32.dll. | 2 | 2 |
| `api-ms-win-core-delayload` | `l1-1-0, l1-1-1` | kernelbase.dll / kernel32.dll | Microsoft Learn: Windows API sets (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) and API set loader operation (https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation): core OS contracts hosted in kernelbase.dll and kernel32.dll. | 2 | 2 |
| `api-ms-win-core-handle` | `l1-1-0` | kernelbase.dll / kernel32.dll | Microsoft Learn: Windows API sets (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) and API set loader operation (https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation): core OS contracts hosted in kernelbase.dll and kernel32.dll. | 2 | 2 |
| `api-ms-win-core-memory` | `l1-1-0` | kernelbase.dll / kernel32.dll | Microsoft Learn: Windows API sets (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) and API set loader operation (https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation): core OS contracts hosted in kernelbase.dll and kernel32.dll. | 2 | 6 |
| `api-ms-win-core-timezone` | `l1-1-0` | kernelbase.dll / kernel32.dll | Microsoft Learn: Windows API sets (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) and API set loader operation (https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation): core OS contracts hosted in kernelbase.dll and kernel32.dll. | 2 | 2 |
| `api-ms-win-core-winrt` | `l1-1-0` | kernelbase.dll / kernel32.dll | Microsoft Learn: Windows API sets (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) and API set loader operation (https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation): core OS contracts hosted in kernelbase.dll and kernel32.dll. | 2 | 3 |
| `api-ms-win-security-base` | `l1-1-0` | advapi32.dll | Microsoft Learn: Windows umbrella libraries (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-umbrella-libraries): security contracts hosted in advapi32.dll. | 2 | 6 |
| `api-ms-win-core-com` | `l1-1-0` | kernelbase.dll / kernel32.dll | Microsoft Learn: Windows API sets (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) and API set loader operation (https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation): core OS contracts hosted in kernelbase.dll and kernel32.dll. | 1 | 6 |
| `api-ms-win-core-debug` | `l1-1-0` | kernelbase.dll / kernel32.dll | Microsoft Learn: Windows API sets (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) and API set loader operation (https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation): core OS contracts hosted in kernelbase.dll and kernel32.dll. | 1 | 3 |
| `api-ms-win-core-interlocked` | `l1-1-0` | kernelbase.dll / kernel32.dll | Microsoft Learn: Windows API sets (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) and API set loader operation (https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation): core OS contracts hosted in kernelbase.dll and kernel32.dll. | 1 | 1 |
| `api-ms-win-core-io` | `l1-1-0` | kernelbase.dll / kernel32.dll | Microsoft Learn: Windows API sets (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) and API set loader operation (https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation): core OS contracts hosted in kernelbase.dll and kernel32.dll. | 1 | 1 |
| `api-ms-win-core-kernel32-legacy` | `l1-1-0` | kernelbase.dll / kernel32.dll | Microsoft Learn: Windows API sets (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) and API set loader operation (https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation): core OS contracts hosted in kernelbase.dll and kernel32.dll. | 1 | 1 |
| `api-ms-win-core-misc` | `l1-1-0` | kernelbase.dll / kernel32.dll | Microsoft Learn: Windows API sets (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) and API set loader operation (https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation): core OS contracts hosted in kernelbase.dll and kernel32.dll. | 1 | 2 |
| `api-ms-win-core-processtopology` | `l1-1-0` | kernelbase.dll / kernel32.dll | Microsoft Learn: Windows API sets (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) and API set loader operation (https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation): core OS contracts hosted in kernelbase.dll and kernel32.dll. | 1 | 1 |
| `api-ms-win-core-string-obsolete` | `l1-1-0` | kernelbase.dll / kernel32.dll | Microsoft Learn: Windows API sets (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) and API set loader operation (https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation): core OS contracts hosted in kernelbase.dll and kernel32.dll. | 1 | 1 |
| `api-ms-win-core-systemtopology` | `l1-1-0` | kernelbase.dll / kernel32.dll | Microsoft Learn: Windows API sets (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) and API set loader operation (https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation): core OS contracts hosted in kernelbase.dll and kernel32.dll. | 1 | 2 |
| `api-ms-win-core-threadpool` | `l1-2-0` | kernelbase.dll / kernel32.dll | Microsoft Learn: Windows API sets (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) and API set loader operation (https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation): core OS contracts hosted in kernelbase.dll and kernel32.dll. | 1 | 4 |
| `api-ms-win-core-version` | `l1-1-0` | kernelbase.dll / kernel32.dll | Microsoft Learn: Windows API sets (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) and API set loader operation (https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation): core OS contracts hosted in kernelbase.dll and kernel32.dll. | 1 | 3 |
| `api-ms-win-core-winrt-string` | `l1-1-0` | kernelbase.dll / kernel32.dll | Microsoft Learn: Windows API sets (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) and API set loader operation (https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation): core OS contracts hosted in kernelbase.dll and kernel32.dll. | 1 | 4 |
| `api-ms-win-crt-private` | `l1-1-0` | ucrtbase.dll | Microsoft Learn: Universal CRT deployment (https://learn.microsoft.com/en-us/cpp/windows/universal-crt-deployment) and Upgrade your code to the Universal CRT (https://learn.microsoft.com/en-us/cpp/porting/upgrade-your-code-to-the-universal-crt): api-ms-win-crt-* contracts resolve to ucrtbase.dll. | 1 | 81 |
| `api-ms-win-crt-string` | `l1-1-0` | ucrtbase.dll | Microsoft Learn: Universal CRT deployment (https://learn.microsoft.com/en-us/cpp/windows/universal-crt-deployment) and Upgrade your code to the Universal CRT (https://learn.microsoft.com/en-us/cpp/porting/upgrade-your-code-to-the-universal-crt): api-ms-win-crt-* contracts resolve to ucrtbase.dll. | 1 | 4 |
| `api-ms-win-crt-time` | `l1-1-0` | ucrtbase.dll | Microsoft Learn: Universal CRT deployment (https://learn.microsoft.com/en-us/cpp/windows/universal-crt-deployment) and Upgrade your code to the Universal CRT (https://learn.microsoft.com/en-us/cpp/porting/upgrade-your-code-to-the-universal-crt): api-ms-win-crt-* contracts resolve to ucrtbase.dll. | 1 | 1 |
| `api-ms-win-eventing-provider` | `l1-1-0` | *Unresolved* | None (unresolved) | 1 | 4 |
| `api-ms-win-security-lsapolicy` | `l1-1-0` | advapi32.dll | Microsoft Learn: Windows umbrella libraries (https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-umbrella-libraries): security contracts hosted in advapi32.dll. | 1 | 5 |
| `ext-ms-win-appmodel-shellexecute` | `l1-1-0` | *Unresolved* | None (unresolved) | 1 | 1 |
| `ext-ms-win-branding-winbrand` | `l1-1-0` | *Unresolved* | None (unresolved) | 1 | 1 |
| `ext-ms-win-cmd-util` | `l1-1-0` | *Unresolved* | None (unresolved) | 1 | 13 |
| `ext-ms-win-ntuser-chartranslation` | `l1-1-0` | *Unresolved* | None (unresolved) | 1 | 1 |

## Ranked Table of Imports (Top 100)

| Rank | Export Symbol | DLL or API Set Contract | Type | Resolved Host DLL | Count | Programs |
|---|---|---|---|---|---|---|
| 1 | `__set_app_type` | `msvcrt.dll` | DLL | - | 17 | certutil.exe, fc.exe, find.exe, findstr.exe, hostname.exe, ipconfig.exe, more.com, robocopy.exe, rust_env_argv_gnu.exe, rust_file_io_gnu.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe, sort.exe, tasklist.exe, where.exe, whoami.exe, xcopy.exe |
| 2 | `__setusermatherr` | `msvcrt.dll` | DLL | - | 17 | certutil.exe, fc.exe, find.exe, findstr.exe, hostname.exe, ipconfig.exe, more.com, robocopy.exe, rust_env_argv_gnu.exe, rust_file_io_gnu.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe, sort.exe, tasklist.exe, where.exe, whoami.exe, xcopy.exe |
| 3 | `_amsg_exit` | `msvcrt.dll` | DLL | - | 17 | certutil.exe, fc.exe, find.exe, findstr.exe, hostname.exe, ipconfig.exe, more.com, robocopy.exe, rust_env_argv_gnu.exe, rust_file_io_gnu.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe, sort.exe, tasklist.exe, where.exe, whoami.exe, xcopy.exe |
| 4 | `_cexit` | `msvcrt.dll` | DLL | - | 17 | certutil.exe, fc.exe, find.exe, findstr.exe, hostname.exe, ipconfig.exe, more.com, robocopy.exe, rust_env_argv_gnu.exe, rust_file_io_gnu.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe, sort.exe, tasklist.exe, where.exe, whoami.exe, xcopy.exe |
| 5 | `_commode` | `msvcrt.dll` | DLL | - | 17 | certutil.exe, fc.exe, find.exe, findstr.exe, hostname.exe, ipconfig.exe, more.com, robocopy.exe, rust_env_argv_gnu.exe, rust_file_io_gnu.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe, sort.exe, tasklist.exe, where.exe, whoami.exe, xcopy.exe |
| 6 | `_fmode` | `msvcrt.dll` | DLL | - | 17 | certutil.exe, fc.exe, find.exe, findstr.exe, hostname.exe, ipconfig.exe, more.com, robocopy.exe, rust_env_argv_gnu.exe, rust_file_io_gnu.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe, sort.exe, tasklist.exe, where.exe, whoami.exe, xcopy.exe |
| 7 | `_initterm` | `msvcrt.dll` | DLL | - | 17 | certutil.exe, fc.exe, find.exe, findstr.exe, hostname.exe, ipconfig.exe, more.com, robocopy.exe, rust_env_argv_gnu.exe, rust_file_io_gnu.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe, sort.exe, tasklist.exe, where.exe, whoami.exe, xcopy.exe |
| 8 | `exit` | `msvcrt.dll` | DLL | - | 17 | certutil.exe, fc.exe, find.exe, findstr.exe, hostname.exe, ipconfig.exe, more.com, robocopy.exe, rust_env_argv_gnu.exe, rust_file_io_gnu.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe, sort.exe, tasklist.exe, where.exe, whoami.exe, xcopy.exe |
| 9 | `CloseHandle` | `kernel32.dll` | DLL | - | 16 | c_file_io.exe, c_thread_spawn.exe, certutil.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe, sort.exe, tasklist.exe, where.exe, whoami.exe |
| 10 | `GetCurrentThreadId` | `kernel32.dll` | DLL | - | 16 | certutil.exe, fc.exe, find.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe, sort.exe, tasklist.exe, where.exe, whoami.exe |
| 11 | `GetStdHandle` | `kernel32.dll` | DLL | - | 16 | c_hello.exe, certutil.exe, hello_console.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe, sort.exe, tasklist.exe, where.exe, whoami.exe |
| 12 | `GetCurrentProcess` | `kernel32.dll` | DLL | - | 15 | certutil.exe, fc.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe, sort.exe, tasklist.exe, where.exe, whoami.exe |
| 13 | `GetCurrentProcessId` | `kernel32.dll` | DLL | - | 15 | certutil.exe, fc.exe, find.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe, sort.exe, where.exe, whoami.exe |
| 14 | `GetModuleHandleW` | `kernel32.dll` | DLL | - | 15 | certutil.exe, fc.exe, find.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe, sort.exe, where.exe, whoami.exe |
| 15 | `QueryPerformanceCounter` | `kernel32.dll` | DLL | - | 15 | certutil.exe, fc.exe, find.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe, sort.exe, where.exe, whoami.exe |
| 16 | `SetUnhandledExceptionFilter` | `kernel32.dll` | DLL | - | 15 | certutil.exe, fc.exe, find.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe, sort.exe, where.exe, whoami.exe |
| 17 | `GetConsoleMode` | `kernel32.dll` | DLL | - | 14 | certutil.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe, sort.exe, tasklist.exe, where.exe, whoami.exe |
| 18 | `GetLastError` | `kernel32.dll` | DLL | - | 14 | certutil.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe, sort.exe, tasklist.exe, where.exe, whoami.exe |
| 19 | `GetProcessHeap` | `kernel32.dll` | DLL | - | 14 | certutil.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe, sort.exe, tasklist.exe, where.exe, whoami.exe |
| 20 | `HeapAlloc` | `kernel32.dll` | DLL | - | 14 | certutil.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe, sort.exe, tasklist.exe, where.exe, whoami.exe |
| 21 | `HeapFree` | `kernel32.dll` | DLL | - | 14 | certutil.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe, sort.exe, tasklist.exe, where.exe, whoami.exe |
| 22 | `WideCharToMultiByte` | `kernel32.dll` | DLL | - | 14 | certutil.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe, sort.exe, tasklist.exe, where.exe, whoami.exe |
| 23 | `ExitProcess` | `kernel32.dll` | DLL | - | 13 | c_env_argv.exe, c_file_io.exe, c_hello.exe, c_thread_spawn.exe, hello_console.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_file_io_gnu.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe, tasklist.exe, where.exe, whoami.exe |
| 24 | `FormatMessageW` | `kernel32.dll` | DLL | - | 13 | certutil.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe, tasklist.exe, where.exe, whoami.exe |
| 25 | `GetConsoleOutputCP` | `kernel32.dll` | DLL | - | 13 | certutil.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe, tasklist.exe, where.exe, whoami.exe |
| 26 | `SetLastError` | `kernel32.dll` | DLL | - | 13 | certutil.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe, tasklist.exe, where.exe, whoami.exe |
| 27 | `WriteConsoleW` | `kernel32.dll` | DLL | - | 13 | certutil.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe, tasklist.exe, where.exe, whoami.exe |
| 28 | `lstrlenW` | `kernel32.dll` | DLL | - | 13 | certutil.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe, tasklist.exe, where.exe, whoami.exe |
| 29 | `?terminate@@YAXXZ` | `msvcrt.dll` | DLL | - | 13 | certutil.exe, fc.exe, find.exe, findstr.exe, hostname.exe, ipconfig.exe, more.com, robocopy.exe, sort.exe, tasklist.exe, where.exe, whoami.exe, xcopy.exe |
| 30 | `_XcptFilter` | `msvcrt.dll` | DLL | - | 13 | certutil.exe, fc.exe, find.exe, findstr.exe, hostname.exe, ipconfig.exe, more.com, robocopy.exe, sort.exe, tasklist.exe, where.exe, whoami.exe, xcopy.exe |
| 31 | `__C_specific_handler` | `msvcrt.dll` | DLL | - | 13 | certutil.exe, fc.exe, find.exe, findstr.exe, hostname.exe, ipconfig.exe, more.com, robocopy.exe, sort.exe, tasklist.exe, where.exe, whoami.exe, xcopy.exe |
| 32 | `__iob_func` | `msvcrt.dll` | DLL | - | 13 | certutil.exe, findstr.exe, hostname.exe, ipconfig.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_file_io_gnu.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe, sort.exe, tasklist.exe, where.exe, whoami.exe |
| 33 | `_exit` | `msvcrt.dll` | DLL | - | 13 | certutil.exe, fc.exe, find.exe, findstr.exe, hostname.exe, ipconfig.exe, more.com, robocopy.exe, sort.exe, tasklist.exe, where.exe, whoami.exe, xcopy.exe |
| 34 | `memset` | `msvcrt.dll` | DLL | - | 13 | certutil.exe, findstr.exe, ipconfig.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_file_io_gnu.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe, sort.exe, tasklist.exe, where.exe, whoami.exe, xcopy.exe |
| 35 | `GetProcAddress` | `kernel32.dll` | DLL | - | 12 | certutil.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe, sort.exe, tasklist.exe |
| 36 | `HeapReAlloc` | `kernel32.dll` | DLL | - | 12 | robocopy.exe, rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe, tasklist.exe, where.exe, whoami.exe |
| 37 | `WaitForSingleObject` | `kernel32.dll` | DLL | - | 12 | c_thread_spawn.exe, certutil.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe, sort.exe |
| 38 | `GetEnvironmentVariableW` | `kernel32.dll` | DLL | - | 11 | c_env_argv.exe, certutil.exe, rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe, where.exe |
| 39 | `GetSystemTimeAsFileTime` | `kernel32.dll` | DLL | - | 11 | certutil.exe, fc.exe, find.exe, robocopy.exe, rust_env_argv_msvc.exe, rust_file_io_msvc.exe, rust_hello_msvc.exe, rust_thread_spawn_msvc.exe, sort.exe, where.exe, whoami.exe |
| 40 | `MultiByteToWideChar` | `kernel32.dll` | DLL | - | 11 | certutil.exe, rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe, sort.exe, tasklist.exe |
| 41 | `Sleep` | `kernel32.dll` | DLL | - | 11 | certutil.exe, fc.exe, find.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_file_io_gnu.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe, sort.exe, where.exe, whoami.exe |
| 42 | `fprintf` | `msvcrt.dll` | DLL | - | 11 | certutil.exe, findstr.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_file_io_gnu.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe, sort.exe, tasklist.exe, where.exe, whoami.exe |
| 43 | `memcpy` | `msvcrt.dll` | DLL | - | 11 | certutil.exe, findstr.exe, ipconfig.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_file_io_gnu.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe, sort.exe, tasklist.exe, whoami.exe |
| 44 | `RtlNtStatusToDosError` | `ntdll.dll` | DLL | - | 11 | cmd.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe, tasklist.exe |
| 45 | `GetFileType` | `kernel32.dll` | DLL | - | 10 | certutil.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_file_io_gnu.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe, sort.exe, tasklist.exe, where.exe, whoami.exe |
| 46 | `RtlCaptureContext` | `kernel32.dll` | DLL | - | 10 | robocopy.exe, rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe, where.exe |
| 47 | `RtlLookupFunctionEntry` | `kernel32.dll` | DLL | - | 10 | robocopy.exe, rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe, where.exe |
| 48 | `RtlVirtualUnwind` | `kernel32.dll` | DLL | - | 10 | robocopy.exe, rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe, where.exe |
| 49 | `TerminateProcess` | `kernel32.dll` | DLL | - | 10 | certutil.exe, fc.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_file_io_gnu.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe, sort.exe, where.exe, whoami.exe |
| 50 | `UnhandledExceptionFilter` | `kernel32.dll` | DLL | - | 10 | certutil.exe, fc.exe, robocopy.exe, rust_env_argv_msvc.exe, rust_file_io_msvc.exe, rust_hello_msvc.exe, rust_thread_spawn_msvc.exe, sort.exe, where.exe, whoami.exe |
| 51 | `__getmainargs` | `msvcrt.dll` | DLL | - | 10 | fc.exe, find.exe, findstr.exe, more.com, rust_env_argv_gnu.exe, rust_file_io_gnu.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe, sort.exe, xcopy.exe |
| 52 | `CreateFileW` | `kernel32.dll` | DLL | - | 9 | c_file_io.exe, certutil.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe, where.exe |
| 53 | `GetCurrentDirectoryW` | `kernel32.dll` | DLL | - | 9 | rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe, where.exe |
| 54 | `GetCurrentThread` | `kernel32.dll` | DLL | - | 9 | certutil.exe, rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe |
| 55 | `GetModuleHandleA` | `kernel32.dll` | DLL | - | 9 | rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe, sort.exe |
| 56 | `malloc` | `msvcrt.dll` | DLL | - | 9 | certutil.exe, findstr.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_file_io_gnu.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe, tasklist.exe, whoami.exe |
| 57 | `WaitOnAddress` | `api-ms-win-core-synch` | API Set | kernelbase.dll / kernel32.dll | 8 | rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe |
| 58 | `WakeByAddressAll` | `api-ms-win-core-synch` | API Set | kernelbase.dll / kernel32.dll | 8 | rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe |
| 59 | `WakeByAddressSingle` | `api-ms-win-core-synch` | API Set | kernelbase.dll / kernel32.dll | 8 | rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe |
| 60 | `AddVectoredExceptionHandler` | `kernel32.dll` | DLL | - | 8 | rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe |
| 61 | `CreateThread` | `kernel32.dll` | DLL | - | 8 | c_thread_spawn.exe, certutil.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_file_io_gnu.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe |
| 62 | `DeleteFileW` | `kernel32.dll` | DLL | - | 8 | c_file_io.exe, certutil.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe |
| 63 | `GetFullPathNameW` | `kernel32.dll` | DLL | - | 8 | certutil.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe, where.exe |
| 64 | `GetModuleFileNameW` | `kernel32.dll` | DLL | - | 8 | rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe, tasklist.exe, where.exe, whoami.exe |
| 65 | `HeapSetInformation` | `kernel32.dll` | DLL | - | 8 | certutil.exe, fc.exe, find.exe, robocopy.exe, sort.exe, tasklist.exe, where.exe, whoami.exe |
| 66 | `ReadFile` | `kernel32.dll` | DLL | - | 8 | c_file_io.exe, certutil.exe, rust_env_argv_gnu.exe, rust_file_io_gnu.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe, sort.exe, tasklist.exe |
| 67 | `SetThreadStackGuarantee` | `kernel32.dll` | DLL | - | 8 | rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe |
| 68 | `_fileno` | `msvcrt.dll` | DLL | - | 8 | certutil.exe, findstr.exe, hostname.exe, ipconfig.exe, robocopy.exe, tasklist.exe, where.exe, whoami.exe |
| 69 | `free` | `msvcrt.dll` | DLL | - | 8 | certutil.exe, findstr.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_file_io_gnu.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe, tasklist.exe |
| 70 | `memmove` | `msvcrt.dll` | DLL | - | 8 | certutil.exe, fc.exe, findstr.exe, rust_env_argv_gnu.exe, rust_file_io_gnu.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe, whoami.exe |
| 71 | `NtWriteFile` | `ntdll.dll` | DLL | - | 8 | rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_hello_msvc.exe, rust_thread_spawn_gnu.exe, rust_thread_spawn_msvc.exe |
| 72 | `SetUnhandledExceptionFilter` | `api-ms-win-core-errorhandling` | API Set | kernelbase.dll / kernel32.dll | 7 | cmd.exe, findstr.exe, hostname.exe, ipconfig.exe, more.com, tasklist.exe, xcopy.exe |
| 73 | `UnhandledExceptionFilter` | `api-ms-win-core-errorhandling` | API Set | kernelbase.dll / kernel32.dll | 7 | cmd.exe, findstr.exe, hostname.exe, ipconfig.exe, more.com, tasklist.exe, xcopy.exe |
| 74 | `GetModuleHandleW` | `api-ms-win-core-libraryloader` | API Set | kernelbase.dll / kernel32.dll | 7 | cmd.exe, findstr.exe, hostname.exe, ipconfig.exe, more.com, tasklist.exe, xcopy.exe |
| 75 | `GetCurrentProcessId` | `api-ms-win-core-processthreads` | API Set | kernelbase.dll / kernel32.dll | 7 | cmd.exe, findstr.exe, hostname.exe, ipconfig.exe, more.com, tasklist.exe, xcopy.exe |
| 76 | `TerminateProcess` | `api-ms-win-core-processthreads` | API Set | kernelbase.dll / kernel32.dll | 7 | cmd.exe, findstr.exe, hostname.exe, ipconfig.exe, more.com, tasklist.exe, xcopy.exe |
| 77 | `QueryPerformanceCounter` | `api-ms-win-core-profile` | API Set | kernelbase.dll / kernel32.dll | 7 | cmd.exe, findstr.exe, hostname.exe, ipconfig.exe, more.com, tasklist.exe, xcopy.exe |
| 78 | `GetSystemTimeAsFileTime` | `api-ms-win-core-sysinfo` | API Set | kernelbase.dll / kernel32.dll | 7 | cmd.exe, findstr.exe, hostname.exe, ipconfig.exe, more.com, tasklist.exe, xcopy.exe |
| 79 | `FindClose` | `kernel32.dll` | DLL | - | 7 | certutil.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_file_io_gnu.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe, where.exe |
| 80 | `GetCommandLineW` | `kernel32.dll` | DLL | - | 7 | c_env_argv.exe, certutil.exe, rust_env_argv_gnu.exe, rust_env_argv_msvc.exe, rust_file_io_gnu.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe |
| 81 | `GetFileAttributesW` | `kernel32.dll` | DLL | - | 7 | certutil.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_file_io_gnu.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe, where.exe |
| 82 | `GetFileInformationByHandle` | `kernel32.dll` | DLL | - | 7 | robocopy.exe, rust_env_argv_gnu.exe, rust_file_io_gnu.exe, rust_file_io_msvc.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe, where.exe |
| 83 | `GetTickCount` | `kernel32.dll` | DLL | - | 7 | certutil.exe, fc.exe, find.exe, robocopy.exe, sort.exe, where.exe, whoami.exe |
| 84 | `__wgetmainargs` | `msvcrt.dll` | DLL | - | 7 | certutil.exe, hostname.exe, ipconfig.exe, robocopy.exe, tasklist.exe, where.exe, whoami.exe |
| 85 | `_onexit` | `msvcrt.dll` | DLL | - | 7 | certutil.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_file_io_gnu.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe, whoami.exe |
| 86 | `fflush` | `msvcrt.dll` | DLL | - | 7 | certutil.exe, hostname.exe, ipconfig.exe, robocopy.exe, tasklist.exe, where.exe, whoami.exe |
| 87 | `RtlCaptureContext` | `ntdll.dll` | DLL | - | 7 | certutil.exe, cmd.exe, fc.exe, findstr.exe, more.com, sort.exe, whoami.exe |
| 88 | `RtlLookupFunctionEntry` | `ntdll.dll` | DLL | - | 7 | certutil.exe, cmd.exe, fc.exe, findstr.exe, more.com, sort.exe, whoami.exe |
| 89 | `RtlVirtualUnwind` | `ntdll.dll` | DLL | - | 7 | certutil.exe, cmd.exe, fc.exe, findstr.exe, more.com, sort.exe, whoami.exe |
| 90 | `GetCurrentProcess` | `api-ms-win-core-processthreads` | API Set | kernelbase.dll / kernel32.dll | 6 | cmd.exe, findstr.exe, hostname.exe, ipconfig.exe, more.com, xcopy.exe |
| 91 | `GetCurrentThreadId` | `api-ms-win-core-processthreads` | API Set | kernelbase.dll / kernel32.dll | 6 | cmd.exe, findstr.exe, hostname.exe, ipconfig.exe, more.com, xcopy.exe |
| 92 | `Sleep` | `api-ms-win-core-synch` | API Set | kernelbase.dll / kernel32.dll | 6 | findstr.exe, hostname.exe, ipconfig.exe, more.com, tasklist.exe, xcopy.exe |
| 93 | `GetTickCount` | `api-ms-win-core-sysinfo` | API Set | kernelbase.dll / kernel32.dll | 6 | findstr.exe, hostname.exe, ipconfig.exe, more.com, tasklist.exe, xcopy.exe |
| 94 | `CompareStringW` | `kernel32.dll` | DLL | - | 6 | certutil.exe, find.exe, robocopy.exe, tasklist.exe, where.exe, whoami.exe |
| 95 | `CreateDirectoryW` | `kernel32.dll` | DLL | - | 6 | certutil.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_file_io_gnu.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe |
| 96 | `CreateEventW` | `kernel32.dll` | DLL | - | 6 | certutil.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_file_io_gnu.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe |
| 97 | `DeleteCriticalSection` | `kernel32.dll` | DLL | - | 6 | certutil.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_file_io_gnu.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe |
| 98 | `EnterCriticalSection` | `kernel32.dll` | DLL | - | 6 | certutil.exe, robocopy.exe, rust_env_argv_gnu.exe, rust_file_io_gnu.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe |
| 99 | `FindNextFileW` | `kernel32.dll` | DLL | - | 6 | certutil.exe, rust_env_argv_gnu.exe, rust_file_io_gnu.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe, where.exe |
| 100 | `GetSystemDirectoryW` | `kernel32.dll` | DLL | - | 6 | certutil.exe, rust_env_argv_gnu.exe, rust_file_io_gnu.exe, rust_hello_gnu.exe, rust_thread_spawn_gnu.exe, tasklist.exe |

## Per-Program Import Summaries

### c_env_argv.exe

- **Category:** clean_room_built
- **Path:** `target/census-fixtures/c_env_argv.exe`
- **Total Imports:** 4
- **Modules Imported:**

| Module / Contract | Mechanism | Symbols Count | Sample Symbols |
|---|---|---|---|
| `KERNEL32.dll` | standard | 4 | `ExitProcess, GetCommandLineW, GetEnvironmentVariableW, ...` |

### c_file_io.exe

- **Category:** clean_room_built
- **Path:** `target/census-fixtures/c_file_io.exe`
- **Total Imports:** 6
- **Modules Imported:**

| Module / Contract | Mechanism | Symbols Count | Sample Symbols |
|---|---|---|---|
| `KERNEL32.dll` | standard | 6 | `CloseHandle, CreateFileW, DeleteFileW, ...` |

### c_hello.exe

- **Category:** clean_room_built
- **Path:** `target/census-fixtures/c_hello.exe`
- **Total Imports:** 3
- **Modules Imported:**

| Module / Contract | Mechanism | Symbols Count | Sample Symbols |
|---|---|---|---|
| `KERNEL32.dll` | standard | 3 | `ExitProcess, GetStdHandle, WriteFile` |

### c_thread_spawn.exe

- **Category:** clean_room_built
- **Path:** `target/census-fixtures/c_thread_spawn.exe`
- **Total Imports:** 4
- **Modules Imported:**

| Module / Contract | Mechanism | Symbols Count | Sample Symbols |
|---|---|---|---|
| `KERNEL32.dll` | standard | 4 | `CloseHandle, CreateThread, ExitProcess, ...` |

### certutil.exe

- **Category:** system32_console
- **Path:** `/home/carrick/nt-census-inputs/system32/certutil.exe`
- **Total Imports:** 831
- **Modules Imported:**

| Module / Contract | Mechanism | Symbols Count | Sample Symbols |
|---|---|---|---|
| `ADVAPI32.dll` | standard | 81 | `IsValidSecurityDescriptor, GetSecurityDescriptorLength, CryptReleaseContext, ...` |
| `COMCTL32.dll` | standard | 1 | `InitCommonControlsEx` |
| `COMDLG32.dll` | delay-load | 2 | `GetOpenFileNameW, CommDlgExtendedError` |
| `CRYPT32.dll` | standard | 121 | `CryptExportPKCS8, PFXExportCertStoreEx, PFXExportCertStore, ...` |
| `CRYPTSP.dll` | standard | 7 | `CryptGetDefaultProviderW, CryptSignHashW, CryptContextAddRef, ...` |
| `CRYPTUI.dll` | standard | 3 | `CryptUIDlgViewCertificateW, CryptUIDlgViewCRLW, CryptUIDlgFreeCAContext` |
| `Cabinet.dll` | standard | 4 | `#22, #23, #21, ...` |
| `GDI32.dll` | standard | 1 | `GetStockObject` |
| `KERNEL32.dll` | standard | 148 | `OpenEventW, GetSystemDefaultUILanguage, GetUserDefaultUILanguage, ...` |
| `NETAPI32.dll` | standard | 6 | `DsRoleFreeMemory, DsRoleGetPrimaryDomainInformation, NetUserGetGroups, ...` |
| `NTDSAPI.dll` | standard | 6 | `DsUnBindW, DsGetDomainControllerInfoW, DsFreeNameResultW, ...` |
| `Normaliz.dll` | standard | 2 | `IdnToAscii, IdnToUnicode` |
| `OLEAUT32.dll` | standard | 22 | `#26, #184, #7, ...` |
| `RPCRT4.dll` | standard | 3 | `I_RpcExceptionFilter, NdrClientCall3, UuidCreate` |
| `RstrtMgr.DLL` | delay-load | 4 | `RmGetList, RmEndSession, RmStartSession, ...` |
| `SETUPAPI.dll` | standard | 8 | `SetupFindFirstLineW, SetupGetFieldCount, SetupFindNextLine, ...` |
| `SHELL32.dll` | standard | 2 | `SHGetKnownFolderPath, SHGetFolderPathW` |
| `SHLWAPI.dll` | standard | 1 | `PathFindFileNameW` |
| `Secur32.dll` | standard | 3 | `GetUserNameExW, TranslateNameW, GetComputerObjectNameW` |
| `TpmCoreProvisioning.DLL` | delay-load | 4 | `TpmIsFIPS, TpmGetCapLockoutInfo, TpmIsReadyInformation, ...` |
| `USER32.dll` | standard | 35 | `GetDesktopWindow, SendMessageW, MessageBoxW, ...` |
| `VAULTCLI.dll` | delay-load | 10 | `VaultGetItem, VaultFindItems, VaultFree, ...` |
| `VERSION.dll` | standard | 3 | `GetFileVersionInfoW, GetFileVersionInfoSizeW, VerQueryValueW` |
| `WININET.dll` | delay-load | 16 | `InternetCloseHandle, InternetCrackUrlW, InternetOpenUrlW, ...` |
| `WLDAP32.dll` | standard | 27 | `#12, #14, #145, ...` |
| `WinSCard.dll` | delay-load | 12 | `SCardDisconnect, SCardEndTransaction, SCardGetCardTypeProviderNameW, ...` |
| `api-ms-win-core-winrt-l1-1-0.dll` | delay-load | 1 | `RoGetActivationFactory` |
| `api-ms-win-core-winrt-string-l1-1-0.dll` | delay-load | 4 | `WindowsDuplicateString, WindowsDeleteString, WindowsGetStringRawBuffer, ...` |
| `api-ms-win-security-lsapolicy-l1-1-0.dll` | standard | 5 | `LsaOpenPolicy, LsaStorePrivateData, LsaRetrievePrivateData, ...` |
| `certcli.dll` | standard | 71 | `#255, CAEnumCertTypesForCA, CACountCertTypes, ...` |
| `certenroll.dll` | delay-load | 2 | `#41, #42` |
| `cryptngc.dll` | delay-load | 3 | `NgcEnumUserIdKeys, NgcDeleteContainerEx, NgcFreeEnumState` |
| `dsreg.dll` | delay-load | 2 | `DsrGetJoinInfoEx, DsrFreeJoinInfoEx` |
| `msvcrt.dll` | standard | 117 | `_onexit, __dllonexit, _unlock, ...` |
| `ncrypt.dll` | standard | 49 | `NCryptFreeObject, BCryptVerifySignature, BCryptDestroyKey, ...` |
| `ntdll.dll` | standard | 7 | `RtlCaptureContext, RtlLookupFunctionEntry, RtlVirtualUnwind, ...` |
| `ole32.dll` | standard | 14 | `CoTaskMemFree, CoInitialize, CoUninitialize, ...` |
| `urlmon.dll` | delay-load | 1 | `CreateUri` |
| `webservices.dll` | delay-load | 23 | `WsReadValue, WsSetReaderPosition, WsDateTimeToFileTime, ...` |

### cmd.exe

- **Category:** system32_console
- **Path:** `/home/carrick/nt-census-inputs/system32/cmd.exe`
- **Total Imports:** 304
- **Modules Imported:**

| Module / Contract | Mechanism | Symbols Count | Sample Symbols |
|---|---|---|---|
| `Wldp.dll` | delay-load | 1 | `#2` |
| `api-ms-win-core-apiquery-l1-1-0.dll` | standard | 1 | `ApiSetQueryApiSetPresence` |
| `api-ms-win-core-console-l1-1-0.dll` | standard | 6 | `WriteConsoleW, GetConsoleOutputCP, ReadConsoleW, ...` |
| `api-ms-win-core-console-l2-1-0.dll` | standard | 7 | `SetConsoleCursorPosition, ScrollConsoleScreenBufferW, FillConsoleOutputAttribute, ...` |
| `api-ms-win-core-console-l2-2-0.dll` | standard | 2 | `SetConsoleTitleW, GetConsoleTitleW` |
| `api-ms-win-core-console-l3-2-0.dll` | standard | 1 | `GetConsoleWindow` |
| `api-ms-win-core-datetime-l1-1-0.dll` | standard | 2 | `GetDateFormatW, GetTimeFormatW` |
| `api-ms-win-core-debug-l1-1-0.dll` | standard | 3 | `OutputDebugStringW, DebugBreak, IsDebuggerPresent` |
| `api-ms-win-core-delayload-l1-1-0.dll` | standard | 1 | `DelayLoadFailureHook` |
| `api-ms-win-core-delayload-l1-1-1.dll` | standard | 1 | `ResolveDelayLoadedAPI` |
| `api-ms-win-core-errorhandling-l1-1-0.dll` | standard | 5 | `SetUnhandledExceptionFilter, SetErrorMode, UnhandledExceptionFilter, ...` |
| `api-ms-win-core-file-l1-1-0.dll` | standard | 27 | `GetDiskFreeSpaceExW, FindFirstFileExW, GetFullPathNameW, ...` |
| `api-ms-win-core-file-l2-1-0.dll` | standard | 5 | `GetFileInformationByHandleEx, MoveFileExW, CreateHardLinkW, ...` |
| `api-ms-win-core-file-l2-1-2.dll` | standard | 1 | `CopyFileW` |
| `api-ms-win-core-handle-l1-1-0.dll` | standard | 2 | `CloseHandle, DuplicateHandle` |
| `api-ms-win-core-heap-l1-1-0.dll` | standard | 6 | `HeapSize, HeapSetInformation, HeapReAlloc, ...` |
| `api-ms-win-core-heap-l2-1-0.dll` | standard | 3 | `GlobalFree, GlobalAlloc, LocalFree` |
| `api-ms-win-core-interlocked-l1-1-0.dll` | standard | 1 | `InitializeSListHead` |
| `api-ms-win-core-io-l1-1-0.dll` | standard | 1 | `DeviceIoControl` |
| `api-ms-win-core-libraryloader-l1-2-0.dll` | standard | 6 | `LoadLibraryExW, GetModuleFileNameA, GetModuleFileNameW, ...` |
| `api-ms-win-core-localization-l1-2-0.dll` | standard | 7 | `GetACP, GetLocaleInfoW, FormatMessageW, ...` |
| `api-ms-win-core-memory-l1-1-0.dll` | standard | 4 | `VirtualQuery, ReadProcessMemory, VirtualFree, ...` |
| `api-ms-win-core-misc-l1-1-0.dll` | standard | 2 | `lstrcmpW, lstrcmpiW` |
| `api-ms-win-core-processenvironment-l1-1-0.dll` | standard | 11 | `GetStdHandle, GetEnvironmentVariableW, GetCommandLineW, ...` |
| `api-ms-win-core-processenvironment-l1-2-0.dll` | standard | 1 | `NeedCurrentDirectoryForExePathW` |
| `api-ms-win-core-processthreads-l1-1-0.dll` | standard | 13 | `GetCurrentThreadId, OpenThread, GetCurrentProcessId, ...` |
| `api-ms-win-core-processthreads-l1-1-1.dll` | standard | 1 | `IsProcessorFeaturePresent` |
| `api-ms-win-core-processtopology-l1-1-0.dll` | standard | 1 | `GetThreadGroupAffinity` |
| `api-ms-win-core-profile-l1-1-0.dll` | standard | 1 | `QueryPerformanceCounter` |
| `api-ms-win-core-registry-l1-1-0.dll` | standard | 9 | `RegDeleteKeyExW, RegQueryValueExW, RegGetValueW, ...` |
| `api-ms-win-core-string-l1-1-0.dll` | standard | 3 | `MultiByteToWideChar, CompareStringOrdinal, WideCharToMultiByte` |
| `api-ms-win-core-synch-l1-1-0.dll` | standard | 17 | `ReleaseSemaphore, CreateSemaphoreExW, InitializeCriticalSection, ...` |
| `api-ms-win-core-synch-l1-2-0.dll` | standard | 2 | `InitOnceComplete, InitOnceBeginInitialize` |
| `api-ms-win-core-sysinfo-l1-1-0.dll` | standard | 6 | `SetLocalTime, GetSystemTime, GetLocalTime, ...` |
| `api-ms-win-core-systemtopology-l1-1-0.dll` | standard | 2 | `GetNumaNodeProcessorMaskEx, GetNumaHighestNodeNumber` |
| `api-ms-win-core-threadpool-l1-2-0.dll` | standard | 4 | `CreateThreadpoolTimer, SetThreadpoolTimer, CloseThreadpoolTimer, ...` |
| `api-ms-win-core-timezone-l1-1-0.dll` | standard | 2 | `FileTimeToSystemTime, SystemTimeToFileTime` |
| `api-ms-win-core-winrt-l1-1-0.dll` | delay-load | 2 | `RoUninitialize, RoInitialize` |
| `api-ms-win-crt-private-l1-1-0.dll` | standard | 81 | `_o__get_initial_narrow_environment, _o__get_osfhandle, _o__getch, ...` |
| `api-ms-win-crt-runtime-l1-1-0.dll` | standard | 4 | `_initterm, _initterm_e, _register_thread_local_exe_atexit_callback, ...` |
| `api-ms-win-crt-string-l1-1-0.dll` | standard | 4 | `wcscmp, wcsncmp, memset, ...` |
| `api-ms-win-crt-time-l1-1-0.dll` | standard | 1 | `_time32` |
| `api-ms-win-eventing-provider-l1-1-0.dll` | standard | 4 | `EventWriteTransfer, EventUnregister, EventRegister, ...` |
| `api-ms-win-security-base-l1-1-0.dll` | standard | 3 | `GetSecurityDescriptorOwner, GetFileSecurityW, RevertToSelf` |
| `ext-ms-win-appmodel-shellexecute-l1-1-0.dll` | delay-load | 1 | `ShellExecuteExW` |
| `ext-ms-win-branding-winbrand-l1-1-0.dll` | delay-load | 1 | `BrandingFormatString` |
| `ext-ms-win-cmd-util-l1-1-0.dll` | delay-load | 13 | `GetVDMCurrentDirectoriesStub, ShellExecuteWorker, MessageBeepStub, ...` |
| `ntdll.dll` | standard | 22 | `RtlLookupFunctionEntry, RtlVirtualUnwind, NtOpenProcessToken, ...` |

### fc.exe

- **Category:** system32_console
- **Path:** `/home/carrick/nt-census-inputs/system32/fc.exe`
- **Total Imports:** 112
- **Modules Imported:**

| Module / Contract | Mechanism | Symbols Count | Sample Symbols |
|---|---|---|---|
| `KERNEL32.dll` | standard | 12 | `HeapSetInformation, SetUnhandledExceptionFilter, GetModuleHandleW, ...` |
| `msvcrt.dll` | standard | 15 | `_fmode, ?terminate@@YAXXZ, _commode, ...` |
| `ntdll.dll` | standard | 5 | `RtlCaptureContext, RtlFreeHeap, RtlAllocateHeap, ...` |
| `ulib.dll` | standard | 80 | `?Strcmpis@MBSTR@@SAHPEAD0@Z, ?Strcmps@MBSTR@@SAHPEAD0@Z, ?Stricmp@MBSTR@@SAHPEAD0@Z, ...` |

### find.exe

- **Category:** system32_console
- **Path:** `/home/carrick/nt-census-inputs/system32/find.exe`
- **Total Imports:** 79
- **Modules Imported:**

| Module / Contract | Mechanism | Symbols Count | Sample Symbols |
|---|---|---|---|
| `KERNEL32.dll` | standard | 10 | `CompareStringW, HeapSetInformation, Sleep, ...` |
| `msvcrt.dll` | standard | 13 | `?terminate@@YAXXZ, _commode, _fmode, ...` |
| `ntdll.dll` | standard | 2 | `RtlFreeHeap, RtlAllocateHeap` |
| `ulib.dll` | standard | 54 | `?Compare@OBJECT@@UEBAJPEBV1@@Z, ??1OBJECT@@UEAA@XZ, ?SetCaseSensitive@ARGUMENT_LEXEMIZER@@QEAAXE@Z, ...` |

### findstr.exe

- **Category:** system32_console
- **Path:** `/home/carrick/nt-census-inputs/system32/findstr.exe`
- **Total Imports:** 102
- **Modules Imported:**

| Module / Contract | Mechanism | Symbols Count | Sample Symbols |
|---|---|---|---|
| `api-ms-win-core-apiquery-l1-1-0.dll` | standard | 1 | `ApiSetQueryApiSetPresence` |
| `api-ms-win-core-console-l1-1-0.dll` | standard | 2 | `SetConsoleCtrlHandler, GetConsoleOutputCP` |
| `api-ms-win-core-console-l2-1-0.dll` | standard | 2 | `SetConsoleTextAttribute, GetConsoleScreenBufferInfo` |
| `api-ms-win-core-delayload-l1-1-0.dll` | standard | 1 | `DelayLoadFailureHook` |
| `api-ms-win-core-delayload-l1-1-1.dll` | standard | 1 | `ResolveDelayLoadedAPI` |
| `api-ms-win-core-errorhandling-l1-1-0.dll` | standard | 3 | `SetUnhandledExceptionFilter, UnhandledExceptionFilter, GetLastError` |
| `api-ms-win-core-file-l1-1-0.dll` | standard | 8 | `GetFileSize, FindNextFileA, CreateFileA, ...` |
| `api-ms-win-core-file-l1-2-2.dll` | standard | 1 | `SetFileApisToOEM` |
| `api-ms-win-core-handle-l1-1-0.dll` | standard | 1 | `CloseHandle` |
| `api-ms-win-core-heap-l1-1-0.dll` | standard | 1 | `HeapSetInformation` |
| `api-ms-win-core-kernel32-legacy-l1-1-0.dll` | standard | 1 | `CreateFileMappingA` |
| `api-ms-win-core-libraryloader-l1-2-0.dll` | standard | 1 | `GetModuleHandleW` |
| `api-ms-win-core-localization-l1-2-0.dll` | standard | 3 | `FormatMessageA, IsDBCSLeadByte, SetThreadPreferredUILanguages` |
| `api-ms-win-core-memory-l1-1-0.dll` | standard | 2 | `UnmapViewOfFile, MapViewOfFile` |
| `api-ms-win-core-processenvironment-l1-1-0.dll` | standard | 3 | `GetCurrentDirectoryA, SetCurrentDirectoryA, GetStdHandle` |
| `api-ms-win-core-processthreads-l1-1-0.dll` | standard | 5 | `TerminateProcess, GetCurrentProcessId, ExitProcess, ...` |
| `api-ms-win-core-profile-l1-1-0.dll` | standard | 1 | `QueryPerformanceCounter` |
| `api-ms-win-core-string-obsolete-l1-1-0.dll` | standard | 1 | `lstrlenA` |
| `api-ms-win-core-synch-l1-1-0.dll` | standard | 3 | `InitializeCriticalSection, LeaveCriticalSection, EnterCriticalSection` |
| `api-ms-win-core-synch-l1-2-0.dll` | standard | 1 | `Sleep` |
| `api-ms-win-core-sysinfo-l1-1-0.dll` | standard | 2 | `GetSystemTimeAsFileTime, GetTickCount` |
| `ext-ms-win-ntuser-chartranslation-l1-1-0.dll` | delay-load | 1 | `CharToOemA` |
| `msvcrt.dll` | standard | 51 | `_splitpath_s, strcat_s, clock, ...` |
| `ntdll.dll` | standard | 6 | `RtlCaptureContext, RtlUnicodeToOemN, DbgPrint, ...` |

### hello_console.exe

- **Category:** clean_room_built
- **Path:** `target/census-fixtures/hello_console.exe`
- **Total Imports:** 3
- **Modules Imported:**

| Module / Contract | Mechanism | Symbols Count | Sample Symbols |
|---|---|---|---|
| `kernel32.dll` | standard | 3 | `ExitProcess, GetStdHandle, WriteFile` |

### hostname.exe

- **Category:** system32_console
- **Path:** `/home/carrick/nt-census-inputs/system32/hostname.exe`
- **Total Imports:** 52
- **Modules Imported:**

| Module / Contract | Mechanism | Symbols Count | Sample Symbols |
|---|---|---|---|
| `MSWSOCK.dll` | standard | 1 | `GetSocketErrorMessageW` |
| `WS2_32.dll` | standard | 2 | `#115, GetHostNameW` |
| `api-ms-win-core-console-l1-1-0.dll` | standard | 1 | `GetConsoleMode` |
| `api-ms-win-core-errorhandling-l1-1-0.dll` | standard | 3 | `UnhandledExceptionFilter, SetUnhandledExceptionFilter, GetLastError` |
| `api-ms-win-core-file-l1-1-0.dll` | standard | 1 | `GetFileType` |
| `api-ms-win-core-heap-l1-1-0.dll` | standard | 1 | `HeapSetInformation` |
| `api-ms-win-core-heap-l2-1-0.dll` | standard | 2 | `LocalFree, LocalAlloc` |
| `api-ms-win-core-libraryloader-l1-2-0.dll` | standard | 1 | `GetModuleHandleW` |
| `api-ms-win-core-localization-l1-2-0.dll` | standard | 2 | `FormatMessageW, SetThreadUILanguage` |
| `api-ms-win-core-processenvironment-l1-1-0.dll` | standard | 1 | `GetEnvironmentVariableW` |
| `api-ms-win-core-processthreads-l1-1-0.dll` | standard | 4 | `GetCurrentThreadId, GetCurrentProcessId, GetCurrentProcess, ...` |
| `api-ms-win-core-profile-l1-1-0.dll` | standard | 1 | `QueryPerformanceCounter` |
| `api-ms-win-core-rtlsupport-l1-1-0.dll` | standard | 3 | `RtlVirtualUnwind, RtlLookupFunctionEntry, RtlCaptureContext` |
| `api-ms-win-core-string-l1-1-0.dll` | standard | 1 | `WideCharToMultiByte` |
| `api-ms-win-core-synch-l1-2-0.dll` | standard | 1 | `Sleep` |
| `api-ms-win-core-sysinfo-l1-1-0.dll` | standard | 2 | `GetTickCount, GetSystemTimeAsFileTime` |
| `msvcrt.dll` | standard | 25 | `_wcsicmp, exit, fflush, ...` |

### ipconfig.exe

- **Category:** system32_console
- **Path:** `/home/carrick/nt-census-inputs/system32/ipconfig.exe`
- **Total Imports:** 111
- **Modules Imported:**

| Module / Contract | Mechanism | Symbols Count | Sample Symbols |
|---|---|---|---|
| `DNSAPI.dll` | standard | 9 | `DnsRecordStringForType, DnsFree, DnsGetDdrInfo, ...` |
| `IPHLPAPI.DLL` | standard | 11 | `SetCurrentThreadCompartmentId, GetNetworkParams, FreeInterfaceDnsSettings, ...` |
| `NSI.dll` | standard | 4 | `NsiGetAllParameters, NsiAllocateAndGetTable, NsiFreeTable, ...` |
| `WS2_32.dll` | standard | 1 | `InetNtopW` |
| `api-ms-win-core-console-l1-1-0.dll` | standard | 1 | `GetConsoleMode` |
| `api-ms-win-core-datetime-l1-1-0.dll` | standard | 2 | `GetTimeFormatW, GetDateFormatW` |
| `api-ms-win-core-errorhandling-l1-1-0.dll` | standard | 3 | `SetUnhandledExceptionFilter, GetLastError, UnhandledExceptionFilter` |
| `api-ms-win-core-file-l1-1-0.dll` | standard | 2 | `GetFileType, FileTimeToLocalFileTime` |
| `api-ms-win-core-heap-l1-1-0.dll` | standard | 4 | `HeapFree, HeapAlloc, HeapSetInformation, ...` |
| `api-ms-win-core-heap-l2-1-0.dll` | standard | 2 | `LocalAlloc, LocalFree` |
| `api-ms-win-core-libraryloader-l1-2-0.dll` | standard | 4 | `GetModuleHandleW, FreeLibrary, LoadLibraryExW, ...` |
| `api-ms-win-core-localization-l1-2-0.dll` | standard | 2 | `SetThreadUILanguage, FormatMessageW` |
| `api-ms-win-core-processenvironment-l1-1-0.dll` | standard | 1 | `GetEnvironmentVariableW` |
| `api-ms-win-core-processthreads-l1-1-0.dll` | standard | 4 | `GetCurrentProcess, GetCurrentProcessId, TerminateProcess, ...` |
| `api-ms-win-core-profile-l1-1-0.dll` | standard | 1 | `QueryPerformanceCounter` |
| `api-ms-win-core-registry-l1-1-0.dll` | standard | 4 | `RegSetValueExW, RegQueryValueExW, RegOpenKeyExW, ...` |
| `api-ms-win-core-rtlsupport-l1-1-0.dll` | standard | 3 | `RtlVirtualUnwind, RtlLookupFunctionEntry, RtlCaptureContext` |
| `api-ms-win-core-string-l1-1-0.dll` | standard | 3 | `WideCharToMultiByte, MultiByteToWideChar, CompareStringW` |
| `api-ms-win-core-synch-l1-2-0.dll` | standard | 1 | `Sleep` |
| `api-ms-win-core-sysinfo-l1-1-0.dll` | standard | 3 | `GetTickCount, GetComputerNameExW, GetSystemTimeAsFileTime` |
| `api-ms-win-core-timezone-l1-1-0.dll` | standard | 1 | `FileTimeToSystemTime` |
| `api-ms-win-security-base-l1-1-0.dll` | standard | 3 | `CheckTokenMembership, AllocateAndInitializeSid, FreeSid` |
| `dhcpcsvc.DLL` | standard | 4 | `DhcpAcquireParameters, DhcpReleaseParameters, DhcpHandlePnPEvent, ...` |
| `dhcpcsvc6.DLL` | standard | 5 | `Dhcpv6SetUserClass, Dhcpv6ReleaseParameters, Dhcpv6IsEnabled, ...` |
| `msvcrt.dll` | standard | 28 | `_wcsicmp, _get_osfhandle, _initterm, ...` |
| `ntdll.dll` | standard | 5 | `RtlIpv6AddressToStringExW, RtlIpv6AddressToStringW, RtlFreeUnicodeString, ...` |

### more.com

- **Category:** system32_console
- **Path:** `/home/carrick/nt-census-inputs/system32/more.com`
- **Total Imports:** 128
- **Modules Imported:**

| Module / Contract | Mechanism | Symbols Count | Sample Symbols |
|---|---|---|---|
| `api-ms-win-core-console-l1-1-0.dll` | standard | 1 | `GetConsoleOutputCP` |
| `api-ms-win-core-console-l2-1-0.dll` | standard | 1 | `GenerateConsoleCtrlEvent` |
| `api-ms-win-core-errorhandling-l1-1-0.dll` | standard | 2 | `UnhandledExceptionFilter, SetUnhandledExceptionFilter` |
| `api-ms-win-core-libraryloader-l1-2-0.dll` | standard | 1 | `GetModuleHandleW` |
| `api-ms-win-core-localization-l1-2-0.dll` | standard | 2 | `IsDBCSLeadByte, GetCPInfo` |
| `api-ms-win-core-processenvironment-l1-1-0.dll` | standard | 1 | `GetCommandLineW` |
| `api-ms-win-core-processthreads-l1-1-0.dll` | standard | 5 | `GetCurrentThreadId, GetCurrentProcess, TerminateProcess, ...` |
| `api-ms-win-core-profile-l1-1-0.dll` | standard | 1 | `QueryPerformanceCounter` |
| `api-ms-win-core-registry-l1-1-0.dll` | standard | 3 | `RegOpenKeyExW, RegCloseKey, RegQueryValueExW` |
| `api-ms-win-core-synch-l1-1-0.dll` | standard | 2 | `ReleaseSRWLockExclusive, AcquireSRWLockExclusive` |
| `api-ms-win-core-synch-l1-2-0.dll` | standard | 3 | `Sleep, WakeAllConditionVariable, SleepConditionVariableSRW` |
| `api-ms-win-core-sysinfo-l1-1-0.dll` | standard | 2 | `GetTickCount, GetSystemTimeAsFileTime` |
| `msvcrt.dll` | standard | 13 | `__C_specific_handler, _fmode, _commode, ...` |
| `ntdll.dll` | standard | 5 | `RtlCaptureContext, RtlFreeHeap, RtlAllocateHeap, ...` |
| `ulib.dll` | standard | 86 | `?Initialize@BSTRING@@QEAAEPEBDK@Z, ?QueryScreenSize@SCREEN@@QEBAXPEAG000@Z, ?MoveCursorTo@SCREEN@@QEAAEGG@Z, ...` |

### robocopy.exe

- **Category:** system32_console
- **Path:** `/home/carrick/nt-census-inputs/system32/robocopy.exe`
- **Total Imports:** 234
- **Modules Imported:**

| Module / Contract | Mechanism | Symbols Count | Sample Symbols |
|---|---|---|---|
| `ADVAPI32.dll` | standard | 16 | `GetUserNameW, AdjustTokenPrivileges, LookupPrivilegeValueW, ...` |
| `KERNEL32.dll` | standard | 133 | `lstrlenW, WriteConsoleW, GetStdHandle, ...` |
| `USER32.dll` | standard | 2 | `UnregisterClassA, LoadStringW` |
| `WS2_32.dll` | standard | 1 | `#116` |
| `msvcrt.dll` | standard | 62 | `exit, __set_app_type, __wgetmainargs, ...` |
| `ntdll.dll` | standard | 20 | `NtSetInformationProcess, NtOpenFile, RtlGetDaclSecurityDescriptor, ...` |

### rust_env_argv_gnu.exe

- **Category:** clean_room_built
- **Path:** `target/census-fixtures/rust_env_argv_gnu.exe`
- **Total Imports:** 183
- **Modules Imported:**

| Module / Contract | Mechanism | Symbols Count | Sample Symbols |
|---|---|---|---|
| `KERNEL32.dll` | standard | 118 | `AddVectoredExceptionHandler, CancelIo, CloseHandle, ...` |
| `USERENV.dll` | standard | 1 | `GetUserProfileDirectoryW` |
| `WS2_32.dll` | standard | 26 | `GetHostNameW, WSACleanup, WSADuplicateSocketW, ...` |
| `api-ms-win-core-synch-l1-2-0.dll` | standard | 3 | `WaitOnAddress, WakeByAddressAll, WakeByAddressSingle` |
| `bcryptprimitives.dll` | standard | 1 | `ProcessPrng` |
| `msvcrt.dll` | standard | 28 | `__getmainargs, __initenv, __iob_func, ...` |
| `ntdll.dll` | standard | 6 | `NtCreateFile, NtCreateNamedPipeFile, NtOpenFile, ...` |

### rust_env_argv_msvc.exe

- **Category:** clean_room_built
- **Path:** `target/census-fixtures/rust_env_argv_msvc.exe`
- **Total Imports:** 82
- **Modules Imported:**

| Module / Contract | Mechanism | Symbols Count | Sample Symbols |
|---|---|---|---|
| `KERNEL32.dll` | standard | 44 | `AddVectoredExceptionHandler, CloseHandle, CreateMutexA, ...` |
| `VCRUNTIME140.dll` | standard | 9 | `_CxxThrowException, __C_specific_handler, __CxxFrameHandler3, ...` |
| `api-ms-win-core-synch-l1-2-0.dll` | standard | 3 | `WaitOnAddress, WakeByAddressAll, WakeByAddressSingle` |
| `api-ms-win-crt-heap-l1-1-0.dll` | standard | 2 | `_set_new_mode, free` |
| `api-ms-win-crt-locale-l1-1-0.dll` | standard | 1 | `_configthreadlocale` |
| `api-ms-win-crt-math-l1-1-0.dll` | standard | 1 | `__setusermatherr` |
| `api-ms-win-crt-runtime-l1-1-0.dll` | standard | 18 | `__p___argc, __p___argv, _c_exit, ...` |
| `api-ms-win-crt-stdio-l1-1-0.dll` | standard | 2 | `__p__commode, _set_fmode` |
| `ntdll.dll` | standard | 2 | `NtWriteFile, RtlNtStatusToDosError` |

### rust_file_io_gnu.exe

- **Category:** clean_room_built
- **Path:** `target/census-fixtures/rust_file_io_gnu.exe`
- **Total Imports:** 183
- **Modules Imported:**

| Module / Contract | Mechanism | Symbols Count | Sample Symbols |
|---|---|---|---|
| `KERNEL32.dll` | standard | 118 | `AddVectoredExceptionHandler, CancelIo, CloseHandle, ...` |
| `USERENV.dll` | standard | 1 | `GetUserProfileDirectoryW` |
| `WS2_32.dll` | standard | 26 | `GetHostNameW, WSACleanup, WSADuplicateSocketW, ...` |
| `api-ms-win-core-synch-l1-2-0.dll` | standard | 3 | `WaitOnAddress, WakeByAddressAll, WakeByAddressSingle` |
| `bcryptprimitives.dll` | standard | 1 | `ProcessPrng` |
| `msvcrt.dll` | standard | 28 | `__getmainargs, __initenv, __iob_func, ...` |
| `ntdll.dll` | standard | 6 | `NtCreateFile, NtCreateNamedPipeFile, NtOpenFile, ...` |

### rust_file_io_msvc.exe

- **Category:** clean_room_built
- **Path:** `target/census-fixtures/rust_file_io_msvc.exe`
- **Total Imports:** 88
- **Modules Imported:**

| Module / Contract | Mechanism | Symbols Count | Sample Symbols |
|---|---|---|---|
| `KERNEL32.dll` | standard | 49 | `AddVectoredExceptionHandler, CloseHandle, CreateFileW, ...` |
| `VCRUNTIME140.dll` | standard | 9 | `_CxxThrowException, __C_specific_handler, __CxxFrameHandler3, ...` |
| `api-ms-win-core-synch-l1-2-0.dll` | standard | 3 | `WaitOnAddress, WakeByAddressAll, WakeByAddressSingle` |
| `api-ms-win-crt-heap-l1-1-0.dll` | standard | 2 | `_set_new_mode, free` |
| `api-ms-win-crt-locale-l1-1-0.dll` | standard | 1 | `_configthreadlocale` |
| `api-ms-win-crt-math-l1-1-0.dll` | standard | 1 | `__setusermatherr` |
| `api-ms-win-crt-runtime-l1-1-0.dll` | standard | 18 | `__p___argc, __p___argv, _c_exit, ...` |
| `api-ms-win-crt-stdio-l1-1-0.dll` | standard | 2 | `__p__commode, _set_fmode` |
| `ntdll.dll` | standard | 3 | `NtReadFile, NtWriteFile, RtlNtStatusToDosError` |

### rust_hello_gnu.exe

- **Category:** clean_room_built
- **Path:** `target/census-fixtures/rust_hello_gnu.exe`
- **Total Imports:** 183
- **Modules Imported:**

| Module / Contract | Mechanism | Symbols Count | Sample Symbols |
|---|---|---|---|
| `KERNEL32.dll` | standard | 118 | `AddVectoredExceptionHandler, CancelIo, CloseHandle, ...` |
| `USERENV.dll` | standard | 1 | `GetUserProfileDirectoryW` |
| `WS2_32.dll` | standard | 26 | `GetHostNameW, WSACleanup, WSADuplicateSocketW, ...` |
| `api-ms-win-core-synch-l1-2-0.dll` | standard | 3 | `WaitOnAddress, WakeByAddressAll, WakeByAddressSingle` |
| `bcryptprimitives.dll` | standard | 1 | `ProcessPrng` |
| `msvcrt.dll` | standard | 28 | `__getmainargs, __initenv, __iob_func, ...` |
| `ntdll.dll` | standard | 6 | `NtCreateFile, NtCreateNamedPipeFile, NtOpenFile, ...` |

### rust_hello_msvc.exe

- **Category:** clean_room_built
- **Path:** `target/census-fixtures/rust_hello_msvc.exe`
- **Total Imports:** 79
- **Modules Imported:**

| Module / Contract | Mechanism | Symbols Count | Sample Symbols |
|---|---|---|---|
| `KERNEL32.dll` | standard | 41 | `AddVectoredExceptionHandler, CloseHandle, CreateMutexA, ...` |
| `VCRUNTIME140.dll` | standard | 9 | `_CxxThrowException, __C_specific_handler, __CxxFrameHandler3, ...` |
| `api-ms-win-core-synch-l1-2-0.dll` | standard | 3 | `WaitOnAddress, WakeByAddressAll, WakeByAddressSingle` |
| `api-ms-win-crt-heap-l1-1-0.dll` | standard | 2 | `_set_new_mode, free` |
| `api-ms-win-crt-locale-l1-1-0.dll` | standard | 1 | `_configthreadlocale` |
| `api-ms-win-crt-math-l1-1-0.dll` | standard | 1 | `__setusermatherr` |
| `api-ms-win-crt-runtime-l1-1-0.dll` | standard | 18 | `__p___argc, __p___argv, _c_exit, ...` |
| `api-ms-win-crt-stdio-l1-1-0.dll` | standard | 2 | `__p__commode, _set_fmode` |
| `ntdll.dll` | standard | 2 | `NtWriteFile, RtlNtStatusToDosError` |

### rust_thread_spawn_gnu.exe

- **Category:** clean_room_built
- **Path:** `target/census-fixtures/rust_thread_spawn_gnu.exe`
- **Total Imports:** 183
- **Modules Imported:**

| Module / Contract | Mechanism | Symbols Count | Sample Symbols |
|---|---|---|---|
| `KERNEL32.dll` | standard | 118 | `AddVectoredExceptionHandler, CancelIo, CloseHandle, ...` |
| `USERENV.dll` | standard | 1 | `GetUserProfileDirectoryW` |
| `WS2_32.dll` | standard | 26 | `GetHostNameW, WSACleanup, WSADuplicateSocketW, ...` |
| `api-ms-win-core-synch-l1-2-0.dll` | standard | 3 | `WaitOnAddress, WakeByAddressAll, WakeByAddressSingle` |
| `bcryptprimitives.dll` | standard | 1 | `ProcessPrng` |
| `msvcrt.dll` | standard | 28 | `__getmainargs, __initenv, __iob_func, ...` |
| `ntdll.dll` | standard | 6 | `NtCreateFile, NtCreateNamedPipeFile, NtOpenFile, ...` |

### rust_thread_spawn_msvc.exe

- **Category:** clean_room_built
- **Path:** `target/census-fixtures/rust_thread_spawn_msvc.exe`
- **Total Imports:** 80
- **Modules Imported:**

| Module / Contract | Mechanism | Symbols Count | Sample Symbols |
|---|---|---|---|
| `KERNEL32.dll` | standard | 42 | `AddVectoredExceptionHandler, CloseHandle, CreateMutexA, ...` |
| `VCRUNTIME140.dll` | standard | 9 | `_CxxThrowException, __C_specific_handler, __CxxFrameHandler3, ...` |
| `api-ms-win-core-synch-l1-2-0.dll` | standard | 3 | `WaitOnAddress, WakeByAddressAll, WakeByAddressSingle` |
| `api-ms-win-crt-heap-l1-1-0.dll` | standard | 2 | `_set_new_mode, free` |
| `api-ms-win-crt-locale-l1-1-0.dll` | standard | 1 | `_configthreadlocale` |
| `api-ms-win-crt-math-l1-1-0.dll` | standard | 1 | `__setusermatherr` |
| `api-ms-win-crt-runtime-l1-1-0.dll` | standard | 18 | `__p___argc, __p___argv, _c_exit, ...` |
| `api-ms-win-crt-stdio-l1-1-0.dll` | standard | 2 | `__p__commode, _set_fmode` |
| `ntdll.dll` | standard | 2 | `NtWriteFile, RtlNtStatusToDosError` |

### sort.exe

- **Category:** system32_console
- **Path:** `/home/carrick/nt-census-inputs/system32/sort.exe`
- **Total Imports:** 79
- **Modules Imported:**

| Module / Contract | Mechanism | Symbols Count | Sample Symbols |
|---|---|---|---|
| `ADVAPI32.dll` | standard | 1 | `IsTextUnicode` |
| `KERNEL32.dll` | standard | 42 | `GetCurrentThreadId, GetCurrentProcessId, QueryPerformanceCounter, ...` |
| `msvcrt.dll` | standard | 31 | `__iob_func, memcpy, ?terminate@@YAXXZ, ...` |
| `ntdll.dll` | standard | 5 | `RtlCaptureContext, RtlUnicodeToOemN, RtlMultiByteToUnicodeN, ...` |

### tasklist.exe

- **Category:** system32_console
- **Path:** `/home/carrick/nt-census-inputs/system32/tasklist.exe`
- **Total Imports:** 183
- **Modules Imported:**

| Module / Contract | Mechanism | Symbols Count | Sample Symbols |
|---|---|---|---|
| `ADVAPI32.dll` | standard | 10 | `OpenProcessToken, LookupPrivilegeValueW, AdjustTokenPrivileges, ...` |
| `KERNEL32.dll` | standard | 44 | `GetSystemDirectoryW, LoadLibraryW, GetProcAddress, ...` |
| `MPR.dll` | standard | 3 | `WNetAddConnection2W, WNetCancelConnection2W, WNetGetLastErrorW` |
| `OLEAUT32.dll` | standard | 8 | `#2, #6, #150, ...` |
| `SspiCli.dll` | standard | 1 | `GetUserNameExW` |
| `USER32.dll` | standard | 18 | `IsHungAppWindow, GetWindowTextW, wsprintfW, ...` |
| `WS2_32.dll` | standard | 6 | `#116, FreeAddrInfoW, GetNameInfoW, ...` |
| `api-ms-win-core-com-l1-1-0.dll` | standard | 6 | `CoUninitialize, CoInitializeEx, CoInitializeSecurity, ...` |
| `api-ms-win-core-errorhandling-l1-1-0.dll` | standard | 2 | `SetUnhandledExceptionFilter, UnhandledExceptionFilter` |
| `api-ms-win-core-heap-l2-1-0.dll` | standard | 1 | `LocalFree` |
| `api-ms-win-core-libraryloader-l1-2-0.dll` | standard | 2 | `GetModuleHandleW, LoadStringW` |
| `api-ms-win-core-processthreads-l1-1-0.dll` | standard | 2 | `GetCurrentProcessId, TerminateProcess` |
| `api-ms-win-core-profile-l1-1-0.dll` | standard | 1 | `QueryPerformanceCounter` |
| `api-ms-win-core-rtlsupport-l1-1-0.dll` | standard | 3 | `RtlVirtualUnwind, RtlLookupFunctionEntry, RtlCaptureContext` |
| `api-ms-win-core-string-l2-1-0.dll` | standard | 1 | `CharUpperW` |
| `api-ms-win-core-synch-l1-2-0.dll` | standard | 1 | `Sleep` |
| `api-ms-win-core-sysinfo-l1-1-0.dll` | standard | 2 | `GetTickCount, GetSystemTimeAsFileTime` |
| `api-ms-win-core-version-l1-1-0.dll` | standard | 3 | `VerQueryValueW, GetFileVersionInfoSizeExW, GetFileVersionInfoExW` |
| `framedynos.dll` | standard | 20 | `?GetBufferSetLength@CHString@@QEAAPEAGH@Z, ?GetData@CHString@@IEBAPEAUCHStringData@@XZ, ??1CHString@@QEAA@XZ, ...` |
| `imagehlp.dll` | standard | 1 | `EnumerateLoadedModulesW64` |
| `msvcrt.dll` | standard | 40 | `memcpy, _CxxThrowException, memset, ...` |
| `netutils.dll` | standard | 1 | `NetApiBufferFree` |
| `ntdll.dll` | standard | 6 | `RtlLargeIntegerToChar, RtlVerifyVersionInfo, RtlNtStatusToDosError, ...` |
| `srvcli.dll` | standard | 1 | `NetServerGetInfo` |

### where.exe

- **Category:** system32_console
- **Path:** `/home/carrick/nt-census-inputs/system32/where.exe`
- **Total Imports:** 99
- **Modules Imported:**

| Module / Contract | Mechanism | Symbols Count | Sample Symbols |
|---|---|---|---|
| `KERNEL32.dll` | standard | 57 | `TerminateProcess, HeapValidate, HeapFree, ...` |
| `SHLWAPI.dll` | standard | 1 | `StrTrimW` |
| `USER32.dll` | standard | 2 | `LoadStringW, CharUpperW` |
| `VERSION.dll` | standard | 3 | `GetFileVersionInfoSizeExW, VerQueryValueW, GetFileVersionInfoExW` |
| `WS2_32.dll` | standard | 1 | `#116` |
| `msvcrt.dll` | standard | 33 | `__iob_func, _memicmp, _errno, ...` |
| `ntdll.dll` | standard | 2 | `VerSetConditionMask, RtlVerifyVersionInfo` |

### whoami.exe

- **Category:** system32_console
- **Path:** `/home/carrick/nt-census-inputs/system32/whoami.exe`
- **Total Imports:** 127
- **Modules Imported:**

| Module / Contract | Mechanism | Symbols Count | Sample Symbols |
|---|---|---|---|
| `ADVAPI32.dll` | standard | 15 | `LookupPrivilegeDisplayNameW, LookupPrivilegeNameW, GetSidIdentifierAuthority, ...` |
| `AUTHZ.dll` | standard | 4 | `FreeClaimDefinitions, InitializeClaimDictionary, GetClaimDefinitions, ...` |
| `KERNEL32.dll` | standard | 43 | `LocalFree, CloseHandle, GetCurrentProcess, ...` |
| `SspiCli.dll` | standard | 4 | `GetUserNameExW, LsaConnectUntrusted, LsaCallAuthenticationPackage, ...` |
| `USER32.dll` | standard | 3 | `LoadStringW, CharLowerW, CharUpperW` |
| `VERSION.dll` | standard | 3 | `GetFileVersionInfoSizeExW, GetFileVersionInfoExW, VerQueryValueW` |
| `WS2_32.dll` | standard | 1 | `#116` |
| `msvcrt.dll` | standard | 47 | `fflush, fprintf, wcstok, ...` |
| `netutils.dll` | standard | 1 | `NetApiBufferFree` |
| `ntdll.dll` | standard | 5 | `RtlVerifyVersionInfo, RtlCaptureContext, RtlLookupFunctionEntry, ...` |
| `wkscli.dll` | standard | 1 | `NetGetJoinInformation` |

### xcopy.exe

- **Category:** system32_console
- **Path:** `/home/carrick/nt-census-inputs/system32/xcopy.exe`
- **Total Imports:** 175
- **Modules Imported:**

| Module / Contract | Mechanism | Symbols Count | Sample Symbols |
|---|---|---|---|
| `IfsUtil.dll` | standard | 1 | `?QueryFreeDiskSpace@IFS_SYSTEM@@SAEPEBVWSTRING@@PEAVBIG_INT@@@Z` |
| `api-ms-win-core-errorhandling-l1-1-0.dll` | standard | 3 | `UnhandledExceptionFilter, SetUnhandledExceptionFilter, GetLastError` |
| `api-ms-win-core-file-l1-1-0.dll` | standard | 3 | `SetFileTime, FindClose, GetFileTime` |
| `api-ms-win-core-file-l2-1-0.dll` | standard | 1 | `CreateDirectoryExW` |
| `api-ms-win-core-heap-l1-1-0.dll` | standard | 1 | `HeapSetInformation` |
| `api-ms-win-core-libraryloader-l1-2-0.dll` | standard | 1 | `GetModuleHandleW` |
| `api-ms-win-core-processenvironment-l1-1-0.dll` | standard | 1 | `GetCommandLineW` |
| `api-ms-win-core-processthreads-l1-1-0.dll` | standard | 4 | `GetCurrentProcess, TerminateProcess, GetCurrentProcessId, ...` |
| `api-ms-win-core-profile-l1-1-0.dll` | standard | 1 | `QueryPerformanceCounter` |
| `api-ms-win-core-rtlsupport-l1-1-0.dll` | standard | 3 | `RtlLookupFunctionEntry, RtlVirtualUnwind, RtlCaptureContext` |
| `api-ms-win-core-synch-l1-2-0.dll` | standard | 1 | `Sleep` |
| `api-ms-win-core-sysinfo-l1-1-0.dll` | standard | 2 | `GetSystemTimeAsFileTime, GetTickCount` |
| `msvcrt.dll` | standard | 17 | `_fmode, _amsg_exit, _initterm, ...` |
| `ntdll.dll` | standard | 4 | `RtlAllocateHeap, RtlFreeHeap, NtSetInformationProcess, ...` |
| `ulib.dll` | standard | 132 | `??0ARGUMENT_LEXEMIZER@@QEAA@XZ, ?Initialize@STRING_ARRAY@@QEAAEKKK@Z, ??0STRING_ARRAY@@QEAA@XZ, ...` |

