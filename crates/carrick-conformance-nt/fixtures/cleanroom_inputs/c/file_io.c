__declspec(dllimport) void* __stdcall CreateFileW(const unsigned short* lpFileName, unsigned long dwDesiredAccess, unsigned long dwShareMode, void* lpSecurityAttributes, unsigned long dwCreationDisposition, unsigned long dwFlagsAndAttributes, void* hTemplateFile);
__declspec(dllimport) int __stdcall WriteFile(void* hFile, const void* lpBuffer, unsigned long nNumberOfBytesToWrite, unsigned long* lpNumberOfBytesWritten, void* lpOverlapped);
__declspec(dllimport) int __stdcall ReadFile(void* hFile, void* lpBuffer, unsigned long nNumberOfBytesToRead, unsigned long* lpNumberOfBytesRead, void* lpOverlapped);
__declspec(dllimport) int __stdcall CloseHandle(void* hObject);
__declspec(dllimport) int __stdcall DeleteFileW(const unsigned short* lpFileName);
__declspec(dllimport) void __stdcall ExitProcess(unsigned int uExitCode);

void mainCRTStartup(void) {
    const unsigned short filename[] = {'c','e','n','s','u','s','_','t','e','s','t','.','t','x','t',0};
    void* h = CreateFileW(filename, 0x40000000 | 0x80000000, 0, 0, 2, 0x80, 0);
    if (h != (void*)-1) {
        const char data[] = "carrick-nt-io";
        unsigned long bytes = 0;
        WriteFile(h, data, sizeof(data) - 1, &bytes, 0);
        CloseHandle(h);
    }
    h = CreateFileW(filename, 0x80000000, 1, 0, 3, 0x80, 0);
    if (h != (void*)-1) {
        char buf[32];
        unsigned long read_bytes = 0;
        ReadFile(h, buf, sizeof(buf), &read_bytes, 0);
        CloseHandle(h);
    }
    DeleteFileW(filename);
    ExitProcess(0);
}
