__declspec(dllimport) void* __stdcall GetStdHandle(unsigned long nStdHandle);
__declspec(dllimport) int __stdcall WriteFile(void* hFile, const void* lpBuffer, unsigned long nNumberOfBytesToWrite, unsigned long* lpNumberOfBytesWritten, void* lpOverlapped);
__declspec(dllimport) void __stdcall ExitProcess(unsigned int uExitCode);

void mainCRTStartup(void) {
    void* h = GetStdHandle((unsigned long)-11);
    const char msg[] = "Hello from clean-room C!\r\n";
    unsigned long written = 0;
    WriteFile(h, msg, sizeof(msg) - 1, &written, 0);
    ExitProcess(0);
}
