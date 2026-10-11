__declspec(dllimport) void* __stdcall CreateThread(void* lpThreadAttributes, unsigned long long dwStackSize, unsigned long (__stdcall *lpStartAddress)(void*), void* lpParameter, unsigned long dwCreationFlags, unsigned long* lpThreadId);
__declspec(dllimport) unsigned long __stdcall WaitForSingleObject(void* hHandle, unsigned long dwMilliseconds);
__declspec(dllimport) int __stdcall CloseHandle(void* hObject);
__declspec(dllimport) void __stdcall ExitProcess(unsigned int uExitCode);

static volatile unsigned long g_worker_ran = 0;

static unsigned long __stdcall thread_worker(void* param) {
    (void)param;
    g_worker_ran = 1;
    return 0;
}

void mainCRTStartup(void) {
    unsigned long tid = 0;
    void* hThread = CreateThread(0, 0, thread_worker, 0, 0, &tid);
    if (hThread != 0) {
        WaitForSingleObject(hThread, 5000);
        CloseHandle(hThread);
    }
    ExitProcess(0);
}
