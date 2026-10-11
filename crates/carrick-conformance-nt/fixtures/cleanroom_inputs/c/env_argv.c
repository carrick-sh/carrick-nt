__declspec(dllimport) unsigned short* __stdcall GetCommandLineW(void);
__declspec(dllimport) unsigned long __stdcall GetEnvironmentVariableW(const unsigned short* lpName, unsigned short* lpBuffer, unsigned long nSize);
__declspec(dllimport) int __stdcall SetEnvironmentVariableW(const unsigned short* lpName, const unsigned short* lpValue);
__declspec(dllimport) void __stdcall ExitProcess(unsigned int uExitCode);

void mainCRTStartup(void) {
    unsigned short* _cmdline = GetCommandLineW();
    const unsigned short varname[] = {'P','A','T','H',0};
    unsigned short valbuf[256];
    GetEnvironmentVariableW(varname, valbuf, 256);
    const unsigned short testvar[] = {'C','A','R','R','I','C','K',0};
    const unsigned short testval[] = {'1',0};
    SetEnvironmentVariableW(testvar, testval);
    ExitProcess(0);
}
