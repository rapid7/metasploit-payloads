#ifndef _METERPRETER_WINAPI_H
#define _METERPRETER_WINAPI_H

#include <windows.h>

#define KERNEL32_DLL "kernel32.dll"
#define NTDLL_DLL "ntdll.dll"

void *GetFunction(LPCSTR lpModuleName, LPCSTR lpFunctionName) {
    HMODULE hModule;
    hModule = GetModuleHandleA(lpModuleName);
    if(hModule == NULL) {
        hModule = LoadLibraryA(lpModuleName);
    }
    if(hModule != NULL) {
        return GetProcAddress(hModule, lpFunctionName);
    }
    return NULL;
}

BOOL winapi_kernel32_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T  *lpNumberOfBytesWritten) {
    BOOL (*pWriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T  *lpNumberOfBytesWritten) = GetFunction(KERNEL32_DLL, "WriteProcessMemory");
    if(pWriteProcessMemory) {
        return pWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    }
    return FALSE;
}

#endif