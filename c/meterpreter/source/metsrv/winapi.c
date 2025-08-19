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

HANDLE winapi_kernel32_OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {
    HANDLE (*pOpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)  = GetFunction(KERNEL32_DLL, "OpenProcess");
    if(pOpenProcess) {
        return pOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
    }
    return NULL;

}

LPVOID winapi_kernel32_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect){
    LPVOID (*pVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = GetFunction(KERNEL32_DLL, "VirtualAlloc");
    if(pVirtualAlloc) {
        return pVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
    }
    return NULL;
}

LPVOID winapi_kernel32_VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect){
    LPVOID (*pVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = GetFunction(KERNEL32_DLL, "VirtualAllocEx");
    if(pVirtualAllocEx) {
        return pVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
    }
    return NULL;
}

BOOL winapi_kernel32_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect){
    BOOL (*pVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect) = GetFunction(KERNEL32_DLL, "VirtualProtect");
    if(pVirtualProtect) {
        return pVirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
    }
    return FALSE;
}

BOOL winapi_kernel32_VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect){
    BOOL (*pVirtualProtectEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) = GetFunction(KERNEL32_DLL, "VirtualProtectEx");
    if(pVirtualProtectEx) {
        return pVirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
    }
    return FALSE;
}

#endif