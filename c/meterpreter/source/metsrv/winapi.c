#ifndef _METERPRETER_WINAPI_H
#define _METERPRETER_WINAPI_H

#include "common.h"
#include "winapi.h"
#include "../ReflectiveDLLInjection/dll/src/DirectSyscall.h"

#define KERNEL32_DLL "kernel32.dll"
#define NTDLL_DLL "ntdll.dll"

typedef struct NtDllFunction {
    LPCSTR lpFunctionName;
    DWORD  dwNumberOfArgs;
} NtDllFunction;

NtDllFunction lpFunctionsTobeLoaded[] = {
    { .lpFunctionName = "ZwAllocateVirtualMemory", .dwNumberOfArgs = 1}
};

enum NtDllSyscall {
    ZwAllocateVirtualMemory = 0,
};
Syscall **lpWinApiSyscalls = NULL;

Syscall **GetOrInitWinApiSyscalls() {
    if(lpWinApiSyscalls == NULL) {
        BOOL bError = FALSE;
        HANDLE hHeap = GetProcessHeap();
        bError = hHeap == NULL;
        DWORD dwNumbOfSyscalls = sizeof(lpFunctionsTobeLoaded) / sizeof (NtDllFunction);
        Syscall *lpSyscall = NULL;
        if(!bError) {
            lpWinApiSyscalls = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(Syscall *) * dwNumbOfSyscalls);
            bError = lpWinApiSyscalls == NULL;
        }
        if(!bError) {
            for(int i = 0; i < dwNumbOfSyscalls; i++) {
                lpSyscall = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(Syscall));
                bError = lpSyscall == NULL;
                if(bError){
                    break;
                }
                lpSyscall->dwCryptedHash = _hash((char *)lpFunctionsTobeLoaded[i].lpFunctionName);
                lpSyscall->dwNumberOfArgs = lpFunctionsTobeLoaded[i].dwNumberOfArgs;
                lpWinApiSyscalls[i] = lpSyscall;
            }
        }
        if(!bError) {
            bError = !getSyscalls(GetModuleHandleA(NTDLL_DLL), lpWinApiSyscalls, dwNumbOfSyscalls);
        }
        if(bError) {
            dprintf("[WINAPI][GetOrInitWinApiSyscalls] Error creating Syscall structure.");
            if(lpWinApiSyscalls != NULL) {
                for(int i = 0; i < dwNumbOfSyscalls; i++) {
                    lpSyscall = lpWinApiSyscalls[i];
                    if(lpSyscall != NULL) {
                        HeapFree(hHeap, 0, lpSyscall);
                    }
                }
                HeapFree(hHeap, 0, lpWinApiSyscalls);
                lpWinApiSyscalls = NULL;
            }
        }
    }

    return lpWinApiSyscalls;
}

BOOL hasDirectSyscallSupport() {
    return TRUE;
}

void *GetFunction(LPCSTR lpModuleName, LPCSTR lpFunctionName) {
    HMODULE hModule = NULL;
    FARPROC lpOutput = NULL;
    hModule = GetModuleHandleA(lpModuleName);
    if(hModule == NULL) {
        hModule = LoadLibraryA(lpModuleName);
    }
    if(hModule != NULL) {
        lpOutput = GetProcAddress(hModule, lpFunctionName);
    }
    if(hModule == NULL) {
        dprintf("[WINAPI][GetFunction] Unable to find or load '%s' module.", lpModuleName);
    }
    if(lpOutput == NULL) {
        dprintf("[WINAPI][GetFunction] Unable to find '%s' function's address.", lpFunctionName);
    }
    return lpOutput;
}

NTSTATUS winapi_ntdll_ZwAllocateVirtualMemory(HANDLE hProcess, PVOID *pBaseAddress, ULONG_PTR pZeroBits, PSIZE_T pRegionSize, ULONG ulAllocationType, ULONG ulProtect) {
    return SyscallStub(lpWinApiSyscalls[ZwAllocateVirtualMemory], hProcess, pBaseAddress, pZeroBits, pRegionSize, ulAllocationType, ulProtect);
}

BOOL winapi_kernel32_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T  *lpNumberOfBytesWritten) {
    BOOL (WINAPI *pWriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T  *lpNumberOfBytesWritten) = GetFunction(KERNEL32_DLL, "WriteProcessMemory");
    if(pWriteProcessMemory) {
        return pWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    }
    return FALSE;
}

HANDLE winapi_kernel32_OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {
    HANDLE (WINAPI *pOpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)  = GetFunction(KERNEL32_DLL, "OpenProcess");
    if(pOpenProcess) {
        return pOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
    }
    return NULL;
}

LPVOID winapi_kernel32_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect){
    if(hasDirectSyscallSupport()) {
        LPVOID lpBaseAddr = lpAddress;
        NTSTATUS dwStatus = winapi_ntdll_ZwAllocateVirtualMemory(GetCurrentProcess(), &lpBaseAddr, 0, dwSize, flAllocationType, flProtect);
        if(dwStatus == ERROR_SUCCESS){
            return lpBaseAddr;
        }
    }else {
        LPVOID (*pVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = GetFunction(KERNEL32_DLL, "VirtualAlloc");
         if(pVirtualAlloc) {
             return pVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
         }
    }
    return NULL;
}

LPVOID winapi_kernel32_VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect){
    LPVOID (WINAPI *pVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = GetFunction(KERNEL32_DLL, "VirtualAllocEx");
    if(pVirtualAllocEx) {
        return pVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
    }
    return NULL;
}

BOOL winapi_kernel32_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect){
    BOOL (WINAPI *pVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect) = GetFunction(KERNEL32_DLL, "VirtualProtect");
    if(pVirtualProtect) {
        return pVirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
    }
    return FALSE;
}

BOOL winapi_kernel32_VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect){
    BOOL (WINAPI *pVirtualProtectEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) = GetFunction(KERNEL32_DLL, "VirtualProtectEx");
    if(pVirtualProtectEx) {
        return pVirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
    }
    return FALSE;
}

SIZE_T winapi_kernel32_VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer,SIZE_T dwLength) {
    SIZE_T (WINAPI *pVirtualQuery)(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer,SIZE_T dwLength) = GetFunction(KERNEL32_DLL, "VirtualQuery");
    if(pVirtualQuery) {
        return pVirtualQuery(lpAddress, lpBuffer, dwLength);
    }
    return 0;
}

SIZE_T winapi_kernel32_VirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength) {
    SIZE_T (WINAPI *pVirtualQueryEx)(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength) = GetFunction(KERNEL32_DLL, "VirtualQueryEx");
    if(pVirtualQueryEx) {
        return pVirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength);
    }
    return 0;
}

BOOL winapi_kernel32_VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD  dwFreeType) {
    BOOL (WINAPI *pVirtualFree)(LPVOID lpAddress, SIZE_T dwSize, DWORD  dwFreeType) = GetFunction(KERNEL32_DLL, "VirtualFree");
    if(pVirtualFree) {
        return pVirtualFree(lpAddress, dwSize, dwFreeType);
    }
    return FALSE;
}

HANDLE winapi_kernel32_CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
    HANDLE (WINAPI *pCreateRemoteThread)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) = GetFunction(KERNEL32_DLL, "CreateRemoteThread");
    if(pCreateRemoteThread) {
        return pCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    }
    return NULL;
}
#endif