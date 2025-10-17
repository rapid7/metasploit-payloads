#ifndef _METERPRETER_COMMON_WINAPI_H
#define _METERPRETER_COMMON_WINAPI_H

#include <tlhelp32.h>
#include <windows.h>

typedef struct _WinApiKernel32 {
    // Process and Memory Management
    BOOL (*WriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
    BOOL (*ReadProcessMemory)(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);
    HANDLE (*OpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
    LPVOID (*VirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
    LPVOID (*VirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
    BOOL (*VirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
    BOOL (*VirtualProtectEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
    SIZE_T (*VirtualQuery)(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
    SIZE_T (*VirtualQueryEx)(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
    BOOL (*VirtualFree)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
    BOOL (*FlushInstructionCache)(HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T dwSize);

    // Thread Management
    HANDLE (*CreateRemoteThread)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
    HANDLE (*OpenThread)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);
    DWORD (*SuspendThread)(HANDLE hThread);
    DWORD (*ResumeThread)(HANDLE hThread);
    DWORD (*WaitForMultipleObjects)(DWORD nCount, const HANDLE* lpHandles, BOOL bWaitAll, DWORD dwMilliseconds);

    // Handle Management
    BOOL (*CloseHandle)(HANDLE hObject);
    BOOL (*DuplicateHandle)(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions);
    BOOL (*SetHandleInformation)(HANDLE hObject, DWORD dwMask, DWORD dwFlags);

    // Tool-Help Snapshot APIs (for process/thread enumeration)
    HANDLE (*CreateToolhelp32Snapshot)(DWORD dwFlags, DWORD th32ProcessID);
    BOOL (*Thread32First)(HANDLE hSnapshot, LPTHREADENTRY32 lpte);
    BOOL (*Thread32Next)(HANDLE hSnapshot, LPTHREADENTRY32 lpte);

    // Module/Library Management
    HMODULE (*LoadLibraryA)(LPCSTR lpLibFileName);
    BOOL (*FreeLibrary)(HMODULE hLibModule);

    // File Management
    HANDLE (*CreateFileA)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
    BOOL (*WriteFile)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);

    // Memory Management (Legacy)
    HLOCAL (*LocalFree)(HLOCAL hMem);
    HGLOBAL (*GlobalFree)(HGLOBAL hMem);

} WinApiKernel32;

typedef struct _WinApi {
    WinApiKernel32 kernel32;
} WinApi;
#endif  // _METERPRETER_COMMON_WINAPI_H
