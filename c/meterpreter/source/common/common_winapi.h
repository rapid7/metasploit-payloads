#ifndef _METERPRETER_COMMON_WINAPI_H
#define _METERPRETER_COMMON_WINAPI_H

#include <tlhelp32.h>
#include <windows.h>

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

#if !defined(_METERPRETER_POOLPARTY_C)
typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PVOID ObjectName;  // PUNICODE_STRING
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
#endif

typedef struct _WinApiNtdll {
    NTSTATUS (*ZwAllocateVirtualMemory)(HANDLE hProcess, PVOID* pBaseAddress, ULONG_PTR pZeroBits, PSIZE_T pRegionSize, ULONG ulAllocationType, ULONG ulProtect);
    NTSTATUS (*ZwOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes, CLIENT_ID* ClientId);
    NTSTATUS (*ZwWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);
    NTSTATUS (*ZwReadVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesRead);
    NTSTATUS (*ZwProtectVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
    NTSTATUS (*ZwQueryVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
    NTSTATUS (*ZwFreeVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
    NTSTATUS (*NtQueueApcThread)(HANDLE ThreadHandle, PVOID ApcRoutine, PVOID ApcContext, PVOID Argument1, PVOID Argument2);
    NTSTATUS (*NtOpenThread)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes, CLIENT_ID* ClientId);
} WinApiNtdll;

typedef struct _WinApiKernel32 {
    // Process and Memory Management
    BOOL   (*WriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
    BOOL   (*ReadProcessMemory)(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);
    HANDLE (*OpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
    LPVOID (*VirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
    LPVOID (*VirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
    BOOL   (*VirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
    BOOL   (*VirtualProtectEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
    SIZE_T (*VirtualQuery)(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
    SIZE_T (*VirtualQueryEx)(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
    BOOL   (*VirtualFree)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
    BOOL   (*FlushInstructionCache)(HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T dwSize);

    // Thread and Synchronization
    HANDLE (*CreateRemoteThread)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
    HANDLE (*OpenThread)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);
    DWORD  (*SuspendThread)(HANDLE hThread);
    DWORD  (*ResumeThread)(HANDLE hThread);
    DWORD  (*WaitForMultipleObjects)(DWORD nCount, const HANDLE* lpHandles, BOOL bWaitAll, DWORD dwMilliseconds);
    HANDLE (*CreateThread)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
    BOOL   (*ResetEvent)(HANDLE hEvent);
    BOOL   (*SetThreadErrorMode)(DWORD dwNewMode, LPDWORD lpOldMode);

    // Handle Management
    BOOL   (*CloseHandle)(HANDLE hObject);
    BOOL   (*DuplicateHandle)(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions);
    BOOL   (*SetHandleInformation)(HANDLE hObject, DWORD dwMask, DWORD dwFlags);

    // Tool-Help Snapshot APIs
    HANDLE (*CreateToolhelp32Snapshot)(DWORD dwFlags, DWORD th32ProcessID);
    BOOL   (*Thread32First)(HANDLE hSnapshot, LPTHREADENTRY32 lpte);
    BOOL   (*Thread32Next)(HANDLE hSnapshot, LPTHREADENTRY32 lpte);

    // Module/Library Management
    HMODULE (*LoadLibraryA)(LPCSTR lpLibFileName);
    BOOL    (*FreeLibrary)(HMODULE hLibModule);

    // File and Pipe I/O
    HANDLE (*CreateFileA)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
    BOOL   (*WriteFile)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
    HANDLE (*CreateNamedPipeA)(LPCSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
    BOOL   (*ConnectNamedPipe)(HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped);
    BOOL   (*GetOverlappedResult)(HANDLE hFile, LPOVERLAPPED lpOverlapped, LPDWORD lpNumberOfBytesTransferred, BOOL bWait);
    BOOL   (*ReadFile)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
    
    // Legacy Memory Management
    HLOCAL (*LocalFree)(HLOCAL hMem);
    HGLOBAL (*GlobalFree)(HGLOBAL hMem);
} WinApiKernel32;

typedef struct _WinApi {
    WinApiNtdll    ntdll;
    WinApiKernel32 kernel32;
} WinApi;
#endif  // _METERPRETER_COMMON_WINAPI_H
