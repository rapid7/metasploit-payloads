#ifndef _METERPRETER_WINAPI_H
#define _METERPRETER_WINAPI_H

#include <winsock2.h>
#include <windows.h>
#include <winhttp.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <accctrl.h>

#ifndef _METERPRETER_COMMON_WINAPI_H
typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

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

NTSTATUS winapi_ntdll_ZwAllocateVirtualMemory(HANDLE hProcess, PVOID* pBaseAddress, ULONG_PTR pZeroBits, PSIZE_T pRegionSize, ULONG ulAllocationType, ULONG ulProtect);
NTSTATUS winapi_ntdll_ZwOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
NTSTATUS winapi_ntdll_ZwWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);
NTSTATUS winapi_ntdll_ZwReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesRead);
NTSTATUS winapi_ntdll_ZwProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
NTSTATUS winapi_ntdll_ZwQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
NTSTATUS winapi_ntdll_ZwFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
NTSTATUS winapi_ntdll_NtQueueApcThread(HANDLE ThreadHandle, PVOID ApcRoutine, PVOID ApcContext, PVOID Argument1, PVOID Argument2);
NTSTATUS winapi_ntdll_NtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

BOOL winapi_kernel32_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
BOOL winapi_kernel32_ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);
HANDLE winapi_kernel32_OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
LPVOID winapi_kernel32_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
LPVOID winapi_kernel32_VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
BOOL winapi_kernel32_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
BOOL winapi_kernel32_VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
SIZE_T winapi_kernel32_VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
SIZE_T winapi_kernel32_VirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
BOOL winapi_kernel32_VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
HANDLE winapi_kernel32_CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
BOOL winapi_kernel32_CloseHandle(HANDLE hObject);
BOOL winapi_kernel32_DuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions);
HANDLE winapi_kernel32_CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
BOOL winapi_kernel32_Thread32First(HANDLE hSnapshot, LPTHREADENTRY32 lpte);
HANDLE winapi_kernel32_OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);
DWORD winapi_kernel32_SuspendThread(HANDLE hThread);
BOOL winapi_kernel32_Thread32Next(HANDLE hSnapshot, LPTHREADENTRY32 lpte);
DWORD winapi_kernel32_ResumeThread(HANDLE hThread);
BOOL winapi_kernel32_FreeLibrary(HMODULE hLibModule);
BOOL winapi_kernel32_FlushInstructionCache(HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T dwSize);
HLOCAL winapi_kernel32_LocalFree(HLOCAL hMem);
HANDLE winapi_kernel32_CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
BOOL winapi_kernel32_WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
HMODULE winapi_kernel32_LoadLibraryA(LPCSTR lpLibFileName);
DWORD winapi_kernel32_WaitForMultipleObjects(DWORD nCount, const HANDLE* lpHandles, BOOL bWaitAll, DWORD dwMilliseconds);
BOOL winapi_kernel32_SetHandleInformation(HANDLE hObject, DWORD dwMask, DWORD dwFlags);
HGLOBAL winapi_kernel32_GlobalFree(HGLOBAL hMem);
HANDLE winapi_kernel32_CreateNamedPipeA(LPCSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
BOOL winapi_kernel32_ConnectNamedPipe(HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped);
BOOL winapi_kernel32_GetOverlappedResult(HANDLE hFile, LPOVERLAPPED lpOverlapped, LPDWORD lpNumberOfBytesTransferred, BOOL bWait);
BOOL winapi_kernel32_ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
HANDLE winapi_kernel32_CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
BOOL winapi_kernel32_ResetEvent(HANDLE hEvent);
BOOL winapi_kernel32_SetThreadErrorMode(DWORD dwNewMode, LPDWORD lpOldMode);

#endif
