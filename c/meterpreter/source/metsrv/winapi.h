#ifndef _METERPRETER_WINAPI_H
#define _METERPRETER_WINAPI_H

BOOL winapi_kernel32_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T  *lpNumberOfBytesWritten);
HANDLE winapi_kernel32_OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
LPVOID winapi_kernel32_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
LPVOID winapi_kernel32_VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
BOOL winapi_kernel32_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect);
BOOL winapi_kernel32_VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
HANDLE winapi_kernel32_CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);

#endif
