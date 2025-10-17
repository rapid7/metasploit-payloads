#ifndef _METERPRETER_WINAPI_H
#define _METERPRETER_WINAPI_H
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

NTSTATUS winapi_ntdll_ZwAllocateVirtualMemory(HANDLE hProcess, PVOID* pBaseAddress, ULONG_PTR pZeroBits, PSIZE_T pRegionSize, ULONG ulAllocationType, ULONG ulProtect);
#endif
