#ifndef _METERPRETER_COMMON_WINAPI_H
#define _METERPRETER_COMMON_WINAPI_H

#include <windows.h>

typedef struct _WinApiKernel32 {
    BOOL (*WriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T  *lpNumberOfBytesWritten)
} WinApiKernel32;

typedef struct _WinApi {
    WinApiKernel32 kernel32;
} WinApi;


BOOL winapi_kernel32_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T  *lpNumberOfBytesWritten);
#endif

