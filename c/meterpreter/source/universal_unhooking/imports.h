/*************************************************************************************
*  Author: Jeff Tang <jtang@cylance.com>
*  Copyright (c) 2017 Cylance Inc. All rights reserved.                              *
*                                                                                    *
*  Redistribution and use in source and binary forms, with or without modification,  *
*  are permitted provided that the following conditions are met:                     *
*                                                                                    *
*  1. Redistributions of source code must retain the above copyright notice, this    *
*  list of conditions and the following disclaimer.                                  *
*                                                                                    *
*  2. Redistributions in binary form must reproduce the above copyright notice,      *
*  this list of conditions and the following disclaimer in the documentation and/or  *
*  other materials provided with the distribution.                                   *
*                                                                                    *
*  3. Neither the name of the copyright holder nor the names of its contributors     *
*  may be used to endorse or promote products derived from this software without     *
*  specific prior written permission.                                                *
*                                                                                    *
*  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND   *
*  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED     *
*  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE            *
*  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR  *
*  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES    *
*  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;      *
*  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON    *
*  ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT           *
*  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS     *
*  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.                      *
*                                                                                    *
*************************************************************************************/
#pragma once
#ifndef _IMPORTS_H_
#define _IMPORTS_H_
#pragma intrinsic ( memcpy, memcmp, memset )

#define WIN32_LEAN_AND_MEAN 
#include <windows.h>

#ifdef _DEBUG
    #define OUTPUTDBGA(str) OutputDebugStringA_(str);
    #define OUTPUTDBGW(str) OutputDebugStringW_(str);
#else
    #define OUTPUTDBGA(str)
    #define OUTPUTDBGW(str)
#endif

// kernel32.dll
typedef BOOL (WINAPI * CLOSEHANDLE)(HANDLE hObject);
typedef HANDLE (WINAPI * CREATEFILEA)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
typedef HANDLE (WINAPI * CREATEFILEW)(LPWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
typedef HANDLE (WINAPI * CREATEFILEMAPPINGW)(_In_ HANDLE hFile, _In_opt_ LPSECURITY_ATTRIBUTES lpFileMappingAttributes, _In_ DWORD flProtect, _In_ DWORD dwMaximumSizeHigh, _In_ DWORD dwMaximumSizeLow, _In_opt_ LPCWSTR lpName);
typedef LPVOID (WINAPI * MAPVIEWOFFILE)(_In_ HANDLE hFileMappingObject, _In_ DWORD dwDesiredAccess, _In_ DWORD dwFileOffsetHigh, _In_ DWORD dwFileOffsetLow, _In_ SIZE_T dwNumberOfBytesToMap);
typedef BOOL (WINAPI * UNMAPVIEWOFFILE)(_In_ LPCVOID lpBaseAddress);
typedef LPVOID (WINAPI * VIRTUALALLOC)(_In_opt_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flAllocationType, _In_ DWORD flProtect);
typedef BOOL (WINAPI * VIRTUALFREE)(_In_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD dwFreeType);
typedef BOOL (WINAPI * VIRTUALPROTECT)(_In_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flNewProtect, _Out_ PDWORD lpflOldProtect);
typedef HANDLE(WINAPI * HEAPCREATE)(_In_ DWORD flOptions, _In_ SIZE_T dwInitialSize, _In_ SIZE_T dwMaximumSize);
typedef VOID (WINAPI * OUTPUTDEBUGSTRINGA)(_In_opt_ LPCSTR lpOutputString);
typedef VOID (WINAPI * OUTPUTDEBUGSTRINGW)(_In_opt_ LPWSTR lpOutputString);

HMODULE hKernel32;
CLOSEHANDLE CloseHandle_;
CREATEFILEA CreateFileA_;
CREATEFILEW CreateFileW_;
CREATEFILEMAPPINGW CreateFileMappingW_;
MAPVIEWOFFILE MapViewOfFile_;
UNMAPVIEWOFFILE UnmapViewOfFile_;
VIRTUALALLOC VirtualAlloc_;
VIRTUALFREE VirtualFree_;
VIRTUALPROTECT VirtualProtect_;
HEAPCREATE HeapCreate_;
#ifdef _DEBUG
    OUTPUTDEBUGSTRINGA OutputDebugStringA_;
    OUTPUTDEBUGSTRINGW OutputDebugStringW_;
#endif

// ntdll.dll
typedef LPVOID (WINAPI * HEAPALLOC)(_In_ HANDLE hHeap, _In_ DWORD dwFlags, _In_ SIZE_T dwBytes);
typedef BOOL (WINAPI * HEAPFREE)(_In_ HANDLE hHeap, _In_ DWORD dwFlags, _In_ LPVOID lpMem);

HMODULE hNtdll;
HEAPALLOC HeapAlloc_;
HEAPFREE HeapFree_;

// implemented crt
void* malloc_(size_t stSize);
void free_(void* pBlock);
int strcmp_(const char* str1, const char* str2);
int stricmp_(const char* str1, const char* str2);
int strnicmp_(const char* str1, const char* str2, size_t length);
size_t strlen_(const char * str);
int wcslen_(wchar_t *wszString);
char* wcstocs_(PWSTR wszStr, size_t stLength);
void* memcpy_(void *dest, const void *src, size_t n);
int memcmp_(const void* s1, const void* s2, size_t n);

VOID ResolveImports();
VOID FreeImports();
void ParseFwdDesc(const PCHAR szFwdDesc, PCHAR* pszModule, PCHAR* pszFunc);
#endif // _IMPORTS_H_