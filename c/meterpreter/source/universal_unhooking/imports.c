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
#include "imports.h"

HANDLE hCustomHeap = NULL;

VOID ResolveImports()
{
    hKernel32 = LoadLibraryA("kernel32.dll");
    CloseHandle_ = (CLOSEHANDLE)GetProcAddress(hKernel32, "CloseHandle");
    CreateFileA_ = (CREATEFILEA)GetProcAddress(hKernel32, "CreateFileA");
    CreateFileW_ = (CREATEFILEW)GetProcAddress(hKernel32, "CreateFileW");
    CreateFileMappingW_ = (CREATEFILEMAPPINGW)GetProcAddress(hKernel32, "CreateFileMappingW");
    MapViewOfFile_ = (MAPVIEWOFFILE)GetProcAddress(hKernel32, "MapViewOfFile");
    UnmapViewOfFile_ = (UNMAPVIEWOFFILE)GetProcAddress(hKernel32, "UnmapViewOfFile");
    VirtualAlloc_ = (VIRTUALALLOC)GetProcAddress(hKernel32, "VirtualAlloc");
    VirtualFree_ = (VIRTUALFREE)GetProcAddress(hKernel32, "VirtualFree");
    VirtualProtect_ = (VIRTUALPROTECT)GetProcAddress(hKernel32, "VirtualProtect");
    HeapCreate_ = (HEAPCREATE)GetProcAddress(hKernel32, "HeapCreate");
#ifdef _DEBUG
    OutputDebugStringA_ = (OUTPUTDEBUGSTRINGA)GetProcAddress(hKernel32, "OutputDebugStringA");
    OutputDebugStringW_ = (OUTPUTDEBUGSTRINGW)GetProcAddress(hKernel32, "OutputDebugStringW");
#endif

    hNtdll = LoadLibraryA("ntdll.dll");
    HeapAlloc_ = (HEAPALLOC)GetProcAddress(hNtdll, "RtlAllocateHeap");
    HeapFree_ = (HEAPFREE)GetProcAddress(hNtdll, "RtlFreeHeap");

}

VOID FreeImports()
{
    OUTPUTDBGA("[*] Freeing library imports\n");
    FreeLibrary(hNtdll);
    FreeLibrary(hKernel32);
}

void* malloc_(size_t stSize)
{
    void* pBuffer;

    if (hCustomHeap == NULL)
        hCustomHeap = HeapCreate_(0, 0, 0);

    pBuffer = HeapAlloc_(hCustomHeap, HEAP_ZERO_MEMORY, stSize);

    return pBuffer;
}

void free_(void* pBlock)
{
    HeapFree_(hCustomHeap, 0, pBlock);
}

size_t strlen_(const char* str)
{
    char* curPtr;

    for (curPtr = (char *)str; *curPtr != 0; curPtr++);

    return curPtr - str;
}

int strcmp_(const char* str1, const char* str2)
{
    const char *szP0;
    const char *szP1;

    for (szP0 = str1, szP1 = str2; *szP0 != 0 && *szP1 != 0 && *szP0 == *szP1; szP0++, szP1++);

    return *szP0 - *szP1;
}

int stricmp_(const char* str1, const char* str2)
{
    const char *szP0;
    const char *szP1;
    char char0;
    char char1;

    for (szP0 = str1, szP1 = str2; *szP0 != 0 && *szP1 != 0; szP0++, szP1++)
    {
        char0 = *szP0;
        char1 = *szP1;
        if (0x61 <= char0 && char0 <= 0x7A)
            char0 -= 0x20;
        if (0x61 <= char1 && char1 <= 0x7A)
            char1 -= 0x20;
        if (char0 != char1)
            break;
    }

    char0 = *szP0;
    char1 = *szP1;

    if (0x61 <= char0 && char0 <= 0x7A)
        char0 -= 0x20;
    if (0x61 <= char1 && char1 <= 0x7A)
        char1 -= 0x20;

    return char0 - char1;
}

int strnicmp_(const char* str1, const char* str2, size_t length)
{
    const char *szP0;
    const char *szP1;
    char char0;
    char char1;
    size_t count;
    
    for (szP0 = str1, szP1 = str2, count = 0; *szP0 != 0 && *szP1 != 0 && count < length - 1; szP0++, szP1++,count++)
    {
        char0 = *szP0;
        char1 = *szP1;
        if (0x61 <= char0 && char0 <= 0x7A)
            char0 -= 0x20;
        if (0x61 <= char1 && char1 <= 0x7A)
            char1 -= 0x20;
        if (char0 != char1)
            break;
    }

    char0 = *szP0;
    char1 = *szP1;

    if (0x61 <= char0 && char0 <= 0x7A)
        char0 -= 0x20;
    if (0x61 <= char1 && char1 <= 0x7A)
        char1 -= 0x20;



    return char0 - char1;
}


int wcslen_(wchar_t *wszString)
{
    wchar_t* wcsPtr;

    for (wcsPtr = wszString; *wcsPtr != 0; wcsPtr++);

    return (int)(wcsPtr - wszString);
}

char* wcstocs_(PWSTR wszStr, size_t stLength)
{
    char* szRet;
    size_t stIdx;

    szRet = (PCHAR)malloc_(stLength + 1);

    for (stIdx = 0; stIdx < stLength; stIdx++)
    {
        szRet[stIdx] = (char)wszStr[stIdx];
    }

    szRet[stLength] = 0;

    return szRet;
}
void* memcpy_(void *dest, const void *src, size_t n)
{
    char *dp = dest;
    const char *sp = src;
    while (n--)
        *dp++ = *sp++;
    return dest;
}

int memcmp_(const void* s1, const void* s2,size_t n)
{
    const unsigned char *p1 = s1, *p2 = s2;
    while(n--)
        if( *p1 != *p2 )
            return *p1 - *p2;
        else
            p1++,p2++;
    return 0;
}

void ParseFwdDesc(const PCHAR szFwdDesc, PCHAR* pszModule, PCHAR* pszFunc)
{
    char *szModName;
    char *szFuncName;
    char *pcSep;
    char *pcCur;
    size_t stModLen;
    size_t stFuncLen;

    pcSep = NULL;
    *pszModule = NULL;
    *pszFunc = NULL;

    for (pcCur = szFwdDesc; *pcCur != 0; pcCur++)
    {
        if (*pcCur == '.')
        {
            pcSep = pcCur;
            break;
        }
    }

    if (pcSep)
    {
        stModLen = (pcSep - szFwdDesc);
        szModName = (char *)malloc_(stModLen + 4 + 1);
        memcpy_(szModName, szFwdDesc, stModLen);
        memcpy_(szModName + stModLen, ".dll", 5);

        stFuncLen = strlen_(szFwdDesc) - (stModLen);
        szFuncName = (char *)malloc_(stFuncLen + 1);
        memcpy_(szFuncName, pcSep + 1, stFuncLen);
        szFuncName[stFuncLen] = 0;

        *pszModule = szModName;
        *pszFunc = szFuncName;
    }
}