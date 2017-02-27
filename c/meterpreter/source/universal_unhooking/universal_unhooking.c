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
#include "universal_unhooking.h"

void RefreshPE()
{
    HMODULE hModule;
    PWCHAR wszFullDllName;
    PWCHAR wszBaseDllName;
    ULONG_PTR pDllBase;

    PLDR_DATA_TABLE_ENTRY pLdteHead = NULL;
    PLDR_DATA_TABLE_ENTRY pLdteCurrent = NULL;

	ResolveImports();

    OUTPUTDBGA("[*] Running DLLRefresher\n");

    pLdteHead = GetInMemoryOrderModuleList();
    pLdteCurrent = pLdteHead;

    do {
        if (pLdteCurrent->FullDllName.Length > 2)
        {
            wszFullDllName = pLdteCurrent->FullDllName.pBuffer;
            wszBaseDllName = pLdteCurrent->BaseDllName.pBuffer;
            pDllBase = (ULONG_PTR)pLdteCurrent->DllBase;

            OUTPUTDBGA("[*] Refreshing DLL: ");
            OUTPUTDBGW(wszBaseDllName);
            OUTPUTDBGA("\n");

            hModule = CustomLoadLibrary(wszFullDllName, wszBaseDllName, pDllBase);

            if (hModule)
            {
                ScanAndFixModule((ULONG_PTR)hModule, pDllBase, wszBaseDllName);
                VirtualFree_(hModule, 0, MEM_RELEASE);
            }
        }
        pLdteCurrent = (PLDR_DATA_TABLE_ENTRY)pLdteCurrent->InMemoryOrderModuleList.Flink;
    } while (pLdteCurrent != pLdteHead);

	FreeImports();
}

HMODULE CustomLoadLibrary(const PWCHAR wszFullDllName, const PWCHAR wszBaseDllName, ULONG_PTR pDllBase)
{
    // File handles
    HANDLE hFile;
    HANDLE hMap;
    ULONG_PTR pFile;

    // PE headers
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader;
    PIMAGE_SECTION_HEADER pSectionHeader;

    // Library 
    ULONG_PTR pLibraryAddr;
    DWORD dwIdx;

    // Relocation
    PIMAGE_DATA_DIRECTORY pDataDir;
    PIMAGE_BASE_RELOCATION pBaseReloc;
    ULONG_PTR pReloc;
    DWORD dwNumRelocs;
    ULONG_PTR pInitialImageBase;
    PIMAGE_RELOC pImageReloc;

    // Import
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
    PIMAGE_IMPORT_BY_NAME pImportName;
    PCHAR szDllName;
    PCHAR szBaseDllName;
    PCHAR szRedirName;
    HMODULE hModule;
    PIMAGE_THUNK_DATA pThunkData;
    FARPROC* pIatEntry;

    // ----
    // Step 1: Map the file into memory
    // ----

    OUTPUTDBGA("\t[+] Opening file: ");
    OUTPUTDBGW(wszFullDllName);
    OUTPUTDBGA("\n");

    hFile = CreateFileW_(wszFullDllName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return NULL;

    hMap = CreateFileMappingW_(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMap == NULL)
    {
        CloseHandle_(hFile);
        return NULL;
    }

    pFile = (ULONG_PTR) MapViewOfFile_(hMap, FILE_MAP_READ, 0, 0, 0);
    CloseHandle_(hFile);
    CloseHandle_(hMap);

    if (!pFile)
    {
        return NULL;
    }

    // ----
    // Step 2: Parse the file headers and load it into memory
    // ----
    pDosHeader = (PIMAGE_DOS_HEADER)pFile;
    pNtHeader = (PIMAGE_NT_HEADERS)(pFile + pDosHeader->e_lfanew);

    // allocate memory to copy DLL into
    OUTPUTDBGA("\t[+] Allocating memory\n");
    pLibraryAddr = (ULONG_PTR) VirtualAlloc_(NULL, pNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy header
    OUTPUTDBGA("\t[+] Copying PE header into memory\n");
    memcpy_((PVOID)pLibraryAddr, (PVOID)pFile, pNtHeader->OptionalHeader.SizeOfHeaders);

    // copy sections
    OUTPUTDBGA("\t[+] Copying PE sections into memory\n");
    for (dwIdx = 0; dwIdx < pNtHeader->FileHeader.NumberOfSections; dwIdx++)
    {
        pSectionHeader = (PIMAGE_SECTION_HEADER)(pFile + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (dwIdx * sizeof(IMAGE_SECTION_HEADER)));
        memcpy_((PVOID)(pLibraryAddr + pSectionHeader->VirtualAddress),
                (PVOID)(pFile + pSectionHeader->PointerToRawData),
                pSectionHeader->SizeOfRawData);
    }

    // unmap the file and update our pointers to the loaded image
    UnmapViewOfFile_((PVOID)pFile);
    pDosHeader = (PIMAGE_DOS_HEADER)pLibraryAddr;
    pNtHeader = (PIMAGE_NT_HEADERS)(pLibraryAddr + pDosHeader->e_lfanew);

    // ----
    // Step 3: Calculate relocations
    // ----
    OUTPUTDBGA("\t[+] Calculating file relocations\n");

    pDataDir = &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    pInitialImageBase = pNtHeader->OptionalHeader.ImageBase;
    
    // set the ImageBase to the already loaded module's base
    pNtHeader->OptionalHeader.ImageBase = pDllBase;

    // check if their are any relocations present
    if (pDataDir->Size)
    {
        // calculate the address of the first IMAGE_BASE_RELOCATION entry
        pBaseReloc = (PIMAGE_BASE_RELOCATION)((PCHAR)pLibraryAddr + pDataDir->VirtualAddress);

        // iterate through each relocation entry
        while (pBaseReloc->SizeOfBlock)
        {
            // the VA for this relocation block
            pReloc = (pLibraryAddr + pBaseReloc->VirtualAddress);

            // number of entries in this relocation block
            dwNumRelocs = (pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);

            // first entry in the current relocation block
            pImageReloc = (PIMAGE_RELOC) ((PCHAR)pBaseReloc + sizeof(IMAGE_BASE_RELOCATION));

            // iterate through each entry in the relocation block
            while (dwNumRelocs--)
            {
                // perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
                // we subtract the initial ImageBase and add in the original dll base
                if (pImageReloc->type == IMAGE_REL_BASED_DIR64)
                {
                    *(ULONG_PTR *)(pReloc + pImageReloc->offset) -= pInitialImageBase;
                    *(ULONG_PTR *)(pReloc + pImageReloc->offset) += pDllBase;
                }
                else if (pImageReloc->type == IMAGE_REL_BASED_HIGHLOW)
                {
                    *(DWORD *)(pReloc + pImageReloc->offset) -= (DWORD)pInitialImageBase;
                    *(DWORD *)(pReloc + pImageReloc->offset) += (DWORD)pDllBase;
                }
                else if (pImageReloc->type == IMAGE_REL_BASED_HIGH)
                {
                    *(WORD *)(pReloc + pImageReloc->offset) -= HIWORD(pInitialImageBase);
                    *(WORD *)(pReloc + pImageReloc->offset) += HIWORD(pDllBase);
                }
                else if (pImageReloc->type == IMAGE_REL_BASED_LOW)
                {
                    *(WORD *)(pReloc + pImageReloc->offset) -= LOWORD(pInitialImageBase);
                    *(WORD *)(pReloc + pImageReloc->offset) += LOWORD(pDllBase);
                }
                
                // get the next entry in the current relocation block
                pImageReloc = (PIMAGE_RELOC) (((PCHAR)pImageReloc) + sizeof(IMAGE_RELOC));
            }

            // get the next entry in the relocation directory
            pBaseReloc = (PIMAGE_BASE_RELOCATION)(((PCHAR)pBaseReloc) + pBaseReloc->SizeOfBlock);
        }
    }

    // ----
    // Step 4: Update import table
    // ----

    OUTPUTDBGA("\t[+] Resolving Import Address Table (IAT) \n");

    pDataDir = &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (pDataDir->Size)
    {
        pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(pLibraryAddr + pDataDir->VirtualAddress);
        szBaseDllName = wcstocs_(wszBaseDllName, wcslen_(wszBaseDllName));

        while (pImportDesc->Characteristics)
        {
            hModule = NULL;
            szDllName = (PCHAR)(pLibraryAddr + pImportDesc->Name);
            OUTPUTDBGA("\t[+] Loading library: ");
            OUTPUTDBGA(szDllName);
            OUTPUTDBGA("\n");

            // If the DLL starts with api- or ext-, resolve the redirected name and load it
            if (strnicmp_(szDllName, "api-", 4) == 0 || strnicmp_(szDllName, "ext-", 4) == 0)
            {
                szRedirName = GetRedirectedName(szBaseDllName, szDllName);
                if (szRedirName)
                {
                    hModule = GetLoadedLibrary(szRedirName);
                    free_(szRedirName);
                }
            }

            // If the redirected name load failed or it is a normal DLL, just load it
            if (hModule == NULL)
                hModule = GetLoadedLibrary(szDllName);

            // Ignore libraries that fail to load
            if (hModule == NULL)
            {
                OUTPUTDBGA("\t[-] Failed to load library\n");
                pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((PCHAR)pImportDesc + sizeof(IMAGE_IMPORT_DESCRIPTOR));
                continue;
            }

            if (pImportDesc->OriginalFirstThunk)
                pThunkData = (PIMAGE_THUNK_DATA)(pLibraryAddr + pImportDesc->OriginalFirstThunk);
            else
                pThunkData = (PIMAGE_THUNK_DATA)(pLibraryAddr + pImportDesc->FirstThunk);

            pIatEntry = (FARPROC*)(pLibraryAddr + pImportDesc->FirstThunk);

            // loop through each thunk and resolve the import
            while (DEREF(pThunkData))
            {
                if (IMAGE_SNAP_BY_ORDINAL(pThunkData->u1.Ordinal))
                {
                    *pIatEntry = CustomGetProcAddressEx(hModule, (PCHAR)IMAGE_ORDINAL(pThunkData->u1.Ordinal), szDllName);
                }
                else
                {
                    pImportName = (PIMAGE_IMPORT_BY_NAME)(pLibraryAddr + DEREF(pThunkData));
                    OUTPUTDBGA("\t\t[+] Resolving procedure: ");
                    OUTPUTDBGA((PCHAR)pImportName->Name);
                    OUTPUTDBGA("\n");
                    *pIatEntry = CustomGetProcAddressEx(hModule, (PCHAR)pImportName->Name, szDllName);
                }

                // increment pointer to next entry
                pThunkData++;
                pIatEntry++;
            }

            pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((PCHAR)pImportDesc + sizeof(IMAGE_IMPORT_DESCRIPTOR));

        }
        free_(szBaseDllName);
    }

    return (HMODULE) pLibraryAddr;
}

HMODULE GetLoadedLibrary(const PCHAR szModule)
{

    PLDR_DATA_TABLE_ENTRY pLdteHead = NULL;
    PLDR_DATA_TABLE_ENTRY pLdteCurrent = NULL;
    PCHAR szEntry;

    OUTPUTDBGA("\t\t\t[*] Searching for loaded module: ");
    OUTPUTDBGA(szModule);
    OUTPUTDBGA(" -> ");

    pLdteHead = GetInMemoryOrderModuleList();
    pLdteCurrent = pLdteHead;

    do {
        if (pLdteCurrent->FullDllName.Length > 2)
        {
            szEntry = wcstocs_(pLdteCurrent->BaseDllName.pBuffer, pLdteCurrent->BaseDllName.Length);
            if (stricmp_(szModule, szEntry) == 0)
            {
                OUTPUTDBGA("found in memory\n");
                free_(szEntry);
                return ((HMODULE)pLdteCurrent->DllBase);
            }
            free_(szEntry);
        }
        pLdteCurrent = (PLDR_DATA_TABLE_ENTRY)pLdteCurrent->InMemoryOrderModuleList.Flink;
    } while (pLdteCurrent != pLdteHead);

    OUTPUTDBGA("loading from disk\n");
    return LoadLibraryA(szModule);
}

FARPROC WINAPI CustomGetProcAddressEx(HMODULE hModule, const PCHAR lpProcName, const PCHAR szOriginalModule)
{
    UINT_PTR uiLibraryAddress = 0;
    UINT_PTR uiAddressArray = 0;
    UINT_PTR uiNameArray = 0;
    UINT_PTR uiNameOrdinals = 0;
    UINT_PTR uiFuncVA = 0;
    PCHAR szFwdDesc;
    PCHAR szRedirModule;
    PCHAR szRedirFunc;
    PCHAR szRedir;
    HMODULE hFwdModule;
    PIMAGE_NT_HEADERS pNtHeaders = NULL;
    PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
    FARPROC fpResult = NULL;
    DWORD dwCounter;

    if (hModule == NULL)
        return NULL;

    // a module handle is really its base address
    uiLibraryAddress = (UINT_PTR)hModule;

    // get the VA of the modules NT Header
    pNtHeaders = (PIMAGE_NT_HEADERS)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);

    pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    // get the VA of the export directory
    pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uiLibraryAddress + pDataDirectory->VirtualAddress);

    // get the VA for the array of addresses
    uiAddressArray = (uiLibraryAddress + pExportDirectory->AddressOfFunctions);

    // get the VA for the array of name pointers
    uiNameArray = (uiLibraryAddress + pExportDirectory->AddressOfNames);

    // get the VA for the array of name ordinals
    uiNameOrdinals = (uiLibraryAddress + pExportDirectory->AddressOfNameOrdinals);

    // test if we are importing by name or by ordinal...
    if (((DWORD)lpProcName & 0xFFFF0000) == 0x00000000)
    {
        // import by ordinal...

        // use the import ordinal (- export ordinal base) as an index into the array of addresses
        uiAddressArray += ((IMAGE_ORDINAL((DWORD)lpProcName) - pExportDirectory->Base) * sizeof(DWORD));

        // resolve the address for this imported function
        fpResult = (FARPROC)(uiLibraryAddress + DEREF_32(uiAddressArray));
    }
    else
    {
        // import by name...
        dwCounter = pExportDirectory->NumberOfNames;
        while (dwCounter--)
        {
            char * cpExportedFunctionName = (char *)(uiLibraryAddress + DEREF_32(uiNameArray));

            // test if we have a match...
            if (strcmp_(cpExportedFunctionName, lpProcName) == 0)
            {
                // use the functions name ordinal as an index into the array of name pointers
                uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));
                uiFuncVA = DEREF_32(uiAddressArray);

                // check for redirected exports
                if (pDataDirectory->VirtualAddress <= uiFuncVA && uiFuncVA < (pDataDirectory->VirtualAddress + pDataDirectory->Size))
                {
                    szFwdDesc = (PCHAR)(uiLibraryAddress + uiFuncVA);
                    ParseFwdDesc(szFwdDesc, &szRedirModule, &szRedirFunc);

                    OUTPUTDBGA("\t\t\t[*] Found a redirected entry: ");
                    OUTPUTDBGA(szFwdDesc);
                    OUTPUTDBGA("\n");

                    // check for a redirected module name
                    if (strnicmp_(szRedirModule, "api-", 4) == 0 || strnicmp_(szRedirModule, "ext-", 4) == 0)
                    {
                        szRedir = GetRedirectedName(szOriginalModule, szRedirModule);
                        if (szRedir)
                        {
                            free_(szRedirModule);
                            szRedirModule = szRedir;
                        }
                    }

                    hFwdModule = GetLoadedLibrary(szRedirModule);
                    fpResult = CustomGetProcAddressEx(hFwdModule, szRedirFunc, szRedirModule);
                    free_(szRedirModule);
                    free_(szRedirFunc);
                    return fpResult;
                }
                else
                {
                    // calculate the virtual address for the function
                    fpResult = (FARPROC)(uiLibraryAddress + uiFuncVA);
                }

                // finish...
                break;
            }

            // get the next exported function name
            uiNameArray += sizeof(DWORD);

            // get the next exported function name ordinal
            uiNameOrdinals += sizeof(WORD);
        }
    }

    return fpResult;

}

VOID ScanAndFixModule(ULONG_PTR pKnown, ULONG_PTR pSuspect, PWCHAR wszBaseDllName)
{
    // PE headers
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader;
    PIMAGE_SECTION_HEADER pSectionHeader;

    DWORD dwIdx;

    OUTPUTDBGA("[*] Scanning module: ");
    OUTPUTDBGW(wszBaseDllName);
    OUTPUTDBGA("\n");

    pDosHeader = (PIMAGE_DOS_HEADER)pKnown;
    pNtHeader = (PIMAGE_NT_HEADERS)(pKnown + pDosHeader->e_lfanew);

    // Scan PE header
    ScanAndFixSection("Header", (PCHAR)pKnown, (PCHAR)pSuspect, pNtHeader->OptionalHeader.SizeOfHeaders);

    // Scan each section
    for (dwIdx = 0; dwIdx < pNtHeader->FileHeader.NumberOfSections; dwIdx++)
    {
        pSectionHeader = (PIMAGE_SECTION_HEADER)(pKnown + pDosHeader->e_lfanew +
                                                 sizeof(IMAGE_NT_HEADERS) +
                                                 (dwIdx * sizeof(IMAGE_SECTION_HEADER)));

        // Skip writable sections
        if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE)
            continue;

        ScanAndFixSection((PCHAR)pSectionHeader->Name, (PCHAR)(pKnown + pSectionHeader->VirtualAddress),
                                      (PCHAR)(pSuspect + pSectionHeader->VirtualAddress), pSectionHeader->Misc.VirtualSize);
    }
}

VOID ScanAndFixSection(PCHAR szSectionName, PCHAR pKnown, PCHAR pSuspect, size_t stLength)
{
    DWORD ddOldProtect;
    DWORD count;
    PCHAR pbKnown;
    PCHAR pbSuspect;

    pbKnown = pKnown;
    pbSuspect = pSuspect;

    for (count = 0; count < stLength; count++)
    {
        if (*pbKnown != *pbSuspect)
        {
            OUTPUTDBGA("\t[!] Found modification in: ");
            OUTPUTDBGA(szSectionName);
            OUTPUTDBGA("\n");

            if (!VirtualProtect_(pSuspect, stLength, PAGE_EXECUTE_READWRITE, &ddOldProtect))
            {
                OUTPUTDBGA("\t[!] Failed to set memory permissions to PAGE_EXECUTE_READWRITE.\n");
                return;
            }

            OUTPUTDBGA("\t[+] Copying known good section into memory.\n");
            memcpy_(pSuspect, pKnown, stLength);

            if (!VirtualProtect_(pSuspect, stLength, ddOldProtect, &ddOldProtect))
                OUTPUTDBGA("\t[!] Failed to reset memory permissions.\n");

            return;
        }
        pbKnown++;
        pbSuspect++;
    }
}