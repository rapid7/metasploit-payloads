// Copyright (c) 2013, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are permitted
// provided that the following conditions are met:
//
//     * Redistributions of source code must retain the above copyright notice, this list of
// conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright notice, this list of
// conditions and the following disclaimer in the documentation and/or other materials provided
// with the distribution.
//
//     * Neither the name of Harmony Security nor the names of its contributors may be used to
// endorse or promote products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//
#include "common.h"
#include "common_metapi.h"
#include "load_library_r.h"

static DWORD Rva2Offset(DWORD dwRva, PIMAGE_NT_HEADERS pNtHeaders)
{
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
	
	// Iterate through the PE sections to find which one contains the RVA.
	for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++)
	{
		// Check if the RVA is within the current section's virtual address space.
		// We use VirtualSize for the upper bound, as this is the true size of the
		// section in memory. SizeOfRawData is its size on disk, which can be smaller,
		// and using it can lead to failing to find RVAs on some platforms (e.g., ARM64).
		if (dwRva >= pSectionHeader->VirtualAddress && dwRva < (pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize))
		{
			// The file offset is calculated by taking the RVA, subtracting the section's
			// base virtual address, and adding the section's file offset (PointerToRawData).
			return (dwRva - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData);
		}
	}

	// If the RVA was not found in any section, it must be within the PE header itself.
	// In this case, the RVA is the same as the file offset.
	if (dwRva < pNtHeaders->OptionalHeader.SizeOfHeaders)
	{
		return dwRva;
	}

	return 0;
}

DWORD GetReflectiveLoaderOffset(VOID* lpReflectiveDllBuffer, LPCSTR cpReflectiveLoaderName)
{
	UINT_PTR uiBaseAddress = (UINT_PTR)lpReflectiveDllBuffer;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;

	// Validate the PE headers.
	pDosHeader = (PIMAGE_DOS_HEADER)uiBaseAddress;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return 0;

	pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + pDosHeader->e_lfanew);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	// Get the export directory RVA.
	PIMAGE_DATA_DIRECTORY pDataDirectory = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (pDataDirectory->VirtualAddress == 0)
		return 0;

	// Convert the RVA to a file offset to get the export directory structure.
	DWORD dwExportDirOffset = Rva2Offset(pDataDirectory->VirtualAddress, pNtHeaders);
	if (dwExportDirOffset == 0)
		return 0;

	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uiBaseAddress + dwExportDirOffset);

	// Get pointers to the three critical arrays within the EAT, using file offsets.
	PDWORD pdwAddressArray = (PDWORD)(uiBaseAddress + Rva2Offset(pExportDirectory->AddressOfFunctions, pNtHeaders));
	PDWORD pdwNameArray = (PDWORD)(uiBaseAddress + Rva2Offset(pExportDirectory->AddressOfNames, pNtHeaders));
	PWORD pwNameOrdinals = (PWORD)(uiBaseAddress + Rva2Offset(pExportDirectory->AddressOfNameOrdinals, pNtHeaders));

	// Search for the loader function by name or by ordinal.
	if (((DWORD_PTR)cpReflectiveLoaderName >> 16) == 0)
	{
		// By ordinal
		WORD wOrdinal = LOWORD((DWORD_PTR)cpReflectiveLoaderName);
		DWORD dwOrdinalBase = pExportDirectory->Base;

		if (wOrdinal < dwOrdinalBase || wOrdinal >= dwOrdinalBase + pExportDirectory->NumberOfFunctions)
			return 0;

		DWORD dwFunctionRva = pdwAddressArray[wOrdinal - dwOrdinalBase];
		return Rva2Offset(dwFunctionRva, pNtHeaders);
	}
	else
	{
		// By name
		for (DWORD i = 0; i < pExportDirectory->NumberOfNames; i++)
		{
			LPCSTR cpExportedFunctionName = (LPCSTR)(uiBaseAddress + Rva2Offset(pdwNameArray[i], pNtHeaders));

			// Use strcmp for a precise match.
			if (strcmp(cpExportedFunctionName, cpReflectiveLoaderName) == 0)
			{
				WORD wFunctionOrdinal = pwNameOrdinals[i];
				DWORD dwFunctionRva = pdwAddressArray[wFunctionOrdinal];
				return Rva2Offset(dwFunctionRva, pNtHeaders);
			}
		}
	}

	return 0;
}

HMODULE WINAPI LoadLibraryR(LPVOID lpBuffer, DWORD dwLength, LPCSTR cpReflectiveLoaderName)
{
	HMODULE hResult = NULL;
	DWORD dwReflectiveLoaderOffset;
	REFLECTIVELOADER pReflectiveLoader;
	DLLMAIN pDllMain;
	DWORD dwOldProtect;

	if (lpBuffer == NULL || dwLength == 0)
		return NULL;

	// Find the file offset of the reflective loader function.
	dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer, cpReflectiveLoaderName);
	if (dwReflectiveLoaderOffset == 0)
		return NULL;

	pReflectiveLoader = (ULONG_PTR)((UINT_PTR)lpBuffer + dwReflectiveLoaderOffset);

	// Make the buffer executable so we can call the loader.
	if (!met_api->win_api.kernel32.VirtualProtect(lpBuffer, dwLength, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		return NULL;

	// Call the loader, which performs the mapping and returns a pointer to the new DllMain.
	pDllMain = (DLLMAIN)pReflectiveLoader();
	if (pDllMain == NULL)
	{
		met_api->win_api.kernel32.VirtualProtect(lpBuffer, dwLength, dwOldProtect, &dwOldProtect);
		return NULL;
	}

	// Query the newly loaded DllMain for its module handle.
	if (!pDllMain(NULL, DLL_QUERY_HMODULE, &hResult))
		hResult = NULL;
	
	// Revert the original buffer's memory protection.
	met_api->win_api.kernel32.VirtualProtect(lpBuffer, dwLength, dwOldProtect, &dwOldProtect);

	return hResult;
}

HANDLE WINAPI load_library_r(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPCSTR cpReflectiveLoaderName, DWORD dwActualReflectiveLoaderOffset, LPVOID lpParameter)
{
	LPVOID lpRemoteLibraryBuffer = NULL;
	HANDLE hThread = NULL;
    DWORD dwResult = ERROR_SUCCESS;
	do {
        if (!hProcess || !lpBuffer || !dwLength)
		return NULL;
        // Find the loader's offset within the file buffer.
        DWORD dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer, cpReflectiveLoaderName);
        if(dwActualReflectiveLoaderOffset != 0) {
            dprintf("[LOADREMOTE] Using effective reflective loader offset: %lu\n", dwActualReflectiveLoaderOffset);
            dwReflectiveLoaderOffset = dwActualReflectiveLoaderOffset;
        }

        if (dwReflectiveLoaderOffset == 0) {
            BREAK_WITH_ERROR("[LOADREMOTE] Failed to find reflective loader offset", ERROR_INVALID_DATA);
        }

        // Allocate memory in the remote process for the DLL.
        lpRemoteLibraryBuffer = met_api->win_api.kernel32.VirtualAllocEx(hProcess, NULL, dwLength, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!lpRemoteLibraryBuffer) {
            BREAK_WITH_ERROR("[LOADREMOTE] Failed to allocate memory in remote process", ERROR_OUTOFMEMORY);
        }

        // Write the entire DLL buffer into the allocated remote memory.
        if (!met_api->win_api.kernel32.WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, lpBuffer, dwLength, NULL))
        {
            BREAK_WITH_ERROR("[LOADREMOTE] Failed to write library into remote process memory", ERROR_WRITE_FAULT);
        }
        
        // Set initial memory permissions to Execute+Read. The loader will later set final
        // permissions on each section, but this helps bypass some basic W^X checks.
        DWORD dwOldProt;
        if (!met_api->win_api.kernel32.VirtualProtectEx(hProcess, lpRemoteLibraryBuffer, dwLength, PAGE_EXECUTE_READ, &dwOldProt))
        {
            BREAK_WITH_ERROR("[LOADREMOTE] Failed to set memory protection in remote process", ERROR_INVALID_PARAMETER);
        }

        // Calculate the absolute address of the reflective loader in the remote process.
        LPTHREAD_START_ROUTINE lpReflectiveLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR)lpRemoteLibraryBuffer + dwReflectiveLoaderOffset);

        // Create a remote thread to execute the loader.
        hThread = met_api->win_api.kernel32.CreateRemoteThread(hProcess, NULL, 1024 * 1024, lpReflectiveLoader, lpParameter, 0, NULL);
        if (!hThread)
        {
            BREAK_WITH_ERROR("[LOADREMOTE] Failed to create remote thread", ERROR_INVALID_PARAMETER);
        }
    } while (FALSE);

    if(dwResult != ERROR_SUCCESS)
    {
        if (lpRemoteLibraryBuffer)
        {
            met_api->win_api.kernel32.VirtualFreeEx(hProcess, lpRemoteLibraryBuffer, 0, MEM_RELEASE);
        }
        return NULL;
    }
	return hThread;
}
