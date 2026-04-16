#include "extension_loader.h"
#include "common_metapi.h"
#include "common_exports.h"
#include "metsrv.h"

BOOL FixRelocations(PIMAGE_DATA_DIRECTORY dRelocBaseAddress, ULONG_PTR pBaseAddress, ULONG_PTR pPreferrableAddress)
{
	ULONG_PTR delta = pBaseAddress - pPreferrableAddress;
	PIMAGE_BASE_RELOCATION pBaseRelocationTable = (PIMAGE_BASE_RELOCATION)(pBaseAddress + dRelocBaseAddress->VirtualAddress);
	PBASE_RELOCATION_ENTRY pBaseRelocEntry = NULL;

	while (pBaseRelocationTable->SizeOfBlock != 0)
	{
		pBaseRelocEntry = (PBASE_RELOCATION_ENTRY)(pBaseRelocationTable + 1);
		while ((PBYTE)pBaseRelocEntry != (PBYTE)pBaseRelocationTable + pBaseRelocationTable->SizeOfBlock)
		{
			switch (pBaseRelocEntry->Type)
			{
			case IMAGE_REL_BASED_ABSOLUTE:
				break;
			case IMAGE_REL_BASED_DIR64:
				*((ULONG_PTR*)(pBaseAddress + pBaseRelocationTable->VirtualAddress + pBaseRelocEntry->Offset)) += delta;
				break;
			case IMAGE_REL_BASED_HIGHLOW:
				*((DWORD*)(pBaseAddress + pBaseRelocationTable->VirtualAddress + pBaseRelocEntry->Offset)) += (DWORD)delta;
				break;
			#if defined(_M_ARM)
			case IMAGE_REL_BASED_ARM_MOV32T:
				DWORD dwInstruction = *(DWORD *)((ULONG_PTR)pBaseAddress + pBaseRelocationTable->VirtualAddress + pBaseRelocEntry->Offset + sizeof(DWORD));
				// Flip the words to get the instruction as expected (account for endianness/instruction packing).
				dwInstruction = MAKELONG(HIWORD(dwInstruction), LOWORD(dwInstruction));
				if ((dwInstruction & ARM_MOV_MASK) == ARM_MOVT)
				{
					// Pull out the encoded 16-bit immediate value (high portion of the address-to-relocate).
					WORD wImm = (WORD)(dwInstruction & 0x000000FF);
					wImm |= (WORD)((dwInstruction & 0x00007000) >> 4);
					wImm |= (WORD)((dwInstruction & 0x04000000) >> 15);
					wImm |= (WORD)((dwInstruction & 0x000F0000) >> 4);
					// Apply the relocation delta to the target address.
					DWORD dwAddress = ((WORD)HIWORD(uiDelta) + wImm) & 0xFFFF;
					// Create a new instruction with the same opcode and register parameters.
					dwInstruction &= ARM_MOV_MASK2;
					// Patch in the relocated address, re-encoding the immediate value.
					dwInstruction |= (DWORD)(dwAddress & 0x00FF);
					dwInstruction |= (DWORD)(dwAddress & 0x0700) << 4;
					dwInstruction |= (DWORD)(dwAddress & 0x0800) << 15;
					dwInstruction |= (DWORD)(dwAddress & 0xF000) << 4;
					// Flip the instructions words and patch back into the code.
					*(DWORD *)((ULONG_PTR)pBaseAddress + pBaseRelocationTable->VirtualAddress + pBaseRelocEntry->Offset + sizeof(DWORD)) = MAKELONG(HIWORD(dwInstruction), LOWORD(dwInstruction));
				}
			#endif
			case IMAGE_REL_BASED_HIGH:
				*((WORD*)(pBaseAddress + pBaseRelocationTable->VirtualAddress + pBaseRelocEntry->Offset)) += HIWORD(delta);
				break;
			case IMAGE_REL_BASED_LOW:
				*((WORD*)(pBaseAddress + pBaseRelocationTable->VirtualAddress + pBaseRelocEntry->Offset)) += LOWORD(delta);
				break;
			default:
				dprintf("[FIXRELOC] Unknown relocation type: %d", pBaseRelocEntry->Type);
				return FALSE;

			}
			
			pBaseRelocEntry = pBaseRelocEntry + 1;
		}
		pBaseRelocationTable = (PIMAGE_BASE_RELOCATION)((PBYTE)pBaseRelocationTable + pBaseRelocationTable->SizeOfBlock);
	}

	return TRUE;
}

BOOL FixIAT(PIMAGE_DATA_DIRECTORY pDataDirectoryImportTable, PBYTE pBaseAddress) {

	PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = NULL;
	ULONG_PTR fncPointer = 0;
	HANDLE hModule = NULL;

	for (SIZE_T i = 0; i < pDataDirectoryImportTable->Size; i += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {

		ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(pBaseAddress + pDataDirectoryImportTable->VirtualAddress + i);

		if (ImportDescriptor->OriginalFirstThunk == 0 && ImportDescriptor->FirstThunk == 0)
			break;

		LPCSTR dllName = (LPSTR)(pBaseAddress + ImportDescriptor->Name);

		PIMAGE_THUNK_DATA pINT = (PIMAGE_THUNK_DATA)(pBaseAddress + ImportDescriptor->OriginalFirstThunk);
		PIMAGE_THUNK_DATA pIAT = (PIMAGE_THUNK_DATA)(pBaseAddress + ImportDescriptor->FirstThunk);

		hModule = LoadLibraryA(dllName);

		if (hModule == NULL)
		{
			dprintf("[LOADREFLECTIVELY] Failed to load DLL %s\n", dllName);
			return FALSE;
		}

		while (pIAT->u1.Function != 0 || pINT->u1.Function != 0) {
			LPCSTR fncName = NULL;

			if (IMAGE_SNAP_BY_ORDINAL(pINT->u1.Ordinal))
			{
				// import by ordinal
				//fncPointer = (ULONG_PTR)GetProcAddress(hModule, (LPCSTR)(IMAGE_ORDINAL(pINT->u1.Ordinal)));
				fncName = (LPCSTR)MAKEINTRESOURCEA(IMAGE_ORDINAL(pINT->u1.Ordinal));
			}
			else {

				// import by name
				PIMAGE_IMPORT_BY_NAME pImgImportByName = (PIMAGE_IMPORT_BY_NAME)(pBaseAddress + pINT->u1.AddressOfData);
				fncName = pImgImportByName->Name;
			}
			
			fncPointer = (ULONG_PTR)GetProcAddress(hModule, fncName);
			if (fncPointer == 0)
			{
				dprintf("[LOADREFLECTIVELY] Failed to resolve function in DLL %s\n", dllName);
				return FALSE;
			}
			pIAT->u1.Function = fncPointer;

			pINT = (PIMAGE_THUNK_DATA)((PBYTE)(pINT)+sizeof(IMAGE_THUNK_DATA));
			pIAT = (PIMAGE_THUNK_DATA)((PBYTE)(pIAT)+sizeof(IMAGE_THUNK_DATA));
		}

	}

	return TRUE;
}

BOOL FixPermissions(PIMAGE_NT_HEADERS pNtHeaders, PBYTE pBaseAddress)
{
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)(&(pNtHeaders->OptionalHeader)) + pNtHeaders->FileHeader.SizeOfOptionalHeader);
	DWORD dwProtection, dwOldFlags;
	
	for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		dwProtection = 0;

		if (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE)
			dwProtection = PAGE_WRITECOPY;

		if (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_READ)
			dwProtection = PAGE_READONLY;

		if ((pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_READWRITE;

		if (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
			dwProtection = PAGE_EXECUTE;

		if ((pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE))
			dwProtection = PAGE_EXECUTE_WRITECOPY;

		if ((pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_EXECUTE_READ;

		if ((pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_EXECUTE_READWRITE;

		dprintf("[FIXPERM] Setting permissions for section %p to %x with size %x\n",pBaseAddress + pSectionHeader[i].VirtualAddress , dwProtection, pSectionHeader[i].SizeOfRawData);
		LPVOID lpAddress = (PBYTE)pBaseAddress + pSectionHeader[i].VirtualAddress;
		SIZE_T dwSectionSize = pSectionHeader[i].SizeOfRawData;
		if(dwSectionSize != 0 && met_api->win_api.kernel32.VirtualProtect(lpAddress, dwSectionSize, dwProtection, &dwOldFlags) == 0)
		{
			dprintf("[LOADREFLECTIVELY] Failed to fix permissions for section %d\n", i);
			return FALSE;
		}

	}

	return TRUE;

}

BOOL LoadReflectively(IN ULONG_PTR lpBuffer, OUT HMODULE *phModule) {
	
	dprintf("[LOADREFLECTIVELY] Loading library reflectively from buffer %p\n", lpBuffer);
	PBYTE pBaseAddress = (PBYTE)lpBuffer;
	PBYTE pDLLBaseAddress = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	DWORD dwResult = ERROR_SUCCESS;
	*phModule = NULL;
	do {
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(lpBuffer);
		
		if(pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			BREAK_WITH_ERROR("[LOADREFLECTIVELY] DOS signature not valid\n", ERROR_INVALID_DATA);
		}

		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + pBaseAddress);

		if(pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		{
			BREAK_WITH_ERROR("[LOADREFLECTIVELY] NT signature not valid\n", ERROR_INVALID_DATA);
		}
		dprintf("[LOADREFLECTIVELY] PE headers are valid\n");
		
		dprintf("[LOADREFLECTIVELY] Allocating memory for the library\n");
		pDLLBaseAddress = (PBYTE)met_api->win_api.kernel32.VirtualAlloc(NULL, pNtHeaders->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

		if (pDLLBaseAddress == NULL)
		{
			BREAK_WITH_ERROR("[LOADREFLECTIVELY] VirtualAlloc failed\n", ERROR_OUTOFMEMORY);
		}
		
		dprintf("[LOADREFLECTIVELY] Allocation successful, got %p\n", pDLLBaseAddress);

		pSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)(&(pNtHeaders->OptionalHeader)) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

		DWORD dwSizeOfHeaders = pNtHeaders->OptionalHeader.SizeOfHeaders;
		PBYTE pSourceBase = pBaseAddress;
		PBYTE pDestinationBase = pDLLBaseAddress;

		dprintf("[LOADREFLECTIVELY] Copying headers\n");
		
		while (dwSizeOfHeaders--)
			*pDestinationBase++ = *pSourceBase++;

		dprintf("[LOADREFLECTIVELY] Copying PE sections\n");
		
		// 1. Copy the PE sections to the new location
		for(DWORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
		{ 

			PBYTE pDestinationBase = pDLLBaseAddress + pSectionHeader[i].VirtualAddress;
			PBYTE pSourceBase = pBaseAddress + pSectionHeader[i].PointerToRawData;
			DWORD dwSizeOfHeaders = pSectionHeader[i].SizeOfRawData;
			dprintf("[LOADREFLECTIVELY] Copying section %p to %p with length %x\n", pSourceBase, pDestinationBase, dwSizeOfHeaders);
			while (dwSizeOfHeaders--)
				*pDestinationBase++ = *pSourceBase++;
		}

		// 2. Get all necessary sections	
		PIMAGE_DATA_DIRECTORY pImportTableDirectory = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		PIMAGE_DATA_DIRECTORY pRelocationTableDirectory = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

		// 3. Fix relocations
		dprintf("[LOADREFLECTIVELY] Fixing relocations\n");
		if(pRelocationTableDirectory->Size > 0 && !FixRelocations(pRelocationTableDirectory, (ULONG_PTR)pDLLBaseAddress, pNtHeaders->OptionalHeader.ImageBase))
		{
			BREAK_WITH_ERROR("[LOADREFLECTIVELY] Failed to fix relocations\n", ERROR_INVALID_DATA);
		}

		// 4. Fix the IAT
		dprintf("[LOADREFLECTIVELY] Fixing IAT\n");
		if(!FixIAT(pImportTableDirectory, pDLLBaseAddress))
		{
			BREAK_WITH_ERROR("[LOADREFLECTIVELY] Failed to fix IAT\n", ERROR_INVALID_DATA);
		}

		// 5. Set the correct permissions for the sections
		dprintf("[LOADREFLECTIVELY] Fixing permissions\n");
		if(!FixPermissions(pNtHeaders, pDLLBaseAddress))
		{
			BREAK_WITH_ERROR("[LOADREFLECTIVELY] Failed to fix permissions\n", ERROR_INVALID_DATA);
		}

		// 6. Call the entry point

		dprintf("[LOADREFLECTIVELY] Calling entry point\n");
		DLLMAIN dEntryPoint = (DLLMAIN)(pDLLBaseAddress + pNtHeaders->OptionalHeader.AddressOfEntryPoint);

		if (dEntryPoint((HINSTANCE)pDLLBaseAddress, DLL_PROCESS_ATTACH, NULL) == FALSE)
		{
			BREAK_WITH_ERROR("[LOADREFLECTIVELY] DllMain returned FALSE\n", ERROR_INVALID_DATA);
		}

		*phModule = (HMODULE)pDLLBaseAddress;
	}while(FALSE);

	if(dwResult != ERROR_SUCCESS)
	{
		if(pDLLBaseAddress != NULL)
		{
			met_api->win_api.kernel32.VirtualFree(pDLLBaseAddress, 0, MEM_RELEASE);
		}
		dprintf("[LOADREFLECTIVELY] Failed to load library reflectively with error code %d\n", dwResult);
		return FALSE;
	}
	return TRUE;
}