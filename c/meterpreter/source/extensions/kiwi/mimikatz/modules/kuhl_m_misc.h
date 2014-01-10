/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "kuhl_m.h"
#include "../modules/kull_m_process.h"
#include "../modules/kull_m_memory.h"
#include "../modules/kull_m_patch.h"

const KUHL_M kuhl_m_misc;

NTSTATUS kuhl_m_misc_cmd(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_regedit(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_taskmgr(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_ncroutemon(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_detours(int argc, wchar_t * argv[]);

BOOL CALLBACK kuhl_m_misc_detours_callback_process(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg);
BOOL CALLBACK kuhl_m_misc_detours_callback_module(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg);
BOOL CALLBACK kuhl_m_misc_detours_callback_module_exportedEntry(PKULL_M_PROCESS_EXPORTED_ENTRY pExportedEntryInformations, PVOID pvArg);
BOOL CALLBACK kuhl_m_misc_detours_callback_module_name_addr(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg);

typedef struct _KUHL_M_MISC_DETOURS_HOOKS {
    DWORD minLevel;
	PBYTE pattern;
	DWORD szPattern;
	DWORD offsetToRead;
	DWORD szToRead;
	BOOL isRelative;
	BOOL isTarget;
} KUHL_M_MISC_DETOURS_HOOKS, *PKUHL_M_MISC_DETOURS_HOOKS;

PBYTE kuhl_m_misc_detours_testHookDestination(PKULL_M_MEMORY_ADDRESS base, WORD machineOfProcess, DWORD level);

BOOL kuhl_m_misc_generic_nogpo_patch(PCWSTR commandLine, PWSTR disableString, SIZE_T szDisableString, PWSTR enableString, SIZE_T szEnableString);