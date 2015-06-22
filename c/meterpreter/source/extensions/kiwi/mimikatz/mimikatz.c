/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mimikatz.h"
#include "mimikatz_interface.h"

const KUHL_M * mimikatz_modules[] = {
	//&kuhl_m_standard,
	&kuhl_m_crypto,
	&kuhl_m_sekurlsa,
	&kuhl_m_kerberos,
	&kuhl_m_privilege,
	&kuhl_m_process,
	&kuhl_m_service,
	&kuhl_m_lsadump,
	&kuhl_m_ts,
	&kuhl_m_event,
	&kuhl_m_misc,
	&kuhl_m_token,
	&kuhl_m_vault,
#ifdef NET_MODULE
	&kuhl_m_net,
#endif
};

#ifdef KIWIDEBUGTRACE
static wchar_t* output = NULL;
static DWORD outputLen = 0;
static DWORD outputSize = 0;

const wchar_t* mimikatz_get_output()
{
	return output;
}

void mimikatz_free_output()
{
	if (output != NULL)
	{
		free(output);
	}
	output = NULL;
	outputLen = 0;
	outputSize = 0;
}

void mimikatz_append_output(const wchar_t* newOutput)
{
	outputLen += lstrlenW(newOutput) + 1;

	dprintf(L"[KIWI] appending: %s", newOutput);
	dprintf(L"[KIWI] outputSize %u outputLen %u", outputSize, outputLen);

	if (outputSize == 0)
	{
		outputSize = outputLen << 1;
		output = (wchar_t*)malloc(outputSize * sizeof(wchar_t));
		*output = '\0';
	}

	while (outputSize < outputLen)
	{
		outputSize <<= 1;
		output = (wchar_t*)realloc(output, outputSize * sizeof(wchar_t));
	}

	lstrcatW(output, newOutput);
}
#endif

VOID (WINAPI * RtlGetNtVersionNumbers)(LPDWORD pMajor, LPDWORD pMinor, LPDWORD pBuild);

VOID setup_function_pointers()
{
	HMODULE ntDll = GetModuleHandleA("ntdll");

	RtlGetNtVersionNumbers = (VOID (WINAPI *)(LPDWORD pMajor, LPDWORD pMinor, LPDWORD pBuild))GetProcAddress(ntDll, "RtlGetNtVersionNumbers");
	kull_m_process_initialise();
	kull_m_string_initialise();
	kull_m_handle_initialise();
}

DWORD mimikatz_init_or_clean(BOOL Init)
{
	unsigned short indexModule;
	PKUHL_M_C_FUNC_INIT function;
	long offsetToFunc;
	NTSTATUS fStatus;

	if (Init)
	{
		dprintf(L"[KIWI] initorclean - setting up function pointers");
		setup_function_pointers();
#ifdef KIWIDEBUGTRACE
		dprintf(L"[KIWI] initorclean - set writer");
		kull_m_output_set_writer(mimikatz_append_output);
#endif

		if (RtlGetNtVersionNumbers != NULL)
		{
			dprintf(L"[KIWI] initorclean - GetNTVersion");
			RtlGetNtVersionNumbers(&MIMIKATZ_NT_MAJOR_VERSION, &MIMIKATZ_NT_MINOR_VERSION, &MIMIKATZ_NT_BUILD_NUMBER);
		}
		else
		{
			dprintf(L"[KIWI] Defaulting to Win2k");
			// default to Windows 2000
			MIMIKATZ_NT_MAJOR_VERSION = 5;
			MIMIKATZ_NT_MINOR_VERSION = 0;
			MIMIKATZ_NT_BUILD_NUMBER = 2195;
		}
		MIMIKATZ_NT_BUILD_NUMBER &= 0x00003fff;

		dprintf(L"[KIWI] initorclean - Versions: %u %u %u", MIMIKATZ_NT_MAJOR_VERSION, MIMIKATZ_NT_MINOR_VERSION, MIMIKATZ_NT_BUILD_NUMBER);

		offsetToFunc = FIELD_OFFSET(KUHL_M, pInit);
		dprintf(L"[KIWI] initorclean - init done");
	}
	else
	{
		dprintf(L"[KIWI] initorclean - tearing down up");
		offsetToFunc = FIELD_OFFSET(KUHL_M, pClean);

		kull_m_output_set_writer(NULL);
	}

	for (indexModule = 0; indexModule < sizeof(mimikatz_modules) / sizeof(KUHL_M *); indexModule++)
	{
		if (function = *(PKUHL_M_C_FUNC_INIT *)((ULONG_PTR)(mimikatz_modules[indexModule]) + offsetToFunc))
		{
			dprintf(L"[KIWI] initorclean - setting up module %s", mimikatz_modules[indexModule]->shortName);
			fStatus = function();
			if (!NT_SUCCESS(fStatus))
				kprintf(L">>> %s of \'%s\' module failed : %08x\n", (Init ? L"INIT" : L"CLEAN"), mimikatz_modules[indexModule]->shortName, fStatus);
			dprintf(L"[KIWI] initorclean - %s done", mimikatz_modules[indexModule]->shortName);
		}
	}

	return (DWORD)STATUS_SUCCESS;
}
