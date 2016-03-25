/*!
 * @file powershell.c
 * @brief Entry point and intialisation definitions for the Powershell extension
 */
#include "../../common/common.h"

#include "../../DelayLoadMetSrv/DelayLoadMetSrv.h"
// include the Reflectiveloader() function, we end up linking back to the metsrv.dll's Init function
// but this doesnt matter as we wont ever call DLL_METASPLOIT_ATTACH as that is only used by the
// second stage reflective dll inject payload and not the metsrv itself when it loads extensions.
#include "../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

#include "powershell_bridge.h"
#include "powershell_bindings.h"

// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();

static BOOL gSuccessfullyLoaded = FALSE;

/*! @brief List of commands that the powershell extension provides. */
Command customCommands[] =
{
	COMMAND_REQ("powershell_execute", request_powershell_execute),
	COMMAND_REQ("powershell_shell", request_powershell_shell),
	COMMAND_REQ("powershell_assembly_load", request_powershell_assembly_load),
	COMMAND_REQ("powershell_session_remove", request_powershell_session_remove),
	COMMAND_TERMINATOR
};

/*!
 * @brief Initialize the server extension.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
DWORD __declspec(dllexport) InitServerExtension(Remote *remote)
{
	hMetSrv = remote->met_srv;
	gRemote = remote;

	DWORD result = initialize_dotnet_host();

	if (result == ERROR_SUCCESS)
	{
		command_register_all(customCommands);
	}

	return result;
}

/*!
 * @brief Deinitialize the server extension.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
DWORD __declspec(dllexport) DeinitServerExtension(Remote *remote)
{
	command_deregister_all(customCommands);
	deinitialize_dotnet_host();

	return ERROR_SUCCESS;
}

/*!
 * @brief Get the name of the extension.
 * @param buffer Pointer to the buffer to write the name to.
 * @param bufferSize Size of the \c buffer parameter.
 * @return Indication of success or failure.
 */
DWORD __declspec(dllexport) GetExtensionName(char* buffer, int bufferSize)
{
	strncpy_s(buffer, bufferSize, "powershell", bufferSize - 1);
	return ERROR_SUCCESS;
}

/*!
 * @brief Do a stageless initialisation of the extension.
 * @param buffer Pointer to the buffer that contains the init data.
 * @param bufferSize Size of the \c buffer parameter.
 * @return Indication of success or failure.
 */
DWORD __declspec(dllexport) StagelessInit(const LPBYTE buffer, DWORD bufferSize)
{
	dprintf("[PSH] Executing stagless script:\n%s", (LPCSTR)buffer);
	return invoke_startup_script((LPCSTR)buffer);
}