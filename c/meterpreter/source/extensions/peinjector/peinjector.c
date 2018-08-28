/*!
 * @file peinjector.c
 * @brief Entry point and intialisation definitions for the Peinjector extension
 */
#include "../../common/common.h"

#include "../../DelayLoadMetSrv/DelayLoadMetSrv.h"

#include "../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

#include "peinjector_bridge.h"

// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();

Command customCommands[] =
{
	COMMAND_REQ("peinjector_inject_shellcode", request_peinjector_inject_shellcode),
	COMMAND_TERMINATOR
};

/*!
 * @brief Initialize the server extension
 */
DWORD __declspec(dllexport) InitServerExtension(Remote *remote)
{
	hMetSrv = remote->met_srv;
	dprintf("[PEINJECTOR] Initializing peinjector...");

	command_register_all(customCommands);

	return ERROR_SUCCESS;
}

/*!
 * @brief Deinitialize the server extension
 */
DWORD __declspec(dllexport) DeinitServerExtension(Remote *remote)
{
	command_deregister_all(customCommands);

	return ERROR_SUCCESS;
}

