/*!
 * @file bare.c
 * @brief Entry point and intialisation functionality for the bare extention.
 */
#include "../../common/common.h"

#include "../../DelayLoadMetSrv/DelayLoadMetSrv.h"
// include the Reflectiveloader() function, we end up linking back to the metsrv.dll's Init function
// but this doesnt matter as we wont ever call DLL_METASPLOIT_ATTACH as that is only used by the 
// second stage reflective dll inject payload and not the metsrv itself when it loads extensions.
#include "../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

#include "drivertools.h"

DWORD request_drivertools_do_work(Remote *remote, Packet *request);

// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();

Command customCommands[] =
{
	// custom commands go here
	COMMAND_REQ("drivertools_do_work", request_drivertools_do_work),
	COMMAND_TERMINATOR
};

/*!
 * @brief Initialize the server extension
 */
DWORD __declspec(dllexport) InitServerExtension(Remote *remote)
{
	hMetSrv = remote->met_srv;

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

DWORD __declspec(dllexport) GetExtensionName(char* buffer, int bufferSize)
{
	strncpy_s(buffer, bufferSize, "driver", bufferSize - 1);
	return ERROR_SUCCESS;
}
