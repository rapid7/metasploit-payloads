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

DWORD request_driver_send_vuln();
DWORD request_driver_set_vuln_loc();
DWORD request_driver_do_work();

// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();

// need commands for:
// - uploading the vulnerable vbox driver
// - setting the remote path to save it to
// - executing the tool

Command customCommands[] =
{
	// custom commands go here
	COMMAND_REQ("driver_send_vuln", request_driver_send_vuln),
	COMMAND_REQ("driver_set_vuln_loc", request_driver_set_vuln_loc),
	COMMAND_REQ("driver_do_work", request_driver_do_work),
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

DWORD request_driver_send_vuln()
{
	return 4;
}

DWORD request_driver_set_vuln_loc()
{
	return 3;
}