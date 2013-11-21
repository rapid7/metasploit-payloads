/*!
 * @file extapi.h
 * @brief Entry point and intialisation definitions for the extended API extension.
 */
#include "../../common/common.h"

#include "../../ReflectiveDLLInjection/DelayLoadMetSrv.h"
// include the Reflectiveloader() function, we end up linking back to the metsrv.dll's Init function
// but this doesnt matter as we wont ever call DLL_METASPLOIT_ATTACH as that is only used by the 
// second stage reflective dll inject payload and not the metsrv itself when it loads extensions.
#include "../../ReflectiveDLLInjection/ReflectiveLoader.c"

#include "window.h"
#include "service.h"
#include "clipboard.h"

// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();

/*! @brief List of commands that the extended API extension providers. */
Command customCommands[] =
{
	COMMAND_REQ("extapi_window_enum", request_window_enum),
	COMMAND_REQ("extapi_service_enum", request_service_enum),
	COMMAND_REQ("extapi_service_query", request_service_query),
	COMMAND_REQ("extapi_clipboard_get_data", request_clipboard_get_data),
	COMMAND_REQ("extapi_clipboard_set_data", request_clipboard_set_data),
	COMMAND_REQ("extapi_clipboard_monitor_start", request_clipboard_monitor_start),
	COMMAND_REQ("extapi_clipboard_monitor_pause", request_clipboard_monitor_pause),
	COMMAND_REQ("extapi_clipboard_monitor_resume", request_clipboard_monitor_resume),
	COMMAND_REQ("extapi_clipboard_monitor_stop", request_clipboard_monitor_stop),
	COMMAND_TERMINATOR
};

/*!
 * @brief Initialize the server extension
 * @details Registers all the extended API commands.
 * @param remote Pointer to the \c Remote initialising the extension.
 * @returns Always returns \c ERROR_SUCCESS.
 */
DWORD __declspec(dllexport) InitServerExtension(Remote *remote)
{
	hMetSrv = remote->hMetSrv;

	command_register_all(customCommands);

	return ERROR_SUCCESS;
}

/*!
 * @brief Deinitialize the server extension.
 * @details Unregisters all the extended API commands.
 * @param remote Pointer to the \c Remote destroying the extension.
 * @returns Always returns \c ERROR_SUCCESS.
 */
DWORD __declspec(dllexport) DeinitServerExtension(Remote *remote)
{
	command_deregister_all(customCommands);

	return ERROR_SUCCESS;
}
