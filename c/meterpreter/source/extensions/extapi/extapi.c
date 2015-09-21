/*!
 * @file extapi.h
 * @brief Entry point and intialisation definitions for the extended API extension.
 */
#include "../../common/common.h"

#include "../../DelayLoadMetSrv/DelayLoadMetSrv.h"
// include the Reflectiveloader() function, we end up linking back to the metsrv.dll's Init function
// but this doesnt matter as we wont ever call DLL_METASPLOIT_ATTACH as that is only used by the
// second stage reflective dll inject payload and not the metsrv itself when it loads extensions.
#include "../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

#include "window.h"
#include "service.h"
#include "clipboard.h"
#include "adsi.h"
#include "wmi.h"
#include "ntds.h"
#include "pageantjacker.h"

// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();

/*! @brief List of commands that the extended API extension providers. */
Command customCommands[] =
{
	COMMAND_REQ("extapi_window_enum", request_window_enum),
	COMMAND_REQ("extapi_service_enum", request_service_enum),
	COMMAND_REQ("extapi_service_query", request_service_query),
	COMMAND_REQ("extapi_service_control", request_service_control),
	COMMAND_REQ("extapi_clipboard_get_data", request_clipboard_get_data),
	COMMAND_REQ("extapi_clipboard_set_data", request_clipboard_set_data),
	COMMAND_REQ("extapi_clipboard_monitor_start", request_clipboard_monitor_start),
	COMMAND_REQ("extapi_clipboard_monitor_pause", request_clipboard_monitor_pause),
	COMMAND_REQ("extapi_clipboard_monitor_resume", request_clipboard_monitor_resume),
	COMMAND_REQ("extapi_clipboard_monitor_purge", request_clipboard_monitor_purge),
	COMMAND_REQ("extapi_clipboard_monitor_stop", request_clipboard_monitor_stop),
	COMMAND_REQ("extapi_clipboard_monitor_dump", request_clipboard_monitor_dump),
	COMMAND_REQ("extapi_adsi_domain_query", request_adsi_domain_query),
	COMMAND_REQ("extapi_ntds_parse", ntds_parse),
	COMMAND_REQ("extapi_wmi_query", request_wmi_query),
	COMMAND_REQ("extapi_pageant_send_query", request_pageant_send_query),
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

	command_register_all(customCommands);

	initialise_clipboard();
	initialise_service();

	return ERROR_SUCCESS;
}

/*!
 * @brief Deinitialize the server extension.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
DWORD __declspec(dllexport) DeinitServerExtension(Remote *remote)
{
	command_deregister_all(customCommands);

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
	strncpy_s(buffer, bufferSize, "extapi", bufferSize - 1);
	return ERROR_SUCCESS;
}
