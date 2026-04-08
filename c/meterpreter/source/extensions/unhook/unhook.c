/*!
 * @file unhook.c
 * @brief Entry point and intialisation functionality for the unhook extention.
 */
#include "common.h"
#include "common_metapi.h"

#define RDIDLL_NOEXPORT
#include "../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

#include "unhook.h"
#include "refresh.h"

// Required so that use of the API works.
MetApi* met_api = NULL;

DWORD unhook_pe(Remote* remote, Packet* packet)
{
	Packet* response = met_api->packet.create_response(packet);
	DWORD result = ERROR_SUCCESS;

	RefreshPE();

	met_api->packet.add_tlv_uint(response, TLV_TYPE_UNHOOK_RESPONSE, ERROR_SUCCESS);
	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

Command customCommands[] =
{
	// custom commands go here
	COMMAND_REQ(COMMAND_ID_UNHOOK_PE, unhook_pe),
	COMMAND_TERMINATOR
};

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
DWORD DeinitServerExtension(Remote* remote)
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
