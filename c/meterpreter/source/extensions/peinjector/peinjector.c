/*!
 * @file peinjector.c
 * @brief Entry point and intialisation definitions for the Peinjector extension
 */
#include "common.h"
#include "common_metapi.h"

// Required so that use of the API works.
MetApi* met_api = NULL;

#include "../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

#include "peinjector_bridge.h"

Command customCommands[] =
{
	COMMAND_REQ("peinjector_inject_shellcode", request_peinjector_inject_shellcode),
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


/*!
 * @brief Get the name of the extension.
 * @param buffer Pointer to the buffer to write the name to.
 * @param bufferSize Size of the \c buffer parameter.
 * @return Indication of success or failure.
 */
DWORD __declspec(dllexport) GetExtensionName(char* buffer, int bufferSize)
{
	strncpy_s(buffer, bufferSize, "peinjector", bufferSize - 1);
	return ERROR_SUCCESS;
}
