/*
 * This module implemenet webcam frae capture and mic recording features. 
 */
#define _CRT_SECURE_NO_DEPRECATE 1
#include "common.h"
#include "common_metapi.h"
#include "espia.h"
#include "screen.h"

// Required so that use of the API works.
MetApi* met_api = NULL;

#include "../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

Command customCommands[] =
{
    COMMAND_REQ(COMMAND_ID_ESPIA_IMAGE_GET_DEV_SCREEN, request_image_get_dev_screen),
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
	strncpy_s(buffer, bufferSize, "espia", bufferSize - 1);
	return ERROR_SUCCESS;
}
