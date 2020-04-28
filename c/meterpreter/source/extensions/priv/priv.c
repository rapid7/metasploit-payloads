/*!
 * @brief This module implements privilege escalation features.
 */
#include "precomp.h"
#include "common_metapi.h" 

// Required so that use of the API works.
MetApi* met_api = NULL;

#include "../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

/*!
 * @brief `priv` extension dispatch table.
 */
Command customCommands[] =
{
    COMMAND_REQ(COMMAND_ID_PRIV_ELEVATE_GETSYSTEM, elevate_getsystem),
    COMMAND_REQ(COMMAND_ID_PRIV_PASSWD_GET_SAM_HASHES, request_passwd_get_sam_hashes),
    COMMAND_REQ(COMMAND_ID_PRIV_FS_GET_FILE_MACE, request_fs_get_file_mace),
    COMMAND_REQ(COMMAND_ID_PRIV_FS_SET_FILE_MACE, request_fs_set_file_mace),
    COMMAND_REQ(COMMAND_ID_PRIV_FS_SET_FILE_MACE_FROM_FILE, request_fs_set_file_mace_from_file),
    COMMAND_REQ(COMMAND_ID_PRIV_FS_BLANK_FILE_MACE, request_fs_blank_file_mace),
    COMMAND_REQ(COMMAND_ID_PRIV_FS_BLANK_DIRECTORY_MACE, request_fs_blank_directory_mace),
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

    return ERROR_SUCCESS;
}

/*!
 * @brief Deinitialize the server extension.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
DWORD __declspec(dllexport) DeinitServerExtension(Remote* remote)
{
    met_api->command.deregister_all(customCommands);

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
	strncpy_s(buffer, bufferSize, "priv", bufferSize - 1);
	return ERROR_SUCCESS;
}
