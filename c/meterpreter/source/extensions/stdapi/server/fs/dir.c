#include "precomp.h"

#include "fs_local.h"

void request_fs_ls_cb(void *arg, char *name, char *short_name, char *path)
{
	Packet *response = arg;
	struct meterp_stat s;

	/*
	 * Add the file name, full path and stat information
	 */
	packet_add_tlv_string(response, TLV_TYPE_FILE_NAME, name);
	packet_add_tlv_string(response, TLV_TYPE_FILE_PATH, path);
	if (short_name) {
		packet_add_tlv_string(response, TLV_TYPE_FILE_SHORT_NAME, short_name);
	}
	if (fs_stat(path, &s) >= 0) {
		packet_add_tlv_raw(response, TLV_TYPE_STAT_BUF, &s, sizeof(s));
	}
}

/*
 * Gets the contents of a given directory path and returns the list of file
 * names to the requestor.
 *
 * req: TLV_TYPE_DIRECTORY_PATH - The directory that should be listed
 */
DWORD request_fs_ls(Remote * remote, Packet * packet)
{
	Packet *response = packet_create_response(packet);
	LPCSTR directory = packet_get_tlv_value_string(packet, TLV_TYPE_DIRECTORY_PATH);
	DWORD result;

	if (!directory) {
		result = ERROR_INVALID_PARAMETER;
	} else {
		result = fs_ls(directory, request_fs_ls_cb, response);
	}

	return packet_transmit_response(result, remote, response);
}

/*
 * Gets the current working directory
 *
 * req: TLV_TYPE_DIRECTORY_PATH - The directory path to change the working
 *                                directory to.
 */
DWORD request_fs_getwd(Remote * remote, Packet * packet)
{
	Packet *response = packet_create_response(packet);
	char *directory = NULL;
	DWORD result;

	result = fs_getwd(&directory);
	if (directory != NULL) {
		packet_add_tlv_string(response, TLV_TYPE_DIRECTORY_PATH, directory);
		free(directory);
	}

	return packet_transmit_response(result, remote, response);
}

/*
 * Changes the working directory of the process
 *
 * req: TLV_TYPE_DIRECTORY_PATH - The directory path to change the working
 *                                directory to.
 */
DWORD request_fs_chdir(Remote * remote, Packet * packet)
{
	Packet *response = packet_create_response(packet);
	char *directory;
	DWORD result;
	directory = packet_get_tlv_value_string(packet, TLV_TYPE_DIRECTORY_PATH);

	if (directory == NULL) {
		result = ERROR_INVALID_PARAMETER;
	} else {
		result = fs_chdir(directory);
	}

	return packet_transmit_response(result, remote, response);
}

/*
 * Creates a new directory
 *
 * req: TLV_TYPE_DIRECTORY_PATH - The directory path to create.
 */
DWORD request_fs_mkdir(Remote * remote, Packet * packet)
{
	Packet *response = packet_create_response(packet);
	char *directory;
	DWORD result;
	directory = packet_get_tlv_value_string(packet, TLV_TYPE_DIRECTORY_PATH);

	if (directory == NULL) {
		result = ERROR_INVALID_PARAMETER;
	} else {
		result = fs_mkdir(directory);
	}

	return packet_transmit_response(result, remote, response);
}

/*
 * Removes the supplied directory from disk if it's empty
 *
 * req: TLV_TYPE_DIRECTORY_PATH - The directory that is to be removed.
 */
DWORD request_fs_delete_dir(Remote * remote, Packet * packet)
{
	Packet *response = packet_create_response(packet);
	char *directory;
	DWORD result;
	directory = packet_get_tlv_value_string(packet, TLV_TYPE_DIRECTORY_PATH);

	if (directory == NULL) {
		result = ERROR_INVALID_PARAMETER;
	} else {
		result = fs_delete_dir(directory);
	}

	return packet_transmit_response(result, remote, response);
}
