#include "precomp.h"
#include "fs_local.h"

#include <sys/stat.h>

/***************************
 * File Channel Operations *
 ***************************/

typedef struct
{
	FILE  *fd;
	DWORD mode;
} FileContext;

/*
 * Writes the supplied data to the file
 */
static DWORD file_channel_write(Channel *channel, Packet *request,
		LPVOID context, LPVOID buffer, DWORD bufferSize,
		LPDWORD bytesWritten)
{
	FileContext *ctx = (FileContext *)context;
	DWORD result= ERROR_SUCCESS;
	size_t written = 0;

	// Write a chunk
	if (bufferSize) {
		written = fwrite(buffer, 1, bufferSize, ctx->fd);
		if (written < bufferSize) {
			result  = GetLastError();
		}
	}

	if (bytesWritten) {
		*bytesWritten = (DWORD)written;
	}

	return result;
}

/*
 * Closes the file
 */
static DWORD file_channel_close(Channel *channel, Packet *request,
		LPVOID context)
{
	FileContext *ctx = (FileContext *)context;

	fclose(ctx->fd);
	free(ctx);

	return ERROR_SUCCESS;
}

/*
 * Reads data from the file (if any)
 */
static DWORD file_channel_read(Channel *channel, Packet *request,
		LPVOID context, LPVOID buffer, DWORD bufferSize,
		LPDWORD bytesRead)
{
	FileContext *ctx = (FileContext *)context;
	DWORD result = ERROR_SUCCESS;
	size_t bytes = 0;

	// Read a chunk
	if (bufferSize) {
	       	bytes = fread(buffer, 1, bufferSize, ctx->fd);
		if (bytes < bufferSize) {
			result = GetLastError();
		}
	}

	if (bytesRead) {
		*bytesRead = (DWORD)bytes;
	}

	return ERROR_SUCCESS;
}

/*
 * Checks to see if the file pointer is currently at the end of the file
 */
static DWORD file_channel_eof(Channel *channel, Packet *request,
		LPVOID context, LPBOOL isEof)
{
	FileContext *ctx = (FileContext *)context;
	*isEof = feof(ctx->fd) ? TRUE : FALSE;
	return ERROR_SUCCESS;
}

/*
 * Changes the current file pointer position in the file
 */
static DWORD file_channel_seek(Channel *channel, Packet *request,
		LPVOID context, LONG offset, DWORD whence)
{
	FileContext *ctx = (FileContext *)context;

	return fseek(ctx->fd, offset, whence);
}

/*
 * Returns the current offset in the file to the requestor
 */
static DWORD file_channel_tell(Channel *channel, Packet *request,
		LPVOID context, LPLONG offset)
{
	FileContext *ctx = (FileContext *)context;
	DWORD result = ERROR_SUCCESS;
	LONG pos = 0;

	if ((pos = ftell(ctx->fd)) < 0) {
		result = GetLastError();
	}

	if (offset)
		*offset = pos;

	return result;
}

/*
 * Handles the open request for a file channel and returns a valid channel
 * identifier to the requestor if the file is opened successfully
 */
DWORD request_fs_file_channel_open(Remote *remote, Packet *packet)
{
	Packet *response = NULL;
	PCHAR filePath, mode;
	DWORD res = ERROR_SUCCESS;
	DWORD flags = 0;
	Channel *newChannel = NULL;
	PoolChannelOps chops = { 0 };
	FileContext *ctx;
	LPSTR expandedFilePath = NULL;

	// Allocate a response
	response = packet_create_response(packet);

	// Get the channel flags
	flags = packet_get_tlv_value_uint(packet, TLV_TYPE_FLAGS);

	// Allocate storage for the file context
	if (!(ctx = calloc(1, sizeof(FileContext)))) {
		res = ERROR_NOT_ENOUGH_MEMORY;
		goto out;
	}

	// Get the file path and the mode
	filePath = packet_get_tlv_value_string(packet, TLV_TYPE_FILE_PATH);
	mode     = packet_get_tlv_value_string(packet, TLV_TYPE_FILE_MODE);

	if (mode == NULL) {
		mode = "rb";
	}

	res = fs_fopen(filePath, mode, &ctx->fd);
	if (res != ERROR_SUCCESS) {
		goto out;
	}

	memset(&chops, 0, sizeof(chops));

	// Initialize the pool operation handlers
	chops.native.context = ctx;
	chops.native.write   = file_channel_write;
	chops.native.close   = file_channel_close;
	chops.read           = file_channel_read;
	chops.eof            = file_channel_eof;
	chops.seek           = file_channel_seek;
	chops.tell           = file_channel_tell;

	// Check the response allocation & allocate a un-connected
	// channel
	if ((!response) || (!(newChannel = channel_create_pool(0, flags, &chops)))) {
		res = ERROR_NOT_ENOUGH_MEMORY;
		goto out;
	}

	// Add the channel identifier to the response
	packet_add_tlv_uint(response, TLV_TYPE_CHANNEL_ID, channel_get_id(newChannel));

out:
	// Transmit the packet if it's valid
	packet_transmit_response(res, remote, response);

	// Clean up on failure
	if (res != ERROR_SUCCESS) {
		if (newChannel) {
			channel_destroy(newChannel, NULL);
		}
		free(ctx);
	}

	return res;
}

/*
 * Gets the directory separator for this system
 */
DWORD request_fs_separator(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);

	packet_add_tlv_string(response, TLV_TYPE_STRING, FS_SEPARATOR);

	return packet_transmit_response(ERROR_SUCCESS, remote, response);
}


/*
 * Gets information about the file path that is supplied and returns it to the
 * requestor
 *
 * req: TLV_TYPE_FILE_PATH - The file path that is to be stat'd
 */
DWORD request_fs_stat(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	struct meterp_stat buf;
	char *filePath;
	char *expanded = NULL;
	DWORD result = ERROR_SUCCESS;

	filePath = packet_get_tlv_value_string(packet, TLV_TYPE_FILE_PATH);

	if (!filePath) {
		result = ERROR_INVALID_PARAMETER;
		goto out;
	}

	expanded = fs_expand_path(filePath);
	if (expanded == NULL) {
		result = ERROR_NOT_ENOUGH_MEMORY;
		goto out;
	}

	result = fs_stat(expanded, &buf);
	if (0 == result) {
		packet_add_tlv_raw(response, TLV_TYPE_STAT_BUF, &buf, sizeof(buf));
	}

	free(expanded);

out:
	return packet_transmit_response(result, remote, response);
}

/*
 * Removes the supplied file from disk
 *
 * req: TLV_TYPE_FILE_PATH - The file that is to be removed.
 */
DWORD request_fs_delete_file(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	char *path;
	DWORD result = ERROR_SUCCESS;

	path = packet_get_tlv_value_string(packet, TLV_TYPE_FILE_PATH);

	if (!path) {
		result = ERROR_INVALID_PARAMETER;
	} else {
		result = fs_delete_file(path);
	}

	return packet_transmit_response(result, remote, response);
}

/*
 * Expands a file path and returns the expanded path to the requestor
 *
 * req: TLV_TYPE_FILE_PATH - The file path to expand
 */
DWORD request_fs_file_expand_path(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD result = ERROR_SUCCESS;
	char *expanded = NULL;
	char *regular;

	regular = packet_get_tlv_value_string(packet, TLV_TYPE_FILE_PATH);
	if (regular == NULL) {
		result = ERROR_INVALID_PARAMETER;
		goto out;
	}

	// Allocate storage for the expanded path
	expanded = fs_expand_path(regular);
	if (expanded == NULL) {
		result = ERROR_NOT_ENOUGH_MEMORY;
		goto out;
	}

	packet_add_tlv_string(response, TLV_TYPE_FILE_PATH, expanded);
	free(expanded);
out:
	return packet_transmit_response(result, remote, response);
}

DWORD request_fs_file_hash(Remote* remote, Packet* packet, ALG_ID hashType)
{
	Packet *response = packet_create_response(packet);
	char *filePath;
	DWORD result = ERROR_SUCCESS;
	HCRYPTPROV cryptProv = 0;
	HCRYPTHASH hashInstance = 0;

	FILE *fd = NULL;
	size_t ret;
	unsigned char buff[16384];

	filePath = packet_get_tlv_value_string(packet, TLV_TYPE_FILE_PATH);

	do
	{
		result = fs_fopen(filePath, "rb", &fd);
		if (result != ERROR_SUCCESS)
		{
			dprintf("[FILE HASH] Failed to open file: %s", filePath);
			result = GetLastError();
			break;
		}

		if (!CryptAcquireContext(&cryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		{
			result = GetLastError();
			dprintf("[FILE HASH] Failed to get the Crypt context: %d (%x)", result, result);
			break;
		}

		if (!CryptCreateHash(cryptProv, hashType, 0, 0, &hashInstance))
		{
			result = GetLastError();
			dprintf("[FILE HASH] Failed to get the hash instance: %d (%x)", result, result);
			break;
		}

		BOOL failed = FALSE;
		while ((ret = fread(buff, 1, sizeof(buff), fd)) > 0) {
			if (!CryptHashData(hashInstance, buff, (DWORD)ret, 0))
			{
				result = GetLastError();
				dprintf("[FILE HASH] Failed to hash a chunk of data", result, result);
				failed = TRUE;
				break;
			}
		}

		if (failed)
		{
			break;
		}

		DWORD hashSize = 0;
		DWORD hashBufferSize = sizeof(hashSize);
		if (!CryptGetHashParam(hashInstance, HP_HASHSIZE, (BYTE*)&hashSize, &hashBufferSize, 0) || hashSize == 0)
		{
			result = GetLastError();
			dprintf("[FILE HASH] Failed to get the hash size: %d (%x)", result, result);
		}

		dprintf("[FILE HASH] The given hash is %d bytes in size", hashSize);

		// We'll reuse the buff var here because it's more than big enough for the
		// size of any hash that'll be calculated
		if (!CryptGetHashParam(hashInstance, HP_HASHVAL, buff, &hashSize, 0))
		{
			result = GetLastError();
			dprintf("[FILE HASH] Failed to get the hash value: %d (%x)", result, result);
			break;
		}

		dprintf("[FILE HASH] Successfully generated hash");

		packet_add_tlv_raw(response, TLV_TYPE_FILE_HASH, buff, hashSize);

	} while (0);

	if (hashInstance != 0)
	{
		CryptDestroyHash(hashInstance);
	}

	if (cryptProv != 0)
	{
		CryptReleaseContext(cryptProv, 0);
	}

	if (fd != NULL)
	{
		fclose(fd);
	}

	return packet_transmit_response(result, remote, response);}


/*
 * Returns the MD5 hash for a specified file path
 *
 * req: TLV_TYPE_FILE_PATH - The file path that is to be stat'd
 */
DWORD request_fs_md5(Remote *remote, Packet *packet)
{
	return request_fs_file_hash(remote, packet, CALG_MD5);
}


/*
 * Returns the SHA1 hash for a specified file path
 *
 * req: TLV_TYPE_FILE_PATH - The file path that is to be stat'd
 */
DWORD request_fs_sha1(Remote *remote, Packet *packet)
{
	return request_fs_file_hash(remote, packet, CALG_SHA1);
}

/*
 * Moves source file path to destination
 *
 * req: TLV_TYPE_FILE_PATH - The file path to expand
 */
DWORD request_fs_file_move(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD result = ERROR_SUCCESS;
	char *oldpath;
	char *newpath;

	oldpath = packet_get_tlv_value_string(packet, TLV_TYPE_FILE_NAME);
	newpath = packet_get_tlv_value_string(packet, TLV_TYPE_FILE_PATH);

	if (!oldpath) {
		result = ERROR_INVALID_PARAMETER;
	} else {
		result = fs_move(oldpath, newpath);
	}

	return packet_transmit_response(result, remote, response);
}

/*
 * Copies source file path to destination
 *
 * req: TLV_TYPE_FILE_PATH - The file path to expand
 */
DWORD request_fs_file_copy(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD result = ERROR_SUCCESS;
	char *oldpath;
	char *newpath;

	oldpath = packet_get_tlv_value_string(packet, TLV_TYPE_FILE_NAME);
	newpath = packet_get_tlv_value_string(packet, TLV_TYPE_FILE_PATH);

	if (!oldpath) {
		result = ERROR_INVALID_PARAMETER;
	} else {
		result = fs_copy(oldpath, newpath);
	}

	return packet_transmit_response(result, remote, response);
}
