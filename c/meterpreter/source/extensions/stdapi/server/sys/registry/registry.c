#include "precomp.h"
#include "common_metapi.h"
#include <shlwapi.h>

/*!
 * @brief Check to see if a registry key exists.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the request \c Packet instance.
 * @returns Always returns \c ERROR_SUCCESS.
 */
DWORD request_registry_check_key_exists(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	if (response == NULL) {
		goto out;
	}

	HKEY rootKey = (HKEY)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_ROOT_KEY);
	wchar_t *baseKey = met_api->string.utf8_to_wchar(met_api->packet.get_tlv_value_string(packet, TLV_TYPE_BASE_KEY));

	DWORD result = ERROR_INVALID_PARAMETER;
	if (rootKey && baseKey) {
		BOOL exists = FALSE;
		HKEY resultKey = NULL;
		if (RegOpenKeyExW(rootKey, baseKey, 0, KEY_QUERY_VALUE, &resultKey) == ERROR_SUCCESS) {
			dprintf("[REG] Key found");
			RegCloseKey(resultKey);
			exists = TRUE;
		}

		dprintf("[REG] Key exists? %s", exists ? "TRUE" : "FALSE");
		met_api->packet.add_tlv_bool(response, TLV_TYPE_BOOL, exists);
		result = ERROR_SUCCESS;
	}

	free(baseKey);

	met_api->packet.transmit_response(result, remote, response);
out:
	return ERROR_SUCCESS;
}

/*
 * Creates a subkey and loads data from the specified registry hive into that
 * subkey.
 *
 * TLVs:
 *
 * req: TLV_TYPE_ROOT_KEY   - The root key
 * req: TLV_TYPE_BASE_KEY   - The base key
 * opt: TLV_TYPE_FILE_PATH  - Hive file to load
 */
DWORD request_registry_load_key(Remote *remote, Packet *packet)
{
	Packet *response   = met_api->packet.create_response(packet);
	if (response == NULL) {
		goto out;
	}

	HKEY rootKey       = (HKEY)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_ROOT_KEY);
	wchar_t *baseKey   = met_api->string.utf8_to_wchar(met_api->packet.get_tlv_value_string(packet, TLV_TYPE_BASE_KEY));
	wchar_t *hiveFile  = met_api->string.utf8_to_wchar(met_api->packet.get_tlv_value_string(packet, TLV_TYPE_FILE_PATH));

	DWORD result = ERROR_INVALID_PARAMETER;
	if (rootKey && baseKey && hiveFile) {
		result = RegLoadKeyW(rootKey, baseKey, hiveFile);
	}

	free(baseKey);
	free(hiveFile);
	met_api->packet.transmit_response(result, remote, response);
out:
	return ERROR_SUCCESS;
}

DWORD request_registry_unload_key(Remote *remote, Packet *packet)
{
	Packet *response   = met_api->packet.create_response(packet);
	if (response == NULL) {
		goto out;
	}

	HKEY rootKey       = (HKEY)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_ROOT_KEY);
	wchar_t *baseKey   = met_api->string.utf8_to_wchar(met_api->packet.get_tlv_value_string(packet, TLV_TYPE_BASE_KEY));

	DWORD result = ERROR_INVALID_PARAMETER;
	if (rootKey && baseKey) {
		result = RegUnLoadKeyW(rootKey, baseKey);
	}

	free(baseKey);
	met_api->packet.transmit_response(result, remote, response);
out:
	return ERROR_SUCCESS;
}

static DWORD open_key(Packet *packet, HKEY *rootKey, HKEY *resKey)
{
	*rootKey          = (HKEY)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_ROOT_KEY);
	wchar_t *baseKey  = met_api->string.utf8_to_wchar(met_api->packet.get_tlv_value_string(packet, TLV_TYPE_BASE_KEY));
	DWORD permission  = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_PERMISSION);

	// Validate the parameters and then attempt to create the key
	DWORD result = ERROR_INVALID_PARAMETER;
	if (rootKey && baseKey) {
		if (!permission) {
			permission = KEY_ALL_ACCESS;
		}

		result = RegOpenKeyExW(*rootKey, baseKey, 0, permission, resKey);
	}

	free(baseKey);

	return result;
}

/*
 * Opens a registry key and returns the associated HKEY to the caller if the
 * operation succeeds.
 *
 * TLVs:
 *
 * req: TLV_TYPE_ROOT_KEY   - The root key
 * req: TLV_TYPE_BASE_KEY   - The base key
 * opt: TLV_TYPE_PERMISSION - Permissions with which to open the key
 */
DWORD request_registry_open_key(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	if (response == NULL) {
		goto out;
	}

	HKEY rootKey, resKey;

	DWORD result = open_key(packet, &rootKey, &resKey);

	// Add the HKEY if we succeeded, but always return a result
	if (result == ERROR_SUCCESS) {
		met_api->packet.add_tlv_qword(response, TLV_TYPE_HKEY, (QWORD)resKey);
	}

	met_api->packet.transmit_response(result, remote, response);
out:
	return ERROR_SUCCESS;
}

/*
 * Opens a remote registry key and returns the associated HKEY to the caller if the
 * operation succeeds.
 *
 * TLVs:
 *
 * req: TLV_TYPE_ROOT_KEY      - The root key
 * req: TLV_TYPE_TARGET_HOST   - The target machine name
 */
DWORD request_registry_open_remote_key(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	if (response == NULL) {
		goto out;
	}


	HKEY resKey         = NULL;
	HKEY rootKey        = (HKEY)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_ROOT_KEY);
	wchar_t *targetHost = met_api->string.utf8_to_wchar(met_api->packet.get_tlv_value_string(packet, TLV_TYPE_TARGET_HOST));

	// Validate the parameters and then attempt to create the key
	DWORD result = ERROR_INVALID_PARAMETER;
	if (rootKey && targetHost) {
		result = RegConnectRegistryW(targetHost, rootKey, &resKey);
	}

	// Add the HKEY if we succeeded, but always return a result
	if (result == ERROR_SUCCESS) {
		met_api->packet.add_tlv_qword(response, TLV_TYPE_HKEY, (QWORD)resKey);
	}

	free(targetHost);
	met_api->packet.transmit_response(result, remote, response);
out:
	return ERROR_SUCCESS;
}

/*
 * Creates a registry key and returns the associated HKEY to the caller if the
 * operation succeeds.
 *
 * TLVs:
 *
 * req: TLV_TYPE_ROOT_KEY   - The root key
 * req: TLV_TYPE_BASE_KEY   - The base key
 * opt: TLV_TYPE_PERMISSION - Permissions with which to create the key
 */
DWORD request_registry_create_key(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	if (response == NULL) {
		goto out;
	}

	HKEY resKey      = NULL;
	HKEY rootKey     = (HKEY)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_ROOT_KEY);
	wchar_t *baseKey = met_api->string.utf8_to_wchar(met_api->packet.get_tlv_value_string(packet, TLV_TYPE_BASE_KEY));
	DWORD permission = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_PERMISSION);

	// Validate the parameters and then attempt to create the key
	DWORD result = ERROR_INVALID_PARAMETER;
	if (rootKey && baseKey) {
		if (!permission) {
			permission = KEY_ALL_ACCESS;
		}

		result = RegCreateKeyExW(rootKey, baseKey, 0, NULL, 0,
				permission, NULL, &resKey, NULL);
	}

	// Add the HKEY if we succeeded, but always return a result
	if (result == ERROR_SUCCESS) {
		met_api->packet.add_tlv_qword(response, TLV_TYPE_HKEY, (QWORD)resKey);
	}

	free(baseKey);
	met_api->packet.transmit_response(result, remote, response);
out:
	return ERROR_SUCCESS;
}

static void enum_key(Remote *remote, Packet *packet, HKEY hkey)
{
	Packet *response = met_api->packet.create_response(packet);
	if (response == NULL) {
		return;
	}

	DWORD result = ERROR_INVALID_PARAMETER;
	if (!hkey) {
		goto err;
	}

	DWORD maxSubKeyLen;
	result = RegQueryInfoKeyW(hkey, NULL, NULL, NULL, NULL, &maxSubKeyLen,
		NULL, NULL, NULL, NULL, NULL, NULL);
	if (result != ERROR_SUCCESS) {
		goto err;
	}

	DWORD index = 0;
	maxSubKeyLen++;
	wchar_t *name = calloc(maxSubKeyLen, sizeof(wchar_t));
	if (name == NULL) {
		result = ERROR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	while (1)
	{
		result = RegEnumKeyW(hkey, index, name, maxSubKeyLen);

		if (result == ERROR_SUCCESS) {
			char *tmp = met_api->string.wchar_to_utf8(name);
			if (tmp) {
				met_api->packet.add_tlv_string(response, TLV_TYPE_KEY_NAME, tmp);
				free(tmp);
			}
		} else {
			if (result == ERROR_NO_MORE_ITEMS) {
				result = ERROR_SUCCESS;
			}
			break;
		}

		index++;
	}

	free(name);
err:
	met_api->packet.transmit_response(result, remote, response);
}

static void enum_value(Remote *remote, Packet *packet, HKEY hkey)
{
	Packet *response = met_api->packet.create_response(packet);
	if (response == NULL) {
		return;
	}

	DWORD result = ERROR_INVALID_PARAMETER;
	if (!hkey) {
		goto err;
	}

	DWORD maxValueNameLen;
	result = RegQueryInfoKeyW(hkey, NULL, NULL, NULL, NULL, NULL, NULL,
			NULL, &maxValueNameLen, NULL, NULL, NULL);
	if (result != ERROR_SUCCESS) {
		goto err;
	}

	DWORD index = 0;
	maxValueNameLen++;
	wchar_t *name = calloc(maxValueNameLen, sizeof(wchar_t));
	if (name == NULL) {
		result = ERROR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	while (1)
	{
		DWORD valueLen = maxValueNameLen;
		result = RegEnumValueW(hkey, index, name, &valueLen,
				NULL, NULL, NULL, NULL);

		if (result == ERROR_SUCCESS) {
			char *tmp = met_api->string.wchar_to_utf8(name);
			if (tmp) {
				met_api->packet.add_tlv_string(response, TLV_TYPE_VALUE_NAME, tmp);
				free(tmp);
			}
		} else {
			if (result == ERROR_NO_MORE_ITEMS) {
				result = ERROR_SUCCESS;
			}
			break;
		}

		index++;
	}

	free(name);
err:
	met_api->packet.transmit_response(result, remote, response);
}



/*
 * Enumerates a supplied registry key and returns a list of all the direct
 * sub-keys.
 *
 * TLVs:
 *
 * req: TLV_TYPE_HKEY - The HKEY that is to be enumerated
 */
DWORD request_registry_enum_key(Remote *remote, Packet *packet)
{
	HKEY hkey = (HKEY)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_HKEY);
	enum_key(remote, packet, hkey);

	return ERROR_SUCCESS;
}

/*
 * Enumerates a supplied registry key and returns a list of all the direct
 * sub-keys.
 *
 * TLVs:
 *
 * req: TLV_TYPE_ROOT_KEY   - The root key
 * req: TLV_TYPE_BASE_KEY   - The base key
 * opt: TLV_TYPE_PERMISSION - Permissions with which to open the key
 */
DWORD request_registry_enum_key_direct(Remote *remote, Packet *packet)
{
	HKEY rootkey, hkey = NULL;

	open_key(packet, &rootkey, &hkey);
	enum_key(remote, packet, hkey);
	if (hkey) {
		RegCloseKey(hkey);
	}

	return ERROR_SUCCESS;
}

/*
 * Removes a registry key with the supplied root and base key information.
 *
 * TLVs:
 *
 * req: TLV_TYPE_ROOT_KEY - The root key handle.
 * req: TLV_TYPE_BASE_KEY - The base key name.
 * opt: TLV_TYPE_FLAGS    - Zero or more flags that control how the key is
 *                          deleted.
 */
DWORD request_registry_delete_key(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	if (response == NULL) {
		goto out;
	}

	HKEY rootKey     = (HKEY)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_ROOT_KEY);
	wchar_t *baseKey = met_api->string.utf8_to_wchar(met_api->packet.get_tlv_value_string(packet, TLV_TYPE_BASE_KEY));
	DWORD flags      = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_FLAGS);

	DWORD result = ERROR_INVALID_PARAMETER;
	if (rootKey && baseKey) {
		if (flags & DELETE_KEY_FLAG_RECURSIVE) {
			result = SHDeleteKeyW(rootKey, baseKey);
		} else {
			result = RegDeleteKeyW(rootKey, baseKey);
		}
	}

	free(baseKey);
	met_api->packet.transmit_response(result, remote, response);
out:
	return ERROR_SUCCESS;
}

/*
 * Closes the supplied HKEY
 *
 * TLVs:
 *
 * req: TLV_TYPE_HKEY - The HKEY that is to be closed
 */
DWORD request_registry_close_key(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	if (response == NULL) {
		goto out;
	}

	HKEY hkey = (HKEY)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_HKEY);

	DWORD result = ERROR_INVALID_PARAMETER;
	if (hkey) {
		result = RegCloseKey(hkey);
	}

	// Set the result and send the response
	met_api->packet.transmit_response(result, remote, response);
out:
	return ERROR_SUCCESS;
}

/*
 * @brief Unparse a REG_MULTI_SZ value to send back to Metasploit. Encode the
 *        UTF-16LE string array into UTF-8. The caller must free the returned buffer.
 *        This does not assume that str is terminated by two null characters
 *        which is why it is necessary to pass in the size in bytes of the
 *        input buffer.
 *
 *        Example:
 *          "S1\x00S2\x00\x00" => "S\x001\x00\x00\x00S\x002\x00\x00\x00\x00\x00"
 * @param str The string to convert.
 * @param size A pointer that on input is the size of str in bytes and on
 *             output will receive the size in bytes of the resulting buffer.
 */
static char* reg_multi_sz_unparse(wchar_t* str, size_t* size)
{
	// Count the number of chunks
	int count = 0;
	wchar_t* wchunk = NULL;
	char* chunk = NULL;
	size_t chunk_len = 0;
	size_t total_size = 0;
	char* res = NULL;
	wchar_t* my_str = NULL;
	
	if ((!size) || (*size < 2 * sizeof(str[0]))) {
		SetLastError(ERROR_BAD_ARGUMENTS);
		return NULL;
	}
	// if the input does not end in two null characters, then create and use our own buffer
	// which is obviously less efficient if the input isn't properly terminated
	if ((str[*size - 1] == 0) && (str[*size - 2]) == 0) {
		my_str = str;
	}
	else {
		my_str = malloc(*size + (2 * sizeof(str[0])));
		if (!my_str) {
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			goto out;
		}
		memset(my_str, 0, *size + (2 * sizeof(str[0])));
		memcpy(my_str, str, *size);
	}

	wchunk = my_str;
	while (chunk_len = wcslen(wchunk))
	{
		chunk = met_api->string.wchar_to_utf8(wchunk);
		count++;
		wchunk += chunk_len + 1;
		if (!chunk)
			continue;
		total_size += strlen(chunk);
		free(chunk);
	}

	res = calloc(total_size + (count - 1) + 2, sizeof(char));
	if (!res) {
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		goto out;
	}
	if (size)
		*size = (total_size + (count - 1) + 2) * sizeof(char);

	char* write_cursor = res;
	wchunk = my_str;
	while (chunk_len = wcslen(wchunk))
	{
		chunk = met_api->string.wchar_to_utf8(wchunk);
		wchunk += chunk_len + 1;
		if (!chunk)
			continue;
		strcpy(write_cursor, chunk);
		write_cursor += strlen(chunk) + 1;
		free(chunk);
	}

out:
	if ((my_str) && (my_str != str))
		free(my_str);
	return res;
}

/*
 * @brief Parse a REG_MULTI_SZ value from Metasploit. Encode the UTF-8
 *        string array into UTF-16LE. The caller must free the returned buffer.
 *        This does not assume that str is terminated by two null characters
 *        which is why it is necessary to pass in the size in bytes of the 
 *        input buffer.
 * @param str The string to convert.
 * @param size A pointer that on input is the size of str in bytes and on
 *             output will receive the size in bytes of the resulting buffer.
 */
static wchar_t *reg_multi_sz_parse(char* str, size_t* size)
{
	// Count the number of chunks
	int count = 0;
	wchar_t* wchunk = NULL;
	char* chunk = NULL;
	size_t chunk_len = 0;
	size_t total_size = 0;
	wchar_t* res = NULL;
	char* my_str = NULL;

	if ((!size) || (*size < 2 * sizeof(str[0]))) {
		SetLastError(ERROR_BAD_ARGUMENTS);
		return NULL;
	}
	// if the input does not end in two null characters create and user our own buffer
	// this is obviously less effecient if the input isn't properly terminated
	if ((str[*size - 1] == 0) && (str[*size - 2]) == 0) {
		my_str = str;
	} else {
		my_str = malloc(*size + (2 * sizeof(str[0])));
		if (!my_str) {
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			goto out;
		}
		memset(my_str, 0, *size + (2 * sizeof(str[0])));
		memcpy(my_str, str, *size);
	}

	chunk = my_str;
	while (chunk_len = strlen(chunk))
	{
		wchunk = met_api->string.utf8_to_wchar(chunk);
		count++;
		chunk += chunk_len + 1;
		if (!wchunk)
			continue;
		total_size += wcslen(wchunk);
		free(wchunk);
	}

	res = calloc(total_size + (count - 1) + 2, sizeof(wchar_t));
	if (!res) {
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		goto out;
	}
	if (size)
		*size = (total_size + (count - 1) + 2) * sizeof(wchar_t);

	wchar_t* write_cursor = res;
	chunk = my_str;
	while (chunk_len = strlen(chunk))
	{
		wchunk = met_api->string.utf8_to_wchar(chunk);
		chunk += chunk_len + 1;
		if (!wchunk)
			continue;
		wcscpy(write_cursor, wchunk);
		write_cursor += wcslen(wchunk) + 1;
		free(wchunk);
	}

out:
	if ((my_str) && (my_str != str))
		free(my_str);
	return res;
}

static void set_value(Remote *remote, Packet *packet, HKEY hkey)
{
	Packet *response = met_api->packet.create_response(packet);
	if (response == NULL) {
		return;
	}

	wchar_t *valueName;
	DWORD valueType = 0;
	DWORD result = ERROR_SUCCESS;
	Tlv valueData;

	// Acquire the standard TLVs
	valueName = met_api->string.utf8_to_wchar(met_api->packet.get_tlv_value_string(packet, TLV_TYPE_VALUE_NAME));
	valueType = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_VALUE_TYPE);

	// Get the value data TLV
	if (met_api->packet.get_tlv(packet, TLV_TYPE_VALUE_DATA, &valueData) != ERROR_SUCCESS) {
		result = ERROR_INVALID_PARAMETER;
	} else {
		// Now let's rock this shit!
		void *buf;
		size_t len;
		switch (valueType) {
			case REG_SZ:
			case REG_EXPAND_SZ:
				buf = met_api->string.utf8_to_wchar(valueData.buffer);
				len = (wcslen(buf) + 1) * sizeof(wchar_t);
				break;
			case REG_MULTI_SZ:
				len = valueData.header.length;
				buf = reg_multi_sz_parse(valueData.buffer, &len);
				break;
			default:
				len = valueData.header.length;
				buf = valueData.buffer;
		}
		result = RegSetValueExW(hkey, valueName, 0, valueType, buf, (DWORD)len);
		if (buf != valueData.buffer) {
			free(buf);
		}
	}

	free(valueName);

	// Populate the result code
	met_api->packet.transmit_response(result, remote, response);
}

/*
 * Sets a registry value with the supplied data for a given HKEY.
 *
 * TLVs:
 *
 * req: TLV_TYPE_HKEY       - The HKEY to set the value on
 * req: TLV_TYPE_VALUE_NAME - The name of the value to set
 * req: TLV_TYPE_VALUE_TYPE - The type of the value to set
 * req: TLV_TYPE_VALUE_DATA - The data to set the value to
 */
DWORD request_registry_set_value(Remote *remote, Packet *packet)
{
	HKEY hkey = (HKEY)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_HKEY);
	set_value(remote, packet, hkey);

	return ERROR_SUCCESS;
}

/*
 * Sets a registry value with the supplied data for a given HKEY.
 *
 * TLVs:
 *
 * req: TLV_TYPE_ROOT_KEY   - The root key
 * req: TLV_TYPE_BASE_KEY   - The base key
 * opt: TLV_TYPE_PERMISSION - Permissions with which to open the key
 * req: TLV_TYPE_VALUE_NAME - The name of the value to set
 * req: TLV_TYPE_VALUE_TYPE - The type of the value to set
 * req: TLV_TYPE_VALUE_DATA - The data to set the value to
 */
DWORD request_registry_set_value_direct(Remote *remote, Packet *packet)
{
	HKEY rootkey, hkey = NULL;

	open_key(packet, &rootkey, &hkey);
	set_value(remote, packet, hkey);
	if (hkey) {
		RegCloseKey(hkey);
	}

	return ERROR_SUCCESS;
}

static void query_value(Remote *remote, Packet *packet, HKEY hkey)
{
	Packet *response = met_api->packet.create_response(packet);
	if (response == NULL) {
		return;
	}

	wchar_t *valueName;
	char *tmp;
	size_t tmp_sz = 0;
	void *valueData = NULL;
	DWORD valueDataSize = 0;
	DWORD result = ERROR_SUCCESS;
	DWORD valueType = 0;

	valueName = met_api->string.utf8_to_wchar(met_api->packet.get_tlv_value_string(packet, TLV_TYPE_VALUE_NAME));

	// Get the size of the value data
	if ((result = RegQueryValueExW(hkey, valueName, 0, NULL, NULL,
	    &valueDataSize)) != ERROR_SUCCESS) {
		goto err;
	}

	valueDataSize++;

	// Allocate storage for the value data
	if (!(valueData = calloc(1, valueDataSize))) {
		goto err;
	}

	// Query the value's information
	if ((result = RegQueryValueExW(hkey, valueName, 0, &valueType, valueData,
	    &valueDataSize)) != ERROR_SUCCESS) {
		goto err;
	}

	// Add the information about the value to the response
	met_api->packet.add_tlv_uint(response, TLV_TYPE_VALUE_TYPE, valueType);

	switch (valueType) {
		case REG_SZ:
		case REG_EXPAND_SZ:
			tmp = met_api->string.wchar_to_utf8((wchar_t *)valueData);
			if (tmp) {
				met_api->packet.add_tlv_string(response, TLV_TYPE_VALUE_DATA, tmp);
				free(tmp);
			} else {
				met_api->packet.add_tlv_raw(response, TLV_TYPE_VALUE_DATA,
					valueData, valueDataSize);
			}
			break;
		case REG_MULTI_SZ:
			tmp_sz = valueDataSize;
			tmp = reg_multi_sz_unparse(valueData, &tmp_sz);
			if (tmp) {
				met_api->packet.add_tlv_raw(response, TLV_TYPE_VALUE_DATA,
					tmp, (DWORD)tmp_sz);
				free(tmp);
			}
			else {
				met_api->packet.add_tlv_raw(response, TLV_TYPE_VALUE_DATA,
					valueData, valueDataSize);
			}
			break;
		case REG_DWORD:
			met_api->packet.add_tlv_uint(response, TLV_TYPE_VALUE_DATA,
				*(LPDWORD)valueData);
			break;
		default:
			met_api->packet.add_tlv_raw(response, TLV_TYPE_VALUE_DATA,
				valueData, valueDataSize);
			break;
	}

err:
	free(valueName);
	// Populate the result code
	met_api->packet.transmit_response(result, remote, response);
}

/*
 * Queries a registry value's type and data for a given HKEY.RegEnumValueW
 *
 * TLVs:
 *
 * req: TLV_TYPE_HKEY       - The HKEY to query the value on
 * req: TLV_TYPE_VALUE_NAME - The name of the value to query
 */
DWORD request_registry_query_value(Remote *remote, Packet *packet)
{
	HKEY hkey = (HKEY)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_HKEY);
	query_value(remote, packet, hkey);

	return ERROR_SUCCESS;
}

/*
 * Queries a registry value's type and data for a given HKEY.
 *
 * TLVs:
 *
 * req: TLV_TYPE_ROOT_KEY   - The root key
 * req: TLV_TYPE_BASE_KEY   - The base key
 * opt: TLV_TYPE_PERMISSION - Permissions with which to open the key
 * req: TLV_TYPE_VALUE_NAME - The name of the value to query
 */
DWORD request_registry_query_value_direct(Remote *remote, Packet *packet)
{
	HKEY rootkey, hkey = NULL;

	open_key(packet, &rootkey, &hkey);
	query_value(remote, packet, hkey);
	if (hkey) {
		RegCloseKey(hkey);
	}

	return ERROR_SUCCESS;
}

/*
 * Enumerates all of the value names at the supplied HKEY.
 *
 * TLVs:
 *
 * req: TLV_TYPE_HKEY - The HKEY that will have its values enumerated.
 */
DWORD request_registry_enum_value(Remote *remote, Packet *packet)
{
	HKEY hkey = (HKEY)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_HKEY);
	enum_value(remote, packet, hkey);

	return ERROR_SUCCESS;
}

/*
 * Enumerates all of the value names at the supplied HKEY.
 *
 * TLVs:
 *
 * req: TLV_TYPE_ROOT_KEY   - The root key
 * req: TLV_TYPE_BASE_KEY   - The base key
 * opt: TLV_TYPE_PERMISSION - Permissions with which to open the key
 */
DWORD request_registry_enum_value_direct(Remote *remote, Packet *packet)
{
	HKEY rootkey, hkey = NULL;

	open_key(packet, &rootkey, &hkey);
	enum_value(remote, packet, hkey);
	if (hkey) {
		RegCloseKey(hkey);
	}

	return ERROR_SUCCESS;
}

/*
 * Deletes a registry value from the supplied registry key
 *
 * TLVs:
 *
 * req: TLV_TYPE_HKEY       - The HKEY from which to delete the value
 * req: TLV_TYPE_VALUE_NAME = The name of the value to delete
 */
DWORD request_registry_delete_value(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	if (response == NULL) {
		goto out;
	}

	HKEY hkey          = (HKEY)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_HKEY);
	wchar_t *valueName = met_api->string.utf8_to_wchar(met_api->packet.get_tlv_value_string(packet, TLV_TYPE_VALUE_NAME));

	DWORD result = ERROR_INVALID_PARAMETER;
	if (hkey && valueName) {
		result = RegDeleteValueW(hkey, valueName);
	}

	free(valueName);
	met_api->packet.transmit_response(result, remote, response);
out:
	return ERROR_SUCCESS;
}

/*
 * Queries a registry class for a given HKEY.
 *
 * TLVs:
 *
 * req: TLV_TYPE_HKEY       - The HKEY to query the class on
 */
DWORD request_registry_query_class(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	if (response == NULL) {
		goto out;
	}

	HKEY hkey = (HKEY)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_HKEY);

	DWORD result = ERROR_INVALID_PARAMETER;
	if (!hkey) {
		goto err;
	}

	DWORD classNameLen = 4096;
	char className[4096];

	result = RegQueryInfoKeyA(hkey, className, &classNameLen,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	if (result == ERROR_SUCCESS) {
		met_api->packet.add_tlv_raw(response, TLV_TYPE_VALUE_DATA,
			className, classNameLen);
	}

err:
	met_api->packet.transmit_response(result, remote, response);
out:
	return ERROR_SUCCESS;
}
