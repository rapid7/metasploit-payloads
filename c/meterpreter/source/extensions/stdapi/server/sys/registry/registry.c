#include "precomp.h"
#include <shlwapi.h>

/*!
 * @brief Check to see if a registry key exists.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the request \c Packet instance.
 * @returns Always returns \c ERROR_SUCCESS.
 */
DWORD request_registry_check_key_exists(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	if (response == NULL) {
		goto out;
	}

	HKEY rootKey = (HKEY)packet_get_tlv_value_qword(packet, TLV_TYPE_ROOT_KEY);
	wchar_t *baseKey = utf8_to_wchar(packet_get_tlv_value_string(packet, TLV_TYPE_BASE_KEY));

	DWORD result = ERROR_INVALID_PARAMETER;
	if (rootKey && baseKey) {
		BOOL exists = FALSE;
		HKEY resultKey = NULL;
		if (RegOpenKeyW(rootKey, baseKey, &resultKey) == ERROR_SUCCESS) {
			dprintf("[REG] Key found");
			RegCloseKey(resultKey);
			exists = TRUE;
		}

		dprintf("[REG] Key exists? %s", exists ? "TRUE" : "FALSE");
		packet_add_tlv_bool(response, TLV_TYPE_BOOL, exists);
		result = ERROR_SUCCESS;
	}

	free(baseKey);

	packet_transmit_response(result, remote, response);
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
	Packet *response   = packet_create_response(packet);
	if (response == NULL) {
		goto out;
	}

	HKEY rootKey       = (HKEY)packet_get_tlv_value_qword(packet, TLV_TYPE_ROOT_KEY);
	wchar_t *baseKey   = utf8_to_wchar(packet_get_tlv_value_string(packet, TLV_TYPE_BASE_KEY));
	wchar_t *hiveFile  = utf8_to_wchar(packet_get_tlv_value_string(packet, TLV_TYPE_FILE_PATH));

	DWORD result = ERROR_INVALID_PARAMETER;
	if (rootKey && baseKey && hiveFile) {
		result = RegLoadKeyW(rootKey, baseKey, hiveFile);
	}

	free(baseKey);
	free(hiveFile);
	packet_transmit_response(result, remote, response);
out:
	return ERROR_SUCCESS;
}

DWORD request_registry_unload_key(Remote *remote, Packet *packet)
{
	Packet *response   = packet_create_response(packet);
	if (response == NULL) {
		goto out;
	}

	HKEY rootKey       = (HKEY)packet_get_tlv_value_qword(packet, TLV_TYPE_ROOT_KEY);
	wchar_t *baseKey   = utf8_to_wchar(packet_get_tlv_value_string(packet, TLV_TYPE_BASE_KEY));

	DWORD result = ERROR_INVALID_PARAMETER;
	if (rootKey && baseKey) {
		result = RegUnLoadKeyW(rootKey, baseKey);
	}

	free(baseKey);
	packet_transmit_response(result, remote, response);
out:
	return ERROR_SUCCESS;
}

static DWORD open_key(Packet *packet, HKEY *rootKey, HKEY *resKey)
{
	*rootKey          = (HKEY)packet_get_tlv_value_qword(packet, TLV_TYPE_ROOT_KEY);
	wchar_t *baseKey  = utf8_to_wchar(packet_get_tlv_value_string(packet, TLV_TYPE_BASE_KEY));
	DWORD permission  = packet_get_tlv_value_uint(packet, TLV_TYPE_PERMISSION);

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
	Packet *response = packet_create_response(packet);
	if (response == NULL) {
		goto out;
	}

	HKEY rootKey, resKey;

	DWORD result = open_key(packet, &rootKey, &resKey);

	// Add the HKEY if we succeeded, but always return a result
	if (result == ERROR_SUCCESS) {
		packet_add_tlv_qword(response, TLV_TYPE_HKEY, (QWORD)resKey);
	}

	packet_transmit_response(result, remote, response);
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
	Packet *response = packet_create_response(packet);
	if (response == NULL) {
		goto out;
	}


	HKEY resKey         = NULL;
	HKEY rootKey        = (HKEY)packet_get_tlv_value_qword(packet, TLV_TYPE_ROOT_KEY);
	wchar_t *targetHost = utf8_to_wchar(packet_get_tlv_value_string(packet, TLV_TYPE_TARGET_HOST));

	// Validate the parameters and then attempt to create the key
	DWORD result = ERROR_INVALID_PARAMETER;
	if (rootKey && targetHost) {
		result = RegConnectRegistryW(targetHost, rootKey, &resKey);
	}

	// Add the HKEY if we succeeded, but always return a result
	if (result == ERROR_SUCCESS) {
		packet_add_tlv_qword(response, TLV_TYPE_HKEY, (QWORD)resKey);
	}

	free(targetHost);
	packet_transmit_response(result, remote, response);
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
	Packet *response = packet_create_response(packet);
	if (response == NULL) {
		goto out;
	}

	HKEY resKey      = NULL;
	HKEY rootKey     = (HKEY)packet_get_tlv_value_qword(packet, TLV_TYPE_ROOT_KEY);
	wchar_t *baseKey = utf8_to_wchar(packet_get_tlv_value_string(packet, TLV_TYPE_BASE_KEY));
	DWORD permission = packet_get_tlv_value_uint(packet, TLV_TYPE_PERMISSION);

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
		packet_add_tlv_qword(response, TLV_TYPE_HKEY, (QWORD)resKey);
	}

	free(baseKey);
	packet_transmit_response(result, remote, response);
out:
	return ERROR_SUCCESS;
}

static void enum_key(Remote *remote, Packet *packet, HKEY hkey)
{
	Packet *response = packet_create_response(packet);
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
			char *tmp = wchar_to_utf8(name);
			if (tmp) {
				packet_add_tlv_string(response, TLV_TYPE_KEY_NAME, tmp);
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
	packet_transmit_response(result, remote, response);
}

static void enum_value(Remote *remote, Packet *packet, HKEY hkey)
{
	Packet *response = packet_create_response(packet);
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
			char *tmp = wchar_to_utf8(name);
			if (tmp) {
				packet_add_tlv_string(response, TLV_TYPE_VALUE_NAME, tmp);
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
	packet_transmit_response(result, remote, response);
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
	HKEY hkey = (HKEY)packet_get_tlv_value_qword(packet, TLV_TYPE_HKEY);
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
	Packet *response = packet_create_response(packet);
	if (response == NULL) {
		goto out;
	}

	HKEY rootKey     = (HKEY)packet_get_tlv_value_qword(packet, TLV_TYPE_ROOT_KEY);
	wchar_t *baseKey = utf8_to_wchar(packet_get_tlv_value_string(packet, TLV_TYPE_BASE_KEY));
	DWORD flags      = packet_get_tlv_value_uint(packet, TLV_TYPE_FLAGS);

	DWORD result = ERROR_INVALID_PARAMETER;
	if (rootKey && baseKey) {
		if (flags & DELETE_KEY_FLAG_RECURSIVE) {
			result = SHDeleteKeyW(rootKey, baseKey);
		} else {
			result = RegDeleteKeyW(rootKey, baseKey);
		}
	}

	free(baseKey);
	packet_transmit_response(result, remote, response);
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
	Packet *response = packet_create_response(packet);
	if (response == NULL) {
		goto out;
	}

	HKEY hkey = (HKEY)packet_get_tlv_value_qword(packet, TLV_TYPE_HKEY);

	DWORD result = ERROR_INVALID_PARAMETER;
	if (hkey) {
		result = RegCloseKey(hkey);
	}

	// Set the result and send the response
	packet_transmit_response(result, remote, response);
out:
	return ERROR_SUCCESS;
}

/*
* Parse the REG_MULTI_SZ registry value types.
* A sequence of null-terminated strings, would be splited by \0 and terminated by \0\0 .
* 
* Example:
*	"String1\0String2\0String3\0LastString\0\0" => "String1 String2 String3 LastString"
* 
* Reference: https://docs.microsoft.com/en-us/windows/desktop/sysinfo/registry-value-types
*
*/
static wchar_t *reg_multi_sz_parse(char* str, size_t *length)
{
	const char *delimter = "\\0";
	const char *ender = "\\0\\0";
	*length = 0;

	wchar_t *res = (wchar_t *)calloc(strlen(str) + 1, sizeof(wchar_t));

	char *trun = strstr(str, ender);  // truncated by '\0\0'
	if (trun)
	{
		str[trun - str] = '\0';
	}
	
	// Count the number of delimter
	int count = 1;  
	const char *tmp = str;
	while (tmp = strstr(tmp, delimter)) 
	{
		count++;	
		tmp++;
	}
	free((char*)tmp);

	// Split the strings by '\0'
	char ** string_arr = (char **)malloc(sizeof(char *) * count); 	// store splited strings. 
	char * ch = strtok(str, delimter); 	// delimter by '\0'
	int i = 0;
	while (ch != NULL)
	{
		string_arr[i] = (char *)malloc(sizeof(char) * (strlen(ch) + 1));
		strncpy(string_arr[i], ch, strlen(ch) + 1);		
		ch = strtok(NULL, delimter);
		i++;
	}
	count = i;	// count splited strings.

	wchar_t *ptr = res;  // temp pointer point to res
	for (i = 0; i < count; i++)
	{
		wchar_t * tmp_buf = calloc(strlen(string_arr[i]) + 1, sizeof(wchar_t));
		tmp_buf = utf8_to_wchar(string_arr[i]);

		wcsncpy(ptr, tmp_buf, wcslen(tmp_buf) + 1);		// join the splited strings.
		ptr += wcslen(tmp_buf) + 1;			// append next string to the end of last string, keep the null-terminater.

		(*length) += wcslen(tmp_buf) + 1;			// count of all strings length
		free(tmp_buf);
	}	

	free(string_arr);

	return res;
}

static void set_value(Remote *remote, Packet *packet, HKEY hkey)
{
	Packet *response = packet_create_response(packet);
	if (response == NULL) {
		return;
	}

	wchar_t *valueName;
	DWORD valueType = 0;
	DWORD result = ERROR_SUCCESS;
	Tlv valueData;

	// Acquire the standard TLVs
	valueName = utf8_to_wchar(packet_get_tlv_value_string(packet, TLV_TYPE_VALUE_NAME));
	valueType = packet_get_tlv_value_uint(packet, TLV_TYPE_VALUE_TYPE);

	// Get the value data TLV
	if (packet_get_tlv(packet, TLV_TYPE_VALUE_DATA, &valueData) != ERROR_SUCCESS) {
		result = ERROR_INVALID_PARAMETER;
	} else {
		// Now let's rock this shit!
		void *buf;
		size_t len;
		switch (valueType) {
			case REG_SZ:
			case REG_EXPAND_SZ:
				buf = utf8_to_wchar(valueData.buffer);
				len = (wcslen(buf) + 1) * sizeof(wchar_t);
				break;
			case REG_MULTI_SZ:
				buf = reg_multi_sz_parse(valueData.buffer, &len);
				len = (len + 1) * sizeof(wchar_t);
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
	packet_transmit_response(result, remote, response);
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
	HKEY hkey = (HKEY)packet_get_tlv_value_qword(packet, TLV_TYPE_HKEY);
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
	Packet *response = packet_create_response(packet);
	if (response == NULL) {
		return;
	}

	wchar_t *valueName;
	char *tmp;
	void *valueData = NULL;
	DWORD valueDataSize = 0;
	DWORD result = ERROR_SUCCESS;
	DWORD valueType = 0;

	valueName = utf8_to_wchar(packet_get_tlv_value_string(packet, TLV_TYPE_VALUE_NAME));

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
	packet_add_tlv_uint(response, TLV_TYPE_VALUE_TYPE, valueType);

	switch (valueType) {
		case REG_SZ:
		case REG_EXPAND_SZ:
			tmp = wchar_to_utf8((wchar_t *)valueData);
			if (tmp) {
				packet_add_tlv_string(response, TLV_TYPE_VALUE_DATA, tmp);
				free(tmp);
			} else {
				packet_add_tlv_raw(response, TLV_TYPE_VALUE_DATA,
					valueData, valueDataSize);
			}
			break;
		case REG_DWORD:
			packet_add_tlv_uint(response, TLV_TYPE_VALUE_DATA,
				*(LPDWORD)valueData);
			break;
		default:
			packet_add_tlv_raw(response, TLV_TYPE_VALUE_DATA,
				valueData, valueDataSize);
			break;
	}

err:
	free(valueName);
	// Populate the result code
	packet_transmit_response(result, remote, response);
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
	HKEY hkey = (HKEY)packet_get_tlv_value_qword(packet, TLV_TYPE_HKEY);
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
	HKEY hkey = (HKEY)packet_get_tlv_value_qword(packet, TLV_TYPE_HKEY);
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
	Packet *response = packet_create_response(packet);
	if (response == NULL) {
		goto out;
	}

	HKEY hkey          = (HKEY)packet_get_tlv_value_qword(packet, TLV_TYPE_HKEY);
	wchar_t *valueName = utf8_to_wchar(packet_get_tlv_value_string(packet, TLV_TYPE_VALUE_NAME));

	DWORD result = ERROR_INVALID_PARAMETER;
	if (hkey && valueName) {
		result = RegDeleteValueW(hkey, valueName);
	}

	free(valueName);
	packet_transmit_response(result, remote, response);
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
	Packet *response = packet_create_response(packet);
	if (response == NULL) {
		goto out;
	}

	HKEY hkey = (HKEY)packet_get_tlv_value_qword(packet, TLV_TYPE_HKEY);

	DWORD result = ERROR_INVALID_PARAMETER;
	if (!hkey) {
		goto err;
	}

	DWORD classNameLen = 4096;
	char className[4096];

	result = RegQueryInfoKeyA(hkey, className, &classNameLen,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	if (result == ERROR_SUCCESS) {
		packet_add_tlv_raw(response, TLV_TYPE_VALUE_DATA,
			className, classNameLen);
	}

err:
	packet_transmit_response(result, remote, response);
out:
	return ERROR_SUCCESS;
}
