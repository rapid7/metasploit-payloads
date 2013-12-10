/*!
 * @file adsi.c
 * @brief Definitions for ADSI functionality.
 */
#include "extapi.h"
#include "adsi.h"
#include "adsi_interface.h"

/*!
 * @brief Helper function that converts an ASCII string to a wide char string.
 * @param lpValue ASCII string to convert.
 * @param lpwValue Target memory for the converted string.
 * @remark lpwValue must already have enough memory allocated to hold all the characters.
 * @returns Indication of success or failure.
 */
DWORD to_wide_string(LPSTR lpValue, LPWSTR* lpwValue)
{
	size_t charsCopied = 0;
	DWORD valueLength;
	DWORD dwResult;

	do
	{
		if (lpValue == NULL)
		{
			BREAK_WITH_ERROR("[EXTAPI ADSI] Value parameter missing", ERROR_INVALID_PARAMETER);
		}

		valueLength = lstrlenA(lpValue);
		*lpwValue = (LPWSTR)malloc(sizeof(WCHAR)* (lstrlenA(lpValue) + 1));
		if (*lpwValue == NULL)
		{
			BREAK_WITH_ERROR("[EXTAPI ADSI] Unable to allocate memory", ERROR_OUTOFMEMORY);
		}

		mbstowcs_s(&charsCopied, *lpwValue, valueLength + 1, lpValue, valueLength);
		dwResult = ERROR_SUCCESS;
	} while (0);

	return dwResult;
}

/*!
 * @brief Enumerate all the users in AD.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the incoming \c Packet instance.
 * @returns Indication of success or failure.
 * @remark Real error codes are returned to the caller via a response packet.
 */
DWORD request_adsi_domain_query(Remote *remote, Packet *packet)
{
	DWORD dwResult = ERROR_SUCCESS;
	LPSTR lpValue = NULL;
	LPWSTR lpwDomain = NULL;
	LPWSTR lpwFilter = NULL;
	LPWSTR* lpwFields = NULL;
	DWORD fieldCount = 0;
	DWORD fieldIndex = 0;
	Packet * response = packet_create_response(packet);
	Tlv fieldTlv;
	DWORD maxResults;
	DWORD pageSize;

	do
	{
		if (!response)
		{
			BREAK_WITH_ERROR("[EXTAPI ADSI] Unable to create response packet", ERROR_OUTOFMEMORY);
		}

		lpValue = packet_get_tlv_value_string(packet, TLV_TYPE_EXT_ADSI_DOMAIN);
		dprintf("[EXTAPI ADSI] Domain: %s", lpValue);
		dwResult = to_wide_string(lpValue, &lpwDomain);
		if (dwResult != ERROR_SUCCESS)
		{
			dprintf("[EXTAPI ADSI] Failed to get Domain");
			break;
		}

		lpValue = packet_get_tlv_value_string(packet, TLV_TYPE_EXT_ADSI_FILTER);
		dprintf("[EXTAPI ADSI] Filter: %s", lpValue);
		dwResult = to_wide_string(lpValue, &lpwFilter);
		if (dwResult != ERROR_SUCCESS)
		{
			dprintf("[EXTAPI ADSI] Failed to get Filter");
			break;
		}

		maxResults = packet_get_tlv_value_uint(packet, TLV_TYPE_EXT_ASDI_MAXRESULTS);
		dprintf("[EXTAPI ADSI] Max results will be %u", maxResults);

		pageSize = packet_get_tlv_value_uint(packet, TLV_TYPE_EXT_ASDI_PAGESIZE);

		if (maxResults != 0)
		{
			pageSize = min(pageSize, maxResults);
		}
		dprintf("[EXTAPI ADSI] Page size will be %u", pageSize);

		while (packet_enum_tlv(packet, fieldCount, TLV_TYPE_EXT_ADSI_FIELD, &fieldTlv) == ERROR_SUCCESS)
		{
			lpValue = (char*)fieldTlv.buffer;
			dprintf("[EXTAPI ADSI] Field %u: %s", fieldCount, lpValue);
			lpwFields = (LPWSTR*)realloc(lpwFields, sizeof(LPWSTR) * (fieldCount + 1));

			if (lpwFields == NULL)
			{
				BREAK_WITH_ERROR("[EXTAPI ADSI] Unable to allocate memory", ERROR_OUTOFMEMORY);
			}

			dwResult = to_wide_string(lpValue, &lpwFields[fieldCount]);
			if (dwResult != ERROR_SUCCESS)
			{
				dprintf("[EXTAPI ADSI] Failed to get field as wide string");
				break;
			}
			++fieldCount;
		}

		dprintf("[EXTAPI ADSI] Field count: %u", fieldCount, lpValue);

		if (dwResult == ERROR_SUCCESS)
		{
			dprintf("[EXTAPI ADSI] Beginning user enumeration");
			dwResult = domain_query(lpwDomain, lpwFilter, lpwFields, fieldCount, maxResults, pageSize, response);
		}
	} while (0);

	if (lpwFields)
	{
		for (fieldIndex = 0; fieldIndex < fieldCount; ++fieldIndex)
		{
			if (lpwFields[fieldIndex])
			{
				free(lpwFields[fieldIndex]);
			}
		}
		free(lpwFields);
	}

	if (lpwFilter)
	{
		free(lpwFilter);
	}

	if (lpwDomain)
	{
		free(lpwDomain);
	}

	dprintf("[EXTAPI ADSI] Transmitting response back to caller.");
	if (response)
	{
		packet_transmit_response(dwResult, remote, response);
	}

	return dwResult;
}
