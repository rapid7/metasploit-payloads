/*!
 * @file adsi.c
 * @brief Definitions for ADSI functionality.
 */
#include "extapi.h"
#include "wshelpers.h"
#include "adsi.h"
#include "adsi_interface.h"
#include "common_metapi.h"

/*! @brief The default page size to use when no page size is specified */
#define DEFAULT_PAGE_SIZE 1000

/*!
 * @brief Perform an ADSI query against a domain.
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
	Packet * response = met_api->packet.create_response(packet);
	Tlv fieldTlv;
	DWORD maxResults;
	DWORD pageSize;

	do
	{
		if (!response)
		{
			BREAK_WITH_ERROR("[EXTAPI ADSI] Unable to create response packet", ERROR_OUTOFMEMORY);
		}

		lpValue = met_api->packet.get_tlv_value_string(packet, TLV_TYPE_EXT_ADSI_DOMAIN);
		dprintf("[EXTAPI ADSI] Domain: %s", lpValue);
		dwResult = to_wide_string(lpValue, &lpwDomain);
		if (dwResult != ERROR_SUCCESS)
		{
			dprintf("[EXTAPI ADSI] Failed to get Domain");
			break;
		}

		lpValue = met_api->packet.get_tlv_value_string(packet, TLV_TYPE_EXT_ADSI_FILTER);
		dprintf("[EXTAPI ADSI] Filter: %s", lpValue);
		dwResult = to_wide_string(lpValue, &lpwFilter);
		if (dwResult != ERROR_SUCCESS)
		{
			dprintf("[EXTAPI ADSI] Failed to get Filter");
			break;
		}

		maxResults = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_EXT_ADSI_MAXRESULTS);
		dprintf("[EXTAPI ADSI] Max results will be %u", maxResults);

		pageSize = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_EXT_ADSI_PAGESIZE);
		dprintf("[EXTAPI ADSI] Page size specified as %u", pageSize);

		// Set the page size to something sensible if not given.
		if (pageSize == 0)
		{
			pageSize = DEFAULT_PAGE_SIZE;
		}

		// If max results is given, there's no point in having a page size
		// that's bigger!
		if (maxResults != 0)
		{
			pageSize = min(pageSize, maxResults);
		}
		dprintf("[EXTAPI ADSI] Page size will be %u", pageSize);

		while (met_api->packet.enum_tlv(packet, fieldCount, TLV_TYPE_EXT_ADSI_FIELD, &fieldTlv) == ERROR_SUCCESS)
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
			dprintf("[EXTAPI ADSI] Result of processing: %u (0x%x)", dwResult, dwResult);
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
		met_api->packet.transmit_response(dwResult, remote, response);
	}

	return dwResult;
}
