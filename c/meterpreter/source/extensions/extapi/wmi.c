/*!
 * @file wmi.c
 * @brief Definitions for WMI request handling functionality.
 */
#include "extapi.h"
#include "common_metapi.h"
#include "wshelpers.h"
#include "wmi.h"
#include "wmi_interface.h"

/*!
 * @brief Execute a WMI query.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the incoming \c Packet instance.
 * @returns Indication of success or failure.
 * @remark Real error codes are returned to the caller via a response packet.
 */
DWORD request_wmi_query(Remote *remote, Packet *packet)
{
	DWORD dwResult = ERROR_SUCCESS;
	LPSTR lpValue = NULL;
	LPWSTR lpwRoot = NULL;
	LPWSTR lpwQuery = NULL;
	Packet * response = met_api->packet.create_response(packet);

	do
	{
		if (!response)
		{
			BREAK_WITH_ERROR("[EXTAPI WMI] Unable to create response packet", ERROR_OUTOFMEMORY);
		}

		lpValue = met_api->packet.get_tlv_value_string(packet, TLV_TYPE_EXT_WMI_DOMAIN);

		if (!lpValue)
		{
			lpValue = "root\\CIMV2";
		}

		dprintf("[EXTAPI WMI] Domain: %s", lpValue);
		dwResult = to_wide_string(lpValue, &lpwRoot);
		if (dwResult != ERROR_SUCCESS)
		{
			dprintf("[EXTAPI WMI] Failed to get Domain");
			break;
		}

		lpValue = met_api->packet.get_tlv_value_string(packet, TLV_TYPE_EXT_WMI_QUERY);
		dprintf("[EXTAPI WMI] Query: %s", lpValue);
		dwResult = to_wide_string(lpValue, &lpwQuery);
		if (dwResult != ERROR_SUCCESS)
		{
			dprintf("[EXTAPI WMI] Failed to get Query");
			break;
		}

		dprintf("[EXTAPI WMI] Beginning WMI query enumeration");
		dwResult = wmi_query(lpwRoot, lpwQuery, response);
		dprintf("[EXTAPI WMI] Result of processing: %u (0x%x)", dwResult, dwResult);
	} while (0);

	if (lpwQuery)
	{
		free(lpwQuery);
	}

	if (lpwRoot)
	{
		free(lpwRoot);
	}

	dprintf("[EXTAPI WMI] Transmitting response back to caller.");
	if (response)
	{
		met_api->packet.transmit_response(dwResult, remote, response);
	}

	return dwResult;
}
