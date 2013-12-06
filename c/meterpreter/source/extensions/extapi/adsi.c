/*!
 * @file adsi.c
 * @brief Definitions for ADSI functionality.
 */
#include "extapi.h"
#include "adsi.h"
#include "adsi_interface.h"

/*!
 * @brief Enumerate all the users in AD.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the incoming \c Packet instance.
 * @returns The ERROR_SUCCESS constant.
 * @remark Real error codes are returned to the caller via a response packet.
 */
DWORD request_adsi_user_enum(Remote *remote, Packet *packet)
{
	DWORD dwResult = ERROR_SUCCESS;
	LPSTR lpDomain = NULL;
	LPWSTR lpwDomain = NULL;
	size_t charsCopied = 0;
	size_t domainLength = 0;
	Packet * response = packet_create_response(packet);

	do
	{
		if (!response)
		{
			BREAK_WITH_ERROR("[EXTAPI ADSI] Unable to create response packet", ERROR_OUTOFMEMORY);
		}

		// Get the domain that we're doing the query against
		lpDomain = packet_get_tlv_value_string(packet, TLV_TYPE_EXT_ADSI_DOMAIN);

		if (lpDomain == NULL)
		{
			BREAK_WITH_ERROR("[EXTAPI ADSI] Domain parameter missing", ERROR_INVALID_PARAMETER);
		}

		dprintf("[EXTAPI ADSI] Request to enumerate users in domain %s", lpDomain);

		domainLength = lstrlenA(lpDomain);
		lpwDomain = (LPWSTR)malloc(sizeof(WCHAR)* (lstrlenA(lpDomain) + 1));
		if (lpwDomain == NULL)
		{
			BREAK_WITH_ERROR("[EXTAPI ADSI] Unable to allocate memory", ERROR_OUTOFMEMORY);
		}
		mbstowcs_s(&charsCopied, lpwDomain, domainLength + 1, lpDomain, domainLength);

		dprintf("[EXTAPI ADSI] Beginning user enumeration");
		dwResult = domain_user_enum(lpwDomain, response);
	} while (0);

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

/*!
 * @brief Enumerate all the computers in AD.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the incoming \c Packet instance.
 * @returns The ERROR_SUCCESS constant.
 * @remark Real error codes are returned to the caller via a response packet.
 */
DWORD request_adsi_computer_enum(Remote *remote, Packet *packet)
{
	DWORD dwResult = ERROR_SUCCESS;
	LPSTR lpDomain = NULL;
	LPWSTR lpwDomain = NULL;
	size_t charsCopied = 0;
	size_t domainLength = 0;
	Packet * response = packet_create_response(packet);

	do
	{
		if (!response)
		{
			BREAK_WITH_ERROR("[EXTAPI ADSI] Unable to create response packet", ERROR_OUTOFMEMORY);
		}

		// Get the domain that we're doing the query against
		lpDomain = packet_get_tlv_value_string(packet, TLV_TYPE_EXT_ADSI_DOMAIN);

		if (lpDomain == NULL)
		{
			BREAK_WITH_ERROR("[EXTAPI ADSI] Domain parameter missing", ERROR_INVALID_PARAMETER);
		}

		dprintf("[EXTAPI ADSI] Request to enumerate computers in domain %s", lpDomain);

		domainLength = lstrlenA(lpDomain);
		lpwDomain = (LPWSTR)malloc(sizeof(WCHAR)* (lstrlenA(lpDomain) + 1));
		if (lpwDomain == NULL)
		{
			BREAK_WITH_ERROR("[EXTAPI ADSI] Unable to allocate memory", ERROR_OUTOFMEMORY);
		}
		mbstowcs_s(&charsCopied, lpwDomain, domainLength + 1, lpDomain, domainLength);

		dprintf("[EXTAPI ADSI] Beginning computer enumeration");
		dwResult = domain_computer_enum(lpwDomain, response);
	} while (0);

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