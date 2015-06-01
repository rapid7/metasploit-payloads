/*!
 * @file mimikatz_interface.h
 * @brief Declaration of bridging functions which talk to Mimikatz 2.
 * @remark Also contains helpful forward declarations.
 */
#ifndef _METERPRETER_SOURCE_EXTENSION_MIMIKATZ_MIMIKATZ_INTERFACE_H
#define _METERPRETER_SOURCE_EXTENSION_MIMIKATZ_MIMIKATZ_INTERFACE_H

typedef struct _Packet Packet;

DWORD mimikatz_init_or_clean(BOOL bInit);
DWORD mimikatz_scrape_passwords(DWORD dwCmdId, Packet* pResponse);
DWORD mimikatz_kerberos_golden_ticket_create(char* lpUser, char* lpDomain, char* lpSid, char* lpTgt, DWORD dwId, DWORD* pdwGroupIds, DWORD dwGroupCount, Packet* pResponse);
DWORD mimikatz_kerberos_ticket_use(BYTE* pBuffer, DWORD dwBufferSize);
DWORD mimikatz_kerberos_ticket_purge();
DWORD mimikatz_kerberos_ticket_list(BOOL bExport, Packet* pResponse);
DWORD mimikatz_lsa_dump_secrets(Packet* pResponse);
DWORD mimikatz_wifi_profile_list(Packet* pResponse);

#endif