#ifndef _METERPRETER_SOURCE_EXTENSION_MIMIKATZ_MIMIKATZ_INTERFACE_H
#define _METERPRETER_SOURCE_EXTENSION_MIMIKATZ_MIMIKATZ_INTERFACE_H

typedef struct _Packet Packet;

DWORD mimikatz_initOrClean(BOOL Init);
DWORD mimikatz_scrape_passwords(DWORD cmdId, Packet* packet);
DWORD mimikatz_kerberos_golden_ticket_create(LPSTR user, LPSTR domain, LPSTR sid, LPSTR ntlm, Packet* response);
DWORD mimikatz_kerberos_ticket_use(BYTE* buffer, DWORD bufferSize);
DWORD mimikatz_kerberos_ticket_purge();
DWORD mimikatz_kerberos_ticket_list(BOOL bExport, Packet* response);
DWORD mimikatz_lsa_dump_secrets(Packet* response);

#endif