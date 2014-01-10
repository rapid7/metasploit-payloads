#ifndef _METERPRETER_SOURCE_EXTENSION_MIMIKATZ_MIMIKATZ_INTERFACE_H
#define _METERPRETER_SOURCE_EXTENSION_MIMIKATZ_MIMIKATZ_INTERFACE_H

typedef struct _Packet Packet;

DWORD mimikatz_initOrClean(BOOL Init);
DWORD mimikatz_scrape_passwords(DWORD cmdId, Packet* packet);
DWORD mimikatz_golden_ticket_create(char* user, char* domain, char* sid, char* ntlm, Packet* response);
DWORD mimikatz_golden_ticket_use(BYTE* buffer, DWORD bufferSize);

#endif