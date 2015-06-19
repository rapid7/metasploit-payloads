#ifndef _METERPRETER_SOURCE_EXTENSION_EXTAPI_PRIV_SERVER_NTDS_H
#define _METERPRETER_SOURCE_EXTENSION_EXTAPI_PRIV_SERVER_NTDS_H

DWORD ntds_parse(Remote *remote, Packet *packet);
static DWORD ntds_channel_read(Channel *channel, Packet *request,
	LPVOID context, LPVOID buffer, DWORD bufferSize, LPDWORD bytesRead);
static DWORD ntds_channel_close(Channel *channel, Packet *request,
	LPVOID context);

#define BLANK_LM_HASH "aad3b435b51404eeaad3b435b51404ee"
#define BLANK_NT_HASH "31d6cfe0d16ae931b73c59d7e0c089c0"
#endif
