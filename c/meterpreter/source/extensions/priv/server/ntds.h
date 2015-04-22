#ifndef _METERPRETER_SOURCE_EXTENSION_PRIV_PRIV_SERVER_NTDS_H
#define _METERPRETER_SOURCE_EXTENSION_PRIV_PRIV_SERVER_NTDS_H

DWORD ntds_parse(Remote *remote, Packet *packet);
DWORD ntds_test_channel(Remote *remote, Packet *packet);
static DWORD ntds_channel_write(Channel *channel, Packet *request,
	LPVOID context, LPVOID buffer, DWORD bufferSize, LPDWORD bytesWritten);
static DWORD ntds_channel_read(Channel *channel, Packet *request,
	LPVOID context, LPVOID buffer, DWORD bufferSize, LPDWORD bytesRead);
static DWORD ntds_channel_close(Channel *channel, Packet *request,
	LPVOID context);
#endif