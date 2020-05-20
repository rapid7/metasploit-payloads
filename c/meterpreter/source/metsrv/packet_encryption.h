#ifndef _METERPRETER_METSRV_PACKET_ENCRYPTION_H
#define _METERPRETER_METSRV_PACKET_ENCRYPTION_H

#include <windows.h>

#define AES256_BLOCKSIZE 16
#define ENC_FLAG_NONE   0x0
#define ENC_FLAG_AES256 0x1

typedef struct _Aes256Key
{
	BLOBHEADER header;
	DWORD length;
	BYTE key[256/8];
} Aes256Key;

typedef struct _PacketEncryptionContext
{
	HCRYPTPROV provider;
	HCRYPTKEY aes_key;
	int provider_idx;
	BOOL valid;
	Aes256Key key_data;
	BOOL enabled;
} PacketEncryptionContext;

typedef struct _Remote Remote;
typedef struct _Packet Packet;

DWORD decrypt_packet(Remote* remote, Packet** packet, LPBYTE buffer, DWORD bufferSize);
DWORD encrypt_packet(Remote* remote, Packet* packet, LPBYTE* buffer, LPDWORD bufferSize);
DWORD request_negotiate_aes_key(Remote* remote, Packet* packet);
DWORD free_encryption_context(Remote* remote);

#endif

