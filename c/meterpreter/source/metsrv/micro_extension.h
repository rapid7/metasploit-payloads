#ifndef _METERPRETER_METSRV_MICRO_EXTENSION_H
#define _METERPRETER_METSRV_MICRO_EXTENSION_H

#include "micro_coff.h"

#define MICRO_EXTENSION_ABI_VERSION 2
#define MICRO_EXTENSION_FLAG_INLINE_HANDLERS 1
#define MICRO_EXTENSION_MAX_COMMANDS 64
#define MICRO_EXTENSION_MAX_CHANNEL_PROVIDERS 16
#define MICRO_COMMAND_ID_RANGE 1000

typedef DWORD (*MicroChannelOpen)(Remote* remote, Packet* packet, Channel** channel);

typedef struct _MicroChannelProvider
{
	LPCSTR type;
	MicroChannelOpen open;
} MicroChannelProvider;

typedef struct _MicroExtension
{
	DWORD size;
	DWORD abi_version;
	LPCSTR name;
	DWORD command_count;
	Command* commands;
	DWORD flags;
	DWORD channel_provider_count;
	MicroChannelProvider* channel_providers;
} MicroExtension;

typedef const MicroExtension* (*MicroInit)(MetApi* api, Remote* remote);
typedef DWORD (*MicroDeinit)(Remote* remote);

VOID micro_extension_initialize(VOID);
VOID micro_extension_destroy(Remote* remote);
BOOL micro_extension_owns_command(UINT commandId);
Command* micro_extension_channel_command(Packet* packet);
BOOL micro_request_load(Remote* remote, Packet* packet, DWORD* result);
BOOL micro_request_enum(Remote* remote, Packet* packet, DWORD* result);
BOOL micro_request_unload(Remote* remote, Packet* packet, DWORD* result);
BOOL micro_request_has_command(Remote* remote, Packet* packet, DWORD* result);

#endif
