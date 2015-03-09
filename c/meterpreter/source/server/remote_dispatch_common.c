#include "metsrv.h"

#ifdef _WIN32
// see ReflectiveLoader.c...
extern HINSTANCE hAppInstance;
#endif

PLIST gExtensionList = NULL;

// Dispatch table
Command customCommands[] = 
{
	COMMAND_REQ("core_loadlib", request_core_loadlib),
	COMMAND_REQ("core_listextensions", request_core_listextensions),
	COMMAND_TERMINATOR
};

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

		extension->deinit(remote);

		free(extension);
	}

	command_deregister_all(customCommands);

	list_destroy(gExtensionList);
}
