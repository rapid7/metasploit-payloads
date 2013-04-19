#ifndef _METERPRETER_SOURCE_EXTENSION_BOILER_BOILER_H
#define _METERPRETER_SOURCE_EXTENSION_BOILER_BOILER_H
#include "../../common/common.h"
#endif

/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by-nc-sa/3.0/fr/
*/
#include "modules/globdefs.h"
#include <io.h>
#include <fcntl.h>
#include "mimikatz.h"


#include "../../ReflectiveDLLInjection/DelayLoadMetSrv.h"
// include the Reflectiveloader() function, we end up linking back to the metsrv.dll's Init function
// but this doesnt matter as we wont ever call DLL_METASPLOIT_ATTACH as that is only used by the 
// second stage reflective dll inject payload and not the metsrv itself when it loads extensions.
#include "../../ReflectiveDLLInjection/ReflectiveLoader.c"

// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();

DWORD request_boiler(Remote *remote, Packet *packet)
{
	return 0;
}

Command customCommands[] =
{
	{ "boiler",
	  { request_boiler,                                    { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},

	// Terminator
	{ NULL,
	  { EMPTY_DISPATCH_HANDLER                      },
	  { EMPTY_DISPATCH_HANDLER                      },
	},
};

/*
 * Initialize the server extension
 */
DWORD __declspec(dllexport) InitServerExtension(Remote *remote)
{
	DWORD index;

	hMetSrv = remote->hMetSrv;

	for (index = 0;
	     customCommands[index].method;
	     index++)
		command_register(&customCommands[index]);

	return ERROR_SUCCESS;
}

/*
 * Deinitialize the server extension
 */
DWORD __declspec(dllexport) DeinitServerExtension(Remote *remote)
{
	DWORD index;

	for (index = 0;
	     customCommands[index].method;
	     index++)
		command_deregister(&customCommands[index]);

	return ERROR_SUCCESS;
}


//int wmain(int argc, wchar_t * argv[])
//{
//	setlocale(LC_ALL, "French_France.65001");
//	_setmode(_fileno(stdin), _O_U8TEXT/*_O_WTEXT/*_O_U16TEXT*/);
//	_setmode(_fileno(stdout), _O_U8TEXT/*_O_WTEXT/*_O_U16TEXT*/);
//	_setmode(_fileno(stderr), _O_U8TEXT/*_O_WTEXT/*_O_U16TEXT*/);
//	
//	/*SetConsoleCP(CP_UTF8);
//	SetConsoleOutputCP(CP_UTF8);*/
//	
//	vector<wstring> * mesArguments = new vector<wstring>(argv + 1, argv + argc);
//	
//	mimikatz * myMimiKatz = new mimikatz(mesArguments);
//	delete myMimiKatz, mesArguments;
//	return ERROR_SUCCESS;
//}
