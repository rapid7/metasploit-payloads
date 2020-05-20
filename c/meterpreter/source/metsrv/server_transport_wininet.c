/*!
 * @file server_transport_wininet.c
 */
#include "metsrv.h"
#include <wininet.h>

/*!
 * @brief Prepare a wininet request with the given context.
 * @param ctx Pointer to the HTTP transport context to prepare the request from.
 * @param isGet Indication of whether this request is a GET request, otherwise POST is used.
 * @param direction String representing the direction of the communications (for debug).
 * @return An Internet request handle.
 */
static HINTERNET get_request_wininet(HttpTransportContext *ctx, BOOL isGet, const char *direction)
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
		hReq = HttpOpenRequestW(ctx->connection, isGet ? L"GET" : L"POST", ctx->uri, NULL, NULL, NULL, flags, 0);

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
 * @brief Wrapper around WinINET-specific request handle closing functionality.
 * @param hReq HTTP request handle.
 * @return An indication of the result of sending the request.
 */
static BOOL close_request_wininet(HANDLE hReq)
{
	return InternetCloseHandle(hReq);
}

/*!
 * @brief Wrapper around WinINET-specific response data reading functionality.
 * @param hReq HTTP request handle.
 * @param buffer Pointer to the data buffer.
 * @param bytesToRead The number of bytes to read.
 * @param bytesRead The number of bytes actually read.
 * @return An indication of the result of sending the request.
 */
static BOOL read_response_wininet(HANDLE hReq, LPVOID buffer, DWORD bytesToRead, LPDWORD bytesRead)
{
	return InternetReadFile(hReq, buffer, bytesToRead, bytesRead);
}

/*!
 * @brief Wrapper around WinINET-specific sending functionality.
 * @param ctx Pointer to the current HTTP transport context.
 * @param hReq HTTP request handle.
 * @param buffer Pointer to the buffer to receive the data.
 * @param size Buffer size.
 * @return An indication of the result of sending the request.
 */
static BOOL send_request_wininet(HttpTransportContext* ctx, HANDLE hReq, LPVOID buffer, DWORD size)
{
	if (ctx->custom_headers)
	{
		dprintf("[WINHTTP] Sending with custom headers: %S", ctx->custom_headers);
		return HttpSendRequestW(hReq, ctx->custom_headers, -1L, buffer, size);
	}

	return HttpSendRequestW(hReq, NULL, 0, buffer, size);
}

/*!
 * @brief Wrapper around WinINET-specific request response validation.
 * @param hReq HTTP request handle.
 * @param ctx The HTTP transport context.
 * @return An indication of the result of getting a response.
 */
static DWORD validate_response_wininet(HANDLE hReq, HttpTransportContext* ctx)
{
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
			return ERROR_BAD_CONFIGURATION;
		}
	}

	return ERROR_SUCCESS;
}

/*!
 * @brief Initialise the HTTP(S) connection.
 * @param transport Pointer to the transport instance.
 * @return Indication of success or failure.
 */
static DWORD server_init_wininet(Transport* transport)
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
		return GetLastError();
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
		return GetLastError();
	}

	if (ctx->proxy)
	{
		if (ctx->proxy_user)
		{
			InternetSetOptionW(ctx->connection, INTERNET_OPTION_PROXY_USERNAME, ctx->proxy_user,  (DWORD)wcslen(ctx->proxy_user));
		}
		if (ctx->proxy_pass)
		{
			InternetSetOptionW(ctx->connection, INTERNET_OPTION_PROXY_PASSWORD, ctx->proxy_pass, (DWORD)wcslen(ctx->proxy_pass));
		}
	}

	dprintf("[DISPATCH] Configured hConnection: 0x%.8x", ctx->connection);

	return ERROR_SUCCESS;
}

/*!
 * @brief Take over control from the WinINET transport.
 * @param transport Pointer to the transport to hijack.
 */
void transport_move_to_wininet(Transport* transport)
{
	HttpTransportContext* ctx = (HttpTransportContext*)transport->ctx;

	ctx->create_req = get_request_wininet;
	ctx->send_req = send_request_wininet;
	ctx->close_req = close_request_wininet;
	ctx->validate_response = validate_response_wininet;
	ctx->receive_response = NULL;
	ctx->read_response = read_response_wininet;

	transport->transport_init = server_init_wininet;
}
