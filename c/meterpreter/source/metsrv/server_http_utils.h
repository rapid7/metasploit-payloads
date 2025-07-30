/*!
 * @file server_http_utils.h
 * @remark HTTP utility function declarations.
 */
#ifndef _METERPRETER_METSRV_SERVER_HTTP_UTILS
#define _METERPRETER_METSRV_SERVER_HTTP_UTILS

#include "metsrv.h"

BOOL decode_encoded_packet(HttpTransportContext* ctx, LPBYTE encodedData, DWORD encodedDataLen, LPBYTE* data, LPDWORD dataLen);
BOOL encode_raw_packet(HttpTransportContext* conn, LPBYTE data, DWORD dataLen, LPBYTE* encodedData, LPDWORD encodedDataLen);
PWSTR generate_headers(HttpTransportContext* ctx, HttpConnection* conn);
PWSTR generate_uri(HttpTransportContext* ctx, HttpConnection* conn);

#endif
