/*!
 * @file server_http_utils.h
 * @remark HTTP utility function declarations.
 */
#ifndef _METERPRETER_METSRV_SERVER_HTTP_UTILS
#define _METERPRETER_METSRV_SERVER_HTTP_UTILS

#include "metsrv.h"

PWSTR generate_uri(HttpTransportContext* ctx, HttpConnection* conn);

#endif
