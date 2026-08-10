#ifndef _METERPRETER_METSRV_UTIL_B64_H
#define _METERPRETER_METSRV_UTIL_B64_H

#include "metsrv.h"

/*
 * Decode a base64 (RFC 4648) C string. On success returns a malloc'd buffer
 * of *out_len bytes; caller must free(). Returns NULL on invalid input or
 * allocation failure.
 */
BYTE* b64_decode(const char* input, size_t* out_len);

#endif
