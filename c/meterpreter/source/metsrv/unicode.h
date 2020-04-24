/*!
 * @file common.h
 * @brief Declarations for unicode conversion functions
 */

#ifndef _METERPRETER_METSRV_COMMON_UNICODE_H
#define _METERPRETER_METSRV_COMMON_UNICODE_H

#include <wchar.h>

wchar_t *utf8_to_wchar(const char *in);

char *wchar_to_utf8(const wchar_t *in);

#endif
