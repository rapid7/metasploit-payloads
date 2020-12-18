/*!
 * @file common.h
 * @brief Declarations for various common components used across the Meterpreter suite.
 */
#ifndef _METERPRETER_SOURCE_COMMON_COMMON_H
#define _METERPRETER_SOURCE_COMMON_COMMON_H

/*! @brief Set to 0 for "normal", and 1 to "verbose", comment out to disable completely. */
//#define DEBUGTRACE 0

#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#define SAFE_FREE(x) if(x){free(x);x=NULL;}

#include <winsock2.h>
#include <windows.h>

// Simple trick to get the current meterpreters arch
#define PROCESS_ARCH_UNKNOWN				0
#define PROCESS_ARCH_X86					1
#define PROCESS_ARCH_X64					2
#define PROCESS_ARCH_IA64					3

#ifdef _WIN64
#define dwMeterpreterArch PROCESS_ARCH_X64
#else
#define dwMeterpreterArch PROCESS_ARCH_X86
#endif

#ifdef __MINGW32__
#define ERROR_DBG_TERMINATE_THREAD       691L
#define ERROR_UNHANDLED_EXCEPTION        574L
#define ERROR_UNSUPPORTED_COMPRESSION    618L
#define ERROR_NOT_CAPABLE                775L
#define ERROR_NOTHING_TO_TERMINATE       778L
#define __try
#define __except(x) if(0)

#undef GetExceptionCode
#define GetExceptionCode() 0

#undef GetExceptionInformation
#define GetExceptionInformation() NULL
#endif

typedef struct __UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} _UNICODE_STRING, * _PUNICODE_STRING;

typedef DWORD __u32;
typedef struct ___u128 {
	__u32 a1;
	__u32 a2;
	__u32 a3;
	__u32 a4;
}__u128;

/*
 * Avoid conflicts with Windows crypto API defines
 */
#undef OCSP_RESPONSE
#undef PKCS7_SIGNER_INFO
#undef X509_EXTENSIONS
#undef X509_CERT_PAIR
#undef X509_NAME

#ifdef DEBUGTRACE
#define dprintf(...) real_dprintf(__VA_ARGS__)
#if DEBUGTRACE == 1
#define vdprintf dprintf
#else
#define vdprintf(...) do{}while(0);
#endif
#else
#define dprintf(...) do{}while(0);
#define vdprintf(...) do{}while(0);
#endif

/*! @brief Sets `dwResult` to the return value of `GetLastError()`, prints debug output, then does `break;` */
#define BREAK_ON_ERROR( str ) { dwResult = GetLastError(); dprintf( "%s. error=%d (0x%x)", str, dwResult, (ULONG_PTR)dwResult ); break; }
/*! @brief Sets `dwResult` to `error`, prints debug output, then `break;` */
#define BREAK_WITH_ERROR( str, err ) { dwResult = err; dprintf( "%s. error=%d (0x%x)", str, dwResult, (ULONG_PTR)dwResult ); break; }
/*! @brief Sets `dwResult` to the return value of `WASGetLastError()`, prints debug output, then does `break;` */
#define BREAK_ON_WSAERROR( str ) { dwResult = WSAGetLastError(); dprintf( "%s. error=%d (0x%x)", str, dwResult, (ULONG_PTR)dwResult ); break; }
/*! @brief Sets `dwResult` to the return value of `GetLastError()`, prints debug output, then does `continue;` */
#define CONTINUE_ON_ERROR( str ) { dwResult = GetLastError(); dprintf( "%s. error=%d (0x%x)", str, dwResult, (ULONG_PTR)dwResult ); continue; }

/*! @brief Close a service handle if not already closed and set the handle to NULL. */
#define CLOSE_SERVICE_HANDLE( h )  if( h ) { CloseServiceHandle( h ); h = NULL; }
/*! @brief Close a handle if not already closed and set the handle to NULL. */
#define CLOSE_HANDLE( h )          if( h ) { DWORD dwHandleFlags; if(GetHandleInformation( h , &dwHandleFlags)) CloseHandle( h ); h = NULL; }

/*!
 * @brief Output a debug string to the debug console.
 * @details The function emits debug strings via `OutputDebugStringA`, hence all messages can be viewed
 *          using Visual Studio's _Output_ window, _DebugView_ from _SysInternals_, or _Windbg_.
 */
static _inline void real_dprintf(char *format, ...)
{
	va_list args;
	char buffer[1024];
	size_t len;
	_snprintf_s(buffer, sizeof(buffer), sizeof(buffer)-1, "[%04x] ", GetCurrentThreadId());
	len = strlen(buffer);
	va_start(args, format);
	vsnprintf_s(buffer + len, sizeof(buffer)-len, sizeof(buffer)-len - 3, format, args);
	strcat_s(buffer, sizeof(buffer), "\r\n");
	OutputDebugStringA(buffer);
	va_end(args);
}

#include "common_base.h"
#include "common_core.h"
#include "common_remote.h"
#include "common_channel.h"
#include "common_list.h"
#include "common_config.h"
#include "common_pivot_tree.h"
#include "common_thread.h"
#include "common_scheduler.h"
#include "common_command_ids.h"

#endif
