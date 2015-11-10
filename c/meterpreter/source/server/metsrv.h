#ifndef _METERPRETER_SERVER_METSRV_H
#define _METERPRETER_SERVER_METSRV_H

/*
 * Version number
 *                               v------- major major
 *                                 v----- major minor
 *                                   v--- minor major
 *                                     v- minor minor
 */
#define METSRV_VERSION_NUMBER 0x00010001


#ifdef _WIN32

#define _WIN32_WINNT 0x0500

#define USE_DLL
#endif
#define METERPRETER_EXPORTS
#include "../common/common.h"
#include "config.h"

#include "remote_dispatch.h"
#include "libloader.h"

#ifdef _WIN32
#include "../ReflectiveDLLInjection/inject/src/GetProcAddressR.h"
#include "../ReflectiveDLLInjection/inject/src/LoadLibraryR.h"
#include "../ReflectiveDLLInjection/dll/src/ReflectiveLoader.h"
#endif

DWORD server_setup(MetsrvConfig* config);
typedef DWORD (*PSRVINIT)(Remote *remote);
typedef DWORD (*PSRVDEINIT)(Remote *remote);
typedef DWORD (*PSRVGETNAME)(char* buffer, int bufferSize);
typedef VOID (*PCMDADDED)(const char* commandName);
typedef DWORD (*PSTAGELESSINIT)(LPBYTE data, DWORD dataSize);

typedef struct _EXTENSION
{
	HMODULE library;
	PSRVINIT init;
	PSRVDEINIT deinit;
	PSRVGETNAME getname;
	PCMDADDED commandAdded;
	PSTAGELESSINIT stagelessInit;
	Command* start;
	Command* end;
	char name[16];
} EXTENSION, *PEXTENSION;

#endif
