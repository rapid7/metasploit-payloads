#ifndef METERPRETER_SOURCE_EXTENSION_PRIV_SERVER_PRECOMP_H
#define METERPRETER_SOURCE_EXTENSION_PRIV_SERVER_PRECOMP_H

#define  _WIN32_WINNT 0x0400
#define JET_VERSION 0x0501 
#include <inttypes.h>
#include "../priv.h"
#include "./elevate/elevate.h"
#include "passwd.h"
#include "fs.h"
#include <WinCrypt.h>
#include "syskey.h"
#include "ntds_decrypt.h"
#include "ntds_jet.h"
#include "ntds.h"
#include "../../../common//arch/win/remote_thread.h"

#include "../../../DelayLoadMetSrv/DelayLoadMetSrv.h"
#include "../../../ReflectiveDLLInjection/inject/src/GetProcAddressR.h"
#include "../../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.h"
#pragma comment(lib, "Ws2_32.lib")
#define strcasecmp stricmp

// declared in ReflectiveLoader.c and set by DllMain also in ReflectiveLoader.c
extern HINSTANCE hAppInstance;

#endif
