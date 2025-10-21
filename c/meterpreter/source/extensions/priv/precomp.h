#ifndef METERPRETER_SOURCE_EXTENSION_PRIV_SERVER_PRECOMP_H
#define METERPRETER_SOURCE_EXTENSION_PRIV_SERVER_PRECOMP_H

#define  _WIN32_WINNT _WIN32_WINNT_WINXP
#include "priv.h"
#include "elevate.h"
#include "passwd.h"
#include "fs.h"

#include "../../ReflectiveDLLInjection/inject/src/GetProcAddressR.h"
#include "../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.h"

#define strcasecmp stricmp

// declared in ReflectiveLoader.c and set by DllMain also in ReflectiveLoader.c
extern HINSTANCE hAppInstance;

#endif
