#ifndef METERPRETER_SOURCE_EXTENSION_STDAPI_SERVER_PRECOMP_H
#define METERPRETER_SOURCE_EXTENSION_STDAPI_SERVER_PRECOMP_H

// sf: Compatability fix for a broken sdk? We get errors in Iphlpapi.h using the latest Windows SDK if we dont do this.
#undef  _WIN32_WINNT
#define  _WIN32_WINNT _WIN32_WINNT_WIN2K
#include "../stdapi.h"
#include <tlhelp32.h>
#include <iphlpapi.h>
#include "resource/resource.h"

#include "audio/audio.h"
#include "fs/fs.h"
#include "sys/sys.h"
#include "net/net.h"
#include "ui/ui.h"
#include "webcam/webcam.h"
#include "webcam/audio.h"

#include "railgun/railgun.h"	// PKS, win32 specific at the moment.

#include "../../../ReflectiveDLLInjection/inject/src/GetProcAddressR.h"
#include "../../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.h"
// declared in ReflectiveLoader.c and set by DllMain also in ReflectiveLoader.c
extern HINSTANCE hAppInstance;

#define strcasecmp _stricmp


#endif
