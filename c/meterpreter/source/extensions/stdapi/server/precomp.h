#ifndef METERPRETER_SOURCE_EXTENSION_STDAPI_SERVER_PRECOMP_H
#define METERPRETER_SOURCE_EXTENSION_STDAPI_SERVER_PRECOMP_H

// sf: Compatability fix for a broken sdk? We get errors in Iphlpapi.h using the latest Windows SDK if we dont do this.
#undef  _WIN32_WINNT
#define  _WIN32_WINNT _WIN32_WINNT_WINXP
#include <winsock2.h>
#include <windows.h>
#include <winhttp.h>
#include "../stdapi.h"
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <stdint.h>
#include "resource/resource.h"

#ifdef STDAPI_NAMESPACE_AUDIO
#include "audio/audio.h"
#endif

#ifdef STDAPI_NAMESPACE_FS
#include "fs/fs.h"
#endif

#ifdef STDAPI_NAMESPACE_SYS
#include "sys/sys.h"
#endif

#ifdef STDAPI_NAMESPACE_NET
#include "net/net.h"
#endif

#ifdef STDAPI_NAMESPACE_UI
#include "ui/ui.h"
#endif

#ifdef STDAPI_NAMESPACE_WEBCAM
#include "webcam/webcam.h"
#include "webcam/audio.h"
#endif

#ifdef STDAPI_NAMESPACE_RAILGUN
#include "railgun/railgun.h"	// PKS, win32 specific at the moment.
#endif

#include "../../../ReflectiveDLLInjection/inject/src/GetProcAddressR.h"
#include "../../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.h"
// declared in ReflectiveLoader.c and set by DllMain also in ReflectiveLoader.c
extern HINSTANCE hAppInstance;

#define strcasecmp _stricmp


#endif
