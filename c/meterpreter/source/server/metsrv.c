#include "metsrv.h"
#include "config.h"

#ifdef _WIN32

#include <windows.h> // for EXCEPTION_ACCESS_VIOLATION 
#include <excpt.h> 

#define	UnpackAndLinkLibs(p, s)

#endif

/*
 * Entry point for the DLL (or not if compiled as an EXE)
 */
#ifdef _WIN32
DWORD __declspec(dllexport) Init(LPVOID config)
{
	MetsrvConfig* metConfig = (MetsrvConfig*)config;
	DWORD result = server_setup(metConfig);

	dprintf("[METSRV] Exiting with %08x", metConfig->session.exit_func);

	switch(metConfig->session.exit_func)
	{
		case EXITFUNC_SEH:
			SetUnhandledExceptionFilter( NULL );
			break;
		case EXITFUNC_THREAD:
			ExitThread( 0 );
			break;
		case EXITFUNC_PROCESS:
			ExitProcess( 0 );
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
