#ifndef _METERPRETER_SOURCE_EXTENSION_PRIV_PRIV_SERVER_ELEVATE_TECHNIQUES_NAMEDPIPE_H
#define _METERPRETER_SOURCE_EXTENSION_PRIV_PRIV_SERVER_ELEVATE_TECHNIQUES_NAMEDPIPE_H

typedef DWORD(*PostImpersonationCallback)(LPVOID);
DWORD THREADCALL elevate_namedpipe_thread(THREAD* thread);
DWORD elevate_via_service_namedpipe(Remote* remote, Packet* packet);
DWORD elevate_via_service_namedpipe2(Remote* remote, Packet* packet);
DWORD set_meterp_thread_use_current_token(Remote* remote);

typedef struct _PRIV_POST_IMPERSONATION {
	PostImpersonationCallback pCallback;
	PVOID                     pCallbackParam;
} PRIV_POST_IMPERSONATION, * PPRIV_POST_IMPERSONATION;

BOOL does_pipe_exist(LPWSTR pPipeName);

#endif
