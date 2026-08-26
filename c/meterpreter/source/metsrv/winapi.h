#ifndef _METERPRETER_WINAPI_H
#define _METERPRETER_WINAPI_H

#ifndef _METERPRETER_COMMON_WINAPI_H
#include <stdarg.h>
#include <winsock2.h> // For SOCKET, WSADATA, sockaddr, WSAPROTOCOL_INFOA
#include <ws2tcpip.h> // For ADDRINFOA / PADDRINFOA
#include <windows.h>
#if !defined(__WINE_WINHTTP_H) && !defined(_WINHTTPX_)
#include <wininet.h>
#endif
#if !defined(_WININET_)
#include <winhttp.h>  // For WINHTTP_*, URL_COMPONENTS
#endif
#include <tlhelp32.h>
#include <tlhelp32.h>  // For CreateToolhelp32Snapshot, THREADENTRY32
#include <wincrypt.h> // For HCRYPTPROV, HCRYPTKEY, PTOKEN_PRIVILEGES, etc.
#include <rpcdce.h>   // For UUID generation.
#include <accctrl.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <lm.h>
#include <mmsystem.h>
#include <objbase.h>
#include <oleauto.h>
#include <psapi.h>
#include <shlwapi.h>
#include <winnetwk.h>
typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PVOID ObjectName;  // PUNICODE_STRING
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
#ifdef _WININET_
typedef VOID WINHTTP_CURRENT_USER_IE_PROXY_CONFIG;
typedef VOID WINHTTP_AUTOPROXY_OPTIONS;
typedef VOID WINHTTP_PROXY_INFO;
#endif
#endif

// Hash-based function resolver: parses the module's export directory and
// returns the address of the export whose _hash(name) matches. Used by both
// the winapi_* wrappers and any call site that needs a raw function pointer
// without adding a static string to the binary (e.g. libloader splice-hooks).
FARPROC WINAPI GetProcAddressH(HANDLE hModule, DWORD dwFunctionHash);

// A zero-initialized cache for one export from a system DLL. The first lookup
// pins the module and any forwarded-export modules, then publishes success or
// failure permanently; contending callers resolve without waiting.
// GetFunctionHCached preserves the calling thread's last-error value. Optional
// system exports are supported because their availability cannot change while
// the retained module is loaded. Do not reuse one cache for more than one
// module/hash pair or for a module that is expected to appear later at runtime.
typedef struct _WinApiFunctionCache {
    volatile LONG state;
    FARPROC volatile function;
} WinApiFunctionCache;

#define WINAPI_FUNCTION_CACHE_INIT { 0, NULL }

FARPROC GetFunctionHCached(WinApiFunctionCache* cache, LPCSTR moduleName, DWORD functionHash);

// Compile-time hashes of the exports the wrappers below resolve. Exposed
// here so other TUs can pass them to GetProcAddressH without repeating the
// literal function-name strings.
enum HashedFunctions {
    H_ZwAllocateVirtualMemory = 0xD33D4AED,
    H_ZwOpenProcess = 0xF0D09D60,
    H_ZwWriteVirtualMemory = 0xC5D0A4C2,
    H_ZwReadVirtualMemory = 0x3DEFA5C2,
    H_ZwProtectVirtualMemory = 0xBC3F4D89,
    H_ZwQueryVirtualMemory = 0x4FD39C92,
    H_ZwFreeVirtualMemory = 0xDE63B5C3,
    H_ZwQueueApcThread = 0xD2E9B347,
    H_ZwOpenThread = 0x197D1E8D,
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
    H_ZwQueryInformationProcess = 0xB16FE439,
    H_ZwQueryObject = 0xFEF3F5D0,
    H_ZwQueryInformationWorkerFactory = 0xBBC3527A,
    H_ZwSetInformationWorkerFactory = 0xEC4E91FC,
    H_ZwSetIoCompletion = 0x2FADE3F0,
    H_RtlCreateUserThread = 0x442F2041,
    H_ZwMapViewOfSection = 0xD5189BF4,
    H_ZwCreateSection = 0x5D32CBCB,
    H_ZwOpenSection = 0x92BBDE55,
    H_ZwOpenFile = 0x8829D4B8,
    H_ZwQueryAttributesFile = 0x94A7E91,
    H_ZwClose = 0x5D044C61,
    H_ZwLockVirtualMemory = 0x8169ADC3,
    H_GetModuleHandleA = 0xD3324904,
    H_CreateFileW = 0x7C0017BB,
    H_CreateNamedPipeW = 0xB2D685C,
    H_CreateEventA = 0x30C4B281,
    H_CreateEventW = 0x30C4B297,
    H_SetEvent = 0xF108744E,
    H_WaitForSingleObject = 0xCE05D9AD,
    H_Sleep = 0xDB2D49B0,
    H_GetProcessHeap = 0xA80EECAE,
    H_HeapAlloc = 0x2500383C,
    H_HeapFree = 0x10C32616,
    H_IsWow64Process = 0xE610CFB8,
    H_ProcessIdToSessionId = 0xAC4BA4E8,
    H_GetCurrentThreadId = 0x35BBF99E,
    H_CryptAcquireContextA = 0x43C28BDA,
    H_CryptAcquireContextW = 0x43C28BF0,
    H_AddMandatoryAce = 0x4D8DB756,
    H_send = 0xE97019A4,
    H_bind = 0xC7701AA4,
    H_listen = 0xE92EADA4,
    H_closesocket = 0x79C679E7,
    H_select = 0x5B1E69EE,
    H_gethostbyname = 0x510CFDC4,
    H_getaddrinfo = 0xACA705C,
    H_freeaddrinfo = 0xBC96705E,
    H_htons = 0xEB769C33,
    H_htonl = 0xEB769C2C,
    H_ntohl = 0xEB46FC2C,
    H_inet_addr = 0x2FBA176D,
    H_WinHttpCloseHandle = 0xB47C201,
    H_WinHttpWriteData = 0xFC379FC3,
    H_HeapReAlloc = 0xBDC761A8,
    H_LocalAlloc = 0x4C0297FA,
    H_GetSystemTime = 0xA70B95C5,
    H_SystemTimeToFileTime = 0x45A577EA,
    H_MultiByteToWideChar = 0xEF4AC4E4,
    H_WideCharToMultiByte = 0xC1634AF9,
    H_PeekNamedPipe = 0xB407C411,
    H_SetNamedPipeHandleState = 0xE97BC532,
    H_ReleaseMutex = 0x14A059E5,
    H_CreateMutexA = 0x4EE4A045,
    H_CreateMutexW = 0x4EE4A05B,
    H_TerminateThread = 0xBD016F89,
    H_lstrcmpW = 0xCB534951,
    H_GetProcessWindowStation = 0x13374FFD,
    H_WSAGetLastError = 0x9F5B7976,
    H_inet_ntoa = 0x4A121B5C,
    H_HttpQueryInfoA = 0xFB2F45FA,
    H_CryptBinaryToStringA = 0x7CC2AAAF,
    H_CryptStringToBinaryA = 0xF29E1FE8,
    H_GetLastError = 0x75DA1966,
    H_CryptCreateHash = 0x4105A130,
    H_CryptDestroyHash = 0x25D4AE7A,
    H_CryptGetHashParam = 0xC7AFB4A9,
    H_CryptHashData = 0xC2122629,
    H_CopyFileW = 0x99EC8974,
    H_CreateDirectoryW = 0x9FCF597B,
    H_DeleteFileA = 0xC2FFB025,
    H_DeleteFileW = 0xC2FFB03B,
    H_DisconnectNamedPipe = 0xDC7CCD45,
    H_ExpandEnvironmentStringsA = 0xEEB585D8,
    H_ExpandEnvironmentStringsW = 0xEEB585EE,
    H_FileTimeToSystemTime = 0x3810CB0F,
    H_FindClose = 0x23545978,
    H_FindFirstFileW = 0x63D6C07B,
    H_FindNextFileW = 0xA5E1ACAD,
    H_FindResourceA = 0x3BD09A55,
    H_GetCurrentDirectoryW = 0xBFC6EB65,
    H_GetCurrentProcessId = 0xE60DFA02,
    H_GetDateFormatW = 0xF72A53D0,
    H_GetDiskFreeSpaceExA = 0xCB2210,
    H_GetDriveTypeA = 0xE9D18E21,
    H_GetDriveTypeW = 0xE9D18E37,
    H_GetExitCodeThread = 0x1B3F95F9,
    H_GetFileAttributesA = 0x56F7390A,
    H_GetFileAttributesExW = 0xC18E43EC,
    H_GetFileAttributesW = 0x56F73920,
    H_GetHandleInformation = 0x7F9DF944,
    H_GetLogicalDriveStringsA = 0x79B4095D,
    H_GetLogicalDrives = 0x14C22B19,
    H_GetProcAddress = 0x7C0DFCAA,
    H_GetSystemDefaultLCID = 0x7695E96B,
    H_GetTickCount = 0xF791FB23,
    H_GetTimeFormatW = 0xF02A93D4,
    H_GetVersionExA = 0xC75FC483,
    H_LoadResource = 0x934E1F7B,
    H_LockResource = 0x9A4E2F7B,
    H_OutputDebugStringW = 0x470D22D2,
    H_MoveFileW = 0xA404896A,
    H_RemoveDirectoryW = 0x83D3265D,
    H_SetCurrentDirectoryW = 0xBFC70365,
    H_SetFileAttributesW = 0x56F73980,
    H_SetLastError = 0x75F21966,
    H_SizeofResource = 0x3F2A9609,
    H_lstrcmpiW = 0x4B1E5AF1,
    H_lstrcpyW = 0xCB9B4A11,
    H_lstrlenA = 0xDD43473B,
    H_lstrlenW = 0xDD434751,
    H_RevertToSelf = 0x50DEC82A,
    H_CloseDesktop = 0xCE18D25E,
    H_CloseWindowStation = 0xEF8D2D7A,
    H_CreateWindowExA = 0x84454941,
    H_DefWindowProcA = 0xB9A87723,
    H_DestroyWindow = 0x94305BE0,
    H_DispatchMessageA = 0x690A1701,
    H_EnumChildWindows = 0x94260FDB,
    H_EnumDesktopsA = 0xE84AD584,
    H_EnumWindowStationsA = 0xDD24D8F5,
    H_ExitWindowsEx = 0x89DABEF5,
    H_GetAsyncKeyState = 0x2B245A7A,
    H_GetForegroundWindow = 0x6215F501,
    H_GetKeyboardState = 0xB73BFDCF,
    H_GetKeyNameTextW = 0x10745604,
    H_GetKeyState = 0xA13C7A54,
    H_GetMessageA = 0x7AC67BED,
    H_GetSystemMetrics = 0xA84AA1DC,
    H_GetWindowThreadProcessId = 0xA3E2C997,
    H_MapVirtualKeyA = 0x35063658,
    H_OpenDesktopA = 0xDBBBFCD7,
    H_OpenWindowStationA = 0x9B189FC0,
    H_RegisterClassExA = 0x51E20CCA,
    H_SendInput = 0x3464B947,
    H_SendMessageA = 0xEB6CC3F4,
    H_SetProcessWindowStation = 0x1337502D,
    H_SetThreadDesktop = 0xD6641B8A,
    H_SwitchDesktop = 0xFE80FFED,
    H_ToUnicodeEx = 0xA0D68FBF,
    H_TranslateMessage = 0x8FDE2C7E,
    H_UnregisterClassA = 0xD53A4038,
    H_wvsprintfW = 0x56FA73F1,
    H_getsockname = 0x952DFF51,
    H_ntohs = 0xEB46FC33,
    H_recvfrom = 0x51138B5F,
    H_sendto = 0x5FA669A9,
    H_shutdown = 0x4D5F6AC9,
    H_WSAAddressToStringA = 0x535B7BB9,
    H_WSACleanup = 0x19BD2C47,
    H_WSACreateEvent = 0xC24A0B48,
    H_WSAEventSelect = 0x2DF42CE0,
    H_WSASetLastError = 0x9F737976,
    H_WSASocketA = 0xADF509D9,
    H_CreateIpForwardEntry = 0xDA4F2E1E,
    H_DeleteIpForwardEntry = 0xD7133056,
    H_GetIfEntry = 0x45BAB42D,
    H_GetIpAddrTable = 0x6C60EC01,
    H_GetIpForwardTable = 0xC385CC60,
    H_GetIpInterfaceEntry = 0x5EC1D3F7,
    H_GetIpNetTable = 0x37C5AF6D,
    H_GetTcpTable = 0xFAF48BAF,
    H_GetUdpTable = 0xFAF88BCF,
    H_WNetGetUniversalNameA = 0xD8FA8C8,
    H_CoCreateInstance = 0x6E26C880,
    H_CoInitialize = 0x8C2E8016,
    H_CoUninitialize = 0x6DD38706,
    H_VariantClear = 0x8673E625,
    H_VariantInit = 0x88D67161,
    H_sndPlaySoundA = 0xDBE99F54,
    H_waveInAddBuffer = 0x830ECA06,
    H_waveInOpen = 0x83C6C353,
    H_waveInPrepareHeader = 0x5DE12405,
    H_waveInStart = 0x22BC5DAA,
    H_waveInStop = 0x8C16C455,
    H_FormatMessageA = 0x1EAA62E7,
    H_CreatePipe = 0x170C8F80,
    H_CreateProcessW = 0x16B3FE88,
    H_GetComputerNameA = 0x96A4228F,
    H_GetCurrentProcess = 0x7B8F17E6,
    H_GetCurrentThread = 0xE8CDCFE4,
    H_GetEnvironmentVariableW = 0xF2E1A979,
    H_GetLocalTime = 0xB98C88CF,
    H_GetLocaleInfoA = 0xE8983477,
    H_GetThreadContext = 0x68A7C7D2,
    H_GetTimeZoneInformation = 0x51268313,
    H_SetThreadContext = 0xE8A7C7D3,
    H_TerminateProcess = 0x78B5B983,
    H_VirtualLock = 0xEF632F2,
    H_VirtualUnlock = 0x52A4ADF3,
    H_WaitForSingleObjectEx = 0x839E6BEB,
    H_ClearEventLogA = 0x442101D1,
    H_CloseEventLog = 0x93329886,
    H_ConvertSidToStringSidA = 0xA20AE292,
    H_CreateProcessAsUserW = 0x635DC4A1,
    H_DuplicateTokenEx = 0x3A55BBB2,
    H_GetNumberOfEventLogRecords = 0xFD988251,
    H_GetOldestEventLogRecord = 0x761A13FB,
    H_GetTokenInformation = 0xDBDB6E5A,
    H_LookupAccountSidW = 0x64AC441D,
    H_LookupPrivilegeValueA = 0x97E8C2A2,
    H_OpenEventLogA = 0x22B6E002,
    H_ReadEventLogA = 0x22A09031,
    H_RegCloseKey = 0x35E273E6,
    H_RegConnectRegistryW = 0x2C21BFD6,
    H_RegCreateKeyExW = 0x8B64E6CA,
    H_RegDeleteKeyW = 0xC12E9C8B,
    H_RegDeleteValueW = 0xB4CEEACC,
    H_RegEnumKeyW = 0x28A1A87,
    H_RegEnumValueW = 0xBAE699D,
    H_RegLoadKeyW = 0x28D8B5D,
    H_RegOpenKeyExW = 0xA84AEB97,
    H_RegQueryInfoKeyA = 0xC8F63C08,
    H_RegQueryInfoKeyW = 0xC8F63C1E,
    H_RegQueryValueExW = 0xFCBA95C1,
    H_RegSetValueExW = 0x2D1C9AF3,
    H_RegUnLoadKeyW = 0x4A571082,
    H_NetApiBufferFree = 0xC0AAF20C,
    H_NetWkstaGetInfo = 0x7D863F9D,
    H_EnumDeviceDrivers = 0xCB3AD6F8,
    H_GetDeviceDriverBaseNameW = 0x9E77D81,
    H_GetDeviceDriverFileNameW = 0xDCB7E81,
    H_SHDeleteKeyW = 0x10A9764,
};

NTSTATUS winapi_ntdll_ZwAllocateVirtualMemory(HANDLE hProcess, PVOID* pBaseAddress, ULONG_PTR pZeroBits, PSIZE_T pRegionSize, ULONG ulAllocationType, ULONG ulProtect);
NTSTATUS winapi_ntdll_ZwOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
NTSTATUS winapi_ntdll_ZwWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten); 
NTSTATUS winapi_ntdll_ZwReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesRead);
NTSTATUS winapi_ntdll_ZwProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
NTSTATUS winapi_ntdll_ZwQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
NTSTATUS winapi_ntdll_ZwFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
NTSTATUS winapi_ntdll_ZwQueueApcThread(HANDLE ThreadHandle, PVOID ApcRoutine, PVOID ApcContext, PVOID Argument1, PVOID Argument2); 
NTSTATUS winapi_ntdll_ZwOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
NTSTATUS winapi_ntdll_RtlGetVersion(PRTL_OSVERSIONINFOEXW os);
NTSTATUS winapi_ntdll_ZwQueryInformationProcess(HANDLE ProcessHandle, INT ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
NTSTATUS winapi_ntdll_ZwQueryObject(HANDLE Handle, INT ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);
NTSTATUS winapi_ntdll_ZwQueryInformationWorkerFactory(HANDLE WorkerFactoryHandle, INT WorkerFactoryInformationClass, PVOID WorkerFactoryInformation, ULONG WorkerFactoryInformationLength, PULONG ReturnLength);
NTSTATUS winapi_ntdll_ZwSetInformationWorkerFactory(HANDLE WorkerFactoryHandle, INT WorkerFactoryInformationClass, PVOID WorkerFactoryInformation, ULONG WorkerFactoryInformationLength);
NTSTATUS winapi_ntdll_ZwSetIoCompletion(HANDLE IoCompletionHandle, PVOID KeyContext, PVOID ApcContext, NTSTATUS IoStatus, ULONG_PTR IoStatusInformation);
NTSTATUS winapi_ntdll_RtlCreateUserThread(HANDLE ProcessHandle, PVOID SecurityDescriptor, BOOL CreateSuspended, ULONG StackZeroBits, SIZE_T StackReserve, SIZE_T StackCommit, PVOID StartAddress, PVOID StartParameter, PHANDLE ThreadHandle, PVOID ClientId);
NTSTATUS winapi_ntdll_ZwMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG ZeroBits, ULONG CommitSize, PLARGE_INTEGER SectionOffset, PULONG ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
NTSTATUS winapi_ntdll_ZwCreateSection(PHANDLE SectionHandle, ULONG DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);
NTSTATUS winapi_ntdll_ZwOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
NTSTATUS winapi_ntdll_ZwOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PVOID IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);
NTSTATUS winapi_ntdll_ZwQueryAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes, PVOID FileInformation);
NTSTATUS winapi_ntdll_ZwClose(HANDLE Handle);
NTSTATUS winapi_ntdll_ZwLockVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG RegionSize, ULONG MapType);
BOOL winapi_kernel32_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
BOOL winapi_kernel32_ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);
HANDLE winapi_kernel32_OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
LPVOID winapi_kernel32_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
LPVOID winapi_kernel32_VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
BOOL winapi_kernel32_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
BOOL winapi_kernel32_VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
SIZE_T winapi_kernel32_VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
SIZE_T winapi_kernel32_VirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
BOOL winapi_kernel32_VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
BOOL winapi_kernel32_VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
HANDLE winapi_kernel32_CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
BOOL winapi_kernel32_CloseHandle(HANDLE hObject);
BOOL winapi_kernel32_DuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions);
HANDLE winapi_kernel32_CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
BOOL winapi_kernel32_Thread32First(HANDLE hSnapshot, LPTHREADENTRY32 lpte);
HANDLE winapi_kernel32_OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);
DWORD winapi_kernel32_SuspendThread(HANDLE hThread);
BOOL winapi_kernel32_Thread32Next(HANDLE hSnapshot, LPTHREADENTRY32 lpte);
DWORD winapi_kernel32_ResumeThread(HANDLE hThread);
BOOL winapi_kernel32_FreeLibrary(HMODULE hLibModule);
BOOL winapi_kernel32_FlushInstructionCache(HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T dwSize);
HLOCAL winapi_kernel32_LocalFree(HLOCAL hMem);
HANDLE winapi_kernel32_CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
BOOL winapi_kernel32_WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
HMODULE winapi_kernel32_LoadLibraryA(LPCSTR lpLibFileName);
DWORD winapi_kernel32_WaitForMultipleObjects(DWORD nCount, const HANDLE* lpHandles, BOOL bWaitAll, DWORD dwMilliseconds);
BOOL winapi_kernel32_SetHandleInformation(HANDLE hObject, DWORD dwMask, DWORD dwFlags);
HGLOBAL winapi_kernel32_GlobalFree(HGLOBAL hMem);
HANDLE winapi_kernel32_CreateNamedPipeA(LPCSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
BOOL winapi_kernel32_ConnectNamedPipe(HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped);
BOOL winapi_kernel32_GetOverlappedResult(HANDLE hFile, LPOVERLAPPED lpOverlapped, LPDWORD lpNumberOfBytesTransferred, BOOL bWait);
BOOL winapi_kernel32_ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
HANDLE winapi_kernel32_CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
BOOL winapi_kernel32_ResetEvent(HANDLE hEvent);
BOOL winapi_kernel32_SetThreadErrorMode(DWORD dwNewMode, LPDWORD lpOldMode);
HMODULE winapi_kernel32_GetModuleHandleA(LPCSTR lpModuleName);
HANDLE winapi_kernel32_CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
HANDLE winapi_kernel32_CreateNamedPipeW(LPCWSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
HANDLE winapi_kernel32_CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName);
HANDLE winapi_kernel32_CreateEventW(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCWSTR lpName);
BOOL winapi_kernel32_SetEvent(HANDLE hEvent);
DWORD winapi_kernel32_WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
VOID winapi_kernel32_Sleep(DWORD dwMilliseconds);
HANDLE winapi_kernel32_GetProcessHeap(VOID);
LPVOID winapi_kernel32_HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
BOOL winapi_kernel32_HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
BOOL winapi_kernel32_IsWow64Process(HANDLE hProcess, PBOOL Wow64Process);
BOOL winapi_kernel32_ProcessIdToSessionId(DWORD dwProcessId, DWORD* pSessionId);
DWORD winapi_kernel32_GetCurrentThreadId(VOID);
BOOL winapi_advapi32_OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
BOOL winapi_advapi32_AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);
BOOL winapi_advapi32_ImpersonateLoggedOnUser(HANDLE hToken);
BOOL winapi_advapi32_CryptDuplicateKey(HCRYPTKEY hKey, DWORD* pdwReserved, DWORD dwFlags, HCRYPTKEY* phKey);
BOOL winapi_advapi32_CryptSetKeyParam(HCRYPTKEY hKey, DWORD dwParam, const BYTE* pbData, DWORD dwFlags);
BOOL winapi_advapi32_CryptDecrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen);
BOOL winapi_advapi32_CryptGenRandom(HCRYPTPROV hProv, DWORD dwLen, BYTE* pbBuffer);
BOOL winapi_advapi32_CryptEncrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen, DWORD dwBufLen);
BOOL winapi_advapi32_CryptDestroyKey(HCRYPTKEY hKey);
BOOL winapi_advapi32_CryptReleaseContext(HCRYPTPROV hProv, DWORD dwFlags);
BOOL winapi_advapi32_CryptImportKey(HCRYPTPROV hProv, const BYTE* pbData, DWORD dwDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY* phKey);
BOOL winapi_advapi32_OpenThreadToken(HANDLE ThreadHandle, DWORD DesiredAccess, BOOL OpenAsSelf, PHANDLE TokenHandle);
BOOL winapi_advapi32_AllocateAndInitializeSid(PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority, BYTE nSubAuthorityCount, DWORD dwSubAuthority0, DWORD dwSubAuthority1, DWORD dwSubAuthority2, DWORD dwSubAuthority3, DWORD dwSubAuthority4, DWORD dwSubAuthority5, DWORD dwSubAuthority6, DWORD dwSubAuthority7, PSID* pSid);
DWORD winapi_advapi32_SetEntriesInAclW(ULONG cCountOfExplicitEntries, PEXPLICIT_ACCESS_W pListOfExplicitEntries, PACL OldAcl, PACL* NewAcl);
BOOL winapi_advapi32_InitializeAcl(PACL pAcl, DWORD nAclLength, DWORD dwAclRevision);
BOOL winapi_advapi32_InitializeSecurityDescriptor(PSECURITY_DESCRIPTOR pSecurityDescriptor, DWORD dwRevision);
BOOL winapi_advapi32_SetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR pSecurityDescriptor, BOOL bDaclPresent, PACL pDacl, BOOL bDaclDefaulted);
BOOL winapi_advapi32_SetSecurityDescriptorSacl(PSECURITY_DESCRIPTOR pSecurityDescriptor, BOOL bSaclPresent, PACL pSacl, BOOL bSaclDefaulted);
BOOL winapi_advapi32_LookupPrivilegeValueW(LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid);
BOOL winapi_advapi32_CryptAcquireContextA(HCRYPTPROV* phProv, LPCSTR szContainer, LPCSTR szProvider, DWORD dwProvType, DWORD dwFlags);
BOOL winapi_advapi32_CryptAcquireContextW(HCRYPTPROV* phProv, LPCWSTR szContainer, LPCWSTR szProvider, DWORD dwProvType, DWORD dwFlags);
BOOL winapi_advapi32_AddMandatoryAce(PACL pAcl, DWORD dwAceRevision, DWORD AceFlags, DWORD MandatoryPolicy, PSID pLabelSid);
BOOL winapi_advapi32_CryptCreateHash(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH* phHash);
BOOL winapi_advapi32_CryptDestroyHash(HCRYPTHASH hHash);
BOOL winapi_advapi32_CryptGetHashParam(HCRYPTHASH hHash, DWORD dwParam, BYTE* pbData, DWORD* pdwDataLen, DWORD dwFlags);
BOOL winapi_advapi32_CryptHashData(HCRYPTHASH hHash, const BYTE* pbData, DWORD dwDataLen, DWORD dwFlags);
BOOL winapi_crypt32_CryptDecodeObjectEx(DWORD dwCertEncodingType, LPCSTR lpszStructType, const BYTE* pbEncoded, DWORD cbEncoded, DWORD dwFlags, PCRYPT_DECODE_PARA pDecodePara, void* pvStructInfo, DWORD* pcbStructInfo);
BOOL winapi_crypt32_CryptImportPublicKeyInfo(HCRYPTPROV hCryptProv, DWORD dwCertEncodingType, PCERT_PUBLIC_KEY_INFO pInfo, HCRYPTKEY* phKey);
BOOL winapi_crypt32_CertGetCertificateContextProperty(PCCERT_CONTEXT pCertContext, DWORD dwPropId, void* pvData, DWORD* pcbData);
BOOL winapi_user32_GetUserObjectInformationA(HANDLE hObj, int nIndex, PVOID pvInfo, DWORD nLength, LPDWORD lpnLengthNeeded);
HDESK winapi_user32_GetThreadDesktop(DWORD dwThreadId);
int winapi_ws2_32_WSAStartup(WORD wVersionRequired, LPWSADATA lpWSAData);
SOCKET winapi_ws2_32_socket(int af, int type, int protocol);
int winapi_ws2_32_connect(SOCKET s, const struct sockaddr* name, int namelen);
SOCKET winapi_ws2_32_accept(SOCKET s, struct sockaddr* addr, int* addrlen);
int winapi_ws2_32_setsockopt(SOCKET s, int level, int optname, const char* optval, int optlen);
int winapi_ws2_32_recv(SOCKET s, char* buf, int len, int flags);
int winapi_ws2_32_WSADuplicateSocketA(SOCKET s, DWORD dwProcessId, LPWSAPROTOCOL_INFOA lpProtocolInfo);
int winapi_ws2_32_send(SOCKET s, const char* buf, int len, int flags);
int winapi_ws2_32_bind(SOCKET s, const struct sockaddr* name, int namelen);
int winapi_ws2_32_listen(SOCKET s, int backlog);
int winapi_ws2_32_closesocket(SOCKET s);
int winapi_ws2_32_select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const struct timeval* timeout);
struct hostent* winapi_ws2_32_gethostbyname(const char* name);
int winapi_ws2_32_getaddrinfo(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA* pHints, PADDRINFOA* ppResult);
VOID winapi_ws2_32_freeaddrinfo(PADDRINFOA pAddrInfo);
u_short winapi_ws2_32_htons(u_short hostshort);
u_long winapi_ws2_32_htonl(u_long hostlong);
u_long winapi_ws2_32_ntohl(u_long netlong);
unsigned long winapi_ws2_32_inet_addr(const char* cp);
HINTERNET winapi_wininet_InternetOpenW(LPCWSTR lpszAgent, DWORD dwAccessType, LPCWSTR lpszProxy, LPCWSTR lpszProxyBypass, DWORD dwFlags);
HINTERNET winapi_wininet_InternetConnectW(HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
HINTERNET winapi_wininet_HttpOpenRequestW(HINTERNET hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName, LPCWSTR lpszVersion, LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);
BOOL winapi_wininet_InternetSetOptionW(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength);
BOOL winapi_wininet_HttpSendRequestW(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);
BOOL winapi_wininet_HttpQueryInfoW(HINTERNET hRequest, DWORD dwInfoLevel, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex);
BOOL winapi_wininet_InternetReadFile(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
BOOL winapi_wininet_InternetCloseHandle(HINTERNET hInternet);
BOOL winapi_wininet_InternetCrackUrlW(LPCWSTR lpszUrl, DWORD dwUrlLength, DWORD dwFlags, LPURL_COMPONENTSW lpUrlComponents);
RPC_STATUS winapi_rpcrt4_UuidCreate(UUID* Uuid);
HINTERNET winapi_winhttp_WinHttpOpen(LPCWSTR pszAgentW, DWORD dwAccessType, LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD dwFlags);
HINTERNET winapi_winhttp_WinHttpConnect(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved);
HINTERNET winapi_winhttp_WinHttpOpenRequest(HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR* ppwszAcceptTypes, DWORD dwFlags);
BOOL winapi_winhttp_WinHttpGetIEProxyConfigForCurrentUser(WINHTTP_CURRENT_USER_IE_PROXY_CONFIG* pProxyConfig);
BOOL winapi_winhttp_WinHttpGetProxyForUrl(HINTERNET hSession, LPCWSTR lpcwszUrl, WINHTTP_AUTOPROXY_OPTIONS* pAutoProxyOptions, WINHTTP_PROXY_INFO* pProxyInfo);
BOOL winapi_winhttp_WinHttpSetOption(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength);
BOOL winapi_winhttp_WinHttpSendRequest(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext);
BOOL winapi_winhttp_WinHttpReceiveResponse(HINTERNET hRequest, LPVOID lpReserved);
BOOL winapi_winhttp_WinHttpQueryHeaders(HINTERNET hRequest, DWORD dwInfoLevel, LPCWSTR pwszName, LPVOID lpvBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex);
BOOL winapi_winhttp_WinHttpReadData(HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
BOOL winapi_winhttp_WinHttpQueryOption(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, LPDWORD lpdwBufferLength);
BOOL winapi_winhttp_WinHttpCrackUrl(LPCWSTR pwszUrl, DWORD dwUrlLength, DWORD dwFlags, LPURL_COMPONENTS lpUrlComponents);
BOOL winapi_winhttp_WinHttpCloseHandle(HINTERNET hInternet);
BOOL winapi_winhttp_WinHttpWriteData(HINTERNET hRequest, LPCVOID lpBuffer, DWORD dwNumberOfBytesToWrite, LPDWORD lpdwNumberOfBytesWritten);
LPVOID winapi_kernel32_HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes);
HLOCAL winapi_kernel32_LocalAlloc(UINT uFlags, SIZE_T uBytes);
VOID winapi_kernel32_GetSystemTime(LPSYSTEMTIME lpSystemTime);
BOOL winapi_kernel32_SystemTimeToFileTime(const SYSTEMTIME* lpSystemTime, LPFILETIME lpFileTime);
int winapi_kernel32_MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
int winapi_kernel32_WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar);
BOOL winapi_kernel32_PeekNamedPipe(HANDLE hNamedPipe, LPVOID lpBuffer, DWORD nBufferSize, LPDWORD lpBytesRead, LPDWORD lpTotalBytesAvail, LPDWORD lpBytesLeftThisMessage);
BOOL winapi_kernel32_SetNamedPipeHandleState(HANDLE hNamedPipe, LPDWORD lpMode, LPDWORD lpMaxCollectionCount, LPDWORD lpCollectDataTimeout);
BOOL winapi_kernel32_ReleaseMutex(HANDLE hMutex);
HANDLE winapi_kernel32_CreateMutexA(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName);
HANDLE winapi_kernel32_CreateMutexW(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName);
BOOL winapi_kernel32_TerminateThread(HANDLE hThread, DWORD dwExitCode);
int winapi_kernel32_lstrcmpW(LPCWSTR lpString1, LPCWSTR lpString2);
DWORD winapi_kernel32_GetLastError(VOID);
HWINSTA winapi_user32_GetProcessWindowStation(VOID);
int winapi_ws2_32_WSAGetLastError(VOID);
char* winapi_ws2_32_inet_ntoa(struct in_addr in);
BOOL winapi_wininet_HttpQueryInfoA(HINTERNET hRequest, DWORD dwInfoLevel, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex);
BOOL winapi_crypt32_CryptBinaryToStringA(const BYTE* pbBinary, DWORD cbBinary, DWORD dwFlags, LPSTR pszString, DWORD* pcchString);
BOOL winapi_crypt32_CryptStringToBinaryA(LPCSTR pszString, DWORD cchString, DWORD dwFlags, BYTE* pbBinary, DWORD* pcbBinary, DWORD* pdwSkip, DWORD* pdwFlags);

BOOL winapi_kernel32_CopyFileW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, BOOL bFailIfExists);
BOOL winapi_kernel32_CreateDirectoryW(LPCWSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
BOOL winapi_kernel32_DeleteFileA(LPCSTR lpFileName);
BOOL winapi_kernel32_DeleteFileW(LPCWSTR lpFileName);
BOOL winapi_kernel32_DisconnectNamedPipe(HANDLE hNamedPipe);
DWORD winapi_kernel32_ExpandEnvironmentStringsA(LPCSTR lpSrc, LPSTR lpDst, DWORD nSize);
DWORD winapi_kernel32_ExpandEnvironmentStringsW(LPCWSTR lpSrc, LPWSTR lpDst, DWORD nSize);
BOOL winapi_kernel32_FileTimeToSystemTime(const FILETIME* lpFileTime, LPSYSTEMTIME lpSystemTime);
BOOL winapi_kernel32_FindClose(HANDLE hFindFile);
HANDLE winapi_kernel32_FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData);
BOOL winapi_kernel32_FindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);
HRSRC winapi_kernel32_FindResourceA(HMODULE hModule, LPCSTR lpName, LPCSTR lpType);
DWORD winapi_kernel32_GetCurrentDirectoryW(DWORD nBufferLength, LPWSTR lpBuffer);
DWORD winapi_kernel32_GetCurrentProcessId(VOID);
int winapi_kernel32_GetDateFormatW(LCID Locale, DWORD dwFlags, const SYSTEMTIME* lpDate, LPCWSTR lpFormat, LPWSTR lpDateStr, int cchDate);
BOOL winapi_kernel32_GetDiskFreeSpaceExA(LPCSTR lpDirectoryName, PULARGE_INTEGER lpFreeBytesAvailableToCaller, PULARGE_INTEGER lpTotalNumberOfBytes, PULARGE_INTEGER lpTotalNumberOfFreeBytes);
UINT winapi_kernel32_GetDriveTypeA(LPCSTR lpRootPathName);
UINT winapi_kernel32_GetDriveTypeW(LPCWSTR lpRootPathName);
BOOL winapi_kernel32_GetExitCodeThread(HANDLE hThread, LPDWORD lpExitCode);
DWORD winapi_kernel32_GetFileAttributesA(LPCSTR lpFileName);
BOOL winapi_kernel32_GetFileAttributesExW(LPCWSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileInformation);
DWORD winapi_kernel32_GetFileAttributesW(LPCWSTR lpFileName);
BOOL winapi_kernel32_GetHandleInformation(HANDLE hObject, LPDWORD lpdwFlags);
DWORD winapi_kernel32_GetLogicalDriveStringsA(DWORD nBufferLength, LPSTR lpBuffer);
DWORD winapi_kernel32_GetLogicalDrives(VOID);
FARPROC winapi_kernel32_GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
LCID winapi_kernel32_GetSystemDefaultLCID(VOID);
DWORD winapi_kernel32_GetTickCount(VOID);
int winapi_kernel32_GetTimeFormatW(LCID Locale, DWORD dwFlags, const SYSTEMTIME* lpTime, LPCWSTR lpFormat, LPWSTR lpTimeStr, int cchTime);
BOOL winapi_kernel32_GetVersionExA(LPOSVERSIONINFOA lpVersionInformation);
HGLOBAL winapi_kernel32_LoadResource(HMODULE hModule, HRSRC hResInfo);
LPVOID winapi_kernel32_LockResource(HGLOBAL hResData);
VOID winapi_kernel32_OutputDebugStringW(LPCWSTR lpOutputString);
BOOL winapi_kernel32_MoveFileW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName);
BOOL winapi_kernel32_RemoveDirectoryW(LPCWSTR lpPathName);
BOOL winapi_kernel32_SetCurrentDirectoryW(LPCWSTR lpPathName);
BOOL winapi_kernel32_SetFileAttributesW(LPCWSTR lpFileName, DWORD dwFileAttributes);
VOID winapi_kernel32_SetLastError(DWORD dwErrCode);
DWORD winapi_kernel32_SizeofResource(HMODULE hModule, HRSRC hResInfo);
int winapi_kernel32_lstrcmpiW(LPCWSTR lpString1, LPCWSTR lpString2);
LPWSTR winapi_kernel32_lstrcpyW(LPWSTR lpString1, LPCWSTR lpString2);
int winapi_kernel32_lstrlenA(LPCSTR lpString);
int winapi_kernel32_lstrlenW(LPCWSTR lpString);
PVOID winapi_kernel32_InterlockedExchangePointer(PVOID volatile* Target, PVOID Value);
DWORD winapi_kernel32_FormatMessageA(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPSTR lpBuffer, DWORD nSize, va_list* Arguments);
BOOL winapi_kernel32_CreatePipe(PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize);
BOOL winapi_kernel32_CreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
BOOL winapi_kernel32_GetComputerNameA(LPSTR lpBuffer, LPDWORD nSize);
HANDLE winapi_kernel32_GetCurrentProcess(VOID);
HANDLE winapi_kernel32_GetCurrentThread(VOID);
DWORD winapi_kernel32_GetEnvironmentVariableW(LPCWSTR lpName, LPWSTR lpBuffer, DWORD nSize);
VOID winapi_kernel32_GetLocalTime(LPSYSTEMTIME lpSystemTime);
int winapi_kernel32_GetLocaleInfoA(LCID Locale, LCTYPE LCType, LPSTR lpLCData, int cchData);
BOOL winapi_kernel32_GetThreadContext(HANDLE hThread, LPCONTEXT lpContext);
DWORD winapi_kernel32_GetTimeZoneInformation(LPTIME_ZONE_INFORMATION lpTimeZoneInformation);
BOOL winapi_kernel32_SetThreadContext(HANDLE hThread, const CONTEXT* lpContext);
BOOL winapi_kernel32_TerminateProcess(HANDLE hProcess, UINT uExitCode);
BOOL winapi_kernel32_VirtualLock(LPVOID lpAddress, SIZE_T dwSize);
BOOL winapi_kernel32_VirtualUnlock(LPVOID lpAddress, SIZE_T dwSize);
DWORD winapi_kernel32_WaitForSingleObjectEx(HANDLE hHandle, DWORD dwMilliseconds, BOOL bAlertable);
HANDLE winapi_kernel32_OpenProcessNative(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
BOOL winapi_kernel32_ReadProcessMemoryNative(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);
BOOL winapi_kernel32_WriteProcessMemoryNative(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
LPVOID winapi_kernel32_VirtualAllocNative(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
LPVOID winapi_kernel32_VirtualAllocExNative(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
BOOL winapi_kernel32_VirtualFreeExNative(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
BOOL winapi_kernel32_VirtualProtectExNative(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
SIZE_T winapi_kernel32_VirtualQueryExNative(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);

BOOL winapi_advapi32_RevertToSelf(VOID);
BOOL winapi_advapi32_ClearEventLogA(HANDLE hEventLog, LPCSTR lpBackupFileName);
BOOL winapi_advapi32_CloseEventLog(HANDLE hEventLog);
BOOL winapi_advapi32_ConvertSidToStringSidA(PSID Sid, LPSTR* StringSid);
BOOL winapi_advapi32_CreateProcessAsUserW(HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
BOOL winapi_advapi32_DuplicateTokenEx(HANDLE hExistingToken, DWORD dwDesiredAccess, LPSECURITY_ATTRIBUTES lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, PHANDLE phNewToken);
BOOL winapi_advapi32_GetNumberOfEventLogRecords(HANDLE hEventLog, PDWORD NumberOfRecords);
BOOL winapi_advapi32_GetOldestEventLogRecord(HANDLE hEventLog, PDWORD OldestRecord);
BOOL winapi_advapi32_GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);
BOOL winapi_advapi32_LookupAccountSidW(LPCWSTR lpSystemName, PSID Sid, LPWSTR Name, LPDWORD cchName, LPWSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);
BOOL winapi_advapi32_LookupPrivilegeValueA(LPCSTR lpSystemName, LPCSTR lpName, PLUID lpLuid);
HANDLE winapi_advapi32_OpenEventLogA(LPCSTR lpUNCServerName, LPCSTR lpSourceName);
BOOL winapi_advapi32_ReadEventLogA(HANDLE hEventLog, DWORD dwReadFlags, DWORD dwRecordOffset, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, DWORD* pnBytesRead, DWORD* pnMinNumberOfBytesNeeded);
LSTATUS winapi_advapi32_RegCloseKey(HKEY hKey);
LSTATUS winapi_advapi32_RegConnectRegistryW(LPCWSTR lpMachineName, HKEY hKey, PHKEY phkResult);
LSTATUS winapi_advapi32_RegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired, const LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition);
LSTATUS winapi_advapi32_RegDeleteKeyW(HKEY hKey, LPCWSTR lpSubKey);
LSTATUS winapi_advapi32_RegDeleteValueW(HKEY hKey, LPCWSTR lpValueName);
LSTATUS winapi_advapi32_RegEnumKeyW(HKEY hKey, DWORD dwIndex, LPWSTR lpName, DWORD cchName);
LSTATUS winapi_advapi32_RegEnumValueW(HKEY hKey, DWORD dwIndex, LPWSTR lpValueName, LPDWORD lpcchValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
LSTATUS winapi_advapi32_RegLoadKeyW(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpFile);
LSTATUS winapi_advapi32_RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
LSTATUS winapi_advapi32_RegQueryInfoKeyA(HKEY hKey, LPSTR lpClass, LPDWORD lpcchClass, LPDWORD lpReserved, LPDWORD lpcSubKeys, LPDWORD lpcbMaxSubKeyLen, LPDWORD lpcbMaxClassLen, LPDWORD lpcValues, LPDWORD lpcbMaxValueNameLen, LPDWORD lpcbMaxValueLen, LPDWORD lpcbSecurityDescriptor, PFILETIME lpftLastWriteTime);
LSTATUS winapi_advapi32_RegQueryInfoKeyW(HKEY hKey, LPWSTR lpClass, LPDWORD lpcchClass, LPDWORD lpReserved, LPDWORD lpcSubKeys, LPDWORD lpcbMaxSubKeyLen, LPDWORD lpcbMaxClassLen, LPDWORD lpcValues, LPDWORD lpcbMaxValueNameLen, LPDWORD lpcbMaxValueLen, LPDWORD lpcbSecurityDescriptor, PFILETIME lpftLastWriteTime);
LSTATUS winapi_advapi32_RegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
LSTATUS winapi_advapi32_RegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData);
LSTATUS winapi_advapi32_RegUnLoadKeyW(HKEY hKey, LPCWSTR lpSubKey);

BOOL winapi_user32_CloseDesktop(HDESK hDesktop);
BOOL winapi_user32_CloseWindowStation(HWINSTA hWinSta);
HWND winapi_user32_CreateWindowExA(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam);
LRESULT winapi_user32_DefWindowProcA(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
BOOL winapi_user32_DestroyWindow(HWND hWnd);
LRESULT winapi_user32_DispatchMessageA(const MSG* lpMsg);
BOOL winapi_user32_EnumChildWindows(HWND hWndParent, WNDENUMPROC lpEnumFunc, LPARAM lParam);
BOOL winapi_user32_EnumDesktopsA(HWINSTA hwinsta, DESKTOPENUMPROCA lpEnumFunc, LPARAM lParam);
BOOL winapi_user32_EnumWindowStationsA(WINSTAENUMPROCA lpEnumFunc, LPARAM lParam);
BOOL winapi_user32_ExitWindowsEx(UINT uFlags, DWORD dwReason);
SHORT winapi_user32_GetAsyncKeyState(int vKey);
HWND winapi_user32_GetForegroundWindow(VOID);
BOOL winapi_user32_GetKeyboardState(PBYTE lpKeyState);
int winapi_user32_GetKeyNameTextW(LONG lParam, LPWSTR lpString, int cchSize);
SHORT winapi_user32_GetKeyState(int nVirtKey);
BOOL winapi_user32_GetMessageA(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax);
int winapi_user32_GetSystemMetrics(int nIndex);
DWORD winapi_user32_GetWindowThreadProcessId(HWND hWnd, LPDWORD lpdwProcessId);
UINT winapi_user32_MapVirtualKeyA(UINT uCode, UINT uMapType);
HDESK winapi_user32_OpenDesktopA(LPCSTR lpszDesktop, DWORD dwFlags, BOOL fInherit, ACCESS_MASK dwDesiredAccess);
HWINSTA winapi_user32_OpenWindowStationA(LPCSTR lpszWinSta, BOOL fInherit, ACCESS_MASK dwDesiredAccess);
ATOM winapi_user32_RegisterClassExA(const WNDCLASSEXA* unnamedParam1);
UINT winapi_user32_SendInput(UINT cInputs, LPINPUT pInputs, int cbSize);
LRESULT winapi_user32_SendMessageA(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
BOOL winapi_user32_SetProcessWindowStation(HWINSTA hWinSta);
BOOL winapi_user32_SetThreadDesktop(HDESK hDesktop);
BOOL winapi_user32_SwitchDesktop(HDESK hDesktop);
int winapi_user32_ToUnicodeEx(UINT wVirtKey, UINT wScanCode, const BYTE* lpKeyState, LPWSTR pwszBuff, int cchBuff, UINT wFlags, HKL dwhkl);
BOOL winapi_user32_TranslateMessage(const MSG* lpMsg);
BOOL winapi_user32_UnregisterClassA(LPCSTR lpClassName, HINSTANCE hInstance);
int winapi_user32_wsprintfW(LPWSTR unnamedParam1, LPCWSTR unnamedParam2, ...);

int winapi_ws2_32_getsockname(SOCKET s, struct sockaddr* name, int* namelen);
u_short winapi_ws2_32_ntohs(u_short netshort);
int winapi_ws2_32_recvfrom(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen);
int winapi_ws2_32_sendto(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen);
int winapi_ws2_32_shutdown(SOCKET s, int how);
INT winapi_ws2_32_WSAAddressToStringA(LPSOCKADDR lpsaAddress, DWORD dwAddressLength, LPWSAPROTOCOL_INFOA lpProtocolInfo, LPSTR lpszAddressString, LPDWORD lpdwAddressStringLength);
int winapi_ws2_32_WSACleanup(VOID);
WSAEVENT winapi_ws2_32_WSACreateEvent(VOID);
int winapi_ws2_32_WSAEventSelect(SOCKET s, WSAEVENT hEventObject, long lNetworkEvents);
VOID winapi_ws2_32_WSASetLastError(int iError);
SOCKET winapi_ws2_32_WSASocketA(int af, int type, int protocol, LPWSAPROTOCOL_INFOA lpProtocolInfo, GROUP g, DWORD dwFlags);

DWORD winapi_iphlpapi_CreateIpForwardEntry(PMIB_IPFORWARDROW pRoute);
DWORD winapi_iphlpapi_DeleteIpForwardEntry(PMIB_IPFORWARDROW pRoute);
DWORD winapi_iphlpapi_GetIfEntry(PMIB_IFROW pIfRow);
DWORD winapi_iphlpapi_GetIpAddrTable(PMIB_IPADDRTABLE pIpAddrTable, PULONG pdwSize, BOOL bOrder);
DWORD winapi_iphlpapi_GetIpForwardTable(PMIB_IPFORWARDTABLE pIpForwardTable, PULONG pdwSize, BOOL bOrder);
NETIO_STATUS winapi_iphlpapi_GetIpInterfaceEntry(PMIB_IPINTERFACE_ROW Row);
ULONG winapi_iphlpapi_GetIpNetTable(PMIB_IPNETTABLE IpNetTable, PULONG SizePointer, BOOL Order);
ULONG winapi_iphlpapi_GetTcpTable(PMIB_TCPTABLE TcpTable, PULONG SizePointer, BOOL Order);
ULONG winapi_iphlpapi_GetUdpTable(PMIB_UDPTABLE UdpTable, PULONG SizePointer, BOOL Order);

DWORD winapi_mpr_WNetGetUniversalNameA(LPCSTR lpLocalPath, DWORD dwInfoLevel, LPVOID lpBuffer, LPDWORD lpBufferSize);

HRESULT winapi_ole32_CoCreateInstance(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID* ppv);
HRESULT winapi_ole32_CoInitialize(LPVOID pvReserved);
VOID winapi_ole32_CoUninitialize(VOID);

HRESULT winapi_oleaut32_VariantClear(VARIANTARG* pvarg);
VOID winapi_oleaut32_VariantInit(VARIANTARG* pvarg);

BOOL winapi_winmm_sndPlaySoundA(LPCSTR pszSound, UINT fuSound);
MMRESULT winapi_winmm_waveInAddBuffer(HWAVEIN hwi, LPWAVEHDR pwh, UINT cbwh);
MMRESULT winapi_winmm_waveInOpen(LPHWAVEIN phwi, UINT uDeviceID, LPCWAVEFORMATEX pwfx, DWORD_PTR dwCallback, DWORD_PTR dwInstance, DWORD fdwOpen);
MMRESULT winapi_winmm_waveInPrepareHeader(HWAVEIN hwi, LPWAVEHDR pwh, UINT cbwh);
MMRESULT winapi_winmm_waveInStart(HWAVEIN hwi);
MMRESULT winapi_winmm_waveInStop(HWAVEIN hwi);

NET_API_STATUS winapi_netapi32_NetApiBufferFree(LPVOID Buffer);
NET_API_STATUS winapi_netapi32_NetWkstaGetInfo(LMSTR servername, DWORD level, LPBYTE* bufptr);

BOOL winapi_psapi_EnumDeviceDrivers(LPVOID* lpImageBase, DWORD cb, LPDWORD lpcbNeeded);
DWORD winapi_psapi_GetDeviceDriverBaseNameW(LPVOID ImageBase, LPWSTR lpBaseName, DWORD nSize);
DWORD winapi_psapi_GetDeviceDriverFileNameW(LPVOID ImageBase, LPWSTR lpFilename, DWORD nSize);

LSTATUS winapi_shlwapi_SHDeleteKeyW(HKEY hkey, LPCWSTR pszSubKey);
                                                                                                                             

#endif
