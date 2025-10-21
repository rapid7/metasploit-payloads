#ifndef _METERPRETER_COMMON_WINAPI_H
#define _METERPRETER_COMMON_WINAPI_H
#include <winsock2.h> // For SOCKET, WSADATA, sockaddr, WSAPROTOCOL_INFOA
#include <windows.h>
#include <tlhelp32.h>
#include <tlhelp32.h>  // For CreateToolhelp32Snapshot, THREADENTRY32
#include <wincrypt.h> // For HCRYPTPROV, HCRYPTKEY, PTOKEN_PRIVILEGES, etc.
#ifndef _WININET_
#include <winhttp.h>  // For WINHTTP_*, URL_COMPONENTS
#endif
#ifndef __WINE_WINHTTP_H
#include <wininet.h>
#endif
#include <rpcdce.h>   // For CoCreateGuid (included by windows.h but good to be explicit)
#include <accctrl.h>

#ifdef _WININET_
typedef VOID WINHTTP_CURRENT_USER_IE_PROXY_CONFIG;
typedef VOID WINHTTP_AUTOPROXY_OPTIONS;
typedef VOID WINHTTP_PROXY_INFO;
#endif

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

#if !defined(_METERPRETER_POOLPARTY_C)
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
#endif

// ntdll.dll
typedef struct _WinApiNtdll {
    NTSTATUS (*ZwAllocateVirtualMemory)(HANDLE hProcess, PVOID* pBaseAddress, ULONG_PTR pZeroBits, PSIZE_T pRegionSize, ULONG ulAllocationType, ULONG ulProtect);
    NTSTATUS (*ZwOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
    NTSTATUS (*ZwWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);
    NTSTATUS (*ZwReadVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesRead);
    NTSTATUS (*ZwProtectVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
    NTSTATUS (*ZwQueryVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
    NTSTATUS (*ZwFreeVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
    NTSTATUS (*NtQueueApcThread)(HANDLE ThreadHandle, PVOID ApcRoutine, PVOID ApcContext, PVOID Argument1, PVOID Argument2);
    NTSTATUS (*NtOpenThread)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
} WinApiNtdll;

// kernel32.dll
typedef struct _WinApiKernel32 {
    BOOL   (*WriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
    BOOL   (*ReadProcessMemory)(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);
    HANDLE (*OpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
    LPVOID (*VirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
    LPVOID (*VirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
    BOOL   (*VirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
    BOOL   (*VirtualProtectEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
    SIZE_T (*VirtualQuery)(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
    SIZE_T (*VirtualQueryEx)(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
    BOOL   (*VirtualFree)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
    HANDLE (*CreateRemoteThread)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
    BOOL   (*CloseHandle)(HANDLE hObject);
    BOOL   (*DuplicateHandle)(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions);
    HANDLE (*CreateToolhelp32Snapshot)(DWORD dwFlags, DWORD th32ProcessID);
    BOOL   (*Thread32First)(HANDLE hSnapshot, LPTHREADENTRY32 lpte);
    HANDLE (*OpenThread)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);
    DWORD  (*SuspendThread)(HANDLE hThread);
    BOOL   (*Thread32Next)(HANDLE hSnapshot, LPTHREADENTRY32 lpte);
    DWORD  (*ResumeThread)(HANDLE hThread);
    BOOL   (*FreeLibrary)(HMODULE hLibModule);
    BOOL   (*FlushInstructionCache)(HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T dwSize);
    HLOCAL (*LocalFree)(HLOCAL hMem);
    HANDLE (*CreateFileA)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
    BOOL   (*WriteFile)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
    HMODULE (*LoadLibraryA)(LPCSTR lpLibFileName);
    DWORD  (*WaitForMultipleObjects)(DWORD nCount, const HANDLE* lpHandles, BOOL bWaitAll, DWORD dwMilliseconds);
    BOOL   (*SetHandleInformation)(HANDLE hObject, DWORD dwMask, DWORD dwFlags);
    HGLOBAL (*GlobalFree)(HGLOBAL hMem);
    HANDLE (*CreateNamedPipeA)(LPCSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
    BOOL   (*ConnectNamedPipe)(HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped);
    BOOL   (*GetOverlappedResult)(HANDLE hFile, LPOVERLAPPED lpOverlapped, LPDWORD lpNumberOfBytesTransferred, BOOL bWait);
    BOOL   (*ReadFile)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
    HANDLE (*CreateThread)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
    BOOL   (*ResetEvent)(HANDLE hEvent);
    BOOL   (*SetThreadErrorMode)(DWORD dwNewMode, LPDWORD lpOldMode);
} WinApiKernel32;

// advapi32.dll
typedef struct _WinApiAdvApi32 {
    BOOL  (*OpenProcessToken)(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
    BOOL  (*AdjustTokenPrivileges)(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);
    BOOL  (*ImpersonateLoggedOnUser)(HANDLE hToken);
    BOOL  (*CryptDuplicateKey)(HCRYPTKEY hKey, DWORD* pdwReserved, DWORD dwFlags, HCRYPTKEY* phKey);
    BOOL  (*CryptSetKeyParam)(HCRYPTKEY hKey, DWORD dwParam, const BYTE* pbData, DWORD dwFlags);
    BOOL  (*CryptDecrypt)(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen);
    BOOL  (*CryptGenRandom)(HCRYPTPROV hProv, DWORD dwLen, BYTE* pbBuffer);
    BOOL  (*CryptEncrypt)(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen, DWORD dwBufLen);
    BOOL  (*CryptDestroyKey)(HCRYPTKEY hKey);
    BOOL  (*CryptReleaseContext)(HCRYPTPROV hProv, DWORD dwFlags);
    BOOL  (*CryptImportKey)(HCRYPTPROV hProv, const BYTE* pbData, DWORD dwDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY* phKey);
    BOOL  (*OpenThreadToken)(HANDLE ThreadHandle, DWORD DesiredAccess, BOOL OpenAsSelf, PHANDLE TokenHandle);
    BOOL  (*AllocateAndInitializeSid)(PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority, BYTE nSubAuthorityCount, DWORD dwSubAuthority0, DWORD dwSubAuthority1, DWORD dwSubAuthority2, DWORD dwSubAuthority3, DWORD dwSubAuthority4, DWORD dwSubAuthority5, DWORD dwSubAuthority6, DWORD dwSubAuthority7, PSID* pSid);
    DWORD (*SetEntriesInAclW)(ULONG cCountOfExplicitEntries, PEXPLICIT_ACCESS_W pListOfExplicitEntries, PACL OldAcl, PACL* NewAcl);
    BOOL  (*InitializeAcl)(PACL pAcl, DWORD nAclLength, DWORD dwAclRevision);
    BOOL  (*InitializeSecurityDescriptor)(PSECURITY_DESCRIPTOR pSecurityDescriptor, DWORD dwRevision);
    BOOL  (*SetSecurityDescriptorDacl)(PSECURITY_DESCRIPTOR pSecurityDescriptor, BOOL bDaclPresent, PACL pDacl, BOOL bDaclDefaulted);
    BOOL  (*SetSecurityDescriptorSacl)(PSECURITY_DESCRIPTOR pSecurityDescriptor, BOOL bSaclPresent, PACL pSacl, BOOL bSaclDefaulted);
    BOOL  (*LookupPrivilegeValueW)(LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid);
} WinApiAdvApi32;

// crypt32.dll
typedef struct _WinApiCrypt32 {
    BOOL (*CryptDecodeObjectEx)(DWORD dwCertEncodingType, LPCSTR lpszStructType, const BYTE* pbEncoded, DWORD cbEncoded, DWORD dwFlags, PCRYPT_DECODE_PARA pDecodePara, void* pvStructInfo, DWORD* pcbStructInfo);
    BOOL (*CryptImportPublicKeyInfo)(HCRYPTPROV hCryptProv, DWORD dwCertEncodingType, PCERT_PUBLIC_KEY_INFO pInfo, HCRYPTKEY* phKey);
    BOOL (*CertGetCertificateContextProperty)(PCCERT_CONTEXT pCertContext, DWORD dwPropId, void* pvData, DWORD* pcbData);
} WinApiCrypt32;

// user32.dll
typedef struct _WinApiUser32 {
    BOOL  (*GetUserObjectInformationA)(HANDLE hObj, int nIndex, PVOID pvInfo, DWORD nLength, LPDWORD lpnLengthNeeded);
    HDESK (*GetThreadDesktop)(DWORD dwThreadId);
} WinApiUser32;

// ws2_32.dll
typedef struct _WinApiWs2_32 {
    int    (*WSAStartup)(WORD wVersionRequired, LPWSADATA lpWSAData);
    SOCKET (*socket)(int af, int type, int protocol);
    int    (*connect)(SOCKET s, const struct sockaddr* name, int namelen);
    SOCKET (*accept)(SOCKET s, struct sockaddr* addr, int* addrlen);
    int    (*setsockopt)(SOCKET s, int level, int optname, const char* optval, int optlen);
    int    (*recv)(SOCKET s, char* buf, int len, int flags);
    int    (*WSADuplicateSocketA)(SOCKET s, DWORD dwProcessId, LPWSAPROTOCOL_INFOA lpProtocolInfo);
} WinApiWs2_32;

// wininet.dll
typedef struct _WinApiWinInet {
    HINTERNET (*InternetOpenW)(LPCWSTR lpszAgent, DWORD dwAccessType, LPCWSTR lpszProxy, LPCWSTR lpszProxyBypass, DWORD dwFlags);
    HINTERNET (*InternetConnectW)(HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
    HINTERNET (*HttpOpenRequestW)(HINTERNET hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName, LPCWSTR lpszVersion, LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);
    BOOL      (*InternetSetOptionW)(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength);
    BOOL      (*HttpSendRequestW)(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);
    BOOL      (*HttpQueryInfoW)(HINTERNET hRequest, DWORD dwInfoLevel, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex);
    BOOL      (*InternetReadFile)(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
    BOOL      (*InternetCloseHandle)(HINTERNET hInternet);
    BOOL      (*InternetCrackUrlW)(LPCWSTR lpszUrl, DWORD dwUrlLength, DWORD dwFlags, LPURL_COMPONENTSW lpUrlComponents);
} WinApiWinInet;

// rpcrt4.dll
typedef struct _WinApiRpcRt4 {
    HRESULT (*CoCreateGuid)(GUID* pguid);
} WinApiRpcRt4;

// winhttp.dll
typedef struct _WinApiWinHttp {
    HINTERNET (*WinHttpOpen)(LPCWSTR pszAgentW, DWORD dwAccessType, LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD dwFlags);
    HINTERNET (*WinHttpConnect)(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved);
    HINTERNET (*WinHttpOpenRequest)(HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR* ppwszAcceptTypes, DWORD dwFlags);
    BOOL      (*WinHttpGetIEProxyConfigForCurrentUser)(WINHTTP_CURRENT_USER_IE_PROXY_CONFIG* pProxyConfig);
    BOOL      (*WinHttpGetProxyForUrl)(HINTERNET hSession, LPCWSTR lpcwszUrl, WINHTTP_AUTOPROXY_OPTIONS* pAutoProxyOptions, WINHTTP_PROXY_INFO* pProxyInfo);
    BOOL      (*WinHttpSetOption)(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength);
    BOOL      (*WinHttpSendRequest)(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext);
    BOOL      (*WinHttpReceiveResponse)(HINTERNET hRequest, LPVOID lpReserved);
    BOOL      (*WinHttpQueryHeaders)(HINTERNET hRequest, DWORD dwInfoLevel, LPCWSTR pwszName, LPVOID lpvBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex);
    BOOL      (*WinHttpReadData)(HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
    BOOL      (*WinHttpQueryOption)(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, LPDWORD lpdwBufferLength);
    BOOL      (*WinHttpCrackUrl)(LPCWSTR pwszUrl, DWORD dwUrlLength, DWORD dwFlags, LPURL_COMPONENTS lpUrlComponents);
} WinApiWinHttp;

// Top-level container for all dynamically resolved APIs.
typedef struct _WinApi {
    WinApiNtdll    ntdll;
    WinApiKernel32 kernel32;
    WinApiAdvApi32 advapi32;
    WinApiCrypt32  crypt32;
    WinApiUser32   user32;
    WinApiWs2_32   ws2_32;
    WinApiWinInet  wininet;
    WinApiRpcRt4   rpcrt4;
    WinApiWinHttp  winhttp;
} WinApi;

#endif