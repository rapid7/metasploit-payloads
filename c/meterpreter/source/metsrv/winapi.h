#ifndef _METERPRETER_WINAPI_H
#define _METERPRETER_WINAPI_H

#ifndef _METERPRETER_COMMON_WINAPI_H
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

// Compile-time hashes of the exports the wrappers below resolve. Exposed
// here so other TUs can pass them to GetProcAddressH without repeating the
// literal function-name strings.
#include "winapi_hashes.h"  // Auto-generated at CMake configure time.


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
HWINSTA winapi_user32_GetProcessWindowStation(VOID);
int winapi_ws2_32_WSAGetLastError(VOID);
char* winapi_ws2_32_inet_ntoa(struct in_addr in);
BOOL winapi_wininet_HttpQueryInfoA(HINTERNET hRequest, DWORD dwInfoLevel, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex);
BOOL winapi_crypt32_CryptBinaryToStringA(const BYTE* pbBinary, DWORD cbBinary, DWORD dwFlags, LPSTR pszString, DWORD* pcchString);
BOOL winapi_crypt32_CryptStringToBinaryA(LPCSTR pszString, DWORD cchString, DWORD dwFlags, BYTE* pbBinary, DWORD* pcbBinary, DWORD* pdwSkip, DWORD* pdwFlags);
                                                                                                                             

#endif
