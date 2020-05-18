//===============================================================================================//
#ifndef _METERPRETER_SOURCE_EXTENSION_STDAPI_STDAPI_SERVER_PROCESS_PS_H
#define _METERPRETER_SOURCE_EXTENSION_STDAPI_STDAPI_SERVER_PROCESS_PS_H
//===============================================================================================//

#define PROCESS_ARCH_UNKNOWN	0
#define PROCESS_ARCH_X86		1
#define PROCESS_ARCH_X64		2
#define PROCESS_ARCH_IA64		3

VOID ps_addresult( Packet * response, DWORD dwPid, DWORD dwParentPid, wchar_t * cpExeName, wchar_t * cpExePath, wchar_t * cpUserName, DWORD dwProcessArch );

typedef DWORD(WINAPI * GETMODULEFILENAMEEXW)(HANDLE hProcess, HMODULE hModule, LPWSTR lpExeName, DWORD dwSize);
typedef DWORD(WINAPI * GETPROCESSIMAGEFILENAMEW)(HANDLE hProcess, LPWSTR lpExeName, DWORD dwSize);
typedef BOOL(WINAPI * QUERYFULLPROCESSIMAGENAMEW)(HANDLE hProcess, DWORD dwFlags, LPWSTR lpExeName, PDWORD lpdwSize);
typedef HANDLE (WINAPI * CREATETOOLHELP32SNAPSHOT)( DWORD dwFlags, DWORD th32ProcessID );
typedef BOOL (WINAPI * PROCESS32FIRSTW)( HANDLE hSnapshot, LPPROCESSENTRY32W lppe );
typedef BOOL (WINAPI * PROCESS32NEXTW)( HANDLE hSnapshot, LPPROCESSENTRY32W lppe );
typedef void (WINAPI * GETNATIVESYSTEMINFO)( LPSYSTEM_INFO lpSystemInfo );
typedef BOOL (WINAPI * ISWOW64PROCESS)( HANDLE hProcess, PBOOL Wow64Process );

typedef NTSTATUS (WINAPI * NTQUERYINFORMATIONPROCESS)( HANDLE ProcessHandle, DWORD ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength );

typedef BOOL (WINAPI * ENUMPROCESSES)( DWORD * pProcessIds, DWORD cb, DWORD * pBytesReturned );
typedef BOOL (WINAPI * ENUMPROCESSMODULES)( HANDLE hProcess, HMODULE *lphModule, DWORD cb, LPDWORD lpcbNeeded );
typedef DWORD(WINAPI * GETMODULEBASENAMEW)(HANDLE hProcess, HMODULE hModule, LPWSTR lpBaseName, DWORD nSize);

//===============================================================================================//

typedef struct _DLL_BUFFER
{
	LPVOID lpPE32DllBuffer;
	DWORD  dwPE32DllLength;
	LPVOID lpPE64DllBuffer;
	DWORD  dwPE64DllLength;
} DLL_BUFFER;

typedef struct _PROCESS_BASIC_INFORMATION
{
    PVOID Reserved1;
	PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;
	ULONG Length;
	ULONG Flags;
	ULONG DebugFlags;
	PVOID ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StdInputHandle;
	HANDLE StdOutputHandle;
	HANDLE StdErrorHandle;
	_UNICODE_STRING CurrentDirectoryPath;
	HANDLE CurrentDirectoryHandle;
	_UNICODE_STRING DllPath;
	_UNICODE_STRING ImagePathName;
	_UNICODE_STRING CommandLine;
	//...
} RTL_USER_PROCESS_PARAMETERS, * LPRTL_USER_PROCESS_PARAMETERS;

//===============================================================================================//

DWORD ps_inject(DWORD dwPid, DLL_BUFFER* pDllBuffer, LPCSTR reflectiveLoader, char* cpCommandLine);

DWORD ps_getarch( DWORD dwPid );

DWORD ps_getnativearch( VOID );

DWORD ps_list_via_toolhelp( Packet * response );

DWORD ps_list_via_psapi( Packet * response );

DWORD ps_list_via_brute( Packet * response );

#endif
