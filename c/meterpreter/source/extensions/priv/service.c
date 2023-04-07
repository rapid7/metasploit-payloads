#include "precomp.h"
#include "service.h"

/*
 * Start a service which has allready been created.
 */
DWORD service_start( char * cpName )
{
	DWORD dwResult  = ERROR_SUCCESS;
	HANDLE hManager = NULL;
	HANDLE hService = NULL;

	do
	{
		if( !cpName )
			BREAK_WITH_ERROR( "[SERVICE] service_start. cpName is NULL", ERROR_INVALID_HANDLE );

		hManager = OpenSCManagerA( NULL, NULL, SC_MANAGER_ALL_ACCESS );
		if( !hManager )
			BREAK_ON_ERROR( "[SERVICE] service_start. OpenSCManagerA failed" );
		
		hService = OpenServiceA( hManager, cpName, SERVICE_START );
		if( !hService )
			BREAK_ON_ERROR( "[SERVICE] service_start. OpenServiceA failed" );

		if( !StartService( hService, 0, NULL ) )
			BREAK_ON_ERROR( "[SERVICE] service_start. StartService failed" );

	} while( 0 );

	if( hService )
		CloseServiceHandle( hService ); 

	if( hManager )
		CloseServiceHandle( hManager ); 

	SetLastError( dwResult );

	return dwResult;
}

/*
 * Stop a service.
 */
DWORD service_stop( char * cpName )
{
	DWORD dwResult                = ERROR_SUCCESS;
	HANDLE hManager               = NULL;
	HANDLE hService               = NULL;
	SERVICE_STATUS_PROCESS status = {0};
	DWORD dwTimeout               = 30000; // 30 seconds

	do
	{
		if( !cpName )
			BREAK_WITH_ERROR( "[SERVICE] service_stop. cpName is NULL", ERROR_INVALID_HANDLE );

		hManager = OpenSCManagerA( NULL, NULL, SC_MANAGER_ALL_ACCESS );
		if( !hManager )
			BREAK_ON_ERROR( "[SERVICE] service_stop. OpenSCManagerA failed" );
		
		hService = OpenServiceA( hManager, cpName, SERVICE_STOP | SERVICE_QUERY_STATUS ); 
		if( !hService )
			BREAK_ON_ERROR( "[SERVICE] service_stop. OpenServiceA failed" );

		if( !ControlService( hService, SERVICE_CONTROL_STOP, (SERVICE_STATUS *)&status ) )
			BREAK_ON_ERROR( "[SERVICE] service_stop. ControlService STOP failed" );
		
		if (service_wait_for_status(cpName, SERVICE_STOPPED, dwTimeout) != ERROR_SUCCESS) {
			BREAK_ON_ERROR("[ELEVATE] service_stop: service stop timed out.");
		}

	} while( 0 );

	if( hService )
		CloseServiceHandle( hService ); 

	if( hManager )
		CloseServiceHandle( hManager ); 

	SetLastError( dwResult );

	return dwResult;
}

/*
 * Create a new service.
 */
DWORD service_create( char * cpName, char * cpPath )
{
	DWORD dwResult  = ERROR_SUCCESS;
	HANDLE hManager = NULL;
	HANDLE hService = NULL;

	dprintf("[SERVICE] attempting to create service: %s / %s", cpName, cpPath);

	do
	{
		if( !cpName || !cpPath )
			BREAK_WITH_ERROR( "[SERVICE] service_create. cpName/cpPath is NULL", ERROR_INVALID_HANDLE );

		hManager = OpenSCManagerA( NULL, NULL, SC_MANAGER_ALL_ACCESS );
		if( !hManager )
			BREAK_ON_ERROR( "[SERVICE] service_create. OpenSCManagerA failed" );
		
		hService = CreateServiceA( hManager, cpName, NULL, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, cpPath, NULL, NULL, NULL, NULL, NULL );
		if( !hService )
			BREAK_ON_ERROR( "[SERVICE] service_create. CreateServiceA failed" );
		
		dprintf("[SERVICE] service created: %s / %s", cpName, cpPath);
	} while( 0 );

	if( hService )
		CloseServiceHandle( hService ); 

	if( hManager )
		CloseServiceHandle( hManager ); 

	SetLastError( dwResult );

	return dwResult;
}

/*
 * Destroy an existing service.
 */
DWORD service_destroy( char * cpName )
{
	DWORD dwResult  = ERROR_SUCCESS;
	HANDLE hManager = NULL;
	HANDLE hService = NULL;

	do
	{
		if( !cpName )
			BREAK_WITH_ERROR( "[SERVICE] service_destroy. cpName is NULL", ERROR_INVALID_HANDLE );

		hManager = OpenSCManagerA( NULL, NULL, SC_MANAGER_ALL_ACCESS );
		if( !hManager )
			BREAK_ON_ERROR( "[SERVICE] service_destroy. OpenSCManagerA failed" );
		
		hService = OpenServiceA( hManager, cpName, DELETE ); 
		if( !hService )
			BREAK_ON_ERROR( "[SERVICE] service_destroy. OpenServiceA failed" );

		if( !DeleteService( hService ) )
			BREAK_ON_ERROR( "[SERVICE] service_destroy. DeleteService failed" );

	} while( 0 );

	if( hService )
		CloseServiceHandle( hService ); 

	if( hManager )
		CloseServiceHandle( hManager ); 

	SetLastError( dwResult );

	return dwResult;
}

/*
 * Query service state.
 */
DWORD service_query_status( char* cpName, DWORD* dwState )
{
	DWORD dwResult  = ERROR_SUCCESS;
	HANDLE hManager = NULL;
	HANDLE hService = NULL;
	DWORD dwBytes;
	SERVICE_STATUS_PROCESS procInfo;

	do
	{
		if( !cpName )
			BREAK_WITH_ERROR( "[SERVICE] service_query_status. cpName is NULL", ERROR_INVALID_HANDLE );

		hManager = OpenSCManagerA( NULL, NULL, SC_MANAGER_CONNECT);
		if( !hManager )
			BREAK_ON_ERROR( "[SERVICE] service_query_status. OpenSCManagerA failed" );

		hService = OpenServiceA( hManager, cpName, SERVICE_QUERY_STATUS);
		if( !hService ){
			dwResult = GetLastError();
			dprintf("[SERVICE] service_query_status. QueryServiceStatusEx failed for %s. error=%d (0x%x) ", cpName, dwResult, (ULONG_PTR)dwResult);
			break;
		}

		if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&procInfo, sizeof(procInfo), &dwBytes)) {
			dwResult = GetLastError();
			dprintf("[SERVICE] service_query_status. QueryServiceStatusEx failed for %s. error=%d (0x%x) ", cpName, dwResult, (ULONG_PTR)dwResult);
			break;
		}
		else {
			*dwState = procInfo.dwCurrentState;
		}

	} while( 0 );

	if( hService )
		CloseServiceHandle( hService );

	if( hManager )
		CloseServiceHandle( hManager );

	return dwResult;
}

/*
 * Wait for a service to get into specific status.
 */
DWORD service_wait_for_status( char* cpName, DWORD dwStatus, DWORD dwMaxTimeout )
{
	DWORD dwCurrentStatus;
	DWORD dwElapsed = 0;
	DWORD dwResult;
	do {
		dwResult = service_query_status(cpName, &dwCurrentStatus);
		if( dwResult != ERROR_SUCCESS ) {
			break;
		}
		if( dwCurrentStatus == dwStatus ) {
			break;
		}
		else {
			Sleep(250);
			dwElapsed += 250;
		}
	} while (dwElapsed < dwMaxTimeout);

	if( (dwResult == ERROR_SUCCESS) && (dwCurrentStatus != dwStatus) ) {
		dwResult = WAIT_TIMEOUT;
		SetLastError(dwResult);
	}

	return dwResult;
}
