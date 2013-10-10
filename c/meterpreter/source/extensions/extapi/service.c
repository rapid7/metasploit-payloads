/*!
 * @file service.c
 * @brief Definitions for service management functions
 */
#include "extapi.h"
#include "service.h"

#ifdef _WIN32

typedef SC_HANDLE (WINAPI * POPENSCMANAGERA)( LPCSTR lpMachineName, LPCSTR lpDatabaseName, DWORD dwDesiredAccess );
typedef BOOL (WINAPI * PCLOSESERVICEHANDLE)( SC_HANDLE hSCObject );
typedef BOOL (WINAPI * PENUMSERVICESSTATUSEXA)(
	SC_HANDLE hSCManager,
	SC_ENUM_TYPE InfoLevel,
	DWORD dwServiceType,
	DWORD dwServiceState,
	LPBYTE lpServices,
	DWORD cbBufSize,
	LPDWORD pcbBytesNeeded,
	LPDWORD lpServicesReturned,
	LPDWORD lpResumeHandle,
	LPCSTR pszGroupName
	);

typedef struct _EnumServicesState
{
	Packet* pResponse;
} EnumServicesState;

VOID add_enumerated_service( Packet *pResponse, LPCSTR cpName, LPCSTR cpDisplayName, DWORD dwProcessId, DWORD dwStatus, BOOL bInteractive );
#endif

DWORD enumerate_services( Packet *response );

DWORD request_service_enum(Remote *remote, Packet *packet)
{
	DWORD result = ERROR_SUCCESS;
	Packet * response = packet_create_response( packet );

	do
	{
		if( !response ) {
			dprintf( "Unable to create response packet" );
			result = ERROR_OUTOFMEMORY;
			break;
		}

		dprintf( "Beginning service enumeration" );
		result = enumerate_services( response );

	} while(0);

	dprintf( "Transmitting response back to caller." );
	packet_transmit_response( result, remote, response );

	return result;
}

DWORD enumerate_services( Packet *pResponse )
{
#ifdef _WIN32
	// currently we only support Windoze

	DWORD dwResult = ERROR_SUCCESS;
	HMODULE hAdvapi32 = NULL;
	POPENSCMANAGERA pOpenSCManagerA = NULL;
	PCLOSESERVICEHANDLE pCloseServiceHandle = NULL;
	PENUMSERVICESSTATUSEXA pEnumServicesStatusExA = NULL;
	SC_HANDLE scManager = NULL;
	ENUM_SERVICE_STATUS_PROCESSA* pSsInfo = NULL;
	DWORD dwBytesNeeded = 0;
	DWORD dwServicesReturned = 0;
	DWORD dwResumeHandle = 0;
	DWORD dwServiceIndex = 0;
	BOOL bResult;

	do
	{
		dprintf( "Loading advapi32.dll" );
		if( (hAdvapi32 = LoadLibraryA( "advapi32.dll" )) == NULL)
			BREAK_ON_ERROR( "Unable to load advapi32.dll" );

		dprintf( "Searching for OpenSCManagerA" );
		if( (pOpenSCManagerA = (POPENSCMANAGERA)GetProcAddress( hAdvapi32, "OpenSCManagerA" )) == NULL )
			BREAK_ON_ERROR( "Unable to locate OpenSCManagerA in advapi32.dll" );

		dprintf( "Searching for CloseServiceHandle" );
		if( (pCloseServiceHandle = (PCLOSESERVICEHANDLE)GetProcAddress( hAdvapi32, "CloseServiceHandle" )) == NULL )
			dprintf( "Unable to locate CloseServiceHandle in advapi32.dll. Continuing anyway." );

		dprintf( "Searching for EnumServicesStatusExA" );
		if( (pEnumServicesStatusExA = (PENUMSERVICESSTATUSEXA)GetProcAddress( hAdvapi32, "EnumServicesStatusExA" )) == NULL )
			BREAK_ON_ERROR( "Unable to locate EnumServicesStatusExA in advapi32.dll." );

		// TODO: add support for other machine names so that this instance can query other machines on the network.
		dprintf( "Opening the Service Control manager" );
		if( (scManager = pOpenSCManagerA( NULL, SERVICES_ACTIVE_DATABASEA, SC_MANAGER_CONNECT|GENERIC_READ )) == NULL )
			BREAK_ON_ERROR( "Unable to open the service control manager" );

		bResult = pEnumServicesStatusExA( scManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0,
			&dwBytesNeeded, &dwServicesReturned, &dwResumeHandle, NULL);

		if( !bResult && dwBytesNeeded )
		{
			pSsInfo = (ENUM_SERVICE_STATUS_PROCESSA*)malloc( dwBytesNeeded );

			if( !pSsInfo )
				BREAK_ON_ERROR( "Out of memory" );

			bResult = pEnumServicesStatusExA( scManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, (LPBYTE)pSsInfo, dwBytesNeeded,
				&dwBytesNeeded, &dwServicesReturned, &dwResumeHandle, NULL);
		}

		if( !bResult )
			BREAK_ON_ERROR( "Failed to enumerate services" );

		dprintf( "%s with %u entries returned", ( bResult ? "succeeded" : "failed"), dwServicesReturned );

		for( dwServiceIndex = 0; dwServiceIndex < dwServicesReturned; ++dwServiceIndex )
		{
			add_enumerated_service( pResponse, pSsInfo[dwServiceIndex].lpServiceName, pSsInfo[dwServiceIndex].lpDisplayName,
				pSsInfo[dwServiceIndex].ServiceStatusProcess.dwProcessId, pSsInfo[dwServiceIndex].ServiceStatusProcess.dwCurrentState,
				pSsInfo[dwServiceIndex].ServiceStatusProcess.dwServiceType & SERVICE_INTERACTIVE_PROCESS );
		}

	} while(0);

	if( pSsInfo )
		free( pSsInfo );

	if( scManager && pCloseServiceHandle )
		pCloseServiceHandle( scManager );

	if( hAdvapi32 )
		FreeLibrary( hAdvapi32 );

	return dwResult;
#else
	return ERROR_NOT_SUPPORTED;
#endif
}

#ifdef _WIN32
VOID add_enumerated_service( Packet *pResponse, LPCSTR cpName, LPCSTR cpDisplayName, DWORD dwProcessId, DWORD dwStatus, BOOL bInteractive )
{
	Tlv entries[5] = {0};
	dprintf( "Adding Name: %s", cpName );
	entries[0].header.type   = TLV_TYPE_EXT_SERVICE_ENUM_NAME;
	entries[0].header.length = (DWORD)strlen( cpName ) + 1;
	entries[0].buffer        = (PUCHAR)cpName;

	dprintf( "Adding Display Name: %s", cpDisplayName );
	entries[1].header.type   = TLV_TYPE_EXT_SERVICE_ENUM_DISPLAYNAME;
	entries[1].header.length = (DWORD)strlen( cpDisplayName ) + 1;
	entries[1].buffer        = (PUCHAR)cpDisplayName;

	dprintf( "Adding PID: %u", dwProcessId );
	dwProcessId = htonl( dwProcessId );
	entries[2].header.type   = TLV_TYPE_EXT_SERVICE_ENUM_PID;
	entries[2].header.length = sizeof( DWORD );
	entries[2].buffer        = (PUCHAR)&dwProcessId;

	dprintf( "Adding Status: %u", dwStatus );
	dwStatus = htonl( dwStatus );
	entries[3].header.type   = TLV_TYPE_EXT_SERVICE_ENUM_STATUS;
	entries[3].header.length = sizeof( DWORD );
	entries[3].buffer        = (PUCHAR)&dwStatus;

	dprintf( "Adding Status: %s", (bInteractive ? "TRUE" : "FALSE" ) );
	entries[4].header.type   = TLV_TYPE_EXT_SERVICE_ENUM_INTERACTIVE;
	entries[4].header.length = sizeof( BOOL );
	entries[4].buffer        = (PUCHAR)&bInteractive;

	dprintf( "Adding group to response" );
	packet_add_tlv_group( pResponse, TLV_TYPE_EXT_SERVICE_ENUM_GROUP, entries, 5 );
}
#endif