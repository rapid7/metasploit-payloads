/*!
 * @file window.h
 * @brief Declarations for window management functionality
 */
#include "extapi.h"
#include "window.h"

VOID add_enumerated_window( Packet *pResponse, QWORD qwHandle, const char* lpWindowTitle, DWORD dwProcessId );
DWORD enumerate_windows( Packet *response );

#ifdef _WIN32
#define MAX_WINDOW_TITLE 256

typedef BOOL (WINAPI * PENUMDESKTOPWINDOWS)( HDESK hDesktop, WNDENUMPROC enumProc, LPARAM lparam );
typedef int (WINAPI * PGETWINDOWTEXA)( HWND hWnd, LPSTR lpString, int nMaxCount );
typedef DWORD (WINAPI * PGETWINDOWTHREADPROCESSID)( HWND hWnd, LPDWORD lpdwProcessId );

typedef struct _EnumWindowsState
{
	Packet* pResponse;
	PGETWINDOWTEXA pGetWindowTextA;
	PGETWINDOWTHREADPROCESSID pGetWindowThreadProcessId;
} EnumWindowsState;

BOOL CALLBACK enumerate_windows_callback( HWND hWnd, LPARAM lParam )
{
	char windowTitle[MAX_WINDOW_TITLE];
	DWORD dwThreadId = 0;
	DWORD dwProcessId = 0;
	EnumWindowsState* pState = (EnumWindowsState*)lParam;

	dprintf( "Enumerated window %x", hWnd );

	do
	{
		dprintf( "Getting window title %p", pState->pGetWindowTextA );
		if( pState->pGetWindowTextA( hWnd, windowTitle, MAX_WINDOW_TITLE ) == 0 ) {
			strncpy_s( windowTitle, MAX_WINDOW_TITLE, "<unknown>", MAX_WINDOW_TITLE - 1 );
			dprintf( "Unable to get window title. Skipping." );
			break;
		}

		dprintf( "Getting process ID %p", pState->pGetWindowThreadProcessId );
		dwThreadId = pState->pGetWindowThreadProcessId( hWnd, &dwProcessId );

		dprintf(" Adding enumerated response" );
		add_enumerated_window( pState->pResponse, (QWORD)hWnd, windowTitle, dwProcessId );
	} while(0);

	return TRUE;
}
#endif

DWORD enumerate_windows( Packet *response )
{
#ifdef _WIN32
	// currently we only support Windoze

	DWORD dwResult;
	HMODULE hUser32;
	PENUMDESKTOPWINDOWS pEnumDesktopWindows;
	EnumWindowsState state;

	do
	{
		dprintf( "Loading user32.dll" );
		if( (hUser32 = LoadLibraryA( "user32.dll" )) == NULL)
			BREAK_ON_ERROR( "Unable to load user32.dll" );

		dprintf( "Searching for EnumDesktopWindows" );
		if( (pEnumDesktopWindows = (PENUMDESKTOPWINDOWS)GetProcAddress( hUser32, "EnumDesktopWindows" )) == NULL )
			BREAK_ON_ERROR( "Unable to locate EnumDesktopWindows in user32.dll" );

		dprintf( "Searching for GetWindowTextA" );
		if( (state.pGetWindowTextA = (PGETWINDOWTEXA)GetProcAddress( hUser32, "GetWindowTextA" )) == NULL )
			BREAK_ON_ERROR( "Unable to locate GetWindowTextA in user32.dll" );
		dprintf( "Found GetWindowTextA %p", state.pGetWindowTextA );

		dprintf( "Searching for GetWindowThreadProcessId" );
		if( (state.pGetWindowThreadProcessId = (PGETWINDOWTHREADPROCESSID)GetProcAddress( hUser32, "GetWindowThreadProcessId" )) == NULL )
			BREAK_ON_ERROR( "Unable to locate GetWindowThreadProcessId in user32.dll" );
		dprintf( "Found GetWindowThreadProcessId %p", state.pGetWindowThreadProcessId );

		state.pResponse = response;

		dprintf( "Beginning enumeration of desktop windows" );
		if( !pEnumDesktopWindows( NULL, (WNDENUMPROC)enumerate_windows_callback, (LPARAM)&state ) )
			BREAK_ON_ERROR( "Failed to enumerate windows" );

		dwResult = ERROR_SUCCESS;
	} while(0);

	return dwResult;
#else
	return ERROR_NOT_SUPPORTED;
#endif
}

DWORD request_window_enum( Remote *remote, Packet *packet )
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

		dprintf( "Beginning window enumeration" );
		result = enumerate_windows( response );

	} while(0);

	dprintf( "Transmitting response back to caller." );
	packet_transmit_response( result, remote, response );

	return result;
}

VOID add_enumerated_window( Packet *pResponse, QWORD qwHandle, const char* cpWindowTitle, DWORD dwProcessId, BOOL bVisible )
{
	Tlv entries[4] = {0};

	dprintf( "Adding PID: %u", dwProcessId );
	dwProcessId = htonl( dwProcessId );
	entries[0].header.type   = TLV_TYPE_EXT_WINDOW_ENUM_PID;
	entries[0].header.length = sizeof( DWORD );
	entries[0].buffer        = (PUCHAR)&dwProcessId;

	dprintf( "Adding Handle: %p", qwHandle );
	qwHandle = htonq( qwHandle );
	entries[1].header.type   = TLV_TYPE_EXT_WINDOW_ENUM_HANDLE;
	entries[1].header.length = sizeof( QWORD );
	entries[1].buffer        = (PUCHAR)&qwHandle;

	dprintf( "Adding title: %s", cpWindowTitle );
	entries[2].header.type   = TLV_TYPE_EXT_WINDOW_ENUM_TITLE;
	entries[2].header.length = (DWORD)strlen( cpWindowTitle ) + 1;
	entries[2].buffer        = (PUCHAR)cpWindowTitle;

	dprintf( "Adding group to response" );
	packet_add_tlv_group( pResponse, TLV_TYPE_EXT_WINDOW_ENUM_GROUP, entries, 3 );
}
