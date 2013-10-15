/*!
 * @file window.c
 * @brief Definitions for window management functionality
 */
#include "extapi.h"
#include "window.h"

VOID add_enumerated_window( Packet *pResponse, QWORD qwHandle, const char* lpWindowTitle, DWORD dwProcessId );
DWORD enumerate_windows( Packet *response );

#ifdef _WIN32

/*! @brief The maximum number of characters extracted from a window title. */
#define MAX_WINDOW_TITLE 256

/*! @brief EnumChildWindows function pointer type. */
typedef BOOL (WINAPI * PENUMCHILDWINDOWS)( HWND hWndParent, WNDENUMPROC enumProc, LPARAM lparam );
/*! @brief GetWindowTextA function pointer type. */
typedef int (WINAPI * PGETWINDOWTEXA)( HWND hWnd, LPSTR lpString, int nMaxCount );
/*! @brief GetWindowThreadProcessId function pointer type. */
typedef DWORD (WINAPI * PGETWINDOWTHREADPROCESSID)( HWND hWnd, LPDWORD lpdwProcessId );

/*! @brief Container type used to maintain state across EnumChildWindows callback calls. */
typedef struct _EnumWindowsState
{
	Packet* pResponse;                                     ///< Pointer to the \c Packet to add results to.
	BOOL bIncludeUnknown;                                  ///< Flag indicating if unknown windows should be included.
	PGETWINDOWTEXA pGetWindowTextA;                        ///< Pointer to the GetWindowTextA function.
	PGETWINDOWTHREADPROCESSID pGetWindowThreadProcessId;   ///< Pointer to the GetWindowThreadProcessId function.
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
			dprintf( "Unable to get window title. Setting to <unknown>." );
			if( pState->bIncludeUnknown ) {
				strncpy_s( windowTitle, MAX_WINDOW_TITLE, "<unknown>", MAX_WINDOW_TITLE - 1 );
			} else {
				break;
			}
		}

		dprintf( "Getting process ID %p", pState->pGetWindowThreadProcessId );
		dwThreadId = pState->pGetWindowThreadProcessId( hWnd, &dwProcessId );

		dprintf(" Adding enumerated response" );
		add_enumerated_window( pState->pResponse, (QWORD)hWnd, windowTitle, dwProcessId );
	} while(0);

	return TRUE;
}
#endif

DWORD enumerate_windows( Packet *response, BOOL bIncludeUnknown, QWORD parentWindow )
{
#ifdef _WIN32
	// currently we only support Windoze

	DWORD dwResult;
	HMODULE hUser32 = NULL;
	PENUMCHILDWINDOWS pEnumChildWindows;
	EnumWindowsState state;

	do
	{
		dprintf( "Loading user32.dll" );
		if( (hUser32 = LoadLibraryA( "user32.dll" )) == NULL)
			BREAK_ON_ERROR( "Unable to load user32.dll" );

		dprintf( "Searching for GetWindowTextA" );
		if( (state.pGetWindowTextA = (PGETWINDOWTEXA)GetProcAddress( hUser32, "GetWindowTextA" )) == NULL )
			BREAK_ON_ERROR( "Unable to locate GetWindowTextA in user32.dll" );
		dprintf( "Found GetWindowTextA %p", state.pGetWindowTextA );

		dprintf( "Searching for GetWindowThreadProcessId" );
		if( (state.pGetWindowThreadProcessId = (PGETWINDOWTHREADPROCESSID)GetProcAddress( hUser32, "GetWindowThreadProcessId" )) == NULL )
			BREAK_ON_ERROR( "Unable to locate GetWindowThreadProcessId in user32.dll" );
		dprintf( "Found GetWindowThreadProcessId %p", state.pGetWindowThreadProcessId );

		state.pResponse = response;
		state.bIncludeUnknown = bIncludeUnknown;

		dprintf( "Searching for EnumChildWindows" );
		if( (pEnumChildWindows = (PENUMCHILDWINDOWS)GetProcAddress( hUser32, "EnumChildWindows" )) == NULL )
			BREAK_ON_ERROR( "Unable to locate EnumChildWindows in user32.dll" );

		dprintf( "Beginning enumeration of child windows with parent %u", parentWindow );
		if( !pEnumChildWindows( parentWindow != 0 ? (HWND)parentWindow : NULL, (WNDENUMPROC)enumerate_windows_callback, (LPARAM)&state ) )
			BREAK_ON_ERROR( "Failed to enumerate child windows" );

		dwResult = ERROR_SUCCESS;
	} while(0);

	if( hUser32 )
		FreeLibrary( hUser32 );

	return dwResult;
#else
	return ERROR_NOT_SUPPORTED;
#endif
}

DWORD request_window_enum( Remote *remote, Packet *packet )
{
	QWORD parentWindow = NULL;
	DWORD dwResult = ERROR_SUCCESS;
	BOOL bIncludeUnknown = FALSE;
	Packet * response = packet_create_response( packet );

	do
	{
		if( !response ) {
			dprintf( "Unable to create response packet" );
			dwResult = ERROR_OUTOFMEMORY;
			break;
		}

		// Extract the specified parent window. If this is NULL, that's ok, as we'll
		// just enumerate top-level windows.
		parentWindow = packet_get_tlv_value_qword( packet, TLV_TYPE_EXT_WINDOW_ENUM_HANDLE );

		// Extract the flag that indicates of unknown windows should be included in the output
		bIncludeUnknown = packet_get_tlv_value_bool( packet, TLV_TYPE_EXT_WINDOW_ENUM_INCLUDEUNKNOWN );

		dprintf( "Beginning window enumeration" );
		dwResult = enumerate_windows( response, bIncludeUnknown, parentWindow );

	} while(0);

	dprintf( "Transmitting response back to caller." );
	if( response )
		packet_transmit_response( dwResult, remote, response );

	return dwResult;
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
