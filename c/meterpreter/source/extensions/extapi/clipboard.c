/*!
 * @file clipboard.h
 * @brief Definitions for clipboard interaction functionality.
 */
#include "extapi.h"
#include "clipboard.h"

#ifdef _WIN32
/*! @brief GlobalAlloc function pointer type. */
typedef HGLOBAL (WINAPI * PGLOBALALLOC)( UINT uFlags, SIZE_T dwBytes );

/*! @brief GlobalFree function pointer type. */
typedef HGLOBAL (WINAPI * PGLOBALFREE)( HGLOBAL hMem );

/*! @brief GlobalLock function pointer type. */
typedef LPVOID (WINAPI * PGLOBALLOCK)( HGLOBAL hMem );

/*! @brief GlobalUnlock function pointer type. */
typedef LPVOID (WINAPI * PGLOBALUNLOCK)( HGLOBAL hMem );

/*! @brief OpenClipboard function pointer type. */
typedef BOOL (WINAPI * POPENCLIPBOARD)( HWND hWndNewOwner );

/*! @brief CloseClipboard function pointer type. */
typedef BOOL (WINAPI * PCLOSECLIPBOARD)();

/*! @brief SetClipboardData function pointer type. */
typedef HANDLE (WINAPI * PSETCLIPBOARDDATA)( UINT uFormat, HANDLE hMem );

/*! @brief SetClipboardData function pointer type. */
typedef HANDLE (WINAPI * PGETCLIPBOARDDATA)( UINT uFormat );

/*! @brief EmptyClipboard function pointer type. */
typedef BOOL (WINAPI * PEMPTYCLIPBOARD)();

#endif

/*!
 * @brief Handle the request to get the data from the clipboard.
 * @details This function currently only supports the following clipboard data formats:
 *             - CF_TEXT - raw text data.
 *
 *          Over time more formats will be supported.
 * @param remote Pointer to the remote endpoint.
 * @param packet Pointer to the request packet.
 * @return Indication of success or failure.
 * @todo Add support for more data formats.
 */
DWORD request_clipboard_get_data( Remote *remote, Packet *packet )
{
#ifdef _WIN32
	DWORD dwResult;
	HMODULE hKernel32 = NULL;
	HMODULE hUser32 = NULL;

	PGLOBALLOCK pGlobalLock = NULL;
	PGLOBALUNLOCK pGlobalUnlock = NULL;

	POPENCLIPBOARD pOpenClipboard = NULL;
	PCLOSECLIPBOARD pCloseClipboard = NULL;
	PGETCLIPBOARDDATA pGetClipboardData = NULL;

	PCHAR lpClipString;
	HGLOBAL hClipboardData;

	Packet *pResponse = packet_create_response( packet );

	do
	{
		dprintf( "Loading user32.dll" );
		if( (hUser32 = LoadLibraryA( "user32.dll" )) == NULL)
			BREAK_ON_ERROR( "Unable to load user32.dll" );

		dprintf( "Loading kernel32.dll" );
		if( (hKernel32 = LoadLibraryA( "kernel32.dll" )) == NULL)
			BREAK_ON_ERROR( "Unable to load kernel32.dll" );

		dprintf( "Searching for GlobalLock" );
		if( (pGlobalLock = (PGLOBALLOCK)GetProcAddress( hKernel32, "GlobalLock" )) == NULL )
			BREAK_ON_ERROR( "Unable to locate GlobalLock in kernel32.dll" );

		dprintf( "Searching for GlobalUnlock" );
		if( (pGlobalUnlock = (PGLOBALUNLOCK)GetProcAddress( hKernel32, "GlobalUnlock" )) == NULL )
			BREAK_ON_ERROR( "Unable to locate GlobalUnlock in kernel32.dll" );

		dprintf( "Searching for OpenClipboard" );
		if( (pOpenClipboard = (POPENCLIPBOARD)GetProcAddress( hUser32, "OpenClipboard" )) == NULL )
			BREAK_ON_ERROR( "Unable to locate OpenClipboard in user32.dll" );

		dprintf( "Searching for CloseClipboard" );
		if( (pCloseClipboard = (PCLOSECLIPBOARD)GetProcAddress( hUser32, "CloseClipboard" )) == NULL )
			BREAK_ON_ERROR( "Unable to locate CloseClipboard in user32.dll" );

		dprintf( "Searching for GetClipboardData" );
		if( (pGetClipboardData = (PGETCLIPBOARDDATA)GetProcAddress( hUser32, "GetClipboardData" )) == NULL )
			BREAK_ON_ERROR( "Unable to locate GetClipboardData in user32.dll" );

		// Try to get a lock on the clipboard
		if( !pOpenClipboard( NULL ) ) {
			dwResult = GetLastError();
			BREAK_WITH_ERROR( "Unable to open the clipboard", dwResult );
		}

		dprintf( "Clipboard locked, attempting to get data..." );

		// For now we only support  text, more formats to come later.
		if( (hClipboardData = pGetClipboardData( CF_TEXT ) ) != NULL
			&& (lpClipString = (PCHAR)pGlobalLock( hClipboardData )) != NULL ) {
			dprintf( "Clipboard text captured: %s", lpClipString );
			packet_add_tlv_string( pResponse, TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT, lpClipString );
			pGlobalUnlock( hClipboardData );
			dwResult = ERROR_SUCCESS;
		} else {
			dwResult = GetLastError();
			dprintf( "Unable to get clipboard data %u (0x%x)", dwResult, dwResult );
		}

		pCloseClipboard();

	} while(0);

	if( hKernel32 )
		FreeLibrary( hKernel32 );

	if( hUser32 )
		FreeLibrary( hUser32 );

	if( pResponse )
		packet_transmit_response( dwResult, remote, pResponse );

	return dwResult;
#else
	return ERROR_NOT_SUPPORTED;
#endif
}

/*!
 * @brief Handle the request to set the data that's on the clipboard.
 * @details This function currently only supports the following clipboard data formats:
 *             - CF_TEXT - raw text data.
 *
 *          Over time more formats will be supported.
 * @param remote Pointer to the remote endpoint.
 * @param packet Pointer to the request packet.
 * @return Indication of success or failure.
 * @todo Add support for more data formats.
 */
DWORD request_clipboard_set_data( Remote *remote, Packet *packet )
{
#ifdef _WIN32
	DWORD dwResult;
	HMODULE hKernel32 = NULL;
	HMODULE hUser32 = NULL;

	PGLOBALALLOC pGlobalAlloc = NULL;
	PGLOBALFREE pGlobalFree = NULL;
	PGLOBALLOCK pGlobalLock = NULL;
	PGLOBALUNLOCK pGlobalUnlock = NULL;

	POPENCLIPBOARD pOpenClipboard = NULL;
	PCLOSECLIPBOARD pCloseClipboard = NULL;
	PSETCLIPBOARDDATA pSetClipboardData = NULL;
	PEMPTYCLIPBOARD pEmptyClipboard = NULL;

	PCHAR lpClipString;
	HGLOBAL hClipboardData;
	PCHAR lpLockedData;
	SIZE_T cbStringBytes;

	do
	{
		if( (lpClipString = packet_get_tlv_value_string( packet, TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT )) == NULL )
			BREAK_WITH_ERROR( "No string data specified", ERROR_INVALID_PARAMETER );

		dprintf( "Loading user32.dll" );
		if( (hUser32 = LoadLibraryA( "user32.dll" )) == NULL)
			BREAK_ON_ERROR( "Unable to load user32.dll" );

		dprintf( "Loading kernel32.dll" );
		if( (hKernel32 = LoadLibraryA( "kernel32.dll" )) == NULL)
			BREAK_ON_ERROR( "Unable to load kernel32.dll" );

		dprintf( "Searching for GlobalAlloc" );
		if( (pGlobalAlloc = (PGLOBALALLOC)GetProcAddress( hKernel32, "GlobalAlloc" )) == NULL )
			BREAK_ON_ERROR( "Unable to locate GlobalAlloc in kernel32.dll" );

		dprintf( "Searching for GlobalLock" );
		if( (pGlobalLock = (PGLOBALLOCK)GetProcAddress( hKernel32, "GlobalLock" )) == NULL )
			BREAK_ON_ERROR( "Unable to locate GlobalLock in kernel32.dll" );

		dprintf( "Searching for GlobalUnlock" );
		if( (pGlobalUnlock = (PGLOBALUNLOCK)GetProcAddress( hKernel32, "GlobalUnlock" )) == NULL )
			BREAK_ON_ERROR( "Unable to locate GlobalUnlock in kernel32.dll" );

		dprintf( "Searching for OpenClipboard" );
		if( (pOpenClipboard = (POPENCLIPBOARD)GetProcAddress( hUser32, "OpenClipboard" )) == NULL )
			BREAK_ON_ERROR( "Unable to locate OpenClipboard in user32.dll" );

		dprintf( "Searching for CloseClipboard" );
		if( (pCloseClipboard = (PCLOSECLIPBOARD)GetProcAddress( hUser32, "CloseClipboard" )) == NULL )
			BREAK_ON_ERROR( "Unable to locate CloseClipboard in user32.dll" );

		dprintf( "Searching for EmptyClipboard" );
		if( (pEmptyClipboard = (PEMPTYCLIPBOARD)GetProcAddress( hUser32, "EmptyClipboard" )) == NULL )
			BREAK_ON_ERROR( "Unable to locate EmptyClipboard in user32.dll" );

		dprintf( "Searching for SetClipboardData" );
		if( (pSetClipboardData = (PSETCLIPBOARDDATA)GetProcAddress( hUser32, "SetClipboardData" )) == NULL )
			BREAK_ON_ERROR( "Unable to locate SetClipboardData in user32.dll" );

		cbStringBytes = (SIZE_T)strlen( lpClipString ) + 1;

		// do the "use the right kind of memory once locked" clip board data dance.
		// Note that we don't free up the memory we've allocated with GlobalAlloc
		// because the windows clipboard magic does it for us.
		if( (hClipboardData = pGlobalAlloc( GMEM_MOVEABLE | GMEM_DDESHARE, cbStringBytes )) == NULL ) {
			dwResult = GetLastError();
			pCloseClipboard();
			BREAK_WITH_ERROR( "Failed to allocate clipboard memory", dwResult );
		}

		lpLockedData = (PCHAR)pGlobalLock( hClipboardData );

		memcpy_s( lpLockedData, cbStringBytes, lpClipString, cbStringBytes );

		pGlobalUnlock( hClipboardData );

		// Try to get a lock on the clipboard
		if( !pOpenClipboard( NULL ) ) {
			dwResult = GetLastError();
			BREAK_WITH_ERROR( "Unable to open the clipboard", dwResult );
		}

		// Clear the clipboard data
		pEmptyClipboard();

		if( !pSetClipboardData( CF_TEXT, hClipboardData ) ) {
			dwResult = GetLastError();
			dprintf( "Failed to set the clipboad data: %u", dwResult );
		} else {
			dwResult = ERROR_SUCCESS;
		}

		pCloseClipboard();

	} while(0);

	// If something went wrong and we have clipboard data, then we need to
	// free it up because the clipboard can't do it for us.
	if( dwResult != ERROR_SUCCESS && hClipboardData != NULL ) {
		dprintf( "Searching for GlobalFree" );
		if( (pGlobalFree = (PGLOBALFREE)GetProcAddress( hKernel32, "GlobalFree" )) != NULL )
			pGlobalFree( hClipboardData );
	}

	if( hKernel32 )
		FreeLibrary( hKernel32 );

	if( hUser32 )
		FreeLibrary( hUser32 );

	packet_transmit_empty_response( remote, packet, dwResult );

	return dwResult;
#else
	return ERROR_NOT_SUPPORTED;
#endif
}