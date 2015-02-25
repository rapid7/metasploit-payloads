#pragma once

//#define KIWIDEBUGTRACE

#ifdef KIWIDEBUGTRACE
#define dprintf(...) real_dprintf(__VA_ARGS__)
#else
#define dprintf(...) do{}while(0);
#endif

/*! @brief Sets `dwResult` to the return value of `GetLastError()`, prints debug output, then does `break;` */
#define BREAK_ON_ERROR( str ) { dwResult = GetLastError(); dprintf( L"%s. error=%d (0x%u)", str, dwResult, (ULONG_PTR)dwResult ); break; }
/*! @brief Sets `dwResult` to `error`, prints debug output, then `break;` */
#define BREAK_WITH_ERROR( str, err ) { dwResult = err; dprintf( L"%s. error=%d (0x%u)", str, dwResult, (ULONG_PTR)dwResult ); break; }
/*! @brief Sets `dwResult` to the return value of `WASGetLastError()`, prints debug output, then does `break;` */
#define BREAK_ON_WSAERROR( str ) { dwResult = WSAGetLastError(); dprintf( L"%s. error=%d (0x%u)", str, dwResult, (ULONG_PTR)dwResult ); break; }
/*! @brief Sets `dwResult` to the return value of `GetLastError()`, prints debug output, then does `continue;` */
#define CONTINUE_ON_ERROR( str ) { dwResult = GetLastError(); dprintf( L"%s. error=%d (0x%u)", str, dwResult, (ULONG_PTR)dwResult ); continue; }

/*! @brief Close a service handle if not already closed and set the handle to NULL. */
#define CLOSE_SERVICE_HANDLE( h )  if( h ) { CloseServiceHandle( h ); h = NULL; }
/*! @brief Close a handle if not already closed and set the handle to NULL. */
#define CLOSE_HANDLE( h )          if( h ) { DWORD dwHandleFlags; if(GetHandleInformation( h , &dwHandleFlags)) CloseHandle( h ); h = NULL; }

static _inline void real_dprintf(wchar_t *format, ...) {
	va_list args;
	wchar_t buffer[1024];
	va_start(args,format);
	_vsnwprintf_s(buffer, sizeof(buffer), sizeof(buffer)-3, format, args);
	wcscat_s(buffer, sizeof(buffer), L"\r\n");
	OutputDebugStringW(buffer);
}
