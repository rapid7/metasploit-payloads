#ifndef _METERPRETER_METSRV_THREAD_H
#define _METERPRETER_METSRV_THREAD_H

#include "common_thread.h"

/*****************************************************************************************/
// Win32/64 specific definitions...

typedef HANDLE (WINAPI * OPENTHREAD)( DWORD, BOOL, DWORD ); // kernel32!OpenThread
/*****************************************************************************************/

LOCK * lock_create( VOID );

VOID lock_destroy( LOCK * lock );

VOID lock_acquire( LOCK * lock );

VOID lock_release( LOCK * lock );

/*****************************************************************************************/

EVENT * event_create( VOID );

BOOL event_destroy( EVENT * event );

BOOL event_signal( EVENT * event );

BOOL event_poll( EVENT * event, DWORD timeout );

/*****************************************************************************************/

THREAD * thread_open( VOID );

THREAD * thread_create( THREADFUNK funk, LPVOID param1, LPVOID param2, LPVOID param3 );

void disable_thread_error_reporting(void);

BOOL thread_run( THREAD * thread );

BOOL thread_sigterm( THREAD * thread );

BOOL thread_kill( THREAD * thread );

BOOL thread_join( THREAD * thread );

BOOL thread_destroy( THREAD * thread );

/*****************************************************************************************/

#endif
