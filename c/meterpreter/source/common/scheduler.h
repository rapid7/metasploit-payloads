#ifndef _METERPRETER_LIB_SCHEDULER_H
#define _METERPRETER_LIB_SCHEDULER_H

#include "linkage.h"
#include "remote.h"

typedef enum
{
	Pause  = 1,
	Resume = 2,
	Stop   = 3
} SchedularSignal;

typedef DWORD (*WaitableNotifyRoutine)(Remote *remote, LPVOID entryContext, LPVOID threadContext);
typedef DWORD (*WaitableDestroyRoutine)(HANDLE waitable, LPVOID entryContext, LPVOID threadContext);

LINKAGE DWORD scheduler_initialize( Remote * remote );
LINKAGE DWORD scheduler_destroy( VOID );
LINKAGE DWORD scheduler_insert_waitable( HANDLE waitable, LPVOID entryContext, LPVOID threadContext, WaitableNotifyRoutine routine, WaitableDestroyRoutine destroy );
LINKAGE DWORD scheduler_signal_waitable( HANDLE waitable, SchedularSignal signal );
LINKAGE DWORD THREADCALL scheduler_waitable_thread( THREAD * thread );

#endif
