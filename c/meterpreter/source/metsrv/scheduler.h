#ifndef _METERPRETER_METSRV_SCHEDULER_H
#define _METERPRETER_METSRV_SCHEDULER_H

#include "remote.h"
#include "common_scheduler.h"

DWORD scheduler_initialize( Remote * remote );
DWORD scheduler_destroy( VOID );
DWORD scheduler_insert_waitable( HANDLE waitable, LPVOID entryContext, LPVOID threadContext, WaitableNotifyRoutine routine, WaitableDestroyRoutine destroy );
DWORD scheduler_signal_waitable( HANDLE waitable, SchedulerSignal signal );
DWORD THREADCALL scheduler_waitable_thread( THREAD * thread );

#endif
