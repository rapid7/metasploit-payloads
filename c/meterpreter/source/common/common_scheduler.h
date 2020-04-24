#ifndef _METERPRETER_COMMON_SCHEDULER_H
#define _METERPRETER_COMMON_SCHEDULER_H

typedef enum
{
	SchedulerPause  = 1,
	SchedulerResume = 2,
	SchedulerStop   = 3
} SchedulerSignal;

typedef DWORD (*WaitableNotifyRoutine)(Remote *remote, LPVOID entryContext, LPVOID threadContext);
typedef DWORD (*WaitableDestroyRoutine)(HANDLE waitable, LPVOID entryContext, LPVOID threadContext);

#endif
