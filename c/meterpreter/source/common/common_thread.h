#ifndef _METERPRETER_COMMON_THREAD_H
#define _METERPRETER_COMMON_THREAD_H

typedef struct _LOCK
{
	HANDLE handle;
} LOCK, * LPLOCK;

typedef struct _EVENT
{
	HANDLE handle;
} EVENT, * LPEVENT;

#define THREADCALL __stdcall

typedef DWORD (THREADCALL * THREADFUNK)(struct _THREAD * thread);

struct _THREAD
{
	DWORD id;
	HANDLE handle;
	EVENT * sigterm;
	THREADFUNK funk;
	LPVOID parameter1;
	LPVOID parameter2;
	LPVOID parameter3;
};

typedef struct _THREAD THREAD, * LPTHREAD;

#endif
