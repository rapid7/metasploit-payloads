#include "metsrv.h"

#ifndef _WIN32
#include <poll.h>
#endif

typedef struct _WaitableEntry
{
        Remote *               remote;
        HANDLE                 waitable;
        EVENT*                 pause;
        EVENT*                 resume;
        LPVOID                 context;
        BOOL                   running;
        WaitableNotifyRoutine  routine;
        WaitableDestroyRoutine destroy;
} WaitableEntry;

/*
 * The list of all currenltly running threads in the scheduler subsystem.
 */
LIST * schedulerThreadList = NULL;

/*
 * The Remote that is associated with the scheduler subsystem
 */
Remote * schedulerRemote   = NULL;

/*
 * Initialize the scheduler subsystem. Must be called before any calls to scheduler_insert_waitable.
 */
DWORD scheduler_initialize( Remote * remote )
{
	DWORD result = ERROR_SUCCESS;

	dprintf( "[SCHEDULER] entering scheduler_initialize." );

	if( remote == NULL )
		return ERROR_INVALID_HANDLE;

	schedulerThreadList = list_create();
	if( schedulerThreadList == NULL )
		return ERROR_INVALID_HANDLE;

	schedulerRemote = remote;

	dprintf( "[SCHEDULER] leaving scheduler_initialize." );

	return result;
}

/*
 * Destroy the scheduler subsystem. All waitable threads at signaled to terminate.
 * this function blocks untill all waitable threads have terminated.
 */
DWORD scheduler_destroy(VOID)
{
	DWORD result = ERROR_SUCCESS;
	DWORD index = 0;
	DWORD count = 0;
	LIST * jlist = list_create();
	THREAD * thread = NULL;
	WaitableEntry * entry = NULL;

	dprintf("[SCHEDULER] entering scheduler_destroy.");

	if (schedulerThreadList == NULL)
	{
		return ERROR_SUCCESS;
	}

	lock_acquire(schedulerThreadList->lock);

	count = list_count(schedulerThreadList);

	for (index = 0; index < count; index++)
	{
		thread = (THREAD *)list_get(schedulerThreadList, index);
		if (thread == NULL)
		{
			continue;
		}

		list_push(jlist, thread);

		entry = (WaitableEntry *)thread->parameter1;

		if (!entry->running)
		{
			event_signal(entry->resume);
		}

		thread_sigterm(thread);
	}

	lock_release(schedulerThreadList->lock);

	dprintf("[SCHEDULER] scheduler_destroy, joining all waitable threads...");

	while (TRUE)
	{
		dprintf("[SCHEDULER] scheduler_destroy, popping off another item from thread list...");

		thread = (THREAD *)list_pop(jlist);
		if (thread == NULL)
		{
			break;
		}

		dprintf("[SCHEDULER] scheduler_destroy, joining thread 0x%08X...", thread);

		thread_join(thread);
	}

	dprintf("[SCHEDULER] scheduler_destroy, destroying lists...");

	list_destroy(jlist);

	list_destroy(schedulerThreadList);

	schedulerThreadList = NULL;

	dprintf("[SCHEDULER] leaving scheduler_destroy.");

	return result;
}

/*
 * Insert a new waitable thread for checking and processing.
 */
DWORD scheduler_insert_waitable( HANDLE waitable, LPVOID entryContext, LPVOID threadContext, WaitableNotifyRoutine routine, WaitableDestroyRoutine destroy )
{
	DWORD result = ERROR_SUCCESS;
	THREAD * swt = NULL;

	WaitableEntry * entry = (WaitableEntry *)malloc( sizeof( WaitableEntry ) );
	if( entry == NULL )
		return ERROR_NOT_ENOUGH_MEMORY;

	dprintf( "[SCHEDULER] entering scheduler_insert_waitable( 0x%08X, 0x%08X, 0x%08X, 0x%08X, 0x%08X )",
		waitable, entryContext, threadContext, routine, destroy );

	memset( entry, 0, sizeof( WaitableEntry ) );

	entry->remote   = schedulerRemote;
	entry->waitable = waitable;
	entry->destroy  = destroy;
	entry->context  = entryContext;
	entry->routine  = routine;
	entry->pause    = event_create();
	entry->resume   = event_create();

	swt = thread_create( scheduler_waitable_thread, entry, threadContext, NULL );
	if( swt != NULL )
	{
		dprintf( "[SCHEDULER] created scheduler_waitable_thread 0x%08X", swt );
		thread_run( swt );
	}
	else
	{
		free( entry );
		result = ERROR_INVALID_HANDLE;
	}

	dprintf( "[SCHEDULER] leaving scheduler_insert_waitable" );

	return result;
}

/*
 * Signal a waitable object.
 */
DWORD scheduler_signal_waitable(HANDLE waitable, SchedulerSignal signal)
{
	DWORD index = 0;
	DWORD count = 0;
	THREAD* thread = NULL;
	WaitableEntry* entry = NULL;
	DWORD result = ERROR_NOT_FOUND;

	dprintf("[SCHEDULER] entering scheduler_signal_waitable( 0x%08X )", waitable);

	if (schedulerThreadList == NULL || !waitable)
		return ERROR_INVALID_HANDLE;

	lock_acquire(schedulerThreadList->lock);

	count = list_count(schedulerThreadList);

	for (index = 0; index < count; index++)
	{
		thread = (THREAD*)list_get(schedulerThreadList, index);
		if (thread == NULL)
			continue;

		entry = (WaitableEntry*)thread->parameter1;
		if (entry == NULL)
			continue;

		if (entry->waitable == waitable)
		{
			dprintf("[SCHEDULER] scheduler_signal_waitable: signaling waitable = 0x%08X, thread = 0x%08X", waitable, thread);
			if (signal == SchedulerPause)
			{
				if (entry->running) {
					dprintf("[SCHEDULER] scheduler_signal_waitable: thread running, pausing. waitable = 0x%08X, thread = 0x%08X, handle = 0x%X", waitable, thread, entry->pause->handle);
					event_signal(entry->pause);
				}
				else {
					dprintf("[SCHEDULER] scheduler_signal_waitable: thread already paused. waitable = 0x%08X, thread = 0x%08X", waitable, thread);
				}
			}
			else
			{
				if (!entry->running) {
					dprintf("[SCHEDULER] scheduler_signal_waitable: thread paused, resuming. waitable = 0x%08X, thread = 0x%08X, handle = 0x%X", waitable, thread, entry->resume->handle);
					event_signal(entry->resume);
				}

				if (signal == SchedulerStop) {
					dprintf("[SCHEDULER] scheduler_signal_waitable: stopping thread. waitable = 0x%08X, thread = 0x%08X, handle = 0x%X", waitable, thread, thread->sigterm->handle);
					thread_sigterm(thread);
				}
				else {
					dprintf("[SCHEDULER] scheduler_signal_waitable: thread already running. waitable = 0x%08X, thread = 0x%08X", waitable, thread);
				}
			}

			result = ERROR_SUCCESS;
			break;
		}
	}

	lock_release(schedulerThreadList->lock);

	dprintf("[SCHEDULER] leaving scheduler_signal_waitable");

	return result;
}

/*
 * The schedulers waitable thread. Each scheduled item will have its own thread which
 * waits for either data to process or the threads signal to terminate.
 */
DWORD THREADCALL scheduler_waitable_thread( THREAD * thread )
{
	HANDLE waitableHandles[3] = {0};

	WaitableEntry * entry     = NULL;
	DWORD result              = 0;
	BOOL terminate            = FALSE;
	UINT signalIndex          = 0;

	if( thread == NULL )
		return ERROR_INVALID_HANDLE;

	entry = (WaitableEntry *)thread->parameter1;
	if( entry == NULL )
		return ERROR_INVALID_HANDLE;

	if( entry->routine == NULL )
		return ERROR_INVALID_HANDLE;

	if( schedulerThreadList == NULL )
		return ERROR_INVALID_HANDLE;

	list_add( schedulerThreadList, thread );

	waitableHandles[0] = thread->sigterm->handle;
	waitableHandles[1] = entry->pause->handle;
	waitableHandles[2] = entry->waitable;

	dprintf( "[SCHEDULER] entering scheduler_waitable_thread( 0x%08X )", thread );

	entry->running = TRUE;
	while( !terminate )
	{
		dprintf( "[SCHEDULER] About to wait ( 0x%08X )", thread );
		result = WaitForMultipleObjects( 3, waitableHandles, FALSE, INFINITE );
		dprintf( "[SCHEDULER] Wait returned ( 0x%08X )", thread );
		signalIndex = result - WAIT_OBJECT_0;
		switch( signalIndex )
		{
			case 0:
				dprintf( "[SCHEDULER] scheduler_waitable_thread( 0x%08X ), signaled to terminate...", thread );
				terminate = TRUE;
				break;
			case 1:
				dprintf( "[SCHEDULER] scheduler_waitable_thread( 0x%08X ), signaled to pause...", thread );
				entry->running = FALSE;
				event_poll( entry->resume, INFINITE );
				entry->running = TRUE;
				dprintf( "[SCHEDULER] scheduler_waitable_thread( 0x%08X ), signaled to resume...", thread );
			case 2:
				//dprintf( "[SCHEDULER] scheduler_waitable_thread( 0x%08X ), signaled on waitable...", thread );
				entry->routine( entry->remote, entry->context, thread->parameter2 );
				break;
			default:
				break;
		}
	}

	dprintf( "[SCHEDULER] leaving scheduler_waitable_thread( 0x%08X )", thread );

	// we acquire the lock for this block as we are freeing 'entry' which may be accessed
	// in a second call to scheduler_signal_waitable for this thread (unlikely but best practice).
	lock_acquire( schedulerThreadList->lock );
	if( list_remove( schedulerThreadList, thread ) )
	{
		if( entry->destroy ) {
			entry->destroy( entry->waitable, entry->context, thread->parameter2 );
		}
		else if( entry->waitable ) {
			dprintf( "[SCHEDULER] scheduler_waitable_thread( 0x%08X ) closing handle 0x%08X", thread, entry->waitable);
			CloseHandle( entry->waitable );
		}

		event_destroy( entry->resume );
		event_destroy( entry->pause );
		thread_destroy( thread );
		free( entry );
	}
	lock_release( schedulerThreadList->lock );

	return ERROR_SUCCESS;
}

