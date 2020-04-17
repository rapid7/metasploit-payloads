#include "metsrv.h"
#include "pivot_packet_dispatch.h"

DWORD THREADCALL pivot_packet_dispatch_thread(THREAD* thread)
{
	dprintf("[PIVOTPACKETTHREAD] Dispatching packet on thread %p", thread);
	PivotContext* pivotCtx = (PivotContext*)thread->parameter1;
	LPBYTE packetBuffer = (LPBYTE)thread->parameter2;
	DWORD packetSize = (DWORD)(DWORD_PTR)thread->parameter3;
	DWORD result = pivotCtx->packet_write(pivotCtx->state, packetBuffer, packetSize);
	dprintf("[PIVOTPACKETTHREAD] Packet dispatched: %u (%x)", result, result);
	free(packetBuffer);
	dprintf("[PIVOTPACKETTHREAD] Cleaning up the thread");
	thread_destroy(thread);
	dprintf("[PIVOTPACKETTHREAD] Done");
	return result;
}

DWORD pivot_packet_dispatch(PivotContext* pivotCtx, LPBYTE packetBuffer, DWORD packetSize)
{
	THREAD* thread = thread_create(pivot_packet_dispatch_thread, pivotCtx, packetBuffer, (LPVOID)(DWORD_PTR)packetSize);
	if (thread)
	{
		dprintf("[PIVOTPACKET] Dispatching packet on new thread %p", thread);
		thread_run(thread);
		dprintf("[PIVOTPACKET] Thread invoked %p", thread);
		return ERROR_SUCCESS;
	}
	dprintf("[PIVOTPACKET] Failed to create packet dispatch thread");
	return ERROR_OUTOFMEMORY;
}