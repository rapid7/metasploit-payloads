#include "metsrv.h"
#include "server_pivot.h"
#include "server_pivot_named_pipe.h"

/*!
 * @brief Add a pivot point to the current meterpreter session
 * @remote Pointer to the \c Remote instance.
 * @remote Pointer to the incoming request \c Packet instance.
 * @return Indication of error or success.
 * @remark This allows for meterpreter to become a staging and pivot point
 *         for other Meterpreter instances on the network.
 */
DWORD request_core_pivot_add(Remote* remote, Packet* packet)
{
	// Right now we only support named pipe pivotes, so just go straight there
	return request_core_pivot_add_named_pipe(remote, packet);
}

/*!
 * @brief Remove a pivot point from the current Meterpreter instance.
 * @remote Pointer to the \c Remote instance.
 * @remote Pointer to the incoming request \c Packet instance.
 * @return Indication of error or success.
 */
DWORD request_core_pivot_remove(Remote* remote, Packet* packet)
{
	DWORD result = ERROR_NOT_FOUND;
	DWORD pivotIdLen = 0;
	LPBYTE pivotId = packet_get_tlv_value_raw(packet, TLV_TYPE_PIVOT_ID, &pivotIdLen);

	if (pivotId != NULL)
	{
		PivotContext* ctx = pivot_tree_remove(remote->pivot_listeners, pivotId);
#ifdef DEBUGTRACE
			dprintf("[PIVOTTREE] Pivot listeners (after one removed)");
			dbgprint_pivot_tree(remote->pivot_listeners);
#endif
		if (ctx != NULL)
		{
			ctx->remove(ctx->state);
			free(ctx);
			result = ERROR_SUCCESS;
		}
	}

	packet_transmit_empty_response(remote, packet, result);

	return result;
}
