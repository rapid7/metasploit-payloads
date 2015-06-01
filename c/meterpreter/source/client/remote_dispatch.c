#include "metcli.h"


/*
 * Extension callback for printing out notifications for channels opening
 */
DWORD ex_remote_response_core_channel_open(Remote *remote, Packet *packet)
{
	DWORD channelId = packet_get_tlv_value_uint(packet, TLV_TYPE_CHANNEL_ID);

	if (channelId)
	{
		console_write_output(
				"\n"
				INBOUND_PREFIX " CHANNEL: New remote channel allocated: %lu.\n", 
				channelId);

		console_write_prompt();
	}

	return ERROR_SUCCESS;
}

/*
 * Extension callback for printing out notifications for when the remote
 * endpoint is telling us to close a channel
 */
DWORD ex_remote_request_core_channel_close(Remote *remote, Packet *packet)
{
	DWORD channelId = packet_get_tlv_value_uint(packet, TLV_TYPE_CHANNEL_ID);

	if (channelId)
	{
		// If an interactive channel is closing, reset it
		if (channelId == console_get_interactive_channel_id())
			console_set_interactive_channel(remote, NULL);
	}

	return ERROR_SUCCESS;
}


/****************************
 * Custom dispatch routines *
 ****************************/

// Dispatch table
Command customCommands[] = 
{
	COMMAND_REP("core_channel_open", ex_remote_response_core_channel_open),
	COMMAND_REP("core_channel_close", ex_remote_response_core_channel_cloase),
	COMMAND_TERMINATOR
};


/*
 * Registers custom command handlers
 */
VOID remote_register_core_dispatch_routines()
{
	command_register_all(customCommands);
}

/*
 * Deregisters previously registered custom commands
 */
VOID remote_deregister_core_dispatch_routines()
{
	command_deregister_all(customCommands);
}
