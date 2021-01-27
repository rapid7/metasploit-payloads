/*!
 * @file base.c
 * @brief Definitions that apply to almost any Meterpreter component.
 */
#include "metsrv.h"

// TODO: move these to a header?
// Local remote request implementors
DWORD remote_request_core_console_write(Remote *remote, Packet *packet);
DWORD remote_request_core_channel_open(Remote *remote, Packet *packet);
DWORD remote_request_core_channel_write(Remote *remote, Packet *packet);
DWORD remote_request_core_channel_read(Remote *remote, Packet *packet);
DWORD remote_request_core_channel_close(Remote *remote, Packet *packet);
DWORD remote_request_core_channel_seek(Remote *remote, Packet *packet);
DWORD remote_request_core_channel_eof(Remote *remote, Packet *packet);
DWORD remote_request_core_channel_tell(Remote *remote, Packet *packet);
DWORD remote_request_core_channel_interact(Remote *remote, Packet *packet);
BOOL remote_request_core_shutdown(Remote *remote, Packet *packet, DWORD* pResult);
DWORD remote_request_core_transport_set_timeouts(Remote * remote, Packet * packet);
DWORD remote_request_core_transport_getcerthash(Remote* remote, Packet* packet);
DWORD remote_request_core_transport_setcerthash(Remote* remote, Packet* packet);
BOOL remote_request_core_transport_sleep(Remote* remote, Packet* packet, DWORD* result);
DWORD remote_request_core_transport_list(Remote* remote, Packet* packet);
BOOL remote_request_core_transport_change(Remote* remote, Packet* packet, DWORD* result);
BOOL remote_request_core_transport_next(Remote* remote, Packet* packet, DWORD* result);
BOOL remote_request_core_transport_prev(Remote* remote, Packet* packet, DWORD* result);
DWORD remote_request_core_transport_add(Remote* remote, Packet* packet);
DWORD remote_request_core_transport_remove(Remote* remote, Packet* packet);
BOOL remote_request_core_migrate(Remote *remote, Packet *packet, DWORD* pResult);
DWORD request_negotiate_aes_key(Remote* remote, Packet* packet);

// Local remote response implementors
DWORD remote_response_core_console_write(Remote *remote, Packet *packet);
DWORD remote_response_core_channel_open(Remote *remote, Packet *packet);
DWORD remote_response_core_channel_close(Remote *remote, Packet *packet);

DWORD remote_request_core_console_write(Remote *remote, Packet *packet)
{
	return ERROR_SUCCESS;
}

DWORD remote_response_core_console_write(Remote *remote, Packet *packet)
{
	return ERROR_SUCCESS;
}

BOOL command_is_inline(Command *command, Packet *packet);
Command* command_locate(Packet *packet);
DWORD command_validate_arguments(Command *command, Packet *packet);
DWORD THREADCALL command_process_thread(THREAD * thread);


/*!
 * @brief Base RPC dispatch table.
 */
Command baseCommands[] =
{
	// Console commands
	{ COMMAND_ID_CORE_CONSOLE_WRITE,
		{ remote_request_core_console_write, NULL, { TLV_META_TYPE_STRING }, 1 | ARGUMENT_FLAG_REPEAT },
		{ remote_response_core_console_write, NULL, EMPTY_TLV },
	},

	// Native Channel commands
	// this overloads the COMMAND_ID_CORE_CHANNEL_OPEN in the base command list
	COMMAND_REQ_REP(COMMAND_ID_CORE_CHANNEL_OPEN, remote_request_core_channel_open, remote_response_core_channel_open),
	COMMAND_REQ(COMMAND_ID_CORE_CHANNEL_WRITE, remote_request_core_channel_write),
	COMMAND_REQ_REP(COMMAND_ID_CORE_CHANNEL_CLOSE, remote_request_core_channel_close, remote_response_core_channel_close),

	// Buffered/Pool channel commands
	COMMAND_REQ(COMMAND_ID_CORE_CHANNEL_READ, remote_request_core_channel_read),
	// Pool channel commands
	COMMAND_REQ(COMMAND_ID_CORE_CHANNEL_SEEK, remote_request_core_channel_seek),
	COMMAND_REQ(COMMAND_ID_CORE_CHANNEL_EOF, remote_request_core_channel_eof),
	COMMAND_REQ(COMMAND_ID_CORE_CHANNEL_TELL, remote_request_core_channel_tell),
	// Soon to be deprecated
	COMMAND_REQ(COMMAND_ID_CORE_CHANNEL_INTERACT, remote_request_core_channel_interact),
	// Packet Encryption
	COMMAND_REQ(COMMAND_ID_CORE_NEGOTIATE_TLV_ENCRYPTION, request_negotiate_aes_key),
	// timeouts
	COMMAND_REQ(COMMAND_ID_CORE_TRANSPORT_SET_TIMEOUTS, remote_request_core_transport_set_timeouts),

	COMMAND_REQ(COMMAND_ID_CORE_TRANSPORT_GETCERTHASH, remote_request_core_transport_getcerthash),
	COMMAND_REQ(COMMAND_ID_CORE_TRANSPORT_SETCERTHASH, remote_request_core_transport_setcerthash),

	COMMAND_REQ(COMMAND_ID_CORE_TRANSPORT_LIST, remote_request_core_transport_list),
	COMMAND_INLINE_REQ(COMMAND_ID_CORE_TRANSPORT_SLEEP, remote_request_core_transport_sleep),
	COMMAND_INLINE_REQ(COMMAND_ID_CORE_TRANSPORT_CHANGE, remote_request_core_transport_change),
	COMMAND_INLINE_REQ(COMMAND_ID_CORE_TRANSPORT_NEXT, remote_request_core_transport_next),
	COMMAND_INLINE_REQ(COMMAND_ID_CORE_TRANSPORT_PREV, remote_request_core_transport_prev),
	COMMAND_REQ(COMMAND_ID_CORE_TRANSPORT_ADD, remote_request_core_transport_add),
	COMMAND_REQ(COMMAND_ID_CORE_TRANSPORT_REMOVE, remote_request_core_transport_remove),
	// Migration
	COMMAND_INLINE_REQ(COMMAND_ID_CORE_MIGRATE, remote_request_core_migrate),
	// Shutdown
	COMMAND_INLINE_REQ(COMMAND_ID_CORE_SHUTDOWN, remote_request_core_shutdown),
	// Terminator
	COMMAND_TERMINATOR
};

/*!
 * @brief Dynamically registered command extensions.
 * @details A doubly-linked list of commands registered on the fly by reflectively-loaded extensions.
 */
Command* extensionCommands = NULL;

/*!
 * @brief Register dispatch routines provided by the meterpreter core.
 * @return Returns the first command of the array of commands that were registered.
 */
Command* register_base_dispatch_routines(void)
{
	Command* pFirstCommand = NULL;
	command_register_all(baseCommands);

	pFirstCommand = extensionCommands;
	while (pFirstCommand && pFirstCommand->command_id != baseCommands[0].command_id) {
		pFirstCommand = pFirstCommand->next;
	}
	return pFirstCommand;
}

/*!
 * @brief Deregister dispatch routines provided by the meterpreter core.
 */
void deregister_base_dispatch_routines(void)
{
	command_deregister_all(baseCommands);
}

/*!
 * @brief Register a full list of commands with meterpreter.
 * @param commands The array of commands that are to be registered for the module/extension.
 */
void command_register_all(Command commands[])
{
	DWORD index;

	// Zero indicates the end of the command list
	for (index = 0; commands[index].command_id > 0; index++)
	{
		command_register(&commands[index]);
	}

#ifdef DEBUGTRACE
	Command* command;

	dprintf("[COMMAND LIST] Listing current extension commands");
	for (command = extensionCommands; command; command = command->next)
	{
		dprintf("[COMMAND LIST] Found: %u", command->command_id);
	}
#endif
}

/*!
 * @brief Dynamically register a custom command handler
 * @param command Pointer to the command that should be registered.
 * @return `ERROR_SUCCESS` when command registers successfully, otherwise returns the error.
 */
DWORD command_register(Command *command)
{
	Command *newCommand;

	dprintf("Registering a new command (%u)...", command->command_id);
	if (!(newCommand = (Command *)malloc(sizeof(Command))))
	{
		return ERROR_NOT_ENOUGH_MEMORY;
	}

	dprintf("Allocated memory...");
	memcpy(newCommand, command, sizeof(Command));

	dprintf("Setting new command...");
	if (extensionCommands)
	{
		extensionCommands->prev = newCommand;
	}

	dprintf("Fixing next/prev... %p", newCommand);
	newCommand->next = extensionCommands;
	newCommand->prev = NULL;
	extensionCommands = newCommand;

	dprintf("Done...");
	return ERROR_SUCCESS;
}

/*!
 * @brief Deregister a full list of commands from meterpreter.
 * @param commands The array of commands that are to be deregistered from the module/extension.
 */
void command_deregister_all(Command commands[])
{
	DWORD index;

	for (index = 0; commands[index].command_id > 0; index++)
	{
		command_deregister(&commands[index]);
	}
}

/*!
 * @brief Dynamically deregister a custom command handler
 * @param command Pointer to the command that should be deregistered.
 * @return `ERROR_SUCCESS` when command deregisters successfully, otherwise returns the error.
 */
DWORD command_deregister(Command *command)
{
	Command *current, *prev;
	DWORD res = ERROR_NOT_FOUND;

	// Search the extension list for the command
	for (current = extensionCommands, prev = NULL;
		current;
		prev = current, current = current->next)
	{
		if (command->command_id == current->command_id)
		{
			continue;
		}

		if (prev)
		{
			prev->next = current->next;
		}
		else
		{
			extensionCommands = current->next;
		}

		if (current->next)
		{
			current->next->prev = prev;
		}

		// Deallocate it
		free(current);

		res = ERROR_SUCCESS;

		break;
	}

	return res;
}

/*! @brief A list of all command threads currenlty executing. */
LIST * commandThreadList = NULL;

/*!
 * @brief Block untill all running command threads have finished.
 */
VOID command_join_threads(VOID)
{
	while (list_count(commandThreadList) > 0)
	{
		THREAD * thread = (THREAD *)list_get(commandThreadList, 0);
		if (thread)
		{
			thread_join(thread);
		}
	}
}

/*!
 * @brief Process a command directly on the current thread.
 * @param command Pointer to the \c Command in the extension command list to be executed.
 * @param remote Pointer to the \c Remote endpoint for this command.
 * @param packet Pointer to the \c Packet containing the command detail.
 * @returns Boolean value indicating if the server should continue processing.
 * @retval TRUE The server can and should continue processing.
 * @retval FALSE The server should stop processing and shut down.
 * @sa command_handle
 * @sa command_process_thread
 * @remarks The \c baseCommand is always executed first, but if there is an \c extensionCommand
 *          then the result of the \c baseCommand processing is ignored and the result of
 *          \c extensionCommand is returned instead.
 */
BOOL command_process_inline(Command *command, Remote *remote, Packet *packet)
{
	DWORD result;
	BOOL serverContinue = TRUE;
	Tlv requestIdTlv;
	PCHAR requestId;
	PacketTlvType packetTlvType;
	UINT commandId = 0;

	__try
	{
		do
		{
			commandId = command->command_id;
			dprintf("[COMMAND] Executing command %u", commandId);

			// Impersonate the thread token if needed (only on Windows)
			if (remote->server_token != remote->thread_token)
			{
				if (!ImpersonateLoggedOnUser(remote->thread_token))
				{
					dprintf("[COMMAND] Failed to impersonate thread token (%u) (%u)", commandId, GetLastError());
				}
			}

			// Validate the arguments, if requested.  Always make sure argument
			// lengths are sane.
			if (command_validate_arguments(command, packet) != ERROR_SUCCESS)
			{
				dprintf("[COMMAND] Command arguments failed to validate");
				continue;
			}

			packetTlvType = packet_get_type(packet);
			dprintf("[DISPATCH] Packet type for %u is %u", commandId, packetTlvType);
			switch (packetTlvType)
			{
			case PACKET_TLV_TYPE_REQUEST:
			case PACKET_TLV_TYPE_PLAIN_REQUEST:
				if (command->request.inline_handler) {
					dprintf("[DISPATCH] executing inline request handler %u", commandId);
					serverContinue = command->request.inline_handler(remote, packet, &result) && serverContinue;
					dprintf("[DISPATCH] executed %u, continue %s", commandId, serverContinue ? "yes" : "no");
				}
				else
				{
					dprintf("[DISPATCH] executing request handler %u", commandId);
					result = command->request.handler(remote, packet);
				}
				break;
			case PACKET_TLV_TYPE_RESPONSE:
			case PACKET_TLV_TYPE_PLAIN_RESPONSE:
				if (command->response.inline_handler)
				{
					dprintf("[DISPATCH] executing inline response handler %u", commandId);
					serverContinue = command->response.inline_handler(remote, packet, &result) && serverContinue;
				}
				else
				{
					dprintf("[DISPATCH] executing response handler %u", commandId);
					result = command->response.handler(remote, packet);
				}
				break;
			}

			dprintf("[COMMAND] Calling completion handlers...");

			// Get the request identifier if the packet has one.
			if (packet_get_tlv_string(packet, TLV_TYPE_REQUEST_ID, &requestIdTlv) == ERROR_SUCCESS)
			{
				requestId = (PCHAR)requestIdTlv.buffer;
			}

			// Finally, call completion routines for the provided identifier
			if (((packetTlvType == PACKET_TLV_TYPE_RESPONSE) || (packetTlvType == PACKET_TLV_TYPE_PLAIN_RESPONSE)) && requestId)
			{
				packet_call_completion_handlers(remote, packet, requestId);
			}

			dprintf("[COMMAND] Completion handlers finished for %u.", commandId);
		} while (0);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		dprintf("[COMMAND] Exception hit in command %u", commandId);
	}

	if (!packet->local)
	{
		dprintf("[COMMAND] Packet is not local, destroying");
		packet_destroy(packet);
		dprintf("[COMMAND] Packet destroyed");
	}

	dprintf("[COMMAND] Command processing finishing. Returning: %s", (serverContinue ? "TRUE" : "FALSE"));
	return serverContinue;
}


/*!
 * @brief Attempt to locate a command in the extensions command list.
 * @param commandId ID of the command to locate the associatd extension for.
 * @returns Pointer to the command entry in the extensions command list.
 * @retval NULL Indicates that no command was found for the given commandId.
 * @retval NON-NULL Pointer to the command that can be executed.
 */
Command* command_locate_extension(UINT commandId)
{
	Command* command;

	dprintf("[COMMAND EXEC] Attempting to locate extension command %u (%p)", commandId, extensionCommands);
	for (command = extensionCommands; command; command = command->next)
	{
		if (command->command_id == commandId)
		{
			return command;
		}
	}

	dprintf("[COMMAND EXEC] Couldn't find extension command %u", commandId);
	return NULL;
}

/*!
 * @brief Handle an incoming command.
 * @param remote Pointer to the \c Remote instance associated with this command.
 * @param packet Pointer to the \c Packet containing the command data.
 * @retval TRUE The server can and should continue processing.
 * @retval FALSE The server should stop processing and shut down.
 * @remark This function was incorporate to help support two things in meterpreter:
 *         -# A way of allowing a command to be processed directly on the main server
 *            thread and not on another thread (which in some cases can cause problems).
 *         -# A cleaner way of shutting down the server so that container processes
 *            can shutdown cleanly themselves, where appropriate.
 *
 *         This function will look at the command definition and determine if it should
 *         be executed inline or on a new command thread.
 * @sa command_process_inline
 * @sa command_process_thread
 */
BOOL command_handle(Remote *remote, Packet *packet)
{
	BOOL result = TRUE;
	THREAD* cpt = NULL;
	Command* command = NULL;
	Packet* response = NULL;

	UINT commandId = packet_get_tlv_value_uint(packet, TLV_TYPE_COMMAND_ID);

	do
	{

		if (commandId == 0)
		{
			dprintf("[COMMAND] Unable to extract commandId from packet.");
			break;
		}

		command = command_locate_extension(commandId);

		if (command == NULL)
		{
			dprintf("[DISPATCH] Command not found: %u", commandId);
			// We have no matching command for this packet, so it won't get handled. We
			// need to send an empty response and clean up here before exiting out.
			response = packet_create_response(packet);
			if (packet->local)
			{
				packet_add_tlv_uint(response, TLV_TYPE_RESULT, ERROR_NOT_SUPPORTED);
			}
			else
			{
				packet_transmit_response(ERROR_NOT_SUPPORTED, remote, response);
				packet_destroy(packet);
			}
			break;
		}

		// if either command is registered as inline, run them inline
		if ((command && command_is_inline(command, packet))
			|| packet->local)
		{
			dprintf("[DISPATCH] Executing inline: %u", commandId);
			result = command_process_inline(command, remote, packet);
			dprintf("[DISPATCH] Executed inline: result %u (%x)", result, result);
		}
		else
		{
			dprintf("[DISPATCH] Executing in thread: %u", commandId);

			cpt = thread_create(command_process_thread, remote, packet, command);
			if (cpt)
			{
				dprintf("[DISPATCH] created command_process_thread 0x%08X, handle=0x%08X", cpt, cpt->handle);
				thread_run(cpt);
			}
		}
	} while (0);

	return result;
}

/*!
 * @brief Process a single command in a seperate thread of execution.
 * @param thread Pointer to the thread to execute.
 * @return Result of thread execution (not the result of the command).
 * @sa command_handle
 * @sa command_process_inline
 */
DWORD THREADCALL command_process_thread(THREAD * thread)
{
	Command* command = NULL;
	Remote * remote = NULL;
	Packet * packet = NULL;

	dprintf("[COMMAND] executing in thread %p", thread);

	if (thread == NULL)
	{
		return ERROR_INVALID_HANDLE;
	}

	remote = (Remote *)thread->parameter1;
	if (remote == NULL)
	{
		return ERROR_INVALID_HANDLE;
	}

	packet = (Packet *)thread->parameter2;
	if (packet == NULL)
	{
		return ERROR_INVALID_DATA;
	}

	command = (Command*)thread->parameter3;
	if (command == NULL)
	{
		return ERROR_INVALID_DATA;
	}

	if (commandThreadList == NULL)
	{
		commandThreadList = list_create();
		if (commandThreadList == NULL)
		{
			return ERROR_INVALID_HANDLE;
		}
	}

	list_add(commandThreadList, thread);

	// invoke processing inline, passing in both commands
	dprintf("[COMMAND] About to execute inline -> Command: %p", command);
	command_process_inline(command, remote, packet);
	dprintf("[COMMAND] Executed inline -> Command: %p", command);

	if (list_remove(commandThreadList, thread))
	{
		thread_destroy(thread);
	}
	return ERROR_SUCCESS;
}

/*!
 * @brief Determine if a given command/packet combination should be invoked inline.
 * @param command Pointer to the \c Command being invoked.
 * @param packet Pointer to the \c Packet being received/sent.
 * @returns Boolean indication of whether the command should be executed inline.
 * @retval TRUE The command should be executed inline on the current thread.
 * @retval FALSE The command should be executed on a new thread.
 */
BOOL command_is_inline( Command *command, Packet *packet )
{
	switch (packet_get_type( packet ))
	{
	case PACKET_TLV_TYPE_REQUEST:
	case PACKET_TLV_TYPE_PLAIN_REQUEST:
		if (command->request.inline_handler)
			return TRUE;
	case PACKET_TLV_TYPE_RESPONSE:
	case PACKET_TLV_TYPE_PLAIN_RESPONSE:
		if (command->response.inline_handler)
			return TRUE;
	}

	return FALSE;
}

/*!
 * @brief Validate command arguments
 * @return Indication of whether the commands are valid or not.
 * @retval ERROR_SUCCESS All arguments are valid.
 * @retval ERROR_INVALID_PARAMETER An invalid parameter exists.
 */
DWORD command_validate_arguments(Command *command, Packet *packet)
{
	PacketDispatcher *dispatcher = NULL;
	PacketTlvType type = packet_get_type(packet);
	DWORD res = ERROR_SUCCESS,
		packetIndex, commandIndex;
	Tlv current;

	// Select the dispatcher table
	if ((type == PACKET_TLV_TYPE_RESPONSE) ||
		(type == PACKET_TLV_TYPE_PLAIN_RESPONSE))
		dispatcher = &command->response;
	else
		dispatcher = &command->request;

	// Enumerate the arguments, validating the meta types of each
	for (commandIndex = 0, packetIndex = 0;
		((packet_enum_tlv(packet, packetIndex, TLV_TYPE_ANY, &current) == ERROR_SUCCESS)
		&& (res == ERROR_SUCCESS));
		commandIndex++, packetIndex++)
	{
		TlvMetaType tlvMetaType;

		// Check to see if we've reached the end of the command arguments
		if ((dispatcher->numArgumentTypes) &&
			(commandIndex == (dispatcher->numArgumentTypes & ARGUMENT_FLAG_MASK)))
		{
			// If the repeat flag is set, reset the index
			if (commandIndex & ARGUMENT_FLAG_REPEAT)
				commandIndex = 0;
			else
				break;
		}

		// Make sure the argument is at least one of the meta types
		tlvMetaType = packet_get_tlv_meta(packet, &current);

		// Validate argument meta types
		switch (tlvMetaType)
		{
		case TLV_META_TYPE_STRING:
			if (packet_is_tlv_null_terminated(&current) != ERROR_SUCCESS)
			{
				dprintf("[COMMAND] string is not null terminated");
				res = ERROR_INVALID_PARAMETER;
			}
			break;
		default:
			break;
		}

		if ((res != ERROR_SUCCESS) &&
			(commandIndex < dispatcher->numArgumentTypes))
			break;
	}

	return res;
}
