/*!
 * @file named_pipe_server.c
 * @brief Contains functions that allow for the creation of a named pipe server channel.
 */

#include "precomp.h"

#define PIPE_NAME_SIZE 256
#define PIPE_BUFFER_SIZE 0x1000

typedef struct _NamedPipeContext
{
	char       name[PIPE_NAME_SIZE];
	DWORD      open_mode;
	DWORD      pipe_mode;
	DWORD      pipe_count;
	Remote*    remote;
	Channel*   channel;
	HANDLE     pipe;
	OVERLAPPED overlapped;
	BOOL       established;
	BOOL       client_connected;
	BOOL       repeat;
} NamedPipeContext;

static DWORD server_close(Channel* channel, Packet* request, LPVOID context);
static DWORD server_notify(Remote* remote, LPVOID entryContext, LPVOID threadContext, BOOL timedOut);

/*!
 * @brief Writes data from the remote half of the channel to the established connection.
 * @param channel Pointer to the channel to write to.
 * @param request Pointer to the request packet.
 * @param context Pointer to the channel's context.
 * @param buffer Buffer containing the data to write to the channel.
 * @param bufferSize Size of the buffer indicating how many bytes to write.
 * @param bytesWritten Pointer that receives the number of bytes written to the \c channel.
 * @returns Indication of success or failure.
 * @retval ERROR_SUCCESS writing the data completed successfully.
 */
static DWORD server_write(Channel *channel, Packet *request, LPVOID context, LPVOID buffer, DWORD bufferSize, LPDWORD bytesWritten)
{
	DWORD dwResult = ERROR_SUCCESS;
	NamedPipeContext* ctx = (NamedPipeContext*)context;
	DWORD written = 0;

	*bytesWritten = 0;

	do
	{
		OVERLAPPED ovl = { 0 };
		if (!WriteFile(ctx->pipe, buffer, bufferSize, &written, &ovl))
		{
			BREAK_ON_ERROR("[NP-SERVER] unable to write");
		}
		dprintf("[NP-SERVER] wrote to named pipe: %u", written);
		*bytesWritten += written;
	} while (*bytesWritten < bufferSize);

	dprintf("[NP SERVER] server write. finished. dwResult=%d, written=%d", dwResult, written);

	return dwResult;
}

DWORD create_pipe_server_instance(NamedPipeContext* ctx)
{
	DWORD dwResult = ERROR_SUCCESS;
	StreamChannelOps chops = { 0 };

	do
	{
		dprintf("[NP-SERVER] Creating new server instance of %s", ctx->name);
		dprintf("[NP-SERVER]   - open mode: 0x%x", ctx->open_mode);
		dprintf("[NP-SERVER]   - pipe mode: 0x%x", ctx->pipe_mode);
		dprintf("[NP-SERVER]   - pipe cnt : %d", ctx->pipe_count ? ctx->pipe_count : PIPE_UNLIMITED_INSTANCES);
		ctx->pipe = CreateNamedPipeA(ctx->name, ctx->open_mode, ctx->pipe_mode, ctx->pipe_count ? ctx->pipe_count : PIPE_UNLIMITED_INSTANCES, PIPE_BUFFER_SIZE, PIPE_BUFFER_SIZE, 0, NULL);

		if (ctx->pipe == INVALID_HANDLE_VALUE)
		{
			BREAK_ON_ERROR("[NP-SERVER] Failed to create named pipe.");
		}

		dprintf("[NP-SERVER] Creating the handler event");
		ctx->overlapped.hEvent = CreateEvent(NULL, TRUE, TRUE, NULL);
		if (ctx->overlapped.hEvent == NULL)
		{
			BREAK_ON_ERROR("[NP-SERVER] Failed to create connect event.");
		}

		dprintf("[NP-SERVER] Connecting to the named pipe async");
		if (ConnectNamedPipe(ctx->pipe, &ctx->overlapped) == 0)
		{
			dwResult = GetLastError();
			dprintf("[NP-SERVER] connect failed, making sure the result is valid... %u 0x%x", dwResult, dwResult);
			if (dwResult == ERROR_IO_PENDING)
			{
				dprintf("[NP-SERVER] still waiting for an overlapped connection");
			}
			else if (dwResult == ERROR_PIPE_LISTENING)
			{
				dprintf("[NP-SERVER] client has connected apparently");
				ctx->client_connected = TRUE;
			}
			else
			{
				BREAK_WITH_ERROR("[NP-SERVER] Failed to connect to the named pipe", dwResult);
			}
			dwResult = ERROR_SUCCESS;
		}

		chops.native.context = ctx;
		chops.native.close = server_close;
		chops.native.write = server_write;

		dprintf("[NP-SERVER] Creating the named pipe channel");
		ctx->channel = channel_create_stream(0, CHANNEL_FLAG_SYNCHRONOUS, &chops);
		if (!ctx->channel)
		{
			BREAK_WITH_ERROR("[NP-SERVER] channel_create_stream failed", ERROR_INVALID_HANDLE);
		}

		dprintf("[NP-SERVER] Inserting the named pipe schedule entry");
		scheduler_insert_waitable(ctx->overlapped.hEvent, ctx, NULL, server_notify, NULL);
	} while (0);

	return dwResult;
}

/*!
 * @brief Deallocates and cleans up the attributes of a named pipe server context.
 * @param ctx Pointer to the context to free.
 */
static VOID free_server_context(NamedPipeContext* ctx)
{
	do
	{
		if (!ctx)
		{
			break;
		}

		dprintf("[NP-SERVER] free_server_context. ctx=0x%08X", ctx);

		if (ctx->pipe != NULL && ctx->pipe != INVALID_HANDLE_VALUE)
		{
			CloseHandle(ctx->pipe);
			ctx->pipe = NULL;
		}

		if (ctx->channel)
		{
			channel_close(ctx->channel, ctx->remote, NULL, 0, NULL);
			ctx->channel = NULL;
		}

		if (ctx->overlapped.hEvent != NULL)
		{
			dprintf("[NP-SERVER] free_server_context. signaling the thread to stop");
			scheduler_signal_waitable(ctx->overlapped.hEvent, Stop);
			ctx->overlapped.hEvent = NULL;
		}

		free(ctx);

	} while (0);
}

/*!
 * @brief Closes the server handle and brings down the client connections.
 * @param channel Pointer to the Named pipe channel to close.
 * @param request The request packet.
 * @param context The channel context.
 * @returns Indication of success or failure.
 * @retval ERROR_SUCCESS This value is always returned.
 */
static DWORD server_close(Channel* channel, Packet* request, LPVOID context)
{
	NamedPipeContext* ctx = (NamedPipeContext*)context;

	do
	{
		dprintf("[NP-SERVER] server_close. channel=0x%08X, ctx=0x%08X", channel, ctx);

		if (!ctx)
		{
			break;
		}

		// Set the context channel to NULL so we don't try to close the
		// channel (since it's already being closed)
		ctx->channel = NULL;

		// Free the context
		free_server_context(ctx);

		// Set the native channel operations context to NULL
		channel_set_native_io_context(channel, NULL);

	} while (0);

	return ERROR_SUCCESS;
}

/*!
 * @brief Notify routine for a named pipe server channel to pick up its new client connections..
 * @param remote Pointer to the remote instance.
 * @param serverCtx Pointer to the named pipe server context.
 * @returns Indication of success or failure.
 * @retval ERROR_SUCCESS Notification completed successfully.
 */
static DWORD server_notify(Remote* remote, LPVOID entryContext, LPVOID threadContext, BOOL timedOut)
{
	char dataBuffer[PIPE_BUFFER_SIZE];
	DWORD dwResult = ERROR_SUCCESS;
	Packet* request = NULL;
	NamedPipeContext* serverCtx = (NamedPipeContext*)entryContext;

	do
	{
		if (!serverCtx)
		{
			BREAK_WITH_ERROR("[NP-SERVER] server_notify. serverCtx == NULL", ERROR_INVALID_HANDLE);
		}

		if (serverCtx->pipe == NULL || serverCtx->pipe == INVALID_HANDLE_VALUE)
		{
			BREAK_WITH_ERROR("[NP-SERVER] pipe isn't present, we might be shutting down.", ERROR_INVALID_HANDLE);
		}

		DWORD bytesRead = 0;
		dprintf("[NP-SERVER] Checking the overlapped result");
		if (!GetOverlappedResult(serverCtx->pipe, &serverCtx->overlapped, &bytesRead, FALSE))
		{
			dwResult = GetLastError();
			dprintf("[NP-SERVER] server_notify. unable to get the connect result, %u", dwResult);
			dprintf("[NP-SERVER] server_notify. unable to get the connect result, so disconnecting and reconnecting");
			if(DisconnectNamedPipe(serverCtx->pipe))
			{
				dprintf("[NP-SERVER] disconnect worked");
			}
			else
			{
				dprintf("[NP-SERVER] disconnect didn't work: %u", GetLastError());
			}

			if (ConnectNamedPipe(serverCtx->pipe, &serverCtx->overlapped) == 0)
			{
				dprintf("[NP-SERVER] Connect was 0 resulted in %u", GetLastError());
			}
			else
			{
				dprintf("[NP-SERVER] Connect was not 0 resulted in %u", GetLastError());
			}
			break;
		}

		// spin up a new named pipe server instance to handle the next connection if this
		// connection is new.
		dprintf("[NP-SERVER] Apparently we have a result! With %u bytes", bytesRead);
		if (!serverCtx->established)
		{
			request = packet_create(PACKET_TLV_TYPE_REQUEST, "named_pipe_channel_open");
			if (!request)
			{
				BREAK_WITH_ERROR("[NP-SERVER] request_net_tcp_server_channel_open. packet_create failed", ERROR_INVALID_HANDLE);
			}

			if (serverCtx->repeat)
			{
				dprintf("[NP-SERVER] This appears to be a new connection, setting up context.");
				// connection received, here we're going to create a new named pipe handle so that
				// other connections can come in on it. We'll assume that it if worked once, it
				// will work again this time
				NamedPipeContext* nextCtx = (NamedPipeContext*)calloc(1, sizeof(NamedPipeContext));

				// copy the relevant content over.
				nextCtx->open_mode = serverCtx->open_mode;
				nextCtx->pipe_mode = serverCtx->pipe_mode;
				nextCtx->pipe_count = serverCtx->pipe_count;
				nextCtx->remote = serverCtx->remote;
				memcpy_s(&nextCtx->name, PIPE_NAME_SIZE, &serverCtx->name, PIPE_NAME_SIZE);

				// create a new pipe for the next connection
				if (create_pipe_server_instance(nextCtx) != ERROR_SUCCESS)
				{
					free_server_context(nextCtx);
					dprintf("[NP-SERVER] failed to create the pipe server instance");
				}
				else
				{
					dprintf("[NP-SERVER] Creation of the new pipe succeeded");
					// indicate that there's a new server channel ready and waiting for the next connection
					packet_add_tlv_uint(request, TLV_TYPE_CHANNEL_ID, channel_get_id(nextCtx->channel));
				}
			}

			packet_add_tlv_uint(request, TLV_TYPE_CHANNEL_PARENTID, channel_get_id(serverCtx->channel));

			// send back the generated pipe name for MSF-side tracking.
			packet_add_tlv_string(request, TLV_TYPE_NAMED_PIPE_NAME, serverCtx->name);

			dwResult = PACKET_TRANSMIT(serverCtx->remote, request, NULL);

			serverCtx->established = TRUE;
		}

		if (bytesRead > 0)
		{
			// prepare for reading
			serverCtx->overlapped.Offset = 0;
			serverCtx->overlapped.OffsetHigh = 0;

			// read the data from the pipe
			if (!ReadFile(serverCtx->pipe, dataBuffer, bytesRead == 0 ? PIPE_BUFFER_SIZE : bytesRead, &bytesRead, &serverCtx->overlapped))
			{
				BREAK_ON_ERROR("[NP-SERVER] failed to read data from the pipe.");
			}

			// write data to the other end of the channel
			channel_write(serverCtx->channel, serverCtx->remote, NULL, 0, dataBuffer, bytesRead, 0);
		}

		// now 
	} while (0);

	if (serverCtx->overlapped.hEvent != NULL)
	{
		dprintf("[NP-SERVER] Resetting the event handle");
		ResetEvent(serverCtx->overlapped.hEvent);
	}

	return dwResult;
}

/*!
 * @brief Allocates a streaming named pipe server channel.
 * @param remote Pointer to the remote instance.
 * @param packet Pointer to the request packet.
 * @returns Indication of success or failure.
 * @retval ERROR_SUCCESS Opening the server channel completed successfully.
 */
DWORD request_net_named_pipe_server_channel_open(Remote* remote, Packet* packet)
{
	DWORD dwResult = ERROR_SUCCESS;
	NamedPipeContext* ctx = NULL;
	Packet* response = NULL;
	char* namedPipeName = NULL;
	char* namedPipeServer = NULL;

	do
	{
		response = packet_create_response(packet);
		if (!response)
		{
			BREAK_WITH_ERROR("[NP-SERVER] request_net_named_pipe_server_channel_open. response == NULL", ERROR_NOT_ENOUGH_MEMORY);
		}

		ctx = (NamedPipeContext *)calloc(1, sizeof(NamedPipeContext));
		if (!ctx)
		{
			BREAK_WITH_ERROR("[NP-SERVER] request_net_named_pipe_server_channel_open. ctx == NULL", ERROR_NOT_ENOUGH_MEMORY);
		}

		ctx->remote = remote;

		namedPipeName = packet_get_tlv_value_string(packet, TLV_TYPE_NAMED_PIPE_NAME);
		if (!namedPipeName)
		{
			BREAK_WITH_ERROR("[NP-SERVER] request_net_named_pipe_server_channel_open. namedPipeName == NULL", ERROR_INVALID_PARAMETER);
		}

		if (strchr(namedPipeName, '\\') != NULL)
		{
			BREAK_WITH_ERROR("[NP-SERVER] request_net_named_pipe_server_channel_open. namedPipeName contains backslash (invalid)", ERROR_INVALID_PARAMETER);
		}

		namedPipeServer = packet_get_tlv_value_string(packet, TLV_TYPE_NAMED_PIPE_SERVER);
		if (namedPipeServer == NULL)
		{
			namedPipeServer = ".";
		}

		// Both of these can be zero, let's hope that the user doesn't forget to set them if required!
		ctx->open_mode = packet_get_tlv_value_uint(packet, TLV_TYPE_NAMED_PIPE_OPEN_MODE);
		ctx->pipe_mode = packet_get_tlv_value_uint(packet, TLV_TYPE_NAMED_PIPE_PIPE_MODE);
		ctx->pipe_count = packet_get_tlv_value_uint(packet, TLV_TYPE_NAMED_PIPE_COUNT);
		ctx->repeat = packet_get_tlv_value_bool(packet, TLV_TYPE_NAMED_PIPE_REPEAT);

		// we always need overlapped mode
		ctx->open_mode |= FILE_FLAG_OVERLAPPED;

		// never allow PIPE_NOWAIT
		ctx->pipe_mode &= ~PIPE_NOWAIT;

		// set a sane value for the count
		if (ctx->pipe_count == 0)
		{
			ctx->pipe_count = PIPE_UNLIMITED_INSTANCES;
		}

		_snprintf_s(ctx->name, PIPE_NAME_SIZE, PIPE_NAME_SIZE - 1, "\\\\%s\\pipe\\%s", namedPipeServer, namedPipeName);

		dwResult = create_pipe_server_instance(ctx);

		dprintf("[NP-SERVER] creation of the named pipe returned: %d 0x%x", dwResult, dwResult);

		if (dwResult == ERROR_SUCCESS)
		{
			// send back the generated pipe name for MSF-side tracking.
			packet_add_tlv_string(response, TLV_TYPE_NAMED_PIPE_NAME, ctx->name);
			packet_add_tlv_uint(response, TLV_TYPE_CHANNEL_ID, channel_get_id(ctx->channel));

			dprintf("[NP-SERVER] request_net_named_pipe_server_channel_open. named pipe server %s on channel %d", namedPipeName, channel_get_id(ctx->channel));
		}

	} while (0);

	packet_transmit_response(dwResult, remote, response);

	do
	{
		if (dwResult == ERROR_SUCCESS)
		{
			break;
		}

		dprintf("[NP-SERVER] Error encountered %u 0x%x", dwResult, dwResult);

		if (!ctx)
		{
			break;
		}

		if (ctx->overlapped.hEvent != NULL)
		{
			dprintf("[NP-SERVER] Destroying wait handle");
			CloseHandle(ctx->overlapped.hEvent);
		}

		if (ctx->pipe != NULL && ctx->pipe != INVALID_HANDLE_VALUE)
		{
			dprintf("[NP-SERVER] Destroying pipe");
			CloseHandle(ctx->pipe);
		}

		if (ctx->channel)
		{
			dprintf("[NP-SERVER] Destroying channel");
			channel_destroy(ctx->channel, packet);
		}

		free(ctx);

	} while (0);

	return dwResult;
}
