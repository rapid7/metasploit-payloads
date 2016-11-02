/*!
 * @file named_pipe_server.c
 * @brief Contains functions that allow for the creation of a named pipe server channel.
 */

#include "precomp.h"
#include <AccCtrl.h>
#include <AclApi.h>

#define PIPE_NAME_SIZE 256
#define PIPE_BUFFER_SIZE 0x1000

typedef struct _NamedPipeContext
{
	// make sure we leave this as the first element, so that it can be cast
	// to an OVERLAPPED pointer for various operations.
	OVERLAPPED read_overlap;
	OVERLAPPED write_overlap;
	char       name[PIPE_NAME_SIZE];
	DWORD      open_mode;
	DWORD      pipe_mode;
	DWORD      pipe_count;
	Remote*    remote;
	Channel*   channel;
	HANDLE     pipe;
	BOOL       connecting;
	BOOL       established;
	BOOL       repeat;
	BYTE       read_buffer[PIPE_BUFFER_SIZE];
} NamedPipeContext;

static DWORD server_close(Channel* channel, Packet* request, LPVOID context);
static DWORD server_notify(Remote* remote, LPVOID entryContext, LPVOID threadContext, BOOL timedOut);

typedef BOOL (WINAPI *PAddMandatoryAce)(PACL pAcl, DWORD dwAceRevision, DWORD dwAceFlags, DWORD dwMandatoryPolicy, PSID pLabelSid);
static BOOL WINAPI AddMandatoryAce(PACL pAcl, DWORD dwAceRevision, DWORD dwAceFlags, DWORD dwMandatoryPolicy, PSID pLabelSid)
{
	static BOOL attempted = FALSE;
	static PAddMandatoryAce pAddMandatoryAce = NULL;

	if (attempted)
	{
		attempted = TRUE;

		HMODULE lib = LoadLibraryA("advapi32.dll");
		if (lib != NULL)
		{
			pAddMandatoryAce = (PAddMandatoryAce)GetProcAddress(lib, "AddMandatoryAce");
			dprintf("[NP-SERVER] AddMandatoryAce: %p", pAddMandatoryAce);
		}
	}

	if (pAddMandatoryAce != NULL)
	{
		pAddMandatoryAce(pAcl, dwAceRevision, dwAceFlags, dwMandatoryPolicy, pLabelSid);
	}

	return TRUE;
}

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

	*bytesWritten = 0;

	dprintf("[NP-SERVER] Writing a total of %u", bufferSize);
	while (*bytesWritten < bufferSize)
	{
		DWORD byteCount = 0;
		WriteFile(ctx->pipe, buffer, bufferSize - *bytesWritten, NULL, &ctx->write_overlap);
		// blocking here is just fine, it's the reads we care about
		if (GetOverlappedResult(ctx->pipe, &ctx->write_overlap, &byteCount, TRUE))
		{
			dprintf("[NP-SERVER] Wrote %u", byteCount);
			*bytesWritten += byteCount;
		}
		else
		{
			dprintf("[NP-SERVER] failed to do the write: %u", GetLastError());
		}
		dprintf("[NP-SERVER] left to go: %u", bufferSize - *bytesWritten);
	}

	//do
	//{
		// copy data over to the context for the async write to happen, we can't rely
		// on the buffer being here at the time of writing.
		//if (bufferSize > ctx->write_buffer_size || ctx->write_buffer == NULL)
		//{
		//	dprintf("[NP-SERVER] reallocating %p for %u bytes", ctx->write_buffer, bufferSize);
		//	ctx->write_buffer_size = bufferSize;
		//	ctx->write_buffer = (BYTE*)realloc(ctx->write_buffer, ctx->write_buffer_size);
		//}

		//dprintf("[NP-SERVER] writing to %p total of %u bytes", ctx->write_buffer, bufferSize);
		//memcpy_s(ctx->write_buffer, ctx->write_buffer_size, buffer, bufferSize);

		//WriteFile(ctx->pipe, buffer, bufferSize, NULL, &ovl);
		//WriteFile(ctx->pipe, ctx->write_buffer, bufferSize, NULL, &ovl);
		//WriteFile(ctx->pipe, ctx->write_buffer, bufferSize, NULL, &ctx->read_overlap);
		//if (!WriteFile(ctx->pipe, ctx->write_buffer, bufferSize, NULL, &ctx->read_overlap));
		//{
			//BREAK_ON_ERROR("[NP-SERVER] unable to write");
		//}
		//dprintf("[NP-SERVER] wrote to named pipe: %u", written);
		//*bytesWritten += written;
	//} while (*bytesWritten < bufferSize);

	dprintf("[NP SERVER] server write. finished. dwResult=%d, written=%d", dwResult, *bytesWritten);

	return dwResult;
}

VOID create_pipe_security_attributes(PSECURITY_ATTRIBUTES psa)
{
	// Start with the DACL (perhaps try the NULL sid if it doesn't work?)
	SID_IDENTIFIER_AUTHORITY sidWorld = SECURITY_WORLD_SID_AUTHORITY;
	PSID sidEveryone = NULL;
	if (!AllocateAndInitializeSid(&sidWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &sidEveryone))
	{
		dprintf("[NP-SERVER] AllocateAndInitializeSid failed: %u", GetLastError());
		return;
	}

	dprintf("[NP-SERVER] sidEveryone: %p", sidEveryone);

	EXPLICIT_ACCESSW ea = { 0 };
	ea.grfAccessPermissions = SPECIFIC_RIGHTS_ALL | STANDARD_RIGHTS_ALL;
	ea.grfAccessMode = SET_ACCESS;
	ea.grfInheritance = NO_INHERITANCE;
	ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	ea.Trustee.ptstrName = (LPWSTR)sidEveryone;

	//PACL dacl = (PACL)LocalAlloc(LPTR, 256);
	PACL dacl = NULL;
	DWORD result = SetEntriesInAclW(1, &ea, NULL, &dacl);
	if (result != ERROR_SUCCESS)
	{
		dprintf("[NP-SERVER] SetEntriesInAclW failed: %u", result);
	}
	dprintf("[NP-SERVER] DACL: %p", dacl);

	// set up the sacl
	SID_IDENTIFIER_AUTHORITY sidLabel = SECURITY_MANDATORY_LABEL_AUTHORITY;
	PSID sidLow = NULL;
	if (!AllocateAndInitializeSid(&sidLabel, 1, SECURITY_MANDATORY_LOW_RID, 0, 0, 0, 0, 0, 0, 0, &sidLow))
	{
		dprintf("[NP-SERVER] AllocateAndInitializeSid failed: %u", GetLastError());
	}
	dprintf("[NP-SERVER] sidLow: %p", dacl);

	PACL sacl = (PACL)LocalAlloc(LPTR, 256);
	if (!InitializeAcl(sacl, 256, ACL_REVISION_DS))
	{
		dprintf("[NP-SERVER] InitializeAcl failed: %u", GetLastError());
	}

	if (!AddMandatoryAce(sacl, ACL_REVISION_DS, NO_PROPAGATE_INHERIT_ACE, 0, sidLow))
	{
		dprintf("[NP-SERVER] AddMandatoryAce failed: %u", GetLastError());
	}

	// now build the descriptor
	PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
	if (!InitializeSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION))
	{
		dprintf("[NP-SERVER] InitializeSecurityDescriptor failed: %u", GetLastError());
	}

	// add the dacl
	if (!SetSecurityDescriptorDacl(sd, TRUE, dacl, FALSE))
	{
		dprintf("[NP-SERVER] SetSecurityDescriptorDacl failed: %u", GetLastError());
	}

	// now the sacl
	if (!SetSecurityDescriptorSacl(sd, TRUE, sacl, FALSE))
	{
		dprintf("[NP-SERVER] SetSecurityDescriptorSacl failed: %u", GetLastError());
	}

	psa->nLength = sizeof(SECURITY_ATTRIBUTES);
	psa->bInheritHandle = FALSE;
	psa->lpSecurityDescriptor = sd;
}

DWORD create_pipe_server_instance(NamedPipeContext* ctx)
{
	DWORD dwResult = ERROR_SUCCESS;
	StreamChannelOps chops = { 0 };

	do
	{
		// we always need overlapped mode
		ctx->open_mode |= FILE_FLAG_OVERLAPPED;

		// never allow PIPE_NOWAIT
		ctx->pipe_mode &= ~PIPE_NOWAIT;

		// set a sane value for the count
		if (ctx->pipe_count == 0)
		{
			ctx->pipe_count = PIPE_UNLIMITED_INSTANCES;
		}

		dprintf("[NP-SERVER] Creating new server instance of %s", ctx->name);
		dprintf("[NP-SERVER]   - open mode: 0x%x", ctx->open_mode);
		dprintf("[NP-SERVER]   - pipe mode: 0x%x", ctx->pipe_mode);
		dprintf("[NP-SERVER]   - pipe cnt : %d", ctx->pipe_count ? ctx->pipe_count : PIPE_UNLIMITED_INSTANCES);
		dprintf("[NP-SERVER]   - repeat?  : %s", ctx->repeat ? "Yes" : "No");

		// set up a session that let's anyone with SMB access connect
		SECURITY_ATTRIBUTES sa = { 0 };
		create_pipe_security_attributes(&sa);

		ctx->pipe = CreateNamedPipeA(ctx->name, ctx->open_mode, ctx->pipe_mode, ctx->pipe_count ? ctx->pipe_count : PIPE_UNLIMITED_INSTANCES, PIPE_BUFFER_SIZE, PIPE_BUFFER_SIZE, 0, &sa);

		if (ctx->pipe == INVALID_HANDLE_VALUE)
		{
			BREAK_ON_ERROR("[NP-SERVER] Failed to create named pipe.");
		}

		dprintf("[NP-SERVER] Creating the handler event");
		// This must be signalled, so that the connect event kicks off on the new thread.
		ctx->read_overlap.hEvent = CreateEvent(NULL, TRUE, TRUE, NULL);
		if (ctx->read_overlap.hEvent == NULL)
		{
			BREAK_ON_ERROR("[NP-SERVER] Failed to create connect event for read overlap.");
		}

		// this should not be signalled as it's just for handling named pipe writes.
		ctx->write_overlap.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
		if (ctx->write_overlap.hEvent == NULL)
		{
			BREAK_ON_ERROR("[NP-SERVER] Failed to create connect event for read overlap.");
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
		scheduler_insert_waitable(ctx->read_overlap.hEvent, ctx, NULL, server_notify, NULL);
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

		dprintf("[NP-SERVER] freeing up pipe handle 0x%x", ctx->pipe);
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

		if (ctx->read_overlap.hEvent != NULL)
		{
			dprintf("[NP-SERVER] free_server_context. signaling the thread to stop");
			scheduler_signal_waitable(ctx->read_overlap.hEvent, Stop);
			ctx->read_overlap.hEvent = NULL;
		}

		if (ctx->write_overlap.hEvent != NULL)
		{
			CloseHandle(ctx->write_overlap.hEvent);
			ctx->write_overlap.hEvent = NULL;
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
	DWORD dwResult = ERROR_SUCCESS;
	Packet* request = NULL;
	NamedPipeContext* serverCtx = (NamedPipeContext*)entryContext;
	BOOL performRead = FALSE;

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

		if (!serverCtx->connecting)
		{
			serverCtx->connecting = TRUE;
			dprintf("[NP-SERVER] Connecting to the named pipe async");
			ConnectNamedPipe(serverCtx->pipe, &serverCtx->read_overlap);

			dwResult = GetLastError();
			dprintf("[NP-SERVER] checking the result of connect %u 0x%x", dwResult, dwResult);
			if (dwResult == ERROR_IO_PENDING)
			{
				dprintf("[NP-SERVER] still waiting for an overlapped connection");
				break;
			}
			else if (dwResult == ERROR_PIPE_LISTENING)
			{
				dprintf("[NP-SERVER] client has connected apparently");
				serverCtx->established = TRUE;
				// no break here, we want to continue
			}
			else
			{
				BREAK_WITH_ERROR("[NP-SERVER] Failed to connect to the named pipe", dwResult);
			}
			dwResult = ERROR_SUCCESS;
		}

		DWORD bytesProcessed = 0;
		dprintf("[NP-SERVER] Checking the overlapped result");
		if (!GetOverlappedResult(serverCtx->pipe, &serverCtx->read_overlap, &bytesProcessed, FALSE))
		{
			dwResult = GetLastError();
			dprintf("[NP-SERVER] server_notify. unable to get the result, %u", dwResult);

			if (dwResult == ERROR_IO_INCOMPLETE)
			{
				dprintf("[NP-SERVER] still waiting for something to happen on the pipe");
			}
			else if (dwResult == ERROR_BROKEN_PIPE)
			{
				dprintf("[NP-SERVER] the client appears to have bailed out, disconnecting...");
				channel_close(serverCtx->channel, serverCtx->remote, NULL, 0, NULL);
				ResetEvent(serverCtx->read_overlap.hEvent);
				return ERROR_BROKEN_PIPE;
			}
			break;
		}

		// spin up a new named pipe server instance to handle the next connection if this
		// connection is new.
		dprintf("[NP-SERVER] Apparently we have a result! With %u bytes", bytesProcessed);
		if (!serverCtx->established)
		{
			// this is a connect, so tell MSF about it.
			dprintf("[NP-SERVER] This appears to be a new connection, setting up context.");
			request = packet_create(PACKET_TLV_TYPE_REQUEST, "named_pipe_channel_open");
			if (!request)
			{
				BREAK_WITH_ERROR("[NP-SERVER] request_net_tcp_server_channel_open. packet_create failed", ERROR_INVALID_HANDLE);
			}

			if (serverCtx->repeat)
			{
				// Connection received, here we're going to create a new named pipe handle so that
				// other connections can come in on it. We'll assume that it if worked once, it
				// will work again this time
				NamedPipeContext* nextCtx = (NamedPipeContext*)calloc(1, sizeof(NamedPipeContext));

				// copy the relevant content over.
				nextCtx->open_mode = serverCtx->open_mode;
				nextCtx->pipe_mode = serverCtx->pipe_mode;
				nextCtx->pipe_count = serverCtx->pipe_count;
				nextCtx->repeat = serverCtx->repeat;
				nextCtx->remote = serverCtx->remote;
				memcpy_s(&nextCtx->name, PIPE_NAME_SIZE, &serverCtx->name, PIPE_NAME_SIZE);

				// create a new pipe for the next connection
				DWORD result = create_pipe_server_instance(nextCtx);
				if (result != ERROR_SUCCESS)
				{
					dprintf("[NP-SERVER] failed to create the pipe server instance: %u", result);
					free_server_context(nextCtx);
				}
				else
				{
					dprintf("[NP-SERVER] Creation of the new pipe succeeded");
					// indicate that there's a new server channel ready and waiting for the next connection
					packet_add_tlv_uint(request, TLV_TYPE_CHANNEL_ID, channel_get_id(nextCtx->channel));
				}
			}

			packet_add_tlv_uint(request, TLV_TYPE_CHANNEL_PARENTID, channel_get_id(serverCtx->channel));

			dprintf("[NP-SERVER] telling MSF we have a connection");
			// send back the generated pipe name for MSF-side tracking.
			packet_add_tlv_string(request, TLV_TYPE_NAMED_PIPE_NAME, serverCtx->name);

			dwResult = PACKET_TRANSMIT(serverCtx->remote, request, NULL);

			serverCtx->established = TRUE;
		}

		if (bytesProcessed > 0)
		{
			dprintf("[NP-SERVER] read & sending bytes %u", bytesProcessed);

			// back ya go!
			channel_write(serverCtx->channel, serverCtx->remote, NULL, 0, serverCtx->read_buffer, bytesProcessed, 0);
		}

		performRead = TRUE;
	} while (0);

	if (serverCtx->read_overlap.hEvent != NULL)
	{
		dprintf("[NP-SERVER] Resetting the event handle");
		ResetEvent(serverCtx->read_overlap.hEvent);
	}

	// this has to be done after the signal is reset, otherwise ... STRANGE THINGS HAPPEN!
	if (performRead)
	{
		// prepare for reading
		serverCtx->read_overlap.Offset = 0;
		serverCtx->read_overlap.OffsetHigh = 0;

		// read the data from the pipe, we're async, so the return value of the function is meaningless.
		dprintf("[NP-SERVER] kicking off another read operation...");
		ReadFile(serverCtx->pipe, serverCtx->read_buffer, PIPE_BUFFER_SIZE, NULL, &serverCtx->read_overlap);
		// TODO: error checking?
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

		if (ctx->read_overlap.hEvent != NULL)
		{
			dprintf("[NP-SERVER] Destroying wait handle");
			CloseHandle(ctx->read_overlap.hEvent);
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
