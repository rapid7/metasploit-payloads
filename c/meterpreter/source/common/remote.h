/*!
 * @file remote.h
 * @brief Declarations of functions and types that interact with a remote endpoint.
 */
#ifndef _METERPRETER_LIB_REMOTE_H
#define _METERPRETER_LIB_REMOTE_H

#include "crypto.h"
#include "thread.h"

/*!
 * @brief Remote context allocation.
 * @details Wraps the initialized file descriptor for extension purposes.
 *          A \c Remote is effectively a pointer to a remote client context
 *          which contains magic pixie dust that identifies the connection
 *          along with a way to interact with it.
 * @remark The `Original` and `Current` members are used to allow for
 *         functionality such as `rev2self` and reverting back to the initial
 *         desktop stations/desktops.
 */
typedef struct _Remote
{
	HMODULE hMetSrv;              ///< Reference to the Meterpreter server instance.
	SOCKET fd;                    ///< Remote socket file descriptor.
	CryptoContext *crypto;        ///< Cryptographic context associated with the connection.
	SSL_METHOD *meth;             ///< The current SSL method in use.
	SSL_CTX *ctx;                 ///< SSL-specific context information.
	SSL *ssl;                     ///< Pointer to the SSL detail/version/etc.
	LOCK * lock;                  ///< OpenSSL usage lock.
	HANDLE hServerThread;         ///< Handle to the current server thread.
	HANDLE hServerToken;          ///< Handle to the current server security token.
	HANDLE hThreadToken;          ///< Handle to the current thread security token.

	DWORD dwOrigSessionId;        ///< ID of the original Meterpreter session.
	DWORD dwCurrentSessionId;     ///< ID of the currently active session.
	char * cpOrigStationName;     ///< Original station name.
	char * cpCurrentStationName;  ///< Name of the current station.
	char * cpOrigDesktopName;     ///< Original desktop name.
	char * cpCurrentDesktopName;  ///< Name of the current desktop.

	DWORD transport;              ///< Indicator of the transport in use for this session.
	char *url;                    ///< Full URL in use during HTTP or HTTPS transport use.
	char *uri;                    ///< URI endpoint in use during HTTP or HTTPS transport use.
	HANDLE hInternet;             ///< Handle to the internet module for use with HTTP and HTTPS.
	HANDLE hConnection;           ///< Handle to the HTTP or HTTPS connection.

	int expiration_time;          ///< Unix timestamp for when the server should shut down.
	int start_time;               ///< Unix timestamp representing the session startup time.
	int comm_last_packet;         ///< Unix timestamp of the last packet received.
	int comm_timeout;             ///< Unix timestamp for when to shutdown due to comms timeout.
} Remote;

Remote *remote_allocate(SOCKET fd);
VOID remote_deallocate(Remote *remote);

VOID remote_set_fd(Remote *remote, SOCKET fd);
SOCKET remote_get_fd(Remote *remote);

DWORD remote_set_cipher(Remote *remote, LPCSTR cipher,
	struct _Packet *initializer);
CryptoContext *remote_get_cipher(Remote *remote);

#endif
