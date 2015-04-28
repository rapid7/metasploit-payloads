/*!
 * @file remote.h
 * @brief Declarations of functions and types that interact with a remote endpoint.
 */
#ifndef _METERPRETER_LIB_REMOTE_H
#define _METERPRETER_LIB_REMOTE_H

#include "crypto.h"
#include "thread.h"

/*! @brief This is the size of the certificate hash that is validated (sha1) */
#define CERT_HASH_SIZE 20

#ifdef _WIN32
typedef wchar_t CHARTYPE;
typedef CHARTYPE* STRTYPE;
#else
typedef char CHARTYPE;
typedef CHARTYPE* STRTYPE;
#endif

// Forward declarations required to keep compilers happy.
typedef struct _Packet Packet;
typedef struct _PacketRequestCompletion PacketRequestCompletion;
typedef struct _Transport Transport;
typedef struct _Remote Remote;
typedef struct _TimeoutSettings TimeoutSettings;

typedef SOCKET(*PTransportGetSocket)(Transport* transport);
typedef void(*PTransportReset)(Transport* transport);
typedef BOOL(*PTransportInit)(Remote* remote, SOCKET fd);
typedef BOOL(*PTransportDeinit)(Remote* remote);
typedef void(*PTransportDestroy)(Remote* remote);
typedef BOOL(*PServerDispatch)(Remote* remote, THREAD* dispatchThread);
typedef DWORD(*PPacketTransmit)(Remote* remote, Packet* packet, PacketRequestCompletion* completion);

typedef Transport*(*PTransCreateTcp)(STRTYPE url, TimeoutSettings* timeouts);
typedef Transport*(*PTransCreateHttp)(BOOL ssl, STRTYPE url, STRTYPE ua, STRTYPE proxy,
		STRTYPE proxyUser, STRTYPE proxyPass, BYTE* certHash, TimeoutSettings* timeouts);

typedef struct _TimeoutSettings
{
	/*! @ brief The total number of seconds to wait before killing off the session. */
	int expiry;
	/*! @ brief The total number of seconds to wait for a new packet before killing off the session. */
	int comms;
	/*! @ brief The total number of seconds to keep retrying for before a new session is established. */
	UINT retry_total;
	/*! @ brief The number of seconds to wait between reconnects. */
	UINT retry_wait;
} TimeoutSettings;

typedef struct _MetsrvConfigData
{
	CHARTYPE transport[28];
	CHARTYPE url[524];
	CHARTYPE ua[256];
	CHARTYPE proxy[104];
	CHARTYPE proxy_username[112];
	CHARTYPE proxy_password[112];
	BYTE ssl_cert_hash[28];
	union
	{
		char placeholder[sizeof(TimeoutSettings)];
		TimeoutSettings values;
	} timeouts;
} MetsrvConfigData;

typedef struct _TcpTransportContext
{
	SOCKET fd;                            ///! Remote socket file descriptor.
	SSL_METHOD* meth;                     ///! The current SSL method in use.
	SSL_CTX* ctx;                         ///! SSL-specific context information.
	SSL* ssl;                             ///! Pointer to the SSL detail/version/etc.
	struct sockaddr_storage sock_desc;    ///! Details of the current socket.
	int sock_desc_size;                   ///! Details of the current socket.
	BOOL bound;                           ///! Flag to indicate if the socket was a bound socket.
} TcpTransportContext;

typedef struct _HttpTransportContext
{
	BOOL ssl;                             ///! Flag indicating whether the connection uses SSL.
	STRTYPE uri;                          ///! URI endpoint in use during HTTP or HTTPS transport use.
	HANDLE internet;                      ///! Handle to the internet module for use with HTTP and HTTPS.
	HANDLE connection;                    ///! Handle to the HTTP or HTTPS connection.
	unsigned char* cert_hash;             ///! Pointer to the 20-byte certificate hash to validate

	STRTYPE ua;                           ///! User agent string.
	STRTYPE proxy;                        ///! Proxy details.
	STRTYPE proxy_user;                   ///! Proxy username.
	STRTYPE proxy_pass;                   ///! Proxy password.
} HttpTransportContext;

typedef struct _Transport
{
	DWORD type;                           ///! The type of transport in use.
	PTransportGetSocket get_socket;       ///! Function to get the socket from the transport.
	PTransportReset transport_reset;      ///! Function to reset/clean the transport ready for restarting.
	PTransportInit transport_init;        ///! Initialises the transport.
	PTransportDeinit transport_deinit;    ///! Deinitialises the transport.
	PTransportDestroy transport_destroy;  ///! Destroy the transport.
	PServerDispatch server_dispatch;      ///! Transport dispatch function.
	PPacketTransmit packet_transmit;      ///! Transmits a packet over the transport.
	STRTYPE url;                          ///! Full URL describing the comms in use.
	VOID* ctx;                            ///! Pointer to the type-specific transport context;
	TimeoutSettings timeouts;             ///! Container for the timeout settings.
	int expiration_end;                   ///! Unix timestamp for when the server should shut down.
	int start_time;                       ///! Unix timestamp representing the session startup time.
	int comms_last_packet;                ///! Unix timestamp of the last packet received.
} Transport;

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
	HMODULE met_srv;                      ///! Reference to the Meterpreter server instance.

	CryptoContext* crypto;                ///! Cryptographic context associated with the connection.

	Transport* transport;                 ///! Pointer to the currently used transport mechanism.
	Transport* next_transport;            ///! Pointer to the next transport to use, if any.

	LOCK* lock;                           ///! General transport usage lock (used by SSL, and desktop stuff too).

	HANDLE server_thread;                 ///! Handle to the current server thread.
	HANDLE server_token;                  ///! Handle to the current server security token.
	HANDLE thread_token;                  ///! Handle to the current thread security token.

	DWORD orig_sess_id;                   ///! ID of the original Meterpreter session.
	DWORD curr_sess_id;                   ///! ID of the currently active session.
	char* orig_station_name;              ///! Original station name.
	char* curr_station_name;              ///! Name of the current station.
#ifdef _WIN32
	char* orig_desktop_name;              ///! Original desktop name.
	char* curr_desktop_name;              ///! Name of the current desktop.
#endif

	PTransCreateTcp trans_create_tcp;     ///! Pointer to a function that creates TCP transports.
	PTransCreateHttp trans_create_http;   ///! Pointer to a function that creates HTTP transports.
} Remote;

Remote* remote_allocate();
VOID remote_deallocate(Remote *remote);

VOID remote_set_fd(Remote *remote, SOCKET fd);

DWORD remote_set_cipher(Remote *remote, LPCSTR cipher, struct _Packet *initializer);
CryptoContext *remote_get_cipher(Remote *remote);

#endif
