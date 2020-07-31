/*!
 * @file remote.h
 * @brief Declarations of functions and types that interact with a remote endpoint.
 */
#ifndef _METERPRETER_COMMON_REMOTE_H
#define _METERPRETER_COMMON_REMOTE_H

#include "common_thread.h"
#include "common_config.h"
#include "common_pivot_tree.h"

/*! @brief This is the size of the certificate hash that is validated (sha1) */
#define CERT_HASH_SIZE 20

typedef wchar_t CHARTYPE;
typedef CHARTYPE* STRTYPE;

// Forward declarations required to keep compilers happy.
typedef struct _Packet Packet;
typedef struct _PacketRequestCompletion PacketRequestCompletion;
typedef struct _Transport Transport;
typedef struct _SslLib SslLib;
typedef struct _Remote Remote;
typedef struct _TimeoutSettings TimeoutSettings;
typedef struct _HttpTransportContext HttpTransportContext;
typedef struct _PacketEncryptionContext PacketEncryptionContext;

typedef UINT_PTR(*PTransportGetHandle)(Transport* transport);
typedef DWORD(*PTransportGetConfigSize)(Transport* transport);
typedef void(*PTransportSetHandle)(Transport* transport, UINT_PTR handle);
typedef void(*PTransportReset)(Transport* transport, BOOL shuttingDown);
typedef DWORD(*PTransportInit)(Transport* transport);
typedef DWORD(*PTransportDeinit)(Transport* transport);
typedef void(*PTransportDestroy)(Transport* transport);
typedef DWORD(*PTransportGetMigrateContext)(Transport* transport, DWORD targetProcessId, HANDLE targetProcessHandle, LPDWORD contextSize, LPBYTE* contextBuffer);
typedef Transport*(*PTransportCreate)(Remote* remote, MetsrvTransportCommon* config, LPDWORD size);
typedef void(*PTransportRemove)(Remote* remote, Transport* oldTransport);
typedef void(*PConfigCreate)(Remote* remote, LPBYTE uuid, MetsrvConfig** config, LPDWORD size);

typedef DWORD(*PServerDispatch)(Remote* remote, THREAD* dispatchThread);
typedef DWORD(*PPacketTransmit)(Remote* remote, LPBYTE rawPacket, DWORD rawPacketLength);

typedef HANDLE(*PCreateHttpRequest)(HttpTransportContext* ctx, BOOL isGet, const char* direction);
typedef BOOL(*PSendHttpRequest)(HttpTransportContext* ctx, HANDLE hReq, LPVOID buffer, DWORD size);
typedef BOOL(*PCloseRequest)(HANDLE hReq);
typedef DWORD(*PValidateResponse)(HANDLE hReq, HttpTransportContext* ctx);
typedef BOOL(*PReceiveResponse)(HANDLE hReq);
typedef BOOL(*PReadResponse)(HANDLE hReq, LPVOID buffer, DWORD bytesToRead, LPDWORD bytesRead);

typedef struct _TimeoutSettings
{
	/*! @ brief The total number of seconds to wait for a new packet before killing off the session. */
	int comms;
	/*! @ brief The total number of seconds to keep retrying for before a new session is established. */
	UINT retry_total;
	/*! @ brief The number of seconds to wait between reconnects. */
	UINT retry_wait;
} TimeoutSettings;

typedef struct _TcpTransportContext
{
	SOCKET fd;                            ///! Remote socket file descriptor.
	SOCKET listen;                        ///! Listen socket descriptor, if any.
} TcpTransportContext;

typedef struct _NamedPipeTransportContext
{
	STRTYPE pipe_name;                    ///! Name of the pipe in '\\<server>\<name>' format
	HANDLE pipe;                          ///! Reference to the named pipe handle.
	LOCK* write_lock;                     ///! Reference to the thread write lock.
} NamedPipeTransportContext;

typedef struct _HttpTransportContext
{
	BOOL ssl;                             ///! Flag indicating whether the connection uses SSL.
	HANDLE internet;                      ///! Handle to the internet module for use with HTTP and HTTPS.
	HANDLE connection;                    ///! Handle to the HTTP or HTTPS connection.
	unsigned char* cert_hash;             ///! Pointer to the 20-byte certificate hash to validate

	CSTRTYPE url;                         ///! Pointer to the URL stored with the transport.
	STRTYPE ua;                           ///! User agent string.
	STRTYPE uri;                          ///! UUID encoded as a URI.
	STRTYPE new_uri;                      ///! New URI for stageless URI switches
	STRTYPE proxy;                        ///! Proxy details.
	STRTYPE proxy_user;                   ///! Proxy username.
	STRTYPE proxy_pass;                   ///! Proxy password.
	STRTYPE custom_headers;               ///! List of custom headers to add to outgoing requests.

	BOOL proxy_configured;                ///! Indication of whether the proxy has been configured.
	LPVOID proxy_for_url;                 ///! Pointer to the proxy for the current url (if required).

	BOOL move_to_wininet;                 ///! If set, winhttp is busted, and we need to move to wininet.

	PCreateHttpRequest create_req;        ///! WinHTTP/WinINET specific request creation.
	PSendHttpRequest send_req;            ///! WinHTTP/WinINET specifc request sending.
	PCloseRequest close_req;              ///! WinHTTP/WinINET specifc request closing.
	PValidateResponse validate_response;  ///! WinHTTP/WinINET specific response validation.
	PReceiveResponse receive_response;    ///! WinHttp/WinINET specific response data reception.
	PReadResponse read_response;          ///! WinHttp/WinINET specific response data reading.
} HttpTransportContext;

typedef struct _Transport
{
	DWORD type;                           ///! The type of transport in use.
	PTransportGetHandle get_handle;       ///! Function to get the socket/handle from the transport.
	PTransportSetHandle set_handle;       ///! Function to set the socket/handle on the transport.
	PTransportGetConfigSize get_config_size; ///! Function to get the size of the configuration for the transport.
	PTransportReset transport_reset;      ///! Function to reset/clean the transport ready for restarting.
	PTransportInit transport_init;        ///! Initialises the transport.
	PTransportDeinit transport_deinit;    ///! Deinitialises the transport.
	PTransportDestroy transport_destroy;  ///! Destroy the transport.
	PServerDispatch server_dispatch;      ///! Transport dispatch function.
	PPacketTransmit packet_transmit;      ///! Transmits a packet over the transport.
	PTransportGetMigrateContext get_migrate_context; ///! Creates a migrate context that is transport-specific.
	STRTYPE url;                          ///! Full URL describing the comms in use.
	VOID* ctx;                            ///! Pointer to the type-specific transport context;
	TimeoutSettings timeouts;             ///! Container for the timeout settings.
	int comms_last_packet;                ///! Unix timestamp of the last packet received.
	struct _Transport* next_transport;    ///! Pointer to the next transport in the list.
	struct _Transport* prev_transport;    ///! Pointer to the previous transport in the list.
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
	PConfigCreate config_create;          ///! Pointer to the function that will create a configuration block from the curren setup.

	Transport* transport;                 ///! Pointer to the currently used transport mechanism in a circular list of transports
	Transport* next_transport;            ///! Set externally when transports are requested to be changed.
	DWORD next_transport_wait;            ///! Number of seconds to wait before going to the next transport (used for sleeping).

	MetsrvConfig* orig_config;            ///! Pointer to the original configuration.

	LOCK* lock;                           ///! General transport usage lock (used by SSL, and desktop stuff too).

	HANDLE server_thread;                 ///! Handle to the current server thread.
	HANDLE server_token;                  ///! Handle to the current server security token.
	HANDLE thread_token;                  ///! Handle to the current thread security token.

	DWORD orig_sess_id;                   ///! ID of the original Meterpreter session.
	DWORD curr_sess_id;                   ///! ID of the currently active session.
	char* orig_station_name;              ///! Original station name.
	char* curr_station_name;              ///! Name of the current station.

	char* orig_desktop_name;              ///! Original desktop name.
	char* curr_desktop_name;              ///! Name of the current desktop.

	PTransportCreate trans_create;        ///! Helper to create transports from configuration.
	PTransportRemove trans_remove;        ///! Helper to remove transports from the current session.

	int sess_expiry_time;                 ///! Number of seconds that the session runs for.
	int sess_expiry_end;                  ///! Unix timestamp for when the server should shut down.
	int sess_start_time;                  ///! Unix timestamp representing the session startup time.

	PivotTree* pivot_sessions;            ///! Collection of active Meterpreter session pivots.
	PivotTree* pivot_listeners;           ///! Collection of active Meterpreter pivot listeners.

	PacketEncryptionContext* enc_ctx;     ///! Reference to the packet encryption context.
} Remote;

#endif
