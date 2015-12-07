/*!
 * @file remote.h
 * @brief Declarations of functions and types that interact with a remote endpoint.
 */
#ifndef _METERPRETER_LIB_REMOTE_H
#define _METERPRETER_LIB_REMOTE_H

#include "crypto.h"
#include "thread.h"
#include "config.h"

// Include SSL related declarations for required pointers.
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/x509v3.h"

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
typedef struct _SslLib SslLib;
typedef struct _Remote Remote;
typedef struct _TimeoutSettings TimeoutSettings;
typedef struct _HttpTransportContext HttpTransportContext;

typedef SOCKET(*PTransportGetSocket)(Transport* transport);
typedef void(*PTransportReset)(Transport* transport, BOOL shuttingDown);
typedef BOOL(*PTransportInit)(Transport* transport);
typedef BOOL(*PTransportDeinit)(Transport* transport);
typedef void(*PTransportDestroy)(Transport* transport);
typedef Transport*(*PTransportCreate)(Remote* remote, MetsrvTransportCommon* config, LPDWORD size);
typedef void(*PTransportRemove)(Remote* remote, Transport* oldTransport);
typedef void(*PConfigCreate)(Remote* remote, MetsrvConfig** config, LPDWORD size);

typedef BOOL(*PServerDispatch)(Remote* remote, THREAD* dispatchThread);
typedef DWORD(*PPacketTransmit)(Remote* remote, Packet* packet, PacketRequestCompletion* completion);

typedef HANDLE(*PCreateHttpRequest)(HttpTransportContext* ctx, BOOL isGet, const char* direction);
typedef BOOL(*PSendHttpRequest)(HANDLE hReq, LPVOID buffer, DWORD size);
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

#ifdef _WIN32
typedef struct _SslLib
{
	int(*RAND_status)();
	void(*RAND_add)(const void*, int, double);
	int(*RAND_egd)(const char *path);
	ERR_STATE*(*ERR_get_state)();
	const char*(*ERR_reason_error_string)(unsigned long);
	void(*ERR_clear_error)();
	unsigned long(*ERR_peek_last_error)();
	const COMP_METHOD *(*SSL_get_current_compression)(SSL*);
	void*(*SSL_get_ex_data)(const SSL*, int);
	SSL_CTX*(*SSL_set_SSL_CTX)(SSL*, SSL_CTX*);
	SSL_CTX*(*SSL_get_SSL_CTX)(const SSL*);
	int(*SSL_CTX_load_verify_locations)(SSL_CTX*, const char*, const char*);
	int(*SSL_CTX_set_default_verify_paths)(SSL_CTX*);
	int(*SSL_get_shutdown)(const SSL*);
	int(*SSL_library_init)();
	void(*SSL_set_accept_state)(SSL*);
	void(*SSL_set_connect_state)(SSL*);
	int(*SSL_shutdown)(SSL*);
	int(*SSL_do_handshake)(SSL*);
	SSL_METHOD *(*TLSv1_method)();
	SSL_METHOD*(*SSLv23_method)();
	SSL_METHOD*(*SSLv3_method)();
	SSL_METHOD*(*SSLv2_method)();
	const char*(*SSL_get_version)(const SSL*);
	int(*SSL_get_error)(const SSL*, int);
	long(*SSL_CTX_callback_ctrl)(SSL_CTX*, int, void(*)(void));
	long(*SSL_CTX_ctrl)(SSL_CTX*, int, long, void*);
	void(*SSL_free)(SSL*);
	int(*SSL_read)(SSL*, void*, int);
	int(*SSL_write)(SSL*, const void*, int);
	SSL*(*SSL_new)(SSL_CTX*);
	int(*SSL_CTX_set_session_id_context)(SSL_CTX*, const unsigned char*, unsigned int);
	int(*SSL_CTX_check_private_key)(const SSL_CTX*);
	void(*SSL_CTX_set_default_passwd_cb)(SSL_CTX*, pem_password_cb*);
	void(*SSL_CTX_set_default_passwd_cb_userdata)(SSL_CTX*, void*);
	int(*SSL_set_ex_data)(SSL *ssl, int idx, void *data);
	long(*SSL_ctrl)(SSL *ssl, int cmd, long larg, void *parg);
	void(*SSL_CTX_set_verify)(SSL_CTX *ctx, int mode, int(*callback)(int, X509_STORE_CTX *));
	int(*SSL_CTX_get_verify_mode)(const SSL_CTX *ctx);
	X509*(*SSL_get_peer_certificate)(const SSL *s);
	void(*SSL_load_error_strings)(void);
	int(*SSL_CTX_use_certificate_chain_file)(SSL_CTX *ctx, const char *file); /* PEM type */
	int(*SSL_CTX_use_PrivateKey_file)(SSL_CTX *ctx, const char *file, int type);
	void(*SSL_set_read_ahead)(SSL *s, int yes);
	BIO*(*SSL_get_wbio)(const SSL *s);
	BIO*(*SSL_get_rbio)(const SSL *s);
	int(*SSL_set_fd)(SSL *s, int fd);
	int(*SSL_pending)(const SSL *s);
	char*(*SSL_CIPHER_get_version)(const SSL_CIPHER *c);
	const char*(*SSL_CIPHER_get_name)(const SSL_CIPHER *c);
	int(*SSL_CIPHER_get_bits)(const SSL_CIPHER *c, int *alg_bits);
	SSL_CIPHER*(*SSL_get_current_cipher)(const SSL *s);
	X509_STORE*(*SSL_CTX_get_cert_store)(const SSL_CTX *);
	void(*SSL_CTX_free)(SSL_CTX *);
	SSL_CTX *(*SSL_CTX_new)(SSL_METHOD *meth);
	int(*SSL_CTX_set_cipher_list)(SSL_CTX *, const char *str);
	size_t(*SSL_get_finished)(const SSL *s, void *buf, size_t count);
	size_t(*SSL_get_peer_finished)(const SSL *s, void *buf, size_t count);
	const char*(*SSL_get_servername)(const SSL *s, const int type);
	int(*PEM_read_bio)(BIO *bp, char **name, char **header, unsigned char **data, long *len);
	X509*(*PEM_read_bio_X509)(BIO *bp, X509 **x, pem_password_cb *cb, void *u);
	X509*(*PEM_read_bio_X509_AUX)(BIO *bp, X509 **x, pem_password_cb *cb, void *u);
	int(*X509_check_ca)(X509 *x);
	DH *(*PEM_read_bio_DHparams)(BIO *bp, DH **x, pem_password_cb *cb, void *u);
	X509V3_EXT_METHOD *(*X509V3_EXT_get)(X509_EXTENSION *ext);
	void(*AUTHORITY_INFO_ACCESS_free)(AUTHORITY_INFO_ACCESS* a);
	int(*GENERAL_NAME_print)(BIO* out, GENERAL_NAME* gen);
	void(*GENERAL_NAME_free)(GENERAL_NAME* gen);
	int(*X509_add_ext)(X509 *x, X509_EXTENSION *ex, int loc);
	void*(*X509_get_ext_d2i)(X509 *x, int nid, int *crit, int *idx);
	int(*X509_get_ext_by_NID)(X509 *x, int nid, int lastpos);
	ASN1_OBJECT*(*X509_NAME_ENTRY_get_object)(X509_NAME_ENTRY *ne);
	ASN1_STRING*(*X509_NAME_ENTRY_get_data)(X509_NAME_ENTRY *ne);
	X509_NAME_ENTRY*(*X509_NAME_get_entry)(X509_NAME *name, int loc);
	int(*X509_NAME_entry_count)(X509_NAME *name);
	X509_NAME*(*X509_get_subject_name)(X509 *a);
	ASN1_INTEGER*(*X509_get_serialNumber)(X509 *x);
	X509_EXTENSION*(*X509_get_ext)(X509 *x, int loc);
	X509_NAME*(*X509_get_issuer_name)(X509 *a);
	void(*X509_free)(X509*);
	int(*i2d_X509)(X509* a, unsigned char** out);
	char*(*sk_value)(const STACK*, int);
	int(*sk_num)(const STACK* s);
	void(*sk_pop_free)(STACK *st, void (*func)(void *));
	const char*(*SSLeay_version)(int type);
	unsigned long(*SSLeay)(void);
	int(*CRYPTO_num_locks)(void);
	void(*CRYPTO_set_locking_callback)(void (*func)(int mode,int type, const char *file,int line));
	void(*CRYPTO_set_id_callback)(unsigned long (*func)(void));
	void(*CRYPTO_free)(void* p);
	BIO_METHOD*(*BIO_s_file)(void);
	BIO*(*BIO_new_file)(const char *filename, const char *mode);
	BIO*(*BIO_new)(BIO_METHOD *type);
	int(*BIO_gets)(BIO *bp,char *buf, int size);
	long(*BIO_ctrl)(BIO *bp,int cmd,long larg,void *parg);
	BIO_METHOD*(*BIO_s_mem)(void);
	BIO*(*BIO_new_mem_buf)(void *buf, int len);
	int(*BIO_free)(BIO *a);
	void(*ASN1_OBJECT_free)(ASN1_OBJECT *a);
	int(*ASN1_STRING_length)(ASN1_STRING *x);
	unsigned char*(*ASN1_STRING_data)(ASN1_STRING *x);
	int(*i2a_ASN1_INTEGER)(BIO *bp, ASN1_INTEGER *a);
	long(*ASN1_INTEGER_get)(ASN1_INTEGER *a);
	int(*ASN1_STRING_to_UTF8)(unsigned char **out, ASN1_STRING *in);
	int(*ASN1_TIME_print)(BIO *fp,ASN1_TIME *a);
	ASN1_VALUE*(*ASN1_item_d2i)(ASN1_VALUE **val, const unsigned char **in, long len, const ASN1_ITEM *it);
	ASN1_OBJECT*(*OBJ_nid2obj)(int n);
	const char*(*OBJ_nid2ln)(int n);
	const char*(*OBJ_nid2sn)(int n);
	int(*OBJ_obj2nid)(const ASN1_OBJECT *o);
	ASN1_OBJECT*(*OBJ_txt2obj)(const char *s, int no_name);
	int(*OBJ_obj2txt)(char *buf, int buf_len, const ASN1_OBJECT *a, int no_name);
	int(*OBJ_sn2nid)(const char *s);
	void(*OPENSSL_add_all_algorithms_noconf)(void);
	EC_KEY*(*EC_KEY_new_by_curve_name)(int nid);
	void(*EC_KEY_free)(EC_KEY *);
	void(*DH_free)(DH *dh);
	int(*X509_STORE_add_cert)(X509_STORE *ctx, X509 *x);
	int(*X509_VERIFY_PARAM_set_flags)(X509_VERIFY_PARAM *param, unsigned long flags);
	int(*X509_VERIFY_PARAM_clear_flags)(X509_VERIFY_PARAM *param, unsigned long flags);
	unsigned long(*X509_VERIFY_PARAM_get_flags)(X509_VERIFY_PARAM *param);
	X509*(*d2i_X509_bio)(BIO *bp,X509 **x509);
	const char*(*X509_get_default_cert_dir)();
	const char*(*X509_get_default_cert_file)();
	const char*(*X509_get_default_cert_dir_env)();
	const char*(*X509_get_default_cert_file_env)();
} SslLib;
#endif

typedef struct _TcpTransportContext
{
	SOCKET fd;                            ///! Remote socket file descriptor.
	SOCKET listen;                        ///! Listen socket descriptor, if any.
	SSL_METHOD* meth;                     ///! The current SSL method in use.
	SSL_CTX* ctx;                         ///! SSL-specific context information.
	SSL* ssl;                             ///! Pointer to the SSL detail/version/etc.
} TcpTransportContext;

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
	int comms_last_packet;                ///! Unix timestamp of the last packet received.
	struct _Transport* next_transport;    ///! Pointer to the next transport in the list.
	struct _Transport* prev_transport;    ///! Pointer to the previous transport in the list.
	LOCK* lock;                           ///! Shared reference to the lock used in Remote.
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

#ifdef _WIN32
	char* orig_desktop_name;              ///! Original desktop name.
	char* curr_desktop_name;              ///! Name of the current desktop.
#endif

	PTransportCreate trans_create;        ///! Helper to create transports from configuration.
	PTransportRemove trans_remove;        ///! Helper to remove transports from the current session.

	int sess_expiry_time;                 ///! Number of seconds that the session runs for.
	int sess_expiry_end;                  ///! Unix timestamp for when the server should shut down.
	int sess_start_time;                  ///! Unix timestamp representing the session startup time.

#ifdef _WIN32
	SslLib ssl;                           ///! Pointer to SSL related functions, for sharing across extensions.
#endif
} Remote;

Remote* remote_allocate();
VOID remote_deallocate(Remote *remote);

VOID remote_set_fd(Remote *remote, SOCKET fd);

DWORD remote_set_cipher(Remote *remote, LPCSTR cipher, struct _Packet *initializer);
CryptoContext *remote_get_cipher(Remote *remote);

#endif
