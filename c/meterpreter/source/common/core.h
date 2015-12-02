/*!
 * @file core.h
 * @brief Declarations of core components of the Meterpreter suite.
 * @details Much of what exists in the core files is used in almost every area
 *          of the Meterpreter code base, and hence it's very important. Don't
 *          change this stuff unless you know what you're doing!
 */
#ifndef _METERPRETER_CORE_H
#define _METERPRETER_CORE_H

#include "linkage.h"
#include "remote.h"
#include "list.h"

/*!
 * @brief Creates a new TLV value based on `actual` and `meta` values.
 */
#define TLV_VALUE(meta, actual) actual | meta
/*!
 * @brief Creates a new custom TVL type.
 */
#define MAKE_CUSTOM_TLV(meta, base, actual) (TlvType)((base + actual) | meta)

/*!
 * @brief Enumeration of allowed Packet TLV types.
 */
typedef enum 
{
	PACKET_TLV_TYPE_REQUEST        = 0,   ///< Indicates a request packet.
	PACKET_TLV_TYPE_RESPONSE       = 1,   ///< Indicates a response packet.
	PACKET_TLV_TYPE_PLAIN_REQUEST  = 10,  ///< Indicates a plain request packet.
	PACKET_TLV_TYPE_PLAIN_RESPONSE = 11,  ///< Indicates a plain response packet.
} PacketTlvType;

/*! @brief Meta TLV argument type representing a null value. */
#define TLV_META_TYPE_NONE          (0 << 0)
/*! @brief Meta TLV argument type representing a string value. */
#define TLV_META_TYPE_STRING        (1 << 16)
/*! @brief Meta TLV argument type representing a unsigned integer value. */
#define TLV_META_TYPE_UINT          (1 << 17)
/*! @brief Meta TLV argument type representing a raw data value. */
#define TLV_META_TYPE_RAW           (1 << 18)
/*! @brief Meta TLV argument type representing a boolean value. */
#define TLV_META_TYPE_BOOL          (1 << 19)
/*! @brief Meta TLV argument type representing a quad-word value. */
#define TLV_META_TYPE_QWORD         (1 << 20)
/*! @brief Meta TLV argument type representing a compressed data value. */
#define TLV_META_TYPE_COMPRESSED    (1 << 29)
/*! @brief Meta TLV argument type representing a group value. */
#define TLV_META_TYPE_GROUP         (1 << 30)
/*! @brief Meta TLV argument type representing a nested/complex value. */
#define TLV_META_TYPE_COMPLEX       (1 << 31)
/*! @brief Meta TLV argument type representing a flag set/mask value. */
#define TLV_META_TYPE_MASK(x)       ((x) & 0xffff0000)

/*! @brief Base value for reserved TLV definitions. */
#define TLV_RESERVED                0
/*! @brief Base value for TLV definitions that are part of extensions. */
#define TLV_EXTENSIONS              20000
/*! @brief Base value for user TLV definitions. */
#define TLV_USER                    40000
/*! @brief Base value for temporary TLV definitions. */
#define TLV_TEMP                    60000

/*!
 * @brief Indicates that the library in question should be stored on disk.
 * @detail Some libraries can be written to disk and other libraries can't. The use of
 *         this flag will indicate that the library should not be written to disk and
 *         instead should be loaded reflectively.
 */
#define LOAD_LIBRARY_FLAG_ON_DISK   (1 << 0)

/*!
 * @brief Indicates that the library in question is an extension library.
 * @detail Extension libraries have \c InitServerExtension and \c DeinitServerExtension
 *         functions which need to be invoked. This flag indicates that the library has
 *         these functions and that they should be called appropriately.
 */
#define LOAD_LIBRARY_FLAG_EXTENSION (1 << 1)

/*!
 * @brief Indicates that the library in question is a library that exists locally.
 * @detail Libraries can already exist on the target machine. This flag indicates that
 *         the library doesn't need to be uploaded, it just needs to be invoked directly
 *         on the local machine.
 */
#define LOAD_LIBRARY_FLAG_LOCAL     (1 << 2)

/*! @brief An indication of whether the challen is synchronous or asynchronous. */
#define CHANNEL_FLAG_SYNCHRONOUS    (1 << 0)
/*! @brief An indication of whether the content written to the channel should be compressed. */
#define CHANNEL_FLAG_COMPRESS       (1 << 1)

/*! @brief Type definition with defines `TlvMetaType` as an double-word. */
typedef DWORD TlvMetaType;

/*!
 * @brief Full list of recognised TLV types.
 */
typedef enum
{
	TLV_TYPE_ANY                 = TLV_VALUE(TLV_META_TYPE_NONE,        0),   ///! Represents an undefined/arbitrary value.
	TLV_TYPE_METHOD              = TLV_VALUE(TLV_META_TYPE_STRING,      1),   ///! Represents a method/function name value.
	TLV_TYPE_REQUEST_ID          = TLV_VALUE(TLV_META_TYPE_STRING,      2),   ///! Represents a request identifier value.
	TLV_TYPE_EXCEPTION           = TLV_VALUE(TLV_META_TYPE_GROUP,       3),   ///! Represents an exception value.
	TLV_TYPE_RESULT              = TLV_VALUE(TLV_META_TYPE_UINT,        4),   ///! Represents a result value.

	// Argument basic types
	TLV_TYPE_STRING              = TLV_VALUE(TLV_META_TYPE_STRING,     10),   ///! Represents a string value.
	TLV_TYPE_UINT                = TLV_VALUE(TLV_META_TYPE_UINT,       11),   ///! Represents an unsigned integer value.
	TLV_TYPE_BOOL                = TLV_VALUE(TLV_META_TYPE_BOOL,       12),   ///! Represents a boolean value.

	// Extended types
	TLV_TYPE_LENGTH              = TLV_VALUE(TLV_META_TYPE_UINT,       25),   ///! Represents a length (unsigned integer).
	TLV_TYPE_DATA                = TLV_VALUE(TLV_META_TYPE_RAW,        26),   ///! Represents arbitrary data (raw).
	TLV_TYPE_FLAGS               = TLV_VALUE(TLV_META_TYPE_UINT,       27),   ///! Represents a set of flags (unsigned integer).

	// Channel types
	TLV_TYPE_CHANNEL_ID          = TLV_VALUE(TLV_META_TYPE_UINT,       50),   ///! Represents a channel identifier (unsigned integer).
	TLV_TYPE_CHANNEL_TYPE        = TLV_VALUE(TLV_META_TYPE_STRING,     51),   ///! Represents a channel type (string).
	TLV_TYPE_CHANNEL_DATA        = TLV_VALUE(TLV_META_TYPE_RAW,        52),   ///! Represents channel data (raw).
	TLV_TYPE_CHANNEL_DATA_GROUP  = TLV_VALUE(TLV_META_TYPE_GROUP,      53),   ///! Represents a channel data group (group).
	TLV_TYPE_CHANNEL_CLASS       = TLV_VALUE(TLV_META_TYPE_UINT,       54),   ///! Represents a channel class (unsigned integer).
	TLV_TYPE_CHANNEL_PARENTID    = TLV_VALUE(TLV_META_TYPE_UINT,       55),   ///! Represents a channel parent identifier (unsigned integer).

	// Channel extended types
	TLV_TYPE_SEEK_WHENCE         = TLV_VALUE(TLV_META_TYPE_UINT,       70),
	TLV_TYPE_SEEK_OFFSET         = TLV_VALUE(TLV_META_TYPE_UINT,       71),
	TLV_TYPE_SEEK_POS            = TLV_VALUE(TLV_META_TYPE_UINT,       72),

	// Grouped identifiers
	TLV_TYPE_EXCEPTION_CODE      = TLV_VALUE(TLV_META_TYPE_UINT,      300),   ///! Represents an exception code value (unsigned in).
	TLV_TYPE_EXCEPTION_STRING    = TLV_VALUE(TLV_META_TYPE_STRING,    301),   ///! Represents an exception message value (string).

	// Library loading
	TLV_TYPE_LIBRARY_PATH        = TLV_VALUE(TLV_META_TYPE_STRING,    400),   ///! Represents a path to the library to be loaded (string).
	TLV_TYPE_TARGET_PATH         = TLV_VALUE(TLV_META_TYPE_STRING,    401),   ///! Represents a target path (string).
	TLV_TYPE_MIGRATE_PID         = TLV_VALUE(TLV_META_TYPE_UINT,      402),   ///! Represents a process identifier of the migration target (unsigned integer).
	TLV_TYPE_MIGRATE_LEN         = TLV_VALUE(TLV_META_TYPE_UINT,      403),   ///! Represents a migration payload size/length in bytes (unsigned integer).
	TLV_TYPE_MIGRATE_PAYLOAD     = TLV_VALUE(TLV_META_TYPE_STRING,    404),   ///! Represents a migration payload (string).
	TLV_TYPE_MIGRATE_ARCH        = TLV_VALUE(TLV_META_TYPE_UINT,      405),   ///! Represents a migration target architecture.
	TLV_TYPE_MIGRATE_TECHNIQUE   = TLV_VALUE(TLV_META_TYPE_UINT,      406),   ///! Represents a migration technique (unsigned int).
	TLV_TYPE_MIGRATE_BASE_ADDR   = TLV_VALUE(TLV_META_TYPE_UINT,      407),   ///! Represents a migration payload base address (unsigned int).
	TLV_TYPE_MIGRATE_ENTRY_POINT = TLV_VALUE(TLV_META_TYPE_UINT,      408),   ///! Represents a migration payload entry point (unsigned int).
	TLV_TYPE_MIGRATE_SOCKET_PATH = TLV_VALUE(TLV_META_TYPE_STRING,    409),   ///! Represents a unix domain socket path, used to migrate on linux (string)

	// Transport switching
	TLV_TYPE_TRANS_TYPE          = TLV_VALUE(TLV_META_TYPE_UINT,      430),   ///! Represents the type of transport to switch to.
	TLV_TYPE_TRANS_URL           = TLV_VALUE(TLV_META_TYPE_STRING,    431),   ///! Represents the new URL of the transport to use.
	TLV_TYPE_TRANS_UA            = TLV_VALUE(TLV_META_TYPE_STRING,    432),   ///! Represents the user agent (for http).
	TLV_TYPE_TRANS_COMM_TIMEOUT  = TLV_VALUE(TLV_META_TYPE_UINT,      433),   ///! Represents the communications timeout.
	TLV_TYPE_TRANS_SESSION_EXP   = TLV_VALUE(TLV_META_TYPE_UINT,      434),   ///! Represents the session expiration.
	TLV_TYPE_TRANS_CERT_HASH     = TLV_VALUE(TLV_META_TYPE_RAW,       435),   ///! Represents the certificate hash (for https).
	TLV_TYPE_TRANS_PROXY_HOST    = TLV_VALUE(TLV_META_TYPE_STRING,    436),   ///! Represents the proxy host string (for http/s).
	TLV_TYPE_TRANS_PROXY_USER    = TLV_VALUE(TLV_META_TYPE_STRING,    437),   ///! Represents the proxy user name (for http/s).
	TLV_TYPE_TRANS_PROXY_PASS    = TLV_VALUE(TLV_META_TYPE_STRING,    438),   ///! Represents the proxy password (for http/s).
	TLV_TYPE_TRANS_RETRY_TOTAL   = TLV_VALUE(TLV_META_TYPE_UINT,      439),   ///! Total time (seconds) to continue retrying comms.
	TLV_TYPE_TRANS_RETRY_WAIT    = TLV_VALUE(TLV_META_TYPE_UINT,      440),   ///! Time (seconds) to wait between reconnect attempts.
	TLV_TYPE_TRANS_GROUP         = TLV_VALUE(TLV_META_TYPE_GROUP,     441),   ///! A single transport grouping.

	// session/machine identification
	TLV_TYPE_MACHINE_ID          = TLV_VALUE(TLV_META_TYPE_STRING,    460),   ///! Represents a machine identifier.
	TLV_TYPE_UUID                = TLV_VALUE(TLV_META_TYPE_RAW,       461),   ///! Represents a UUID.

	// Cryptography
	TLV_TYPE_CIPHER_NAME         = TLV_VALUE(TLV_META_TYPE_STRING,    500),   ///! Represents the name of a cipher.
	TLV_TYPE_CIPHER_PARAMETERS   = TLV_VALUE(TLV_META_TYPE_GROUP,     501),   ///! Represents parameters for a cipher.

	TLV_TYPE_EXTENSIONS          = TLV_VALUE(TLV_META_TYPE_COMPLEX, 20000),   ///! Represents an extension value.
	TLV_TYPE_USER                = TLV_VALUE(TLV_META_TYPE_COMPLEX, 40000),   ///! Represents a user value.
	TLV_TYPE_TEMP                = TLV_VALUE(TLV_META_TYPE_COMPLEX, 60000),   ///! Represents a temporary value.
} TlvType;

#ifdef _WIN32

#ifndef QWORD
typedef unsigned __int64	QWORD;
#endif

#define ntohq( qword )		( (QWORD)ntohl( qword & 0xFFFFFFFF ) << 32 ) | ntohl( qword >> 32 )
#define htonq( qword )		ntohq( qword )

#endif

typedef struct
{
	DWORD length;
	DWORD type;
} TlvHeader;

typedef struct
{
	TlvHeader header;
	PUCHAR    buffer;
} Tlv;

typedef struct
{
	DWORD xor_key;
	DWORD length;
	DWORD type;
} PacketHeader;

/*! @brief Packet definition. */
typedef struct _Packet
{
	PacketHeader header;

	PUCHAR    payload;
	ULONG     payloadLength;

	LIST *    decompressed_buffers;

	///! @brief Flag indicating if this packet is a local (ie. non-transmittable) packet.
	BOOL local;
	///! @brief Pointer to the associated packet (response/request)
	struct _Packet* partner;
} Packet;

typedef struct _DECOMPRESSED_BUFFER
{
	LPVOID buffer;
	DWORD length;
} DECOMPRESSED_BUFFER;

/*! * @brief Packet request completion notification handler function pointer type. */
typedef DWORD (*PacketRequestCompletionRoutine)(Remote *remote, 
		Packet *response, LPVOID context, LPCSTR method, DWORD result);

typedef struct _PacketRequestCompletion
{
	LPVOID                         context;
	PacketRequestCompletionRoutine routine;
	DWORD                          timeout;
} PacketRequestCompletion;

/*
 * Packet manipulation
 */
LINKAGE Packet *packet_create(PacketTlvType type, LPCSTR method);
LINKAGE Packet *packet_create_response(Packet *packet);
LINKAGE Packet* packet_create_group();
LINKAGE Packet *packet_duplicate(Packet *packet);
LINKAGE VOID packet_destroy(Packet *packet);

LINKAGE DWORD packet_add_group(Packet* packet, TlvType type, Packet* groupPacket);
LINKAGE DWORD packet_add_tlv_string(Packet *packet, TlvType type, LPCSTR str);
LINKAGE DWORD packet_add_tlv_wstring(Packet *packet, TlvType type, LPCWSTR str);
LINKAGE DWORD packet_add_tlv_wstring_len(Packet *packet, TlvType type, LPCWSTR str, size_t strLength);
LINKAGE DWORD packet_add_tlv_uint(Packet *packet, TlvType type, UINT val);
LINKAGE DWORD packet_add_tlv_qword(Packet *packet, TlvType type, QWORD val );
LINKAGE DWORD packet_add_tlv_bool(Packet *packet, TlvType type, BOOL val);
LINKAGE DWORD packet_add_tlv_group(Packet *packet, TlvType type, Tlv *entries, DWORD numEntries);
LINKAGE DWORD packet_add_tlvs(Packet *packet, Tlv *entries, DWORD numEntries);
LINKAGE DWORD packet_add_tlv_raw(Packet *packet, TlvType type, LPVOID buf, DWORD length);
LINKAGE DWORD packet_is_tlv_null_terminated(Tlv *tlv);
LINKAGE PacketTlvType packet_get_type(Packet *packet);
LINKAGE TlvMetaType packet_get_tlv_meta(Packet *packet, Tlv *tlv);
LINKAGE DWORD packet_get_tlv(Packet *packet, TlvType type, Tlv *tlv);
LINKAGE DWORD packet_get_tlv_string(Packet *packet, TlvType type, Tlv *tlv);
LINKAGE DWORD packet_get_tlv_group_entry(Packet *packet, Tlv *group, TlvType type,Tlv *entry);
LINKAGE DWORD packet_enum_tlv(Packet *packet, DWORD index, TlvType type, Tlv *tlv);

LINKAGE PCHAR packet_get_tlv_value_string(Packet *packet, TlvType type); 
LINKAGE wchar_t* packet_get_tlv_value_wstring(Packet* packet, TlvType type);
LINKAGE UINT packet_get_tlv_value_uint(Packet *packet, TlvType type);
LINKAGE BYTE * packet_get_tlv_value_raw( Packet * packet, TlvType type );
LINKAGE QWORD packet_get_tlv_value_qword(Packet *packet, TlvType type);
LINKAGE BOOL packet_get_tlv_value_bool(Packet *packet, TlvType type); 

LINKAGE DWORD packet_add_exception(Packet *packet, DWORD code,PCHAR string, ...);

LINKAGE DWORD packet_get_result(Packet *packet);

/*
 * Packet transmission
 */
LINKAGE DWORD packet_transmit_response(DWORD result, Remote* remote, Packet* response);
LINKAGE DWORD packet_transmit_empty_response(Remote *remote, Packet *packet, DWORD res);
#define PACKET_TRANSMIT(remote, packet, completion) ((packet->partner==NULL||!packet->partner->local)?(remote->transport->packet_transmit(remote, packet, completion)):(ERROR_SUCCESS))

/*
 * Packet completion notification
 */
LINKAGE DWORD packet_add_completion_handler(LPCSTR requestId, PacketRequestCompletion *completion);
LINKAGE DWORD packet_call_completion_handlers(Remote *remote, Packet *response,LPCSTR requestId);
LINKAGE DWORD packet_remove_completion_handler(LPCSTR requestId);

/*
 * Core API
 */
LINKAGE HANDLE core_update_thread_token( Remote *remote, HANDLE token );
LINKAGE VOID core_update_desktop( Remote * remote, DWORD dwSessionID, char * cpStationName, char * cpDesktopName );

#endif
