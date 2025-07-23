/*!
 * @file core.h
 * @brief Declarations of core components of the Meterpreter suite.
 * @details Much of what exists in the core files is used in almost every area
 *          of the Meterpreter code base, and hence it's very important. Don't
 *          change this stuff unless you know what you're doing!
 */
#ifndef _METERPRETER_COMMON_CORE_H
#define _METERPRETER_COMMON_CORE_H

#include "common_remote.h"
#include "common_list.h"

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
	PACKET_TLV_TYPE_CONFIG         = 2,   ///< Indicates a configuration packet.
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


#define C2_ENCODING_FLAG_B64        (1 << 0) //! straight Base64 encoding
#define C2_ENCODING_FLAG_B64URL     (1 << 1) //! encoding Base64 with URL-safe values
#define C2_ENCODING_FLAG_URL        (1 << 2) //! straight URL encoding

/*! @brief Type definition with defines `TlvMetaType` as an double-word. */
typedef DWORD TlvMetaType;

/*!
 * @brief Full list of recognised TLV types.
 */
typedef enum
{
	TLV_TYPE_ANY                 = TLV_VALUE(TLV_META_TYPE_NONE,        0),   ///! Represents an undefined/arbitrary value.
	TLV_TYPE_COMMAND_ID          = TLV_VALUE(TLV_META_TYPE_UINT,        1),   ///! Represents a command identifier.
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
	TLV_TYPE_MIGRATE_PAYLOAD     = TLV_VALUE(TLV_META_TYPE_RAW,       404),   ///! Represents a migration payload (raw).
	TLV_TYPE_MIGRATE_ARCH        = TLV_VALUE(TLV_META_TYPE_UINT,      405),   ///! Represents a migration target architecture.
	TLV_TYPE_MIGRATE_TECHNIQUE   = TLV_VALUE(TLV_META_TYPE_UINT,      406),   ///! Represents a migration technique (unsigned int).
	TLV_TYPE_MIGRATE_BASE_ADDR   = TLV_VALUE(TLV_META_TYPE_UINT,      407),   ///! Represents a migration payload base address (unsigned int).
	TLV_TYPE_MIGRATE_ENTRY_POINT = TLV_VALUE(TLV_META_TYPE_UINT,      408),   ///! Represents a migration payload entry point (unsigned int).
	TLV_TYPE_MIGRATE_SOCKET_PATH = TLV_VALUE(TLV_META_TYPE_STRING,    409),   ///! Represents a unix domain socket path, used to migrate on linux (string)
	TLV_TYPE_MIGRATE_STUB        = TLV_VALUE(TLV_META_TYPE_RAW,       411),   ///! Represents a migration stub (raw).
	TLV_TYPE_LIB_LOADER_NAME     = TLV_VALUE(TLV_META_TYPE_STRING,    412),   ///! Represents the name of the ReflectiveLoader function (string).
	TLV_TYPE_LIB_LOADER_ORDINAL  = TLV_VALUE(TLV_META_TYPE_UINT,      413),   ///! Represents the ordinal of the ReflectiveLoader function (int).

	// session/machine identification
	TLV_TYPE_MACHINE_ID          = TLV_VALUE(TLV_META_TYPE_STRING,    460),   ///! Represents a machine identifier.
	TLV_TYPE_UUID                = TLV_VALUE(TLV_META_TYPE_RAW,       461),   ///! Represents a UUID.
	TLV_TYPE_SESSION_GUID        = TLV_VALUE(TLV_META_TYPE_RAW,       462),   ///! Represents a Session GUID.

	// Packet encryption
	TLV_TYPE_RSA_PUB_KEY         = TLV_VALUE(TLV_META_TYPE_RAW,       550),   ///! Represents DER-encoded RSA public key
	TLV_TYPE_SYM_KEY_TYPE        = TLV_VALUE(TLV_META_TYPE_UINT,      551),   ///! Represents the type of symmetric key
	TLV_TYPE_SYM_KEY             = TLV_VALUE(TLV_META_TYPE_RAW,       552),   ///! Represents the symmetric key
	TLV_TYPE_ENC_SYM_KEY         = TLV_VALUE(TLV_META_TYPE_RAW,       553),   ///! Represents and RSA-encrypted symmetric key

	// Pivots
	TLV_TYPE_PIVOT_ID              = TLV_VALUE(TLV_META_TYPE_RAW,     650),   ///! Represents the id of the pivot listener
	TLV_TYPE_PIVOT_STAGE_DATA      = TLV_VALUE(TLV_META_TYPE_RAW,     651),   ///! Represents the data to be staged on new connections.
	TLV_TYPE_PIVOT_NAMED_PIPE_NAME = TLV_VALUE(TLV_META_TYPE_STRING,  653),   ///! Represents named pipe name.

	TLV_TYPE_SESSION_EXPIRY        = TLV_VALUE(TLV_META_TYPE_UINT,    700),   ///! Session expiration time
	TLV_TYPE_EXITFUNC              = TLV_VALUE(TLV_META_TYPE_UINT,    701),   ///! identifier of the exit function to use
	TLV_TYPE_DEBUG_LOG             = TLV_VALUE(TLV_META_TYPE_STRING,  702),   ///! path to write debug log
	TLV_TYPE_EXTENSION             = TLV_VALUE(TLV_META_TYPE_GROUP,   703),   ///! Group containing extension info
	TLV_TYPE_C2                    = TLV_VALUE(TLV_META_TYPE_GROUP,   704),   ///! a C2/transport grouping
	TLV_TYPE_C2_COMM_TIMEOUT       = TLV_VALUE(TLV_META_TYPE_UINT,    705),   ///! the timeout for this C2 group
	TLV_TYPE_C2_RETRY_TOTAL        = TLV_VALUE(TLV_META_TYPE_UINT,    706),   ///! number of times to retry this C2
	TLV_TYPE_C2_RETRY_WAIT         = TLV_VALUE(TLV_META_TYPE_UINT,    707),   ///! how long to wait between reconnect attempts
	TLV_TYPE_C2_URL                = TLV_VALUE(TLV_META_TYPE_STRING,  708),   ///! base URL of this C2 (scheme://host:port/uri)
	TLV_TYPE_C2_URI                = TLV_VALUE(TLV_META_TYPE_STRING,  709),   ///! URI to append to base URL (for HTTP(s)), if any
	TLV_TYPE_C2_PROXY_HOST         = TLV_VALUE(TLV_META_TYPE_STRING,  710),   ///! Host name of proxy
	TLV_TYPE_C2_PROXY_USER         = TLV_VALUE(TLV_META_TYPE_STRING,  711),   ///! Proxy user name
	TLV_TYPE_C2_PROXY_PASS         = TLV_VALUE(TLV_META_TYPE_STRING,  712),   ///! Proxy password
	TLV_TYPE_C2_GET                = TLV_VALUE(TLV_META_TYPE_GROUP,   713),   ///! A grouping of params associated with GET requests
	TLV_TYPE_C2_POST               = TLV_VALUE(TLV_META_TYPE_GROUP,   714),   ///! A grouping of params associated with POST requests
	TLV_TYPE_C2_HEADERS            = TLV_VALUE(TLV_META_TYPE_STRING,  715),   ///! Custom headers
	TLV_TYPE_C2_UA                 = TLV_VALUE(TLV_META_TYPE_STRING,  716),   ///! User agent
	TLV_TYPE_C2_CERT_HASH          = TLV_VALUE(TLV_META_TYPE_RAW,     717),   ///! Expected SSL certificate hash
	TLV_TYPE_C2_PREFIX             = TLV_VALUE(TLV_META_TYPE_RAW,     718),   ///! Data to prepend to the outgoing payload
	TLV_TYPE_C2_SUFFIX             = TLV_VALUE(TLV_META_TYPE_RAW,     719),   ///! Data to append to the outgoing payload
	TLV_TYPE_C2_ENC                = TLV_VALUE(TLV_META_TYPE_UINT,    720),   ///! Request encoding flags (Base64|URL|Base64url)
	TLV_TYPE_C2_SKIP_COUNT         = TLV_VALUE(TLV_META_TYPE_UINT,    721),   ///! Number of bytes of the incoming payload to ignore before parsing
	TLV_TYPE_C2_UUID_COOKIE        = TLV_VALUE(TLV_META_TYPE_STRING,  722),   ///! Name of the cookie to put the UUID in
	TLV_TYPE_C2_UUID_GET           = TLV_VALUE(TLV_META_TYPE_STRING,  723),   ///! Name of the GET parameter to put the UUID in
	TLV_TYPE_C2_UUID_HEADER        = TLV_VALUE(TLV_META_TYPE_STRING,  724),   ///! Name of the header to put the UUID in
	TLV_TYPE_C2_UUID               = TLV_VALUE(TLV_META_TYPE_STRING,  725),   ///! The UUID string to use for the C2 transport

	TLV_TYPE_EXTENSIONS            = TLV_VALUE(TLV_META_TYPE_COMPLEX, 20000), ///! Represents an extension value.
	TLV_TYPE_USER                  = TLV_VALUE(TLV_META_TYPE_COMPLEX, 40000), ///! Represents a user value.
	TLV_TYPE_TEMP                  = TLV_VALUE(TLV_META_TYPE_COMPLEX, 60000), ///! Represents a temporary value.
} TlvType;

#ifndef QWORD
typedef unsigned __int64	QWORD;
#endif

#define ntohq( qword )		( (QWORD)ntohl( qword & 0xFFFFFFFF ) << 32 ) | ntohl( qword >> 32 )
#define htonq( qword )		ntohq( qword )

typedef struct _TlvHeader
{
	DWORD length;
	DWORD type;
} TlvHeader;

typedef struct _Tlv
{
	TlvHeader header;
	PUCHAR    buffer;
} Tlv;

typedef struct _PacketHeader
{
	BYTE xor_key[4];
	BYTE session_guid[sizeof(GUID)];
	DWORD enc_flags;
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
		Packet *response, LPVOID context, UINT commandId, DWORD result);

typedef struct _PacketRequestCompletion
{
	LPVOID                         context;
	PacketRequestCompletionRoutine routine;
	DWORD                          timeout;
} PacketRequestCompletion;

#endif
