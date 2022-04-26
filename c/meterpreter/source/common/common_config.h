/*!
 * @file config.h
 * @brief Declarations of functions and types that define endpoint and transport configurations.
 */
#ifndef _METERPRETER_COMMON_CONFIG_H
#define _METERPRETER_COMMON_CONFIG_H

/*! @brief This is the size of the certificate hash that is validated (sha1) */
#define CERT_HASH_SIZE 20
#define URL_SIZE 512
#define UA_SIZE 256
#define UUID_SIZE 16
#define PROXY_HOST_SIZE 128
#define PROXY_USER_SIZE 64
#define PROXY_PASS_SIZE 64
#define LOG_PATH_SIZE 260 // https://docs.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation?tabs=cmd

typedef wchar_t CHARTYPE;

typedef CHARTYPE* STRTYPE;
typedef CHARTYPE const * CSTRTYPE;

// Make sure we byte-align based on what we're given in the structure definitions
#pragma pack(push, 1)

typedef struct _MetsrvSession
{
	union
	{
		UINT_PTR handle;
		BYTE padding[8];
	} comms_handle;                       ///! Socket/handle for communications (if there is one).
	DWORD exit_func;                      ///! Exit func identifier for when the session ends.
	int expiry;                           ///! The total number of seconds to wait before killing off the session.
	BYTE uuid[UUID_SIZE];                 ///! UUID
	BYTE session_guid[sizeof(GUID)];      ///! Current session GUID
#ifdef DEBUGTRACE
    CHARTYPE log_path[LOG_PATH_SIZE];      ///! Location to place the log file. Only set when msfconsole specifies MeterpreterDebugLogging
#endif
} MetsrvSession;

typedef struct _MetsrvTransportCommon
{
	CHARTYPE url[URL_SIZE];               ///! Transport url:  scheme://host:port/URI
	int comms_timeout;                    ///! Number of sessions to wait for a new packet.
	int retry_total;                      ///! Total seconds to retry comms for.
	int retry_wait;                       ///! Seconds to wait between reconnects.
} MetsrvTransportCommon;

typedef struct _MetsrvTransportProxy
{
	CHARTYPE hostname[PROXY_HOST_SIZE];   ///! Proxy hostname.
	CHARTYPE username[PROXY_USER_SIZE];   ///! Proxy username.
	CHARTYPE password[PROXY_PASS_SIZE];   ///! Proxy password.
} MetsrvTransportProxy;

typedef struct _MetsrvTransportHttp
{
	MetsrvTransportCommon common;
	MetsrvTransportProxy proxy;
	CHARTYPE ua[256];                     ///! User agent string.
	BYTE ssl_cert_hash[CERT_HASH_SIZE];   ///! Expected SSL certificate hash.
	CHARTYPE custom_headers[1];           ///! Custom headers to add to outbound requests (arb length, NULL terminated).
} MetsrvTransportHttp;

typedef struct _MetsrvTransportTcp
{
	MetsrvTransportCommon common;
} MetsrvTransportTcp;

typedef struct _MetsrvTransportNamedPipe
{
	MetsrvTransportCommon common;
} MetsrvTransportNamedPipe;

typedef struct _MetsrvExtension
{
	DWORD size;                           ///! Size of the extension.
	BYTE dll[1];                          ///! Array of extension bytes (will be more than 1).
} MetsrvExtension;

typedef struct _MetsrvConfig
{
	MetsrvSession session;
	MetsrvTransportCommon transports[1];  ///! Placeholder for 0 or more transports
	// Extensions will appear after this
	// After extensions, we get a list of extension initialisers
	// <name of extension>\x00<datasize><data>
	// <name of extension>\x00<datasize><data>
	// \x00
} MetsrvConfig;

// We force 64bit alignment for HANDLES and POINTERS in order
// to be cross compatible between x86 and x64 migration.
typedef struct _COMMONMIGRATECONTEXT
{
	union
	{
		HANDLE hEvent;
		BYTE bPadding1[8];
	} e;

	union
	{
		LPBYTE lpPayload;
		BYTE bPadding2[8];
	} p;
} COMMONMIGRATECONTEXT, * LPCOMMONMIGRATECONTEXT;

#pragma pack(pop)

#endif
