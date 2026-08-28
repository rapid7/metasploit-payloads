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

typedef struct _MetsrvConfig
{
	union
	{
		UINT_PTR handle;
		BYTE padding[8];
	} comms_handle;                       ///! Socket/handle for communications (if there is one).
	BYTE config_packet[1];                ///! Pointer to the configuration packet
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
