/*++ BUILD Version: 0001    // Increment this if a change has global effects

Copyright (c) 1991-1999  Microsoft Corporation

Module Name:

    lmremutl.h

Abstract:

    This file contains structures, function prototypes, and definitions
    for the NetRemote API.

Environment:

    User Mode - Win32
    Portable to any flat, 32-bit environment.  (Uses Win32 typedefs.)
    Requires ANSI C extensions: slash-slash comments, long external names.

--*/

#ifndef _LMREMUTL_
#define _LMREMUTL_

#if _MSC_VER > 1000
#pragma once
#endif

#ifdef __cplusplus
extern "C" {
#endif

//
// Type Definitions
//

#ifndef DESC_CHAR_UNICODE

typedef CHAR DESC_CHAR;

#else // DESC_CHAR_UNICODE is defined

typedef WCHAR DESC_CHAR;

#endif // DESC_CHAR_UNICODE is defined


typedef DESC_CHAR * LPDESC;


//
// Function Prototypes
//

NET_API_STATUS NET_API_FUNCTION
NetRemoteTOD (
    IN LPCWSTR UncServerName,
    OUT LPBYTE *BufferPtr
    );

NET_API_STATUS NET_API_FUNCTION
NetRemoteComputerSupports(
    IN LPCWSTR UncServerName OPTIONAL,   // Must start with "\\".
    IN DWORD OptionsWanted,             // Set SUPPORTS_ bits wanted.
    OUT LPDWORD OptionsSupported        // Supported features, masked.
    );

NET_API_STATUS
__cdecl
RxRemoteApi(
    IN DWORD ApiNumber,
    IN LPCWSTR UncServerName,                    // Required, with \\name.
    IN LPDESC ParmDescString,
    IN LPDESC DataDesc16 OPTIONAL,
    IN LPDESC DataDesc32 OPTIONAL,
    IN LPDESC DataDescSmb OPTIONAL,
    IN LPDESC AuxDesc16 OPTIONAL,
    IN LPDESC AuxDesc32 OPTIONAL,
    IN LPDESC AuxDescSmb OPTIONAL,
    IN DWORD  Flags,
    ...                                         // rest of API's arguments
    );



//
//  Data Structures
//

typedef struct _TIME_OF_DAY_INFO {
    DWORD      tod_elapsedt;
    DWORD      tod_msecs;
    DWORD      tod_hours;
    DWORD      tod_mins;
    DWORD      tod_secs;
    DWORD      tod_hunds;
    LONG       tod_timezone;
    DWORD      tod_tinterval;
    DWORD      tod_day;
    DWORD      tod_month;
    DWORD      tod_year;
    DWORD      tod_weekday;
} TIME_OF_DAY_INFO, *PTIME_OF_DAY_INFO, *LPTIME_OF_DAY_INFO;

//
// Special Values and Constants
//

//
// Mask bits for use with NetRemoteComputerSupports:
//

#define SUPPORTS_REMOTE_ADMIN_PROTOCOL  0x00000002L
#define SUPPORTS_RPC                    0x00000004L
#define SUPPORTS_SAM_PROTOCOL           0x00000008L
#define SUPPORTS_UNICODE                0x00000010L
#define SUPPORTS_LOCAL                  0x00000020L
#define SUPPORTS_ANY                    0xFFFFFFFFL

//
// Flag bits for RxRemoteApi:
//

#define NO_PERMISSION_REQUIRED  0x00000001      // set if use NULL session
#define ALLOCATE_RESPONSE       0x00000002      // set if RxRemoteApi allocates response buffer
#define USE_SPECIFIC_TRANSPORT  0x80000000

#ifdef __cplusplus
}
#endif

#endif //_LMREMUTL_
