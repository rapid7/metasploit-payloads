/*++ BUILD Version: 0001    // Increment this if a change has global effects

Copyright (c) 1991-1999  Microsoft Corporation

Module Name:

    lmmsg.h

Abstract:

    This file contains structures, function prototypes, and definitions
    for the NetMessage API.

[Environment:]

    User Mode - Win32

[Notes:]

    You must include NETCONS.H before this file, since this file depends
    on values defined in NETCONS.H.

--*/

#ifndef _LMMSG_
#define _LMMSG_

#if _MSC_VER > 1000
#pragma once
#endif

#ifdef __cplusplus
extern "C" {
#endif

//
// Function Prototypes
//

NET_API_STATUS NET_API_FUNCTION
NetMessageNameAdd (
    IN  LPCWSTR  servername,
    IN  LPCWSTR  msgname
    );

NET_API_STATUS NET_API_FUNCTION
NetMessageNameEnum (
    IN  LPCWSTR     servername,
    IN  DWORD       level,
    OUT LPBYTE      *bufptr,
    IN  DWORD       prefmaxlen,
    OUT LPDWORD     entriesread,
    OUT LPDWORD     totalentries,
    IN OUT LPDWORD  resume_handle
    );

NET_API_STATUS NET_API_FUNCTION
NetMessageNameGetInfo (
    IN  LPCWSTR servername,
    IN  LPCWSTR msgname,
    IN  DWORD   level,
    OUT LPBYTE  *bufptr
    );

NET_API_STATUS NET_API_FUNCTION
NetMessageNameDel (
    IN  LPCWSTR   servername,
    IN  LPCWSTR   msgname
    );

NET_API_STATUS NET_API_FUNCTION
NetMessageBufferSend (
    IN  LPCWSTR  servername,
    IN  LPCWSTR  msgname,
    IN  LPCWSTR  fromname,
    IN  LPBYTE   buf,
    IN  DWORD    buflen
    );

//
//  Data Structures
//

typedef struct _MSG_INFO_0 {
    LPWSTR  msgi0_name;
}MSG_INFO_0, *PMSG_INFO_0, *LPMSG_INFO_0;

typedef struct _MSG_INFO_1 {
    LPWSTR  msgi1_name;
    DWORD   msgi1_forward_flag;
    LPWSTR  msgi1_forward;
}MSG_INFO_1, *PMSG_INFO_1, *LPMSG_INFO_1;

//
// Special Values and Constants
//

//
// Values for msgi1_forward_flag.
//

#define MSGNAME_NOT_FORWARDED   0       // Name not forwarded
#define MSGNAME_FORWARDED_TO    0x04    // Name forward to remote station
#define MSGNAME_FORWARDED_FROM  0x10    // Name forwarded from remote station

#ifdef __cplusplus
}
#endif

#endif //_LMMSG_
