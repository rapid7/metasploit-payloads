/*++ BUILD Version: 0001    // Increment this if a change has global effects

Copyright (c) 1991-1999  Microsoft Corporation

Module Name:

    lmapibuf.h

Abstract:

    This file contains information about NetApiBuffer APIs.

Environment:

    User Mode - Win32

Notes:

    You must include LMCONS.H before this file, since this file depends
    on values defined in LMCONS.H.

--*/

#ifndef _LMAPIBUF_
#define _LMAPIBUF_

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
NetApiBufferAllocate(
    IN DWORD ByteCount,
    OUT LPVOID * Buffer
    );

NET_API_STATUS NET_API_FUNCTION
NetApiBufferFree (
    IN LPVOID Buffer
    );

NET_API_STATUS NET_API_FUNCTION
NetApiBufferReallocate(
    IN LPVOID OldBuffer OPTIONAL,
    IN DWORD NewByteCount,
    OUT LPVOID * NewBuffer
    );

NET_API_STATUS NET_API_FUNCTION
NetApiBufferSize(
    IN LPVOID Buffer,
    OUT LPDWORD ByteCount
    );


//
// The following private function will go away eventually.
// Call NetApiBufferAllocate instead.
//
NET_API_STATUS NET_API_FUNCTION
NetapipBufferAllocate (                 // Internal Function
    IN DWORD ByteCount,
    OUT LPVOID * Buffer
    );

#ifdef __cplusplus
}
#endif

#endif // _LMAPIBUF_
