/*++ BUILD Version: 0001    // Increment this if a change has global effects

Copyright (c) 1991-1999  Microsoft Corporation

Module Name:

    lmuseflg.h

Abstract:

    This file contains deletion force levels for deleting a connection.

Environment:

    User Mode - Win32

Notes:

    This file has no dependencies.  It is included by lmwksta.h and
    lmuse.h.

Revision History:

--*/

#ifndef _LMUSEFLG_
#define _LMUSEFLG_

#if _MSC_VER > 1000
#pragma once
#endif

//
// Definition for NetWkstaTransportDel and NetUseDel deletion force levels
//

#define USE_NOFORCE             0
#define USE_FORCE               1
#define USE_LOTS_OF_FORCE       2


#endif // _LMUSEFLG_
