/*++ BUILD Version: 0001    // Increment this if a change has global effects

Copyright (c) 1991-1999  Microsoft Corporation

Module Name:

    lmdfs.h

Abstract:

    This file contains structures, function prototypes, and definitions
    for the NetDfs API

Environment:

    User Mode - Win32

Notes:

    You must include <windef.h> and <lmcons.h> before this file.

--*/

#ifndef _LMDFS_
#define _LMDFS_

#if _MSC_VER > 1000
#pragma once
#endif

#ifdef __cplusplus
extern "C" {
#endif

//
// DFS Volume state
//

#define DFS_VOLUME_STATES              0xF

#define DFS_VOLUME_STATE_OK            1
#define DFS_VOLUME_STATE_INCONSISTENT  2
#define DFS_VOLUME_STATE_OFFLINE       3
#define DFS_VOLUME_STATE_ONLINE        4

//
// These are valid for setting the volume state on the root
// These are available to force a resynchronize on the root
// volume or to put it in a standby mode.
//
#define DFS_VOLUME_STATE_RESYNCHRONIZE 0x10
#define DFS_VOLUME_STATE_STANDBY       0x20

//
// These are valid on getting the volume state on the root
// These are available to determine the flavor of DFS
// A few bits are reserved to determine the flavor of the DFS root.
// To get the flavor, and the state with DFS_VOLUME_FLAVORS.
//
// (_state & DFS_VOLUME_FLAVORS) will tell you the flavor of the dfs root.
//
//

#define DFS_VOLUME_FLAVORS           0x0300


#define DFS_VOLUME_FLAVOR_UNUSED1    0x0000
#define DFS_VOLUME_FLAVOR_STANDALONE 0x0100
#define DFS_VOLUME_FLAVOR_AD_BLOB    0x0200
#define DFS_STORAGE_FLAVOR_UNUSED2   0x0300

//
// DFS Storage State
//

#define DFS_STORAGE_STATES            0xF
#define DFS_STORAGE_STATE_OFFLINE      1
#define DFS_STORAGE_STATE_ONLINE       2
#define DFS_STORAGE_STATE_ACTIVE       4


//
// Priority of a DFS target consists of the
// tuple <priority class, priority rank>. Priority
// ranks are valid only within a priority class and
// not across priority classes.
// Priority rank is 0-n, where 0 is highest rank.
//
// We have consciously chosen 0 to indicate the
// "normal" priority class, i.e. one that would
// be used if target priorities aren't used.
//
// The members of the enumeration have been explicitly
// set in a specific order (in the enumeration).
//
// We need the MIDL_PASS decoration to force sending
// the enums as 32-bit values instead of the default
// 16-bit values for enums. 
//

#ifdef  MIDL_PASS
typedef [v1_enum] enum _DFS_TARGET_PRIORITY_CLASS {
#else
typedef enum _DFS_TARGET_PRIORITY_CLASS {
#endif
    DfsInvalidPriorityClass = -1,
    DfsSiteCostNormalPriorityClass = 0,
    DfsGlobalHighPriorityClass,
    DfsSiteCostHighPriorityClass,
    DfsSiteCostLowPriorityClass,
    DfsGlobalLowPriorityClass
} DFS_TARGET_PRIORITY_CLASS;

typedef struct _DFS_TARGET_PRIORITY {
    DFS_TARGET_PRIORITY_CLASS   TargetPriorityClass;    // Priority class of target.
    USHORT                      TargetPriorityRank;     // Priority rank of target.
    USHORT                      Reserved;               // Must be set to 0.
} DFS_TARGET_PRIORITY, *PDFS_TARGET_PRIORITY;

//
// Level 1:
//
typedef struct _DFS_INFO_1 {
    LPWSTR  EntryPath;              // Dfs name for the top of this piece of storage
} DFS_INFO_1, *PDFS_INFO_1, *LPDFS_INFO_1;

//
// Level 2:
//
typedef struct _DFS_INFO_2 {
    LPWSTR  EntryPath;              // Dfs name for the top of this volume
    LPWSTR  Comment;                // Comment for this volume
    DWORD   State;                  // State of this volume, one of DFS_VOLUME_STATE_*
    DWORD   NumberOfStorages;       // Number of storages for this volume
} DFS_INFO_2, *PDFS_INFO_2, *LPDFS_INFO_2;

typedef struct _DFS_STORAGE_INFO {
    ULONG   State;                  // State of this storage, one of DFS_STORAGE_STATE_*
                                    // possibly OR'd with DFS_STORAGE_STATE_ACTIVE
    LPWSTR  ServerName;             // Name of server hosting this storage
    LPWSTR  ShareName;              // Name of share hosting this storage
} DFS_STORAGE_INFO, *PDFS_STORAGE_INFO, *LPDFS_STORAGE_INFO;

#if defined(_WIN64)

//
// We should be calling this structure DFS_STORAGE_INFO_32 as per
// convention. However, we don't want to pollute the namespace of new
// types that have been defined (for example, DFS_STORAGE_INFO_1) as
// enhancements to the "base" DFS_STORAGE_INFO structure. Hence,
// we define the WOW64 support structure as DFS_STORAGE_INFO_0_32.
//

typedef struct _DFS_STORAGE_INFO_0_32 {
    ULONG   State;                  // State of this storage, one of DFS_STORAGE_STATE_*
                                    // possibly OR'd with DFS_STORAGE_STATE_ACTIVE
    ULONG   ServerName;             // Name of server hosting this storage
    ULONG   ShareName;              // Name of share hosting this storage
} DFS_STORAGE_INFO_0_32, *PDFS_STORAGE_INFO_0_32, *LPDFS_STORAGE_INFO_0_32;

#endif  // _WIN64.

//
// WOW64 support: Permit 32-bit callers to use 64-bit
// driver.
//

typedef struct _DFS_STORAGE_INFO_1 {
    ULONG                   State;          // State of this target, one of DFS_TARGET_STATE_*
                                            // possibly OR'd with DFS_STORAGE_STATE_ACTIVE
    LPWSTR                  ServerName;     // Name of server hosting this target
    LPWSTR                  ShareName;      // Name of share hosting this target
    DFS_TARGET_PRIORITY     TargetPriority; // Priority of this target.
} DFS_STORAGE_INFO_1, *PDFS_STORAGE_INFO_1, *LPDFS_STORAGE_INFO_1;

//
// Level 3:
//
typedef struct _DFS_INFO_3 {
    LPWSTR  EntryPath;              // Dfs name for the top of this volume
    LPWSTR  Comment;                // Comment for this volume
    DWORD   State;                  // State of this volume, one of DFS_VOLUME_STATE_*
    DWORD   NumberOfStorages;       // Number of storage servers for this volume
#ifdef MIDL_PASS
    [size_is(NumberOfStorages)] LPDFS_STORAGE_INFO Storage;
#else
    LPDFS_STORAGE_INFO   Storage;   // An array (of NumberOfStorages elements) of
                                    //      storage-specific information.
#endif // MIDL_PASS
} DFS_INFO_3, *PDFS_INFO_3, *LPDFS_INFO_3;

#if defined(_WIN64)

//
// WOW64 support: Permit 32-bit callers to use 64-bit
// driver.
//

typedef struct _DFS_INFO_3_32 {
    ULONG   EntryPath;              // Dfs name for the top of this volume
    ULONG   Comment;                // Comment for this volume
    DWORD   State;                  // State of this volume, one of DFS_VOLUME_STATE_*
    DWORD   NumberOfStorages;       // Number of storage servers for this volume
    ULONG   Storage;                // An array (of NumberOfStorages elements) of
                                    //      storage-specific information. Each element
                                    //      is of type DFS_STORAGE_INFO_0_32.
} DFS_INFO_3_32, *PDFS_INFO_3_32, *LPDFS_INFO_3_32;

#endif  /* _WIN64   */

//
// Level 4:
//
typedef struct _DFS_INFO_4 {
    LPWSTR  EntryPath;              // Dfs name for the top of this volume
    LPWSTR  Comment;                // Comment for this volume
    DWORD   State;                  // State of this volume, one of DFS_VOLUME_STATE_*
    ULONG   Timeout;                // Timeout, in seconds, of this junction point
    GUID    Guid;                   // Guid of this junction point
    DWORD   NumberOfStorages;       // Number of storage servers for this volume
#ifdef MIDL_PASS
    [size_is(NumberOfStorages)] LPDFS_STORAGE_INFO Storage;
#else
    LPDFS_STORAGE_INFO   Storage;   // An array (of NumberOfStorages elements) of
                                    //      storage-specific information.
#endif // MIDL_PASS
} DFS_INFO_4, *PDFS_INFO_4, *LPDFS_INFO_4;


#if defined(_WIN64)

//
// WOW64 support: Permit 32-bit callers to use 64-bit
// driver.
//

typedef struct _DFS_INFO_4_32 {
    ULONG   EntryPath;              // Dfs name for the top of this volume
    ULONG   Comment;                // Comment for this volume
    DWORD   State;                  // State of this volume, one of DFS_VOLUME_STATE_*
    ULONG   Timeout;                // Timeout, in seconds, of this junction point
    GUID    Guid;                   // Guid of this junction point
    DWORD   NumberOfStorages;       // Number of storage servers for this volume
    ULONG   Storage;                // An array (of NumberOfStorages elements) of
                                    //      storage-specific information. Each element
                                    //      is of type DFS_STORAGE_INFO_0_32.
} DFS_INFO_4_32, *PDFS_INFO_4_32, *LPDFS_INFO_4_32;

#endif  /* _WIN64   */


//
// Level 5:
//
typedef struct _DFS_INFO_5 {
    LPWSTR  EntryPath;              // Name of DFS namespace, DFS root name.
    LPWSTR  Comment;                // Comment for root/link.
    DWORD   State;                  // State of the root/link, one of DFS_VOLUME_STATE_*
                                    //      Also has DFS_VOLUME_FLAVOR_* information.
    ULONG   Timeout;                // Referral TTL, in seconds, of root/link.
    GUID    Guid;                   // GUID of this root/link.
    ULONG   PropertyFlags;          // Properties of root/link. One of DFS_PROPERTY_FLAG_*
    ULONG   MetadataSize;           // Size of Active Directory BLOB for a domain-based
                                    //      DFS namespace; size of metadata stored in registry
                                    //      for stand-alone DFS. Valid for DFS roots only.
    DWORD   NumberOfStorages;       // Number of storage servers for this volume
} DFS_INFO_5, *PDFS_INFO_5, *LPDFS_INFO_5;

//
// Level 6:
//
typedef struct _DFS_INFO_6 {
    LPWSTR  EntryPath;              // Name of DFS namespace, DFS root name.
    LPWSTR  Comment;                // Comment for root/link.
    DWORD   State;                  // State of the root/link, one of DFS_VOLUME_STATE_*
                                    //      Also has DFS_VOLUME_FLAVOR_* information.
    ULONG   Timeout;                // Referral TTL, in seconds, of root/link.
    GUID    Guid;                   // GUID of this root/link.
    ULONG   PropertyFlags;          // Properties of root/link. One of DFS_PROPERTY_FLAG_*
    ULONG   MetadataSize;           // Size of Active Directory BLOB for a domain-based
                                    //      DFS namespace; size of metadata stored in registry
                                    //      for stand-alone DFS. Valid for DFS roots only.
    DWORD   NumberOfStorages;       // Number of targets for this root/link.
#ifdef MIDL_PASS
    [size_is(NumberOfStorages)] LPDFS_STORAGE_INFO_1    Storage;
#else
    LPDFS_STORAGE_INFO_1    Storage;    // An array (of NumberOfStorages elements) of
                                        // storage-specific information.
#endif // MIDL_PASS
} DFS_INFO_6, *PDFS_INFO_6, *LPDFS_INFO_6;

//
// Level 7:
//
typedef struct _DFS_INFO_7 {
    GUID        GenerationGuid;     // Guid representation of the version/generation
                                    // number of the DFS root.
} DFS_INFO_7, *PDFS_INFO_7, *LPDFS_INFO_7;

//
// The PropertyFlags field of DFS_INFO_5, DFS_INFO_6 and DFS_INFO_103.
//

//
// The "insite" flag. When set, only targets in the same
// site as the client are returned.
//
// Valid for domain/standalone roots/links
//

#define DFS_PROPERTY_FLAG_INSITE_REFERRALS  0x00000001

//
// "Root scalability" mode. When set, DFS server polls
// the nearest DC instead of PDC to check for DFS namespace
// changes. Valid only for domain roots.
//

#define DFS_PROPERTY_FLAG_ROOT_SCALABILITY  0x00000002

//
// Enables Active Directory site costing of targets. When enabled,
// targets are grouped into sets of increasing site costs from
// DFS client to target. Each set has targets of same cost.
// If not set, there are only two sets: set of targets in same
// site as client and set of targets not in the same site as the client.
// The latter is called "site awareness".
// Valid only domain/standalone roots
//

#define DFS_PROPERTY_FLAG_SITE_COSTING      0x00000004

//
// Should the DFS client attempt to failback to a closer target
// when it is available after failing over to a non-optimal target?
// Valid for domain/standalone roots/links.
//

#define DFS_PROPERTY_FLAG_TARGET_FAILBACK   0x00000008

//
// Bit will be 1 if the DFS root is clustered. Cannot be set
// using the NetDfsSetInfo() API.
//

#define DFS_PROPERTY_FLAG_CLUSTER_ENABLED   0x00000010


//
// Level 100:
//
typedef struct _DFS_INFO_100 {
    LPWSTR  Comment;                // Comment for this volume or storage
} DFS_INFO_100, *PDFS_INFO_100, *LPDFS_INFO_100;

//
// Level 101:
//
typedef struct _DFS_INFO_101 {
    DWORD   State;                  // State of this storage, one of DFS_STORAGE_STATE_*
                                    // possibly OR'd with DFS_STORAGE_STATE_ACTIVE
} DFS_INFO_101, *PDFS_INFO_101, *LPDFS_INFO_101;

//
// Level 102:
//
typedef struct _DFS_INFO_102 {
    ULONG   Timeout;                // Timeout, in seconds, of the junction
} DFS_INFO_102, *PDFS_INFO_102, *LPDFS_INFO_102;

//
// Level 103:
//
typedef struct _DFS_INFO_103 {
    ULONG       PropertyFlagMask;   // Indicates which flags in PropertyFlags are valid.
    ULONG       PropertyFlags;      // Flag meaningful only if corresponding bit set in
                                    // PropertyFlagMask above.
} DFS_INFO_103, *PDFS_INFO_103, *LPDFS_INFO_103;


//
// Level 104:
//
typedef struct _DFS_INFO_104 {
    DFS_TARGET_PRIORITY     TargetPriority;     // Priority of target.
} DFS_INFO_104, *PDFS_INFO_104, *LPDFS_INFO_104;

//
// Level 105:
//
typedef struct _DFS_INFO_105 {
    LPWSTR      Comment;            // Comment for this root/link.
    DWORD       State;              // State of this root/link. One of DFS_VOLUME_STATE_*
    ULONG       Timeout;            // Referral TTL, in seconds, of root/link.
    ULONG       PropertyFlagMask;   // Indicates which flags in PropertyFlags are valid.
    ULONG       PropertyFlags;      // One of DFS_PROPERTY_FLAG_*
} DFS_INFO_105, *PDFS_INFO_105, *LPDFS_INFO_105;

//
// Level 106:
//
typedef struct _DFS_INFO_106 {
    DWORD               State;              // State of this root/link target.
                                            //      One of DFS_TARGET_STATE_*
    DFS_TARGET_PRIORITY TargetPriority;     // Priority of this target.
} DFS_INFO_106, *PDFS_INFO_106, *LPDFS_INFO_106;

//

// Level 200:
//
typedef struct _DFS_INFO_200 {
    LPWSTR  FtDfsName;              // FtDfs name
} DFS_INFO_200, *PDFS_INFO_200, *LPDFS_INFO_200;


//
// Level 300:
//
typedef struct _DFS_INFO_300 {
    DWORD   Flags;
    LPWSTR  DfsName;              // Dfs name
} DFS_INFO_300, *PDFS_INFO_300, *LPDFS_INFO_300;


//
// Add a new volume or additional storage for an existing volume at
// DfsEntryPath.
//
NET_API_STATUS NET_API_FUNCTION
NetDfsAdd(
    IN  LPWSTR DfsEntryPath,        // DFS entry path for this added volume or storage
    IN  LPWSTR ServerName,          // Name of server hosting the storage
    IN  LPWSTR ShareName,           // Existing share name for the storage
    IN  LPWSTR Comment OPTIONAL,    // Optional comment for this volume or storage
    IN  DWORD  Flags                // See below. Zero for no flags.
);

//
// Flags:
//
#define DFS_ADD_VOLUME          1   // Add a new volume to the DFS if not already there
#define DFS_RESTORE_VOLUME      2   // Volume/Replica is being restored - do not verify share etc.

//
// Setup/teardown API's for standard and FtDfs roots.
//

NET_API_STATUS NET_API_FUNCTION
NetDfsAddStdRoot(
    IN  LPWSTR ServerName,          // Server to remote to
    IN  LPWSTR RootShare,           // Share to make Dfs root
    IN  LPWSTR Comment OPTIONAL,    // Comment
    IN  DWORD  Flags                // Flags for operation.  Zero for no flags.
);

NET_API_STATUS NET_API_FUNCTION
NetDfsRemoveStdRoot(
    IN  LPWSTR ServerName,          // Server to remote to
    IN  LPWSTR RootShare,           // Share that host Dfs root
    IN  DWORD  Flags                // Flags for operation.  Zero for no flags.
);

NET_API_STATUS NET_API_FUNCTION
NetDfsAddFtRoot(
    IN  LPWSTR ServerName,          // Server to remote to
    IN  LPWSTR RootShare,           // Share to make Dfs root
    IN  LPWSTR FtDfsName,           // Name of FtDfs to create/join
    IN  LPWSTR Comment,             // Comment
    IN  DWORD  Flags                // Flags for operation.  Zero for no flags.
);

NET_API_STATUS NET_API_FUNCTION
NetDfsRemoveFtRoot(
    IN  LPWSTR ServerName,          // Server to remote to
    IN  LPWSTR RootShare,           // Share that host Dfs root
    IN  LPWSTR FtDfsName,           // Name of FtDfs to remove or unjoin from.
    IN  DWORD  Flags                // Flags for operation.  Zero for no flags.
);

NET_API_STATUS NET_API_FUNCTION
NetDfsRemoveFtRootForced(
    IN  LPWSTR DomainName,          // Name of domain the server is in
    IN  LPWSTR ServerName,          // Server to remote to
    IN  LPWSTR RootShare,           // Share that host Dfs root
    IN  LPWSTR FtDfsName,           // Name of FtDfs to remove or unjoin from.
    IN  DWORD  Flags                // Flags for operation.  Zero for no flags.
);

//
// Call to reinitialize the dfsmanager on a machine
//

NET_API_STATUS NET_API_FUNCTION
NetDfsManagerInitialize(
    IN  LPWSTR ServerName,          // Server to remote to
    IN  DWORD  Flags                // Flags for operation.  Zero for no flags.
);

NET_API_STATUS NET_API_FUNCTION
NetDfsAddStdRootForced(
    IN  LPWSTR ServerName,          // Server to remote to
    IN  LPWSTR RootShare,           // Share to make Dfs root
    IN  LPWSTR Comment OPTIONAL,    // Comment
    IN  LPWSTR Store                // Drive:\dir backing the share
);

NET_API_STATUS NET_API_FUNCTION
NetDfsGetDcAddress(
    IN  LPWSTR ServerName,          // Server to remote to
    IN  OUT LPWSTR *DcIpAddress,    // The IP address of the DC to use
    IN  OUT BOOLEAN *IsRoot,        // TRUE if server is a Dfs root, FALSE otherwise
    IN  OUT ULONG *Timeout          // Time, in sec, that we stay with this DC
);


//
// Flags for NetDfsSetDcAddress()
//

#define NET_DFS_SETDC_FLAGS                 0x00000000
#define NET_DFS_SETDC_TIMEOUT               0x00000001
#define NET_DFS_SETDC_INITPKT               0x00000002

//
// Structures used for site reporting
//

typedef struct {
    ULONG SiteFlags;    // Below
#ifdef  MIDL_PASS
    [string,unique] LPWSTR SiteName;
#else
    LPWSTR SiteName;
#endif
} DFS_SITENAME_INFO, *PDFS_SITENAME_INFO, *LPDFS_SITENAME_INFO;

// SiteFlags

#define DFS_SITE_PRIMARY    0x1     // This site returned by DsGetSiteName()

typedef struct {
    ULONG cSites;
#ifdef  MIDL_PASS
    [size_is(cSites)] DFS_SITENAME_INFO Site[];
#else
    DFS_SITENAME_INFO Site[1];
#endif
} DFS_SITELIST_INFO, *PDFS_SITELIST_INFO, *LPDFS_SITELIST_INFO;

//
// Remove a volume or additional storage for volume from the Dfs at
// DfsEntryPath. When applied to the last storage in a volume, removes
// the volume from the DFS.
//
NET_API_STATUS NET_API_FUNCTION
NetDfsRemove(
    IN  LPWSTR  DfsEntryPath,       // DFS entry path for this added volume or storage
    IN  LPWSTR  ServerName,         // Name of server hosting the storage
    IN  LPWSTR  ShareName           // Name of share hosting the storage
);

//
// Get information about all of the volumes in the Dfs. DfsName is
// the "server" part of the UNC name used to refer to this particular Dfs.
//
// Valid levels are 1-5, 200, 300
//
NET_API_STATUS NET_API_FUNCTION
NetDfsEnum(
    IN      LPWSTR  DfsName,        // Name of the Dfs for enumeration
    IN      DWORD   Level,          // Level of information requested
    IN      DWORD   PrefMaxLen,     // Advisory, but -1 means "get it all"
    OUT     LPBYTE* Buffer,         // API allocates and returns buffer with requested info
    OUT     LPDWORD EntriesRead,    // Number of entries returned
    IN OUT  LPDWORD ResumeHandle    // Must be 0 on first call, reused on subsequent calls
);

//
// Get information about the volume or storage.
// If ServerName and ShareName are specified, the information returned
// is specific to that server and share, else the information is specific
// to the volume as a whole.
//
// Valid levels are 1-5, 100
//
NET_API_STATUS NET_API_FUNCTION
NetDfsGetInfo(
    IN  LPWSTR  DfsEntryPath,       // DFS entry path for the volume
    IN  LPWSTR  ServerName OPTIONAL,// Name of server hosting a storage
    IN  LPWSTR  ShareName OPTIONAL, // Name of share on server serving the volume
    IN  DWORD   Level,              // Level of information requested
    OUT LPBYTE* Buffer              // API allocates and returns buffer with requested info
);

//
// Set info about the volume or storage.
// If ServerName and ShareName are specified, the information set is
// specific to that server and share, else the information is specific
// to the volume as a whole.
//
// Valid levels are 100, 101 and 102
//
NET_API_STATUS NET_API_FUNCTION
NetDfsSetInfo(
    IN  LPWSTR  DfsEntryPath,           // DFS entry path for the volume
    IN  LPWSTR  ServerName OPTIONAL,    // Name of server hosting a storage
    IN  LPWSTR  ShareName OPTIONAL,     // Name of share hosting a storage
    IN  DWORD   Level,                  // Level of information to be set
    IN  LPBYTE  Buffer                  // Buffer holding information
);

//
// Get client's cached information about the volume or storage.
// If ServerName and ShareName are specified, the information returned
// is specific to that server and share, else the information is specific
// to the volume as a whole.
//
// Valid levels are 1-4
//
NET_API_STATUS NET_API_FUNCTION
NetDfsGetClientInfo(
    IN  LPWSTR  DfsEntryPath,       // DFS entry path for the volume
    IN  LPWSTR  ServerName OPTIONAL,// Name of server hosting a storage
    IN  LPWSTR  ShareName OPTIONAL, // Name of share on server serving the volume
    IN  DWORD   Level,              // Level of information requested
    OUT LPBYTE* Buffer              // API allocates and returns buffer with requested info
);

//
// Set client's cached info about the volume or storage.
// If ServerName and ShareName are specified, the information set is
// specific to that server and share, else the information is specific
// to the volume as a whole.
//
// Valid levels are 101 and 102.
//
NET_API_STATUS NET_API_FUNCTION
NetDfsSetClientInfo(
    IN  LPWSTR  DfsEntryPath,           // DFS entry path for the volume
    IN  LPWSTR  ServerName OPTIONAL,    // Name of server hosting a storage
    IN  LPWSTR  ShareName OPTIONAL,     // Name of share hosting a storage
    IN  DWORD   Level,                  // Level of information to be set
    IN  LPBYTE  Buffer                  // Buffer holding information
);

//
// Move a DFS volume and all subordinate volumes from one place in the
// DFS to another place in the DFS.
//


NET_API_STATUS NET_API_FUNCTION
NetDfsMove(
    IN  LPWSTR  DfsEntryPath,           // Current DFS entry path for this volume
    IN  LPWSTR  DfsNewEntryPath,        // New DFS entry path for this volume
    IN  ULONG   Flags
);

//
//  Flags accepted by NetDfsMove
//

//
//  This  indicates that if a colliding link is found it should be replaced
//

#define  DFS_MOVE_FLAG_REPLACE_IF_EXISTS  0x00000001


NET_API_STATUS NET_API_FUNCTION
NetDfsRename(
    IN  LPWSTR  Path,                   // Current Win32 path in a Dfs
    IN  LPWSTR  NewPath                 // New Win32 path in the same Dfs
);


NET_API_STATUS NET_API_FUNCTION
NetDfsGetSecurity(
    IN LPWSTR DfsEntryPath,
    IN SECURITY_INFORMATION SecurityInformation,
    OUT PSECURITY_DESCRIPTOR *ppSecurityDescriptor,
    OUT LPDWORD lpcbSecurityDescriptor
);

NET_API_STATUS NET_API_FUNCTION
NetDfsSetSecurity(
    IN LPWSTR DfsEntryPath,
    IN SECURITY_INFORMATION SecurityInformation,
    IN PSECURITY_DESCRIPTOR pSecurityDescriptor
);

NET_API_STATUS NET_API_FUNCTION
NetDfsGetStdContainerSecurity(
    IN LPWSTR MachineName,
    IN SECURITY_INFORMATION SecurityInformation,
    OUT PSECURITY_DESCRIPTOR *ppSecurityDescriptor,
    OUT LPDWORD lpcbSecurityDescriptor
);

NET_API_STATUS NET_API_FUNCTION
NetDfsSetStdContainerSecurity(
    IN LPWSTR MachineName,
    IN SECURITY_INFORMATION SecurityInformation,
    IN PSECURITY_DESCRIPTOR pSecurityDescriptor
);
    
NET_API_STATUS NET_API_FUNCTION
NetDfsGetFtContainerSecurity(
    IN LPWSTR DomainName,
    IN SECURITY_INFORMATION SecurityInformation,
    OUT PSECURITY_DESCRIPTOR *ppSecurityDescriptor,
    OUT LPDWORD lpcbSecurityDescriptor
);

NET_API_STATUS NET_API_FUNCTION
NetDfsSetFtContainerSecurity(
    IN LPWSTR DomainName,
    IN SECURITY_INFORMATION SecurityInformation,
    IN PSECURITY_DESCRIPTOR pSecurityDescriptor
);

#ifdef __cplusplus
}
#endif

#endif // _LMDFS_
