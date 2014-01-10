/*++

Copyright (c) 1998-1999  Microsoft Corporation

Module Name:

    netsetup.h

Abstract:

    Definitions and prototypes for the Net setup apis, for joining/unjoinging
    domains and promoting/demoting servers

Environment:

    User Mode - Win32
    Portable to any flat, 32-bit environment.  (Uses Win32 typedefs.)
    Requires ANSI C extensions: slash-slash comments, long external names.

Notes:

--*/

#ifndef __LMJOIN_H__
#define __LMJOIN_H__

#if _MSC_VER > 1000
#pragma once
#endif

#ifdef __cplusplus
extern "C" {
#endif

//
// Types of name that can be validated
//
typedef enum  _NETSETUP_NAME_TYPE {

    NetSetupUnknown = 0,
    NetSetupMachine,
    NetSetupWorkgroup,
    NetSetupDomain,
    NetSetupNonExistentDomain,
#if(_WIN32_WINNT >= 0x0500)
    NetSetupDnsMachine
#endif

} NETSETUP_NAME_TYPE, *PNETSETUP_NAME_TYPE;


//
// Status of a workstation
//
typedef enum _NETSETUP_JOIN_STATUS {

    NetSetupUnknownStatus = 0,
    NetSetupUnjoined,
    NetSetupWorkgroupName,
    NetSetupDomainName

} NETSETUP_JOIN_STATUS, *PNETSETUP_JOIN_STATUS;

//
// Flags to determine the behavior of the join/unjoin APIs
//
#define NETSETUP_JOIN_DOMAIN    0x00000001      // If not present, workgroup is joined
#define NETSETUP_ACCT_CREATE    0x00000002      // Do the server side account creation/rename
#define NETSETUP_ACCT_DELETE    0x00000004      // Delete the account when a domain is left
#define NETSETUP_WIN9X_UPGRADE  0x00000010      // Invoked during upgrade of Windows 9x to
                                                // Windows NT
#define NETSETUP_DOMAIN_JOIN_IF_JOINED  0x00000020  // Allow the client to join a new domain
                                                // even if it is already joined to a domain
#define NETSETUP_JOIN_UNSECURE  0x00000040      // Performs an unsecure join
#define NETSETUP_MACHINE_PWD_PASSED 0x00000080  // Indicates that the machine (not user) password
                                                //  is passed. Valid only for unsecure joins
#define NETSETUP_DEFER_SPN_SET  0x00000100      // Specifies that writting SPN and DnsHostName
                                                //  attributes on the computer object should be
                                                //  defered until rename that will follow join

#define NETSETUP_INSTALL_INVOCATION 0x00040000  // The APIs were invoked during install

#define NETSETUP_IGNORE_UNSUPPORTED_FLAGS  0x10000000  // If this bit is set, unrecognized flags
                                                       //  will be ignored by the NetJoin API and
                                                       //  the API will behave as if the flags
                                                       //  were not set.

#define NETSETUP_VALID_UNJOIN_FLAGS (NETSETUP_ACCT_DELETE | NETSETUP_IGNORE_UNSUPPORTED_FLAGS)

//
// 0x80000000 is reserved for internal use only
//

//
// Joins a machine to the domain.
//
NET_API_STATUS
NET_API_FUNCTION
NetJoinDomain(
    IN  LPCWSTR lpServer OPTIONAL,
    IN  LPCWSTR lpDomain,
    IN  LPCWSTR lpAccountOU, OPTIONAL
    IN  LPCWSTR lpAccount OPTIONAL,
    IN  LPCWSTR lpPassword OPTIONAL,
    IN  DWORD   fJoinOptions
    );

NET_API_STATUS
NET_API_FUNCTION
NetUnjoinDomain(
    IN  LPCWSTR lpServer OPTIONAL,
    IN  LPCWSTR lpAccount OPTIONAL,
    IN  LPCWSTR lpPassword OPTIONAL,
    IN  DWORD   fUnjoinOptions
    );

NET_API_STATUS
NET_API_FUNCTION
NetRenameMachineInDomain(
    IN  LPCWSTR lpServer OPTIONAL,
    IN  LPCWSTR lpNewMachineName OPTIONAL,
    IN  LPCWSTR lpAccount OPTIONAL,
    IN  LPCWSTR lpPassword OPTIONAL,
    IN  DWORD   fRenameOptions
    );


//
// Determine the validity of a name
//
NET_API_STATUS
NET_API_FUNCTION
NetValidateName(
    IN  LPCWSTR             lpServer OPTIONAL,
    IN  LPCWSTR             lpName,
    IN  LPCWSTR             lpAccount OPTIONAL,
    IN  LPCWSTR             lpPassword OPTIONAL,
    IN  NETSETUP_NAME_TYPE  NameType
    );

//
// Determines whether a workstation is joined to a domain or not
//
NET_API_STATUS
NET_API_FUNCTION
NetGetJoinInformation(
    IN   LPCWSTR                lpServer OPTIONAL,
    OUT  LPWSTR                *lpNameBuffer,
    OUT  PNETSETUP_JOIN_STATUS  BufferType
    );


//
// Determines the list of OUs that the client can create a machine account in
//
NET_API_STATUS
NET_API_FUNCTION
NetGetJoinableOUs(
    IN  LPCWSTR     lpServer OPTIONAL,
    IN  LPCWSTR     lpDomain,
    IN  LPCWSTR     lpAccount OPTIONAL,
    IN  LPCWSTR     lpPassword OPTIONAL,
    OUT DWORD      *OUCount,
    OUT LPWSTR    **OUs
    );

//
// Computer rename preparation APIs
//

#define NET_IGNORE_UNSUPPORTED_FLAGS  0x01

NET_API_STATUS
NET_API_FUNCTION
NetAddAlternateComputerName(
    IN  LPCWSTR Server OPTIONAL,
    IN  LPCWSTR AlternateName,
    IN  LPCWSTR DomainAccount OPTIONAL,
    IN  LPCWSTR DomainAccountPassword OPTIONAL,
    IN  ULONG Reserved
    );

NET_API_STATUS
NET_API_FUNCTION
NetRemoveAlternateComputerName(
    IN  LPCWSTR Server OPTIONAL,
    IN  LPCWSTR AlternateName,
    IN  LPCWSTR DomainAccount OPTIONAL,
    IN  LPCWSTR DomainAccountPassword OPTIONAL,
    IN  ULONG Reserved
    );

NET_API_STATUS
NET_API_FUNCTION
NetSetPrimaryComputerName(
    IN  LPCWSTR Server OPTIONAL,
    IN  LPCWSTR PrimaryName,
    IN  LPCWSTR DomainAccount OPTIONAL,
    IN  LPCWSTR DomainAccountPassword OPTIONAL,
    IN  ULONG Reserved
    );

//
// The following enumeration must be kept
// in sync with COMPUTER_NAME_TYPE defined
// in winbase.h
//

typedef enum _NET_COMPUTER_NAME_TYPE {
    NetPrimaryComputerName,
    NetAlternateComputerNames,
    NetAllComputerNames,
    NetComputerNameTypeMax
} NET_COMPUTER_NAME_TYPE, *PNET_COMPUTER_NAME_TYPE;

NET_API_STATUS
NET_API_FUNCTION
NetEnumerateComputerNames(
    IN  LPCWSTR Server OPTIONAL,
    IN  NET_COMPUTER_NAME_TYPE NameType,
    IN  ULONG Reserved,
    OUT PDWORD EntryCount,
    OUT LPWSTR **ComputerNames
    );

#ifdef __cplusplus
}
#endif

#endif // __LMJOIN_H__
