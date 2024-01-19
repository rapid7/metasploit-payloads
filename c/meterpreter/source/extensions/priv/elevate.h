/*!
 * @file elevate.h
 * @brief Declarations for SYSTEM privilege escalation.
 */
#ifndef _METERPRETER_SOURCE_EXTENSION_PRIV_PRIV_SERVER_ELEVATE_ELEVATE_H
#define _METERPRETER_SOURCE_EXTENSION_PRIV_PRIV_SERVER_ELEVATE_ELEVATE_H

#define ELEVATE_TECHNIQUE_NONE                    -1 ///< Identifier that indicates no technique was successful
#define ELEVATE_TECHNIQUE_ANY                     0  ///< Identifier that indicates that all techniques should be attempted.
#define ELEVATE_TECHNIQUE_SERVICE_NAMEDPIPE       1  ///< Identifier for the Named Pipe service technique (#1)
#define ELEVATE_TECHNIQUE_SERVICE_NAMEDPIPE2      2  ///< Identifier for the Named Pipe service technique (#2)
#define ELEVATE_TECHNIQUE_SERVICE_TOKENDUP        3  ///< Identifier for the Token Duplication service technique.
#define ELEVATE_TECHNIQUE_SERVICE_NAMEDPIPE_RPCSS 4  ///< Identifier for the Named Pipe service technique (RPCSS variant)
#define ELEVATE_TECHNIQUE_NAMEDPIPE_PRINTSPOOLER  5  ///< Identifier for the Named Pipe technique (PrintSpooler variant)
#define ELEVATE_TECHNIQUE_NAMEDPIPE_EFS           6  ///< Identifier for the Named Pipe technique (EFSRPC variant - AKA EfsPotato)

typedef void (WINAPI * GETNATIVESYSTEMINFO)( LPSYSTEM_INFO lpSystemInfo ); ///< Stolen from ps.h

#define PROCESS_ARCH_UNKNOWN	0 ///< Indicates that the architecture is not known.
#define PROCESS_ARCH_X86		1 ///< Indicates that the architecture is X86.
#define PROCESS_ARCH_X64		2 ///< Indicates that the architecture is AMDX64.
#define PROCESS_ARCH_IA64		3 ///< Indicates that the architecture is IA64.

DWORD elevate_getnativearch( VOID );

DWORD elevate_getsystem( Remote * remote, Packet * packet );

#endif
