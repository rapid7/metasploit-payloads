#ifndef _METERPRETER_SOURCE_DUMP_SAM_H
#define _METERPRETER_SOURCE_DUMP_SAM_H

#define  WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <ntsecapi.h>

/*! @brief Define the type of information to retrieve from the SAM. */
#define SAM_USER_INFO_PASSWORD_OWFS 0x12

/*! @brief Struct that represents a SAM user in Windows. */
typedef struct _SAM_DOMAIN_USER
{
	DWORD               dwUserId;
	LSA_UNICODE_STRING  wszUsername;
} SAM_DOMAIN_USER;

/*! @brief Struct that contains SAM user enumeration context. */
typedef struct _SAM_DOMAIN_USER_ENUMERATION
{
	DWORD             dwDomainUserCount;
	SAM_DOMAIN_USER*  pSamDomainUser;
} SAM_DOMAIN_USER_ENUMERATION;

/* define types for samsrv */
typedef LONG	  NTSTATUS;
typedef NTSTATUS(WINAPI* SamIConnectType)(DWORD, PHANDLE, DWORD, DWORD);
typedef NTSTATUS(WINAPI* SamrOpenDomainType)(HANDLE, DWORD, PSID, HANDLE*);
typedef NTSTATUS(WINAPI* SamrOpenUserType)(HANDLE, DWORD, DWORD, HANDLE*);
typedef NTSTATUS(WINAPI* SamrEnumerateUsersInDomainType)(HANDLE, HANDLE*, DWORD, SAM_DOMAIN_USER_ENUMERATION**, DWORD, DWORD*);
typedef NTSTATUS(WINAPI* SamrQueryInformationUserType)(HANDLE, DWORD, PVOID);
typedef VOID(WINAPI* SamIFree_SAMPR_USER_INFO_BUFFERType)(PVOID, DWORD);
typedef VOID(WINAPI* SamIFree_SAMPR_ENUMERATION_BUFFERType)(PVOID);
typedef NTSTATUS(WINAPI* SamrCloseHandleType)(HANDLE*);

/* unions are used to ensure that MinGW can correctly calculate the size in WOW64 */
#define STRUCT_USERNAMEHASH(bits) typedef struct \
{ \
	union { \
		char* __ptr##bits  ptr; \
		ULONG##bits        ul; \
	} Username; \
	DWORD              Length; \
	DWORD              RID; \
	char               Hash[32]; \
} USERNAMEHASH##bits;

#define STRUCT_FUNCTIONARGS(bits) typedef struct \
{ \
	/* kernel sync object strings */ \
	char                             ReadSyncEvent[16]; \
	char                             FreeSyncEvent[16]; \
	/* maximum wait time for sync */ \
	DWORD                            dwMillisecondsToWait; \
	/* return values */ \
	DWORD                            dwDataSize; \
	union { \
		USERNAMEHASH##bits* __ptr##bits  ptr; \
		ULONG##bits                      ul; \
	} UsernameHashData; \
} FUNCTIONARGS##bits;

STRUCT_USERNAMEHASH(32);
STRUCT_USERNAMEHASH(64);
STRUCT_FUNCTIONARGS(32);
STRUCT_FUNCTIONARGS(64);

#ifdef _WIN64
typedef USERNAMEHASH64  USERNAMEHASH;
typedef FUNCTIONARGS64  FUNCTIONARGS;
#else
typedef USERNAMEHASH32  USERNAMEHASH;
typedef FUNCTIONARGS32  FUNCTIONARGS;
#endif

DWORD dump_sam(FUNCTIONARGS* fargs);
void dump_sam_end(void);

#endif
