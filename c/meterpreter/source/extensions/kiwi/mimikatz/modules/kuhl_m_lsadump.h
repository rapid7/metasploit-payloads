/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "kuhl_m.h"
#include "../modules/kull_m_process.h"
#include "../modules/kull_m_service.h"
#include "../modules/kull_m_memory.h"
#include "../modules/kull_m_patch.h"
#include "../modules/kull_m_registry.h"
#include "../modules/kull_m_crypto_system.h"
#include "../modules/kull_m_string.h"
#include "kuhl_m_lsadump_struct.h"

const KUHL_M kuhl_m_lsadump;

NTSTATUS kuhl_m_lsadump_sam(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_samrpc(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_secrets(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_cache(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_secretsOrCache(int argc, wchar_t * argv[], BOOL secretsOrCache);

BOOL kuhl_m_lsadump_getComputerAndSyskey(IN PKULL_M_REGISTRY_HANDLE hRegistry, IN HKEY hSystemBase, OUT LPBYTE sysKey, PLSA_CALLBACK_CTX callbackCtx);
BOOL kuhl_m_lsadump_getUsersAndSamKey(IN PKULL_M_REGISTRY_HANDLE hRegistry, IN HKEY hSAMBase, IN LPBYTE sysKey, PLSA_CALLBACK_CTX callbackCtx);

BOOL kuhl_m_lsadump_getCurrentControlSet(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hSystemBase, PHKEY phCurrentControlSet);
BOOL kuhl_m_lsadump_getSyskey(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hLSA, LPBYTE sysKey);
BOOL kuhl_m_lsadump_getSamKey(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hAccount, LPCBYTE sysKey, LPBYTE samKey);
BOOL kuhl_m_lsadump_getHash(PSAM_SENTRY pSamHash, LPCBYTE pStartOfData, LPCBYTE samKey, DWORD rid, BOOL isNtlm, BYTE hashBuffer[LM_NTLM_HASH_LENGTH]);

extern NTSTATUS WINAPI SamConnect(IN PSAMPR_SERVER_NAME ServerName, OUT SAMPR_HANDLE *ServerHandle, IN ACCESS_MASK DesiredAccess, IN BOOLEAN Trusted);
extern NTSTATUS WINAPI SamOpenDomain(IN SAMPR_HANDLE SamHandle, IN ACCESS_MASK DesiredAccess, IN PRPC_SID DomainId, OUT SAMPR_HANDLE* DomainHandle);
extern NTSTATUS WINAPI SamOpenUser(IN SAMPR_HANDLE DomainHandle, IN ACCESS_MASK DesiredAccess, IN DWORD UserId, OUT SAMPR_HANDLE* UserHandle);
extern NTSTATUS WINAPI SamQueryInformationUser(IN SAMPR_HANDLE UserHandle, IN USER_INFORMATION_CLASS UserInformationClass, PSAMPR_USER_INFO_BUFFER* Buffer);
extern NTSTATUS WINAPI SamEnumerateUsersInDomain(IN SAMPR_HANDLE DomainHandle, IN OUT PDWORD EnumerationContext, IN DWORD UserAccountControl, OUT PSAMPR_RID_ENUMERATION* Buffer, IN DWORD PreferedMaximumLength, OUT PDWORD CountReturned);
extern NTSTATUS WINAPI SamCloseHandle(IN SAMPR_HANDLE SamHandle);
extern NTSTATUS WINAPI SamFreeMemory(IN PVOID Buffer);

NTSTATUS kuhl_m_lsadump_full(PLSA_CALLBACK_CTX callbackCtx);

BOOL kuhl_m_lsadump_getLsaKeyAndSecrets(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hSecurityBase, IN PKULL_M_REGISTRY_HANDLE hSystem, IN HKEY hSystemBase, IN LPBYTE sysKey, IN BOOL secretsOrCache, IN PLSA_CALLBACK_CTX callbackCtx);
BOOL kuhl_m_lsadump_getSecrets(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hPolicyBase, IN PKULL_M_REGISTRY_HANDLE hSystem, IN HKEY hSystemBase, PNT6_SYSTEM_KEYS lsaKeysStream, PNT5_SYSTEM_KEY lsaKeyUnique, PLSA_CALLBACK_CTX callbackCtx);
BOOL kuhl_m_lsadump_getNLKMSecretAndCache(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hPolicyBase, IN HKEY hSecurityBase, PNT6_SYSTEM_KEYS lsaKeysStream, PNT5_SYSTEM_KEY lsaKeyUnique, PLSA_CALLBACK_CTX callbackCtx);
void kuhl_m_lsadump_printMsCache(PMSCACHE_ENTRY entry, CHAR version);
void kuhl_m_lsadump_getInfosFromServiceName(IN PKULL_M_REGISTRY_HANDLE hSystem, IN HKEY hSystemBase, IN PCWSTR serviceName, OUT wchar_t** pObjectName);
BOOL kuhl_m_lsadump_decryptSecret(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hSecret, IN PNT6_SYSTEM_KEYS lsaKeysStream, IN PNT5_SYSTEM_KEY lsaKeyUnique, IN PVOID * pBufferOut, IN PDWORD pSzBufferOut);
void kuhl_m_lsadump_candidateSecret(DWORD szBytesSecrets, PVOID bufferSecret, PCWSTR prefix);
BOOL kuhl_m_lsadump_sec_aes256(PNT6_HARD_SECRET hardSecretBlob, DWORD hardSecretBlobSize, PNT6_SYSTEM_KEYS lsaKeysStream, PBYTE sysKey);
void kuhl_m_lsadump_hmac_md5(LPCVOID key, DWORD szKey, LPCVOID data, DWORD szData, LPVOID output);
