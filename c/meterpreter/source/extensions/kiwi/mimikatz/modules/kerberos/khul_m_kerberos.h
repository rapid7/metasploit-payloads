/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "../kuhl_m.h"
#include "../modules/kull_m_file.h"
#include "../modules/kull_m_crypto_system.h"
#include "../modules/kull_m_samlib.h"
#include "khul_m_kerberos_struct.h"

const KUHL_M kuhl_m_kerberos;

NTSTATUS kuhl_m_kerberos_init();
NTSTATUS kuhl_m_kerberos_clean();

NTSTATUS LsaCallKerberosPackage(PVOID ProtocolSubmitBuffer, ULONG SubmitBufferLength, PVOID *ProtocolReturnBuffer, PULONG ReturnBufferLength, PNTSTATUS ProtocolStatus);

NTSTATUS kuhl_m_kerberos_ptt(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kerberos_golden(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kerberos_list(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kerberos_tgt(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kerberos_purge(int argc, wchar_t * argv[]);

#ifdef KERBEROS_TOOLS
NTSTATUS kuhl_m_kerberos_decode(int argc, wchar_t * argv[]);
#endif

wchar_t * kuhl_m_kerberos_generateFileName(const DWORD index, PKERB_TICKET_CACHE_INFO_EX ticket, LPCWSTR ext);
struct _DIRTY_ASN1_SEQUENCE_EASY * kuhl_m_kerberos_golden_data(LPCWSTR username, LPCWSTR domainname, PISID sid, LPCBYTE krbtgt, DWORD userid, PGROUP_MEMBERSHIP groups, DWORD cbGroups);
NTSTATUS kuhl_m_kerberos_encrypt(ULONG eType, ULONG keyUsage, LPCVOID key, DWORD keySize, LPCVOID data, DWORD dataSize, LPVOID * output, DWORD * outputSize, BOOL encrypt);
