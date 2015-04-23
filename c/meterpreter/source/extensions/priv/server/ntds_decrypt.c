#include "precomp.h"

BOOL decrypt_hash(encryptedHash *encryptedNTLM, decryptedPEK *pekDecrypted, char *hashString, DWORD rid){
	BOOL cryptOK = FALSE;
	BYTE encHashData[17] = { 0 };
	BYTE decHash[17] = { 0 };

	memcpy(&encHashData, &encryptedNTLM->encryptedHash, 16);
	cryptOK = decrypt_rc4(pekDecrypted->pekKey, encryptedNTLM->keyMaterial, encHashData, 1, 16);
	if (!cryptOK){
		return FALSE;
	}
	cryptOK = decrypt_hash_from_rid(encHashData, &rid, decHash);
	if (!cryptOK){
		return FALSE;
	}
	bytes_to_string(decHash, 16, hashString);
	return TRUE;
}

BOOL decrypt_hash_from_rid(LPBYTE encodedHash, LPDWORD rid, LPBYTE decodedHash){
	typedef NTSTATUS(__stdcall *PSYS25)(IN LPCBYTE data, IN LPDWORD key, OUT LPBYTE output);
	HMODULE hAdvapi = LoadLibrary("advapi32.dll");
	if (hAdvapi == NULL){
		return FALSE;
	}
	PSYS25 decryptFromRID = (PSYS25)GetProcAddress(hAdvapi, "SystemFunction025");
	if (decryptFromRID(encodedHash, rid, decodedHash) != 0){
		return FALSE;
	}
	return TRUE;
}

BOOL decrypt_hash_history(LPBYTE encHashHistory, size_t sizeHistory, decryptedPEK *pekDecrypted, DWORD rid, char *accountHistory, int *historyCount){
	BOOL cryptOK = FALSE;
	size_t sizeHistoryData = sizeHistory - 24;
	int numHashes = (sizeHistoryData / 16);
	memcpy(historyCount, &numHashes, sizeof(historyCount));
	LPBYTE encHistoryData = (LPBYTE)malloc(sizeHistoryData);
	LPBYTE decHistoryData = (LPBYTE)malloc((sizeHistoryData * 2));
	memcpy(encHistoryData, encHashHistory + 24, sizeHistoryData);
	cryptOK = decrypt_rc4(pekDecrypted->pekKey, encHashHistory + 8, encHistoryData, 1, sizeHistoryData);
	if (!cryptOK){
		return FALSE;
	}
	LPBYTE historicalHash = encHistoryData;
	LPBYTE writeMarker = decHistoryData;
	for (int i = 0; i < numHashes; i++){
		BYTE decHash[16];
		char hashString[33];
		cryptOK = decrypt_hash_from_rid(historicalHash, &rid, decHash);
		if (!cryptOK){
			return FALSE;
		}
		bytes_to_string(decHash, 16, hashString);
		strncpy(writeMarker, hashString, 33);
		historicalHash = historicalHash + 16;
		writeMarker = writeMarker + 33;
	}
	memcpy(accountHistory, decHistoryData, (numHashes * 33));
	//memcpy(accountHistory, &decHistoryData, 4);
	return TRUE;
}

BOOL decrypt_PEK(unsigned char *sysKey, encryptedPEK *pekEncrypted, decryptedPEK *pekDecrypted){
	BOOL cryptOK = FALSE;
	BYTE pekData[52] = { 0 };
	DWORD pekLength = 52;
	memcpy(&pekData, &pekEncrypted->pekData, pekLength);

	cryptOK = decrypt_rc4(sysKey, pekEncrypted->keyMaterial, pekData, 1000, pekLength);
	if (!cryptOK){
		return FALSE;
	}
	memcpy(pekDecrypted, &pekData, pekLength);
	return TRUE;
}

BOOL decrypt_rc4(unsigned char *key1, unsigned char *key2, LPBYTE encrypted, int hashIterations, DWORD lenBuffer){
	BOOL cryptOK = FALSE;
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	DWORD md5Len = 16;
	unsigned char rc4Key[16];
	HCRYPTKEY rc4KeyFinal;

	cryptOK = CryptAcquireContext(&hProv, 0, MS_ENHANCED_PROV, PROV_RSA_FULL, 0);
	if (!cryptOK){
		return FALSE;
	}
	cryptOK = CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash);
	if (!cryptOK){
		return FALSE;
	}
	cryptOK = CryptHashData(hHash, key1, 16, 0);
	if (!cryptOK){
		return FALSE;
	}
	for (int i = 0; i < hashIterations; i++){
		cryptOK = CryptHashData(hHash, key2, 16, 0);
		if (!cryptOK){
			return FALSE;
		}
	}
	cryptOK = CryptGetHashParam(hHash, HP_HASHVAL, rc4Key, &md5Len, 0);
	if (!cryptOK){
		return FALSE;
	}
	cryptOK = CryptDeriveKey(hProv, CALG_RC4, hHash, 0, &rc4KeyFinal);
	if (!cryptOK){
		return FALSE;
	}
	cryptOK = CryptEncrypt(rc4KeyFinal, (HCRYPTHASH)NULL, TRUE, 0, encrypted, &lenBuffer, lenBuffer);
	if (!cryptOK){
		return FALSE;
	}
	// Clean up after ourselves
	CryptDestroyKey(rc4KeyFinal);
	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, NULL);
	return TRUE;
}
