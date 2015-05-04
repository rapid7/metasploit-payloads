#include "precomp.h"

// Converts bytes into a hex string representation of those bytes
void bytes_to_string(LPBYTE data, int length, LPSTR output){
	for (int i = 0; i < length; i++){
		sprintf(output + (i << 1), "%02X", ((LPBYTE)data)[i]);
	}
}

// Takes an encypted NT or LM hash and decrypts it
BOOL decrypt_hash(encryptedHash *encryptedNTLM, decryptedPEK *pekDecrypted, char *hashString, DWORD rid){
	BOOL cryptOK = FALSE;
	BYTE encHashData[NULL_TERIMNATED_HASH_LENGTH] = { 0 };
	BYTE decHash[NULL_TERIMNATED_HASH_LENGTH] = { 0 };

	memcpy(&encHashData, &encryptedNTLM->encryptedHash, HASH_LENGTH_BYTES);
	cryptOK = decrypt_rc4(pekDecrypted->pekKey, encryptedNTLM->keyMaterial, encHashData, 1, HASH_LENGTH_BYTES);
	if (!cryptOK){
		return FALSE;
	}
	cryptOK = decrypt_hash_from_rid(encHashData, &rid, decHash);
	if (!cryptOK){
		return FALSE;
	}
	bytes_to_string(decHash, HASH_LENGTH_BYTES, hashString);
	return TRUE;
}

// This function is wrapper around the RunTime Dynamic Linked Function
// SystemFunction025 which is the secret internal function Windows uses
// to decrypt an encrypted hash using the Realative ID (RID)
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

// This function splits up an encrypted LM or NT hash history record, and decrypts each
// hash enclosed in that history.
BOOL decrypt_hash_history(LPBYTE encHashHistory, size_t sizeHistory, decryptedPEK *pekDecrypted, DWORD rid, char *accountHistory, int *historyCount){
	BOOL cryptOK = FALSE;
	size_t sizeHistoryData = sizeHistory - 24;
	int numHashes = (sizeHistoryData / HASH_LENGTH_BYTES);
	memcpy(historyCount, &numHashes, sizeof(historyCount));
	LPBYTE encHistoryData = (LPBYTE)malloc(sizeHistoryData);
	LPBYTE decHistoryData = (LPBYTE)malloc((sizeHistoryData * 2));
	memcpy(encHistoryData, encHashHistory + 24, sizeHistoryData);
	cryptOK = decrypt_rc4(pekDecrypted->pekKey, encHashHistory + 8, encHistoryData, 1, sizeHistoryData);
	if (!cryptOK){
		free(encHistoryData);
		free(decHistoryData);
		return FALSE;
	}
	LPBYTE historicalHash = encHistoryData;
	LPBYTE writeMarker = decHistoryData;
	for (int i = 0; i < numHashes; i++){
		BYTE decHash[HASH_LENGTH_BYTES];
		char hashString[NULL_TERIMNATED_HASH_STRING_LENGTH];
		cryptOK = decrypt_hash_from_rid(historicalHash, &rid, decHash);
		if (!cryptOK){
			return FALSE;
		}
		bytes_to_string(decHash, HASH_LENGTH_BYTES, hashString);
		strncpy(writeMarker, hashString, NULL_TERIMNATED_HASH_STRING_LENGTH);
		historicalHash = historicalHash + HASH_LENGTH_BYTES;
		writeMarker = writeMarker + NULL_TERIMNATED_HASH_STRING_LENGTH;
	}
	memcpy(accountHistory, decHistoryData, (numHashes * NULL_TERIMNATED_HASH_STRING_LENGTH));
	free(encHistoryData);
	free(decHistoryData);
	return TRUE;
}

// This function is responsible for decrypting the Password Encryption Key(PEK)
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

// This function takes a set of key material and encrypted data
// It generates an md5 hash out of the key material and then uses that
// as an rc4 key to decrypt the ciphertext
BOOL decrypt_rc4(unsigned char *key1, unsigned char *key2, LPBYTE encrypted, int hashIterations, DWORD lenBuffer){
	BOOL cryptOK = FALSE;
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	DWORD md5Len = 16;
	unsigned char rc4Key[HASH_LENGTH_BYTES];
	HCRYPTKEY rc4KeyFinal;

	cryptOK = CryptAcquireContext(&hProv, 0, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
	if (!cryptOK){
		return FALSE;
	}
	cryptOK = CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash);
	if (!cryptOK){
		CryptReleaseContext(hProv, (ULONG_PTR)NULL);
		return FALSE;
	}
	cryptOK = CryptHashData(hHash, key1, HASH_LENGTH_BYTES, 0);
	if (!cryptOK){
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, (ULONG_PTR)NULL);
		return FALSE;
	}
	for (int i = 0; i < hashIterations; i++){
		cryptOK = CryptHashData(hHash, key2, HASH_LENGTH_BYTES, 0);
		if (!cryptOK){
			CryptDestroyHash(hHash);
			CryptReleaseContext(hProv, (ULONG_PTR)NULL);
			return FALSE;
		}
	}
	cryptOK = CryptGetHashParam(hHash, HP_HASHVAL, rc4Key, &md5Len, 0);
	if (!cryptOK){
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, (ULONG_PTR)NULL);
		return FALSE;
	}
	cryptOK = CryptDeriveKey(hProv, CALG_RC4, hHash, 0, &rc4KeyFinal);
	if (!cryptOK){
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, (ULONG_PTR)NULL);
		return FALSE;
	}
	cryptOK = CryptEncrypt(rc4KeyFinal, (HCRYPTHASH)NULL, TRUE, 0, encrypted, &lenBuffer, lenBuffer);
	if (!cryptOK){
		CryptDestroyKey(rc4KeyFinal);
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, (ULONG_PTR)NULL);
		return FALSE;
	}
	// Clean up after ourselves
	CryptDestroyKey(rc4KeyFinal);
	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, (ULONG_PTR)NULL);
	return TRUE;
}
