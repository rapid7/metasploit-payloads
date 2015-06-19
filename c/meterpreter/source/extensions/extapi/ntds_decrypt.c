/*!
* @file ntds_decrypt.c
* @brief Definitions for NTDS decryption functions
*/
#include "extapi.h"

#define JET_VERSION 0x0501

#include <inttypes.h>
#include <WinCrypt.h>
#include "syskey.h"
#include "ntds_decrypt.h"
#include "ntds_jet.h"
#include "ntds.h"

/*!
* @brief Convert bytes into a Hex string representing those bytes.
* @param data Pointer to the byte array we are converting
* @param length Integer representing the length of the byte array
* @param output Pointer to the string we are outputting the result to
*/
void bytes_to_string(LPBYTE data, unsigned int length, LPSTR output)
{
	for (unsigned int i = 0; i < length; i++) {
		sprintf_s(output + (i *2), 3, "%02X", ((LPBYTE)data)[i]);
	}
}

/*!
* @brief Decrypt an  encrypted LM or NT Hash.
* @param encryptedNTLM Pointer to an encryptedhash struct for the LM or NT hash we wish to decrypt.
* @param pekDecrypted Pointer to a decryptedPEK structure that holds our decrypted PEK
* @param hashString Pointer to the string where we will store the decrypted hash
* @param rid DWORD representing the Relative ID(RID) of the account
* @returns Indication of sucess or failure.
*/
BOOL decrypt_hash(struct encryptedHash *encryptedNTLM,
	struct decryptedPEK *pekDecrypted, char *hashString, DWORD rid)
{
	BOOL cryptOK = FALSE;
	BYTE encHashData[NULL_TERMINATED_HASH_LENGTH] = { 0 };
	BYTE decHash[NULL_TERMINATED_HASH_LENGTH] = { 0 };

	memcpy(&encHashData, &encryptedNTLM->encryptedHash, HASH_LENGTH_BYTES);
	cryptOK = decrypt_rc4(pekDecrypted->pekKey, encryptedNTLM->keyMaterial, encHashData, 1, HASH_LENGTH_BYTES);
	if (!cryptOK) {
		return FALSE;
	}
	cryptOK = decrypt_hash_from_rid(encHashData, &rid, decHash);
	if (!cryptOK) {
		return FALSE;
	}
	bytes_to_string(decHash, HASH_LENGTH_BYTES, hashString);
	return TRUE;
}

/*!
* @brief Wraps SystemFunction025 which decrypts a hash using the RID
* @param encodedHash Pointer to a byte array containing the encrypted hash
* @param rid Pointer to a DWORD containing the Relative ID(RID)
* @param decodedHash Pointer to where we store the decrypted hash
* @returns Indication of sucess or failure.
*/
BOOL decrypt_hash_from_rid(LPBYTE encodedHash, LPDWORD rid, LPBYTE decodedHash)
{
	typedef NTSTATUS(__stdcall *PSYS25)(IN LPCBYTE data, IN LPDWORD key, OUT LPBYTE output);
	HMODULE hAdvapi = LoadLibrary("advapi32.dll");
	if (hAdvapi == NULL) {
		return FALSE;
	}
	PSYS25 decryptFromRID = (PSYS25)GetProcAddress(hAdvapi, "SystemFunction025");
	if (decryptFromRID(encodedHash, rid, decodedHash) != 0) {
		return FALSE;
	}
	return TRUE;
}

/*!
* @brief Splits up an encrypted LM or NT hash history and decrypts each stored hash
* @param encHashHistory Pointer to the byte array containing the hash history record
* @param sizeHistory The size of the history record
* @param pekDecrypted Pointer to a decryptedPEK structure that holds our decrypted PEK
* @param rid DWORD representing the Relative ID(RID) of the account
* @param accountHistory Pointer to a string wherewe store all the decrypted historical hashes
* @param historyCount Pointer to n integer where we store a count of the historical hashes
* @returns Indication of sucess or failure.
*/
BOOL decrypt_hash_history(LPBYTE encHashHistory, size_t sizeHistory,
	struct decryptedPEK *pekDecrypted, DWORD rid, char *accountHistory, unsigned int *historyCount)
{
	BOOL cryptOK = FALSE;
	unsigned int sizeHistoryData = (unsigned int)sizeHistory - 24;
	unsigned int numHashes = (sizeHistoryData / HASH_LENGTH_BYTES);
	memcpy(historyCount, &numHashes, sizeof(historyCount));
	LPBYTE encHistoryData = (LPBYTE)calloc(1,sizeHistoryData);
	LPBYTE decHistoryData = (LPBYTE)calloc(1,(sizeHistoryData * 2));
	memcpy(encHistoryData, encHashHistory + 24, sizeHistoryData);
	cryptOK = decrypt_rc4(pekDecrypted->pekKey, encHashHistory + 8, encHistoryData, 1, sizeHistoryData);
	if (!cryptOK) {
		free(encHistoryData);
		free(decHistoryData);
		return FALSE;
	}
	LPBYTE historicalHash = encHistoryData;
	LPBYTE writeMarker = decHistoryData;
	for (unsigned int i = 0; i < numHashes; i++) {
		BYTE decHash[HASH_LENGTH_BYTES];
		char hashString[NULL_TERMINATED_HASH_STRING_LENGTH] = { 0 };
		cryptOK = decrypt_hash_from_rid(historicalHash, &rid, decHash);
		if (!cryptOK) {
			return FALSE;
		}
		bytes_to_string(decHash, HASH_LENGTH_BYTES, hashString);
		strncpy_s(writeMarker, NULL_TERMINATED_HASH_STRING_LENGTH, hashString, NULL_TERMINATED_HASH_STRING_LENGTH - 1);
		historicalHash = historicalHash + HASH_LENGTH_BYTES;
		writeMarker = writeMarker + NULL_TERMINATED_HASH_STRING_LENGTH;
	}
	memcpy(accountHistory, decHistoryData, (numHashes * NULL_TERMINATED_HASH_STRING_LENGTH));
	free(encHistoryData);
	free(decHistoryData);
	return TRUE;
}

/*!
* @brief Decrypts the Password Encryption Key(PEK)
* @param sysKey Pointer to the string holding the SYSKEY
* @param pekEncrypted Pointer to an encryptedPEK struct containing our PEK to be decrypted
* @param pekDecrypted Pointer to the decryptedPEK struct where we will store our decrypted PEK
* @returns Indication of sucess or failure.
*/
BOOL decrypt_PEK(unsigned char *sysKey, struct encryptedPEK *pekEncrypted, struct decryptedPEK *pekDecrypted)
{
	BOOL cryptOK = FALSE;
	BYTE pekData[52] = { 0 };
	memcpy(&pekData, &pekEncrypted->pekData, sizeof(struct decryptedPEK));

	cryptOK = decrypt_rc4(sysKey, pekEncrypted->keyMaterial, pekData, 1000, sizeof(struct decryptedPEK));
	if (!cryptOK) {
		return FALSE;
	}
	memcpy(pekDecrypted, &pekData, sizeof(struct decryptedPEK));
	return TRUE;
}

/*!
* @brief Takes key material and ciphertext and perform an rc4 decryption routine,
* @param key1 Pointer to a string containing the first set of key material
* @param key2 Pointer to a string containing the second set of key material
* @param encrypted Pointer to a byte array containing the ciphertext
* @param iterations How many times to add key2 to the md5 Hash to generate the rc4 key
* @param lenBuffer the length of our output buffer
* @returns Indication of sucess or failure.
*/
BOOL decrypt_rc4(unsigned char *key1, unsigned char *key2, LPBYTE encrypted,
	unsigned int hashIterations, DWORD lenBuffer)
{
	BOOL cryptOK = FALSE;
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	DWORD md5Len = 16;
	unsigned char rc4Key[HASH_LENGTH_BYTES];
	HCRYPTKEY rc4KeyFinal;

	cryptOK = CryptAcquireContext(&hProv, 0, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
	if (!cryptOK) {
		return FALSE;
	}
	cryptOK = CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash);
	if (!cryptOK) {
		CryptReleaseContext(hProv, (ULONG_PTR)NULL);
		return FALSE;
	}
	cryptOK = CryptHashData(hHash, key1, HASH_LENGTH_BYTES, 0);
	if (!cryptOK) {
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, (ULONG_PTR)NULL);
		return FALSE;
	}
	for (unsigned int i = 0; i < hashIterations; i++) {
		cryptOK = CryptHashData(hHash, key2, HASH_LENGTH_BYTES, 0);
		if (!cryptOK) {
			CryptDestroyHash(hHash);
			CryptReleaseContext(hProv, (ULONG_PTR)NULL);
			return FALSE;
		}
	}
	cryptOK = CryptGetHashParam(hHash, HP_HASHVAL, rc4Key, &md5Len, 0);
	if (!cryptOK) {
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, (ULONG_PTR)NULL);
		return FALSE;
	}
	cryptOK = CryptDeriveKey(hProv, CALG_RC4, hHash, 0, &rc4KeyFinal);
	if (!cryptOK) {
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, (ULONG_PTR)NULL);
		return FALSE;
	}
	cryptOK = CryptEncrypt(rc4KeyFinal, (HCRYPTHASH)NULL, TRUE, 0, encrypted, &lenBuffer, lenBuffer);
	if (!cryptOK) {
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
