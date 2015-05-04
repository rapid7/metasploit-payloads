#ifndef _METERPRETER_SOURCE_EXTENSION_PRIV_PRIV_SERVER_NTDS_DECRYPT_H
#define _METERPRETER_SOURCE_EXTENSION_PRIV_PRIV_SERVER_NTDS_DECRYPT_H
typedef struct{
	unsigned char header[8];
	unsigned char keyMaterial[16];
	unsigned char encryptedHash[16];
}encryptedHash;

typedef struct{
	unsigned char header[8];
	unsigned char keyMaterial[16];
	unsigned char pekData[36];
	unsigned char pekFinal[16];
}encryptedPEK;

typedef struct{
	unsigned char pekData[36];
	unsigned char pekKey[16];
}decryptedPEK;

void bytes_to_string(LPBYTE data, int length, LPSTR output);
BOOL decrypt_hash(encryptedHash *encryptedNTLM, decryptedPEK *pekDecrypted, char *hashString, DWORD rid);
BOOL decrypt_hash_from_rid(LPBYTE encodedHash, LPDWORD rid, LPBYTE decodedHash);
BOOL decrypt_hash_history(LPBYTE encHashHistory, size_t sizeHistory, decryptedPEK *pekDecrypted, DWORD rid, char *accountHistory, int *historyCount);
BOOL decrypt_PEK(unsigned char *sysKey, encryptedPEK *pekEncrypted, decryptedPEK *pekDecrypted);
BOOL decrypt_rc4(unsigned char *key1, unsigned char *key2, LPBYTE encrypted, int hashIterations, DWORD lenBuffer);

#define HASH_LENGTH_BYTES 16
#define NULL_TERIMNATED_HASH_LENGTH 17
#endif