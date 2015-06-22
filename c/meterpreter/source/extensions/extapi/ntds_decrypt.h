#ifndef _METERPRETER_SOURCE_EXTENSION_EXTAPI_PRIV_SERVER_NTDS_DECRYPT_H
#define _METERPRETER_SOURCE_EXTENSION_EXTAPI_PRIV_SERVER_NTDS_DECRYPT_H
struct encryptedHash{
	unsigned char header[8];
	unsigned char keyMaterial[16];
	unsigned char encryptedHash[16];
};

struct encryptedPEK{
	unsigned char header[8];
	unsigned char keyMaterial[16];
	unsigned char pekData[36];
	unsigned char pekFinal[16];
};

struct decryptedPEK{
	unsigned char pekData[36];
	unsigned char pekKey[16];
};

void bytes_to_string(LPBYTE data, unsigned int length, LPSTR output);
BOOL decrypt_hash(struct encryptedHash *encryptedNTLM, struct decryptedPEK *pekDecrypted, char *hashString, DWORD rid);
BOOL decrypt_hash_from_rid(LPBYTE encodedHash, LPDWORD rid, LPBYTE decodedHash);
BOOL decrypt_hash_history(LPBYTE encHashHistory, size_t sizeHistory, struct decryptedPEK *pekDecrypted, DWORD rid, char *accountHistory, unsigned int *historyCount);
BOOL decrypt_PEK(unsigned char *sysKey, struct encryptedPEK *pekEncrypted, struct decryptedPEK *pekDecrypted);
BOOL decrypt_rc4(unsigned char *key1, unsigned char *key2, LPBYTE encrypted, unsigned int hashIterations, DWORD lenBuffer);

#define HASH_LENGTH_BYTES 16
#define NULL_TERMINATED_HASH_LENGTH 17
#define NULL_TERMINATED_HASH_STRING_LENGTH 33
#endif
