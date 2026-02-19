#include <winsock2.h>
#include <windows.h>
#include "rc4.h"
#include "common.h"

#define MAX_EXTENSIONS 32
#define KEY_SIZE_RC4 16
#define BUFFER_SIZE 4096
#define ENCRYPTION_5_MINUTES_MS (5 * 60 * 1000)
#define ENCRYPTION_10_MINUTES_MS (10 * 60 * 1000)
#define ENCRYPTION_30_MINUTES_MS (30 * 60 * 1000)
#define ENCRYPTION_1_HOUR_MS (60 * 60 * 1000)

#define EXTENSION_ENCRYPTION_INVALID_HANDLER_FUNCTION 1
#define EXTENSION_ENCRYPTION_INVALID_EXTENSION_MANAGER 2
#define EXTENSION_ENCRYPTION_EXTENSION_NOT_FOUND 3
#define EXTENSION_ENCRYPTION_EXTENSION_NOT_ENCRYPTABLE 4
#define EXTENSION_ENCRYPTION_DECRYPTION_ERROR 5


#define ENCRYPTION_UNUSED_COOLDOWN_MS ENCRYPTION_5_MINUTES_MS

typedef enum {
	CRYPTOGRAPHIC_MANAGER_TYPE_DEBUG,
	CRYPTOGRAPHIC_MANAGER_TYPE_RC4,
} CryptographicManagerType;

typedef struct {
	BOOL bEncryptable;
	BOOL bEncrypted;
	LPVOID lpLoc;
	DWORD dwSize;
	DWORD dwLastUsedTime;
} ExtensionEncryptionStatus;

typedef struct {
	BOOL bInitialized;
	LPVOID lpCryptoContext;
	LPCSTR lpCryptoParams;
	BOOL bNeedsRefresh;
	DWORD (*initialize)(LPVOID* lpCryptoContext, LPVOID lpParams);
	DWORD (*encrypt)(LPVOID lpDataIn, DWORD dwDataInSize, LPVOID lpDataOut, DWORD dwDataOutSize);
	DWORD (*decrypt)(LPVOID lpDataIn, DWORD dwDataInSize, LPVOID lpDataOut, DWORD dwDataOutSize);
	DWORD (*refresh)(LPVOID lpCryptoContext, LPVOID lpParams);
} CryptographicManager;

typedef struct {
	CRITICAL_SECTION cs;
	ExtensionEncryptionStatus* extensionStatuses[MAX_EXTENSIONS];
	DWORD dwExtensionsCount;
	DWORD dwCryptoManagerType;
	CryptographicManager cryptoManager;
	struct {
		BOOL (*add)(LPVOID lpExtensionLocation, DWORD dwExtensionSize);
		BOOL (*get)(LPVOID lpHandlerFunction, ExtensionEncryptionStatus** lpOutExtensionStatus);
		BOOL (*remove)(ExtensionEncryptionStatus* lpStatus);
		BOOL (*encrypt)(ExtensionEncryptionStatus* lpStatus);
		BOOL (*decrypt)(ExtensionEncryptionStatus* lpStatus);
		void (*encryptUnused)();
	};
} ExtensionEncryptionManager;

ExtensionEncryptionManager *GetExtensionEncryptionManager(VOID);
ExtensionEncryptionManager *InitExtensionEncryptionManager(CryptographicManagerType type, LPVOID lpCryptoParams);
BOOL extension_encryption_add(LPVOID lpExtensionLocation, DWORD dwExtensionSize);
BOOL extension_encryption_get(LPVOID lpHandlerFunction, ExtensionEncryptionStatus** lpOutExtensionStatus);
BOOL extension_encryption_remove(ExtensionEncryptionStatus* lpStatus);

BOOL extension_encryption_encrypt(ExtensionEncryptionStatus* lpStatus);
BOOL extension_encryption_decrypt(ExtensionEncryptionStatus* lpStatus);
void extension_encryption_encrypt_unused();
DWORD extensionFindDecrypt(LPVOID lpHandlerFunction);