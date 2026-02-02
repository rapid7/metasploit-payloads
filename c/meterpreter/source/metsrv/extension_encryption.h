#include "rc4.h"
#include "common.h"

#define MAX_EXTENSIONS 32 // ??

typedef struct {
	BOOL encryptable;
	BOOL encrypted;
	LPCSTR key;
	LPVOID loc;
	DWORD size;
	DWORD LastUsedTime;
} extension_encryption_ctx;

BOOL extension_encryption_add(extension_encryption_ctx* ExtensionCtx);
BOOL extension_encryption_remove(extension_encryption_ctx* ExtensionCtx);
BOOL extension_encryption_encrypt(extension_encryption_ctx* ExtensionCtx);
BOOL extension_encryption_decrypt(extension_encryption_ctx* ExtensionCtx);
void extension_encryption_encrypt_unused();