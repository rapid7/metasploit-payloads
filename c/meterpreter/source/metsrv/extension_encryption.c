#include "extension_encryption.h"

extension_encryption_ctx* extension_statuses[MAX_EXTENSIONS] = { 0 };

BOOL extension_encryption_add(extension_encryption_ctx* ExtensionCtx) {
	BOOL ret = FALSE;

	if (ExtensionCtx == NULL || !ExtensionCtx->encryptable) {
		dprintf("[extension_encryption][extension_encryption_add] Either ExtensionCtx is NULL or Extension is not encryptable.");
		return ret;
	}
	
	for (int i = 0; i < MAX_EXTENSIONS; i++) {
		if (extension_statuses[i] == NULL) {
			extension_statuses[i] = ExtensionCtx;
			ret = TRUE;
			break;
		}
	}
	if (!ret) {
		dprintf("[extension_encryption][extension_encryption_add] Couldn't locate an empty member in extension_statuses array.");
	}
	return ret;
}

BOOL extension_encryption_remove(extension_encryption_ctx* ExtensionCtx) {
	BOOL ret = FALSE;

	if (ExtensionCtx == NULL) {
		dprintf("[extension_encryption][extension_encryption_remove] ExtensionCtx is NULL.");
		return ret;
	}

	for (int i = 0; i < MAX_EXTENSIONS; i++) {
		if (extension_statuses[i] == ExtensionCtx) {
			extension_statuses[i] = NULL;
			ret = TRUE;
			break;
		}
	}
	if (!ret) {
		dprintf("[extension_encryption][extension_encryption_remove] Couldn't locate ExtensionCtx in extension_statuses array.");
	}
	return ret;
}

BOOL extension_encryption_encrypt(extension_encryption_ctx* ExtensionCtx) {
	RC4_CTX RC4 = { 0 };
	size_t KeyLength = 0;
	BOOL ret = FALSE;
	unsigned char buff[4096] = { 0 };
	DWORD diff = 4096;
	size_t ByteCounter = 0;

	if (ExtensionCtx == NULL || !ExtensionCtx->encryptable || ExtensionCtx->encrypted || !ExtensionCtx->size || ExtensionCtx->key == NULL || ExtensionCtx->loc == NULL) {
		dprintf("[extension_encryption][extension_encryption_encrypt] Invalid ExtensionCtx.");
		return ret;
	}

	KeyLength = strlen(ExtensionCtx->key);

	if (!KeyLength || !InitRc4(&RC4, ExtensionCtx->key, KeyLength)) {
		dprintf("[extension_encryption][extension_encryption_encrypt] Either KeyLength is 0 or InitRc4 failed.");
		return ret;
	}

	for (DWORD i = 0; i != ExtensionCtx->size; i += diff) {
		if ((ExtensionCtx->size - i) < 4096) {
			diff = ExtensionCtx->size - i;
		}
		ret = ReadProcessMemory(GetCurrentProcess(), (unsigned char*)ExtensionCtx->loc + i, buff, diff, &ByteCounter);
		if (!ret || ByteCounter != diff) {
			dprintf("[extension_encryption][extension_encryption_encrypt] ReadProcessMemory failed with error 0x%x", GetLasatError());
			break;
		}
		if (!RC4Cipher(&RC4, buff, diff)) {
			dprintf("[extension_encryption][extension_encryption_encrypt] RC4Cipher failed.");
			ret = FALSE;
			break;
		}
		ret = WriteProcessMemory(GetCurrentProcess(), (unsigned char*)ExtensionCtx->loc, buff, diff, &ByteCounter);
		if (!ret || ByteCounter != diff) {
			dprintf("[extension_encryption][extension_encryption_encrypt] WriteProcessMemory failed with error 0x%x", GetLastError());
			break;
		}
	}
	if (ret) {
		ExtensionCtx->encrypted = !ExtensionCtx->encrypted;
	}
	return ret;
}

BOOL extension_encryption_decrypt(extension_encryption_ctx* ExtensionCtx) {
	RC4_CTX RC4 = { 0 };
	size_t KeyLength = 0;
	BOOL ret = FALSE;
	unsigned char buff[4096] = { 0 };
	DWORD diff = 4096;
	size_t ByteCounter = 0;

	if (ExtensionCtx == NULL || !ExtensionCtx->encryptable || !ExtensionCtx->encrypted || !ExtensionCtx->size || ExtensionCtx->key == NULL || ExtensionCtx->loc == NULL) {
		dprintf("[extension_encryption][extension_encryption_decrypt] Invalid ExtensionCtx.");
		return ret;
	}

	KeyLength = strlen(ExtensionCtx->key);

	if (!KeyLength || !InitRc4(&RC4, ExtensionCtx->key, KeyLength)) {
		dprintf("[extension_encryption][extension_encryption_decrypt] Either KeyLength is 0 or InitRc4 failed.");
		return ret;
	}

	for (DWORD i = 0; i != ExtensionCtx->size; i += diff) {
		if ((ExtensionCtx->size - i) < 4096) {
			diff = ExtensionCtx->size - i;
		}
		ret = ReadProcessMemory(GetCurrentProcess(), (unsigned char*)ExtensionCtx->loc + i, buff, diff, &ByteCounter);
		if (!ret || ByteCounter != diff) {
			dprintf("[extension_encryption][extension_encryption_decrypt] ReadProcessMemory failed with error 0x%x", GetLasatError());
			break;
		}
		if (!RC4Cipher(&RC4, buff, diff)) {
			dprintf("[extension_encryption][extension_encryption_decrypt] RC4Cipher failed.");
			ret = FALSE;
			break;
		}
		ret = WriteProcessMemory(GetCurrentProcess(), (unsigned char*)ExtensionCtx->loc, buff, diff, &ByteCounter);
		if (!ret || ByteCounter != diff) {
			dprintf("[extension_encryption][extension_encryption_decrypt] WriteProcessMemory failed with error 0x%x", GetLastError());
			break;
		}
	}
	if (ret) {
		ExtensionCtx->encrypted = !ExtensionCtx->encrypted;
	}
	return ret;
}

void extension_encryption_encrypt_unused() {
	for (int i = 0; i < MAX_EXTENSIONS; i++) {
		if (extension_statuses[i] == NULL || !extension_statuses[i]->encryptable || extension_statuses[i]->encrypted || (GetTickCount() - extension_statuses[i]->LastUsedTime) < 600000) {
			continue;
		}
		if (!extension_encryption_encrypt(extension_statuses[i])) {
			dprintf("[extension_encryption][extension_encryption_encrypt_unused] extension_statuses[%d] couldn't be encrypted.", i);
		}
	}
}