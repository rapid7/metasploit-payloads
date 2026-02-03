#include "extension_encryption.h"

ExtensionEncryptionManager *g_ExtensionEncryptionManager = NULL;

DWORD cyptographic_manager_debug_initialize(LPVOID* lpCryptoContext, LPVOID lpParams) {
	*lpCryptoContext = NULL;
	return 0;
}

DWORD cryptographic_manager_debug_encrypt(LPVOID lpDataIn, DWORD dwDataInSize, LPVOID lpDataOut, DWORD dwDataOutSize) {
	if (dwDataOutSize < dwDataInSize) {
		return 0;
	}
	memcpy(lpDataOut, lpDataIn, dwDataInSize);
	return dwDataInSize;
}

DWORD cryptographic_manager_debug_decrypt(LPVOID lpDataIn, DWORD dwDataInSize, LPVOID lpDataOut, DWORD dwDataOutSize) {
	if (dwDataOutSize < dwDataInSize) {
		return 0;
	}
	memcpy(lpDataOut, lpDataIn, dwDataInSize);
	return dwDataInSize;
}

DWORD cryptographic_manager_rc4_initialize(LPVOID* lpCryptoContext, LPVOID lpParams) {
	HANDLE hHeap = GetProcessHeap();
	if (hHeap == NULL) {
		dprintf("[cryptographic_manager_rc4_initialize] GetProcessHeap failed.");
		return ERROR_NOT_ENOUGH_MEMORY;
	}

	*lpCryptoContext = (LPVOID) HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(RC4_CTX));
	if (*lpCryptoContext == NULL) {
		dprintf("[cryptographic_manager_rc4_initialize] HeapAlloc failed.");
		return ERROR_NOT_ENOUGH_MEMORY;
	}

	RC4_CTX* ctx = (RC4_CTX*)(*lpCryptoContext);
	InitRc4(ctx, (unsigned char *)lpParams, KEY_SIZE_RC4);
	return 0;
}

DWORD cryptographic_manager_rc4_refresh(LPVOID lpCryptoContext, LPVOID lpParams) {
	RC4_CTX* ctx = (RC4_CTX*)lpCryptoContext;
	if (ctx == NULL) {
		dprintf("[cryptographic_manager_rc4_refresh] lpCryptoContext is NULL.");
		return ERROR_INVALID_PARAMETER;
	}
	InitRc4(ctx, (unsigned char *)lpParams, KEY_SIZE_RC4);
	dprintf("[cryptographic_manager_rc4] Refreshed RC4 Cryptographic Manager.");
	return 0;
}

DWORD cryptographic_manager_rc4_encrypt(LPVOID lpDataIn, DWORD dwDataInSize, LPVOID lpDataOut, DWORD dwDataOutSize) {
	RC4_CTX* ctx = (RC4_CTX*)g_ExtensionEncryptionManager->cryptoManager.lpCryptoContext;
	if (ctx == NULL) {
		dprintf("[cryptographic_manager_rc4_encrypt] lpCryptoContext is NULL.");
		return 0;
	}
	if (dwDataOutSize < dwDataInSize) {
		dprintf("[cryptographic_manager_rc4_encrypt] dwDataOutSize is smaller than dwDataInSize.");
		return 0;
	}
	memcpy(lpDataOut, lpDataIn, dwDataInSize);
	if (!RC4Cipher(ctx, (unsigned char*)lpDataOut, dwDataInSize)) {
		dprintf("[cryptographic_manager_rc4_encrypt] RC4Cipher failed.");
		return 0;
	}
	return dwDataInSize;
}

DWORD cryptographic_manager_rc4_decrypt(LPVOID lpDataIn, DWORD dwDataInSize, LPVOID lpDataOut, DWORD dwDataOutSize) {
	RC4_CTX* ctx = (RC4_CTX*)g_ExtensionEncryptionManager->cryptoManager.lpCryptoContext;
	if (ctx == NULL) {
		dprintf("[cryptographic_manager_rc4_decrypt] lpCryptoContext is NULL.");
		return 0;
	}
	if (dwDataOutSize < dwDataInSize) {
		dprintf("[cryptographic_manager_rc4_decrypt] dwDataOutSize is smaller than dwDataInSize.");
		return 0;
	}
	memcpy(lpDataOut, lpDataIn, dwDataInSize);
	if (!RC4Cipher(ctx, (unsigned char*)lpDataOut, dwDataInSize)) {
		dprintf("[cryptographic_manager_rc4_decrypt] RC4Cipher failed.");
		return 0;
	}
	return dwDataInSize;
}

BOOL cryptographic_manager_rc4(CryptographicManager* manager, LPVOID lpParams) {
	LPCSTR key = (LPCSTR)lpParams;
	if (manager == NULL) {
		dprintf("[cryptographic_manager_rc4] Invalid parameters.");
		return FALSE;
	}
	dprintf("[cryptographic_manager_rc4] Initializing RC4 Cryptographic Manager.");
	manager->bInitialized = TRUE;
	manager->bNeedsRefresh = TRUE;
	manager->initialize = cryptographic_manager_rc4_initialize;
	manager->encrypt = cryptographic_manager_rc4_encrypt;
	manager->decrypt = cryptographic_manager_rc4_decrypt;
	manager->refresh = cryptographic_manager_rc4_refresh;
	if(lpParams != NULL) {
		manager->lpCryptoParams = (LPCSTR)lpParams;
	} else {
		manager->lpCryptoParams = (LPCSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, KEY_SIZE_RC4);
		if (manager->lpCryptoParams == NULL) {
			dprintf("[cryptographic_manager_rc4] HeapAlloc failed.");
			return FALSE;
		}
		srand((unsigned int)GetTickCount());
		for(int i = 0; i < KEY_SIZE_RC4; i++) {
			((char*)manager->lpCryptoParams)[i] = (char)(rand() % 256);
		}
	}
	if (manager->initialize(&manager->lpCryptoContext, (LPVOID)manager->lpCryptoParams) != 0) {
		dprintf("[cryptographic_manager_rc4] Initialization failed.");
		return FALSE;
	}
	return TRUE;
}

BOOL cryptographic_manager_debug(CryptographicManager* manager, LPVOID lpParams) {
	if (manager == NULL) {
		dprintf("[cryptographic_manager_debug] manager is NULL.");
		return FALSE;
	}
	manager->bInitialized = TRUE;
	manager->bNeedsRefresh = FALSE;
	manager->initialize = cyptographic_manager_debug_initialize;
	manager->encrypt = cryptographic_manager_debug_encrypt;
	manager->decrypt = cryptographic_manager_debug_decrypt;
	manager->lpCryptoParams = NULL;
	manager->refresh = NULL;
	manager->lpCryptoContext = NULL;
	return TRUE;
}

ExtensionEncryptionManager* GetExtensionEncryptionManager(VOID) {
	return g_ExtensionEncryptionManager;
}

ExtensionEncryptionManager* InitExtensionEncryptionManager(CryptographicManagerType type, LPVOID lpCryptoParams) {
	if (g_ExtensionEncryptionManager != NULL) {
		return g_ExtensionEncryptionManager;
	}
	HANDLE hHeap = GetProcessHeap();
	if (hHeap == NULL) {
		dprintf("[extension_encryption][extension_encryption_init_manager] GetProcessHeap failed.");
		return NULL;
	}
	g_ExtensionEncryptionManager = (ExtensionEncryptionManager*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(ExtensionEncryptionManager));
	if (g_ExtensionEncryptionManager == NULL) {
		dprintf("[extension_encryption][extension_encryption_init_manager] HeapAlloc failed.");
		return NULL;
	}
	InitializeCriticalSection(&g_ExtensionEncryptionManager->cs);
	g_ExtensionEncryptionManager->add = extension_encryption_add;
	g_ExtensionEncryptionManager->remove = extension_encryption_remove;
	g_ExtensionEncryptionManager->encrypt = extension_encryption_encrypt;
	g_ExtensionEncryptionManager->decrypt = extension_encryption_decrypt;
	g_ExtensionEncryptionManager->encryptUnused = extension_encryption_encrypt_unused;

	if(type == CRYPTOGRAPHIC_MANAGER_TYPE_RC4 ) {
		if (!cryptographic_manager_rc4(&g_ExtensionEncryptionManager->cryptoManager, lpCryptoParams)) {
			dprintf("[extension_encryption][extension_encryption_init_manager] cryptographic_manager_rc4 failed.");
			HeapFree(hHeap, 0, g_ExtensionEncryptionManager);
			g_ExtensionEncryptionManager = NULL;
			return NULL;
		}
		return g_ExtensionEncryptionManager;
	}else{
		if (!cryptographic_manager_debug(&g_ExtensionEncryptionManager->cryptoManager, lpCryptoParams)) {
			dprintf("[extension_encryption][extension_encryption_init_manager] cryptographic_manager_debug failed.");
			HeapFree(hHeap, 0, g_ExtensionEncryptionManager);
			g_ExtensionEncryptionManager = NULL;
			return NULL;
		}
	}
	return g_ExtensionEncryptionManager;
}

BOOL extension_encryption_add(LPVOID lpExtensionLocation, DWORD dwExtensionSize) {
	BOOL ret = FALSE;
	EnterCriticalSection(&g_ExtensionEncryptionManager->cs);
	if (g_ExtensionEncryptionManager->dwExtensionsCount >= MAX_EXTENSIONS) {
		dprintf("[extension_encryption][extension_encryption_add] Maximum number of extensions reached.");
		return ret;
	}

	if (lpExtensionLocation == NULL || dwExtensionSize == 0) {
		dprintf("[extension_encryption][extension_encryption_add] Invalid parameters.");
		return ret;
	}
	ExtensionEncryptionStatus* lpExtensionStatus = (ExtensionEncryptionStatus*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ExtensionEncryptionStatus));
	if (lpExtensionStatus == NULL) {
		dprintf("[extension_encryption][extension_encryption_add] HeapAlloc failed.");
		return ret;
	}
	lpExtensionStatus->bEncryptable = TRUE;
	lpExtensionStatus->bEncrypted = FALSE;
	lpExtensionStatus->lpLoc = lpExtensionLocation;
	lpExtensionStatus->dwSize = dwExtensionSize;
	lpExtensionStatus->dwLastUsedTime = GetTickCount();
	dprintf("[extension_encryption][extension_encryption_add] lpExtensionStatus->bEncryptable: %d", lpExtensionStatus->bEncryptable);
	dprintf("[extension_encryption][extension_encryption_add] lpExtensionStatus->bEncrypted: %d", lpExtensionStatus->bEncrypted);
	dprintf("[extension_encryption][extension_encryption_add] lpExtensionStatus->lpLoc: %p", lpExtensionStatus->lpLoc);
	dprintf("[extension_encryption][extension_encryption_add] lpExtensionStatus->dwSize: %u", lpExtensionStatus->dwSize);
	dprintf("[extension_encryption][extension_encryption_add] lpExtensionStatus->dwLastUsedTime: %u", lpExtensionStatus->dwLastUsedTime);
	g_ExtensionEncryptionManager->extensionStatuses[g_ExtensionEncryptionManager->dwExtensionsCount - 1] = lpExtensionStatus;
	g_ExtensionEncryptionManager->dwExtensionsCount++;
	dprintf("[extension_encryption][extension_encryption_add] Added extension at %p of size %u", lpExtensionLocation, dwExtensionSize);
	ret = TRUE;
	LeaveCriticalSection(&g_ExtensionEncryptionManager->cs);
	return ret;
}

BOOL extension_encryption_get(LPVOID lpHandlerFunction, ExtensionEncryptionStatus** lpOutExtensionStatus) {
	BOOL ret = FALSE;
	EnterCriticalSection(&g_ExtensionEncryptionManager->cs);
	if (lpHandlerFunction == NULL || lpOutExtensionStatus == NULL) {
		dprintf("[extension_encryption][extension_encryption_get] Invalid parameters.");
		return ret;
	}
	for (int i = 0; i < g_ExtensionEncryptionManager->dwExtensionsCount; i++) {
		if (g_ExtensionEncryptionManager->extensionStatuses[i] != NULL 
			&& g_ExtensionEncryptionManager->extensionStatuses[i]->lpLoc <= lpHandlerFunction
			&& (unsigned char*)lpHandlerFunction <(unsigned char*)g_ExtensionEncryptionManager->extensionStatuses[i]->lpLoc + g_ExtensionEncryptionManager->extensionStatuses[i]->dwSize) 
			{
				*lpOutExtensionStatus = g_ExtensionEncryptionManager->extensionStatuses[i];
				ret = TRUE;
				break;
			}
	}
	LeaveCriticalSection(&g_ExtensionEncryptionManager->cs);
	return ret;
}

BOOL extension_encryption_remove(ExtensionEncryptionStatus* lpExtensionStatus) {
	BOOL ret = FALSE;
	EnterCriticalSection(&g_ExtensionEncryptionManager->cs);
	if (lpExtensionStatus == NULL) {
		dprintf("[extension_encryption][extension_encryption_remove] lpExtensionStatus is NULL.");
		return ret;
	}
	for (int i = 0; i < g_ExtensionEncryptionManager->dwExtensionsCount; i++) {
		if (g_ExtensionEncryptionManager->extensionStatuses[i] == lpExtensionStatus) {
			g_ExtensionEncryptionManager->extensionStatuses[i] = g_ExtensionEncryptionManager->extensionStatuses[g_ExtensionEncryptionManager->dwExtensionsCount - 1];
			g_ExtensionEncryptionManager->extensionStatuses[g_ExtensionEncryptionManager->dwExtensionsCount - 1] = NULL;
			g_ExtensionEncryptionManager->dwExtensionsCount--;
			HeapFree(GetProcessHeap(), 0, lpExtensionStatus);
			ret = TRUE;
			break;
		}
	}
	if (!ret) {
		dprintf("[extension_encryption][extension_encryption_remove] Couldn't locate lpExtensionStatus in extension_statuses array.");
	}
	LeaveCriticalSection(&g_ExtensionEncryptionManager->cs);
	return ret;
}

BOOL extension_encryption_encrypt(ExtensionEncryptionStatus* lpExtensionStatus) {
	EnterCriticalSection(&g_ExtensionEncryptionManager->cs);

	BOOL ret = FALSE;
	unsigned char *lpTempBufferRead = NULL;
	unsigned char *lpTempBufferWrite = NULL;
	HANDLE hHeap = GetProcessHeap();
	DWORD diff = BUFFER_SIZE;
	size_t ByteCounter = 0;

	if(!lpExtensionStatus->bEncryptable) {
		dprintf("[extension_encryption][extension_encryption_encrypt] Extension is not encryptable.");
		return ret;
	}

	if(lpExtensionStatus->bEncrypted) {
		dprintf("[extension_encryption][extension_encryption_encrypt] Extension is already encrypted.");
		ret = TRUE;
		return ret;
	}
	lpTempBufferRead = (unsigned char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, BUFFER_SIZE);
	lpTempBufferWrite = (unsigned char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, BUFFER_SIZE);

	if (lpTempBufferRead == NULL) {
		dprintf("[extension_encryption][extension_encryption_encrypt] HeapAlloc failed on lpTempBufferRead.");
		return ret;
	}
	
	if (lpTempBufferWrite == NULL) {
		dprintf("[extension_encryption][extension_encryption_encrypt] HeapAlloc failed on lpTempBufferWrite.");
		HeapFree(hHeap, 0, lpTempBufferRead);
		return ret;
	}

	LPVOID ExtensionLoc = lpExtensionStatus->lpLoc;
	DWORD ExtensionSize = lpExtensionStatus->dwSize;

	for(DWORD i = 0; i != ExtensionSize; i += diff) {
		if ((ExtensionSize - i) < BUFFER_SIZE) {
			diff = ExtensionSize - i;
		}
		ret = ReadProcessMemory(GetCurrentProcess(), (unsigned char*)ExtensionLoc + i, lpTempBufferRead, diff, &ByteCounter);
		if (!ret || ByteCounter != diff) {
			dprintf("[extension_encryption][extension_encryption_encrypt] ReadProcessMemory failed with error 0x%x", GetLastError());
			break;
		}
		if (!g_ExtensionEncryptionManager->cryptoManager.encrypt(lpTempBufferRead, diff, lpTempBufferWrite, BUFFER_SIZE)) {
			dprintf("[extension_encryption][extension_encryption_encrypt] CryptographicManager encrypt failed.");
			ret = FALSE;
			break;
		}
		ret = WriteProcessMemory(GetCurrentProcess(), (unsigned char*)ExtensionLoc + i, lpTempBufferWrite, diff, &ByteCounter);
		if (!ret || ByteCounter != diff) {
			dprintf("[extension_encryption][extension_encryption_encrypt] WriteProcessMemory failed with error 0x%x", GetLastError());
			break;
		}
	}

	lpExtensionStatus->dwLastUsedTime = GetTickCount();
	lpExtensionStatus->bEncrypted = TRUE;
	LeaveCriticalSection(&g_ExtensionEncryptionManager->cs);
	return ret;
}

BOOL extension_encryption_decrypt(ExtensionEncryptionStatus* lpExtensionStatus) {
	EnterCriticalSection(&g_ExtensionEncryptionManager->cs);

	BOOL ret = FALSE;
	unsigned char *lpTempBufferRead = NULL;
	unsigned char *lpTempBufferWrite = NULL;
	HANDLE hHeap = GetProcessHeap();
	DWORD diff = BUFFER_SIZE;
	size_t ByteCounter = 0;

	if(!lpExtensionStatus->bEncryptable) {
		dprintf("[extension_encryption][extension_encryption_decrypt] Extension is not encryptable.");
		return ret;
	}

	if(!lpExtensionStatus->bEncrypted) {
		dprintf("[extension_encryption][extension_encryption_decrypt] Extension is already decrypted.");
		ret = TRUE;
		return ret;
	}
	lpTempBufferRead = (unsigned char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, BUFFER_SIZE);
	lpTempBufferWrite = (unsigned char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, BUFFER_SIZE);

	if (lpTempBufferRead == NULL) {
		dprintf("[extension_encryption][extension_encryption_decrypt] HeapAlloc failed on lpTempBufferRead.");
		return ret;
	}
	
	if (lpTempBufferWrite == NULL) {
		dprintf("[extension_encryption][extension_encryption_decrypt] HeapAlloc failed on lpTempBufferWrite.");
		HeapFree(hHeap, 0, lpTempBufferRead);
		return ret;
	}

	LPVOID ExtensionLoc = lpExtensionStatus->lpLoc;
	DWORD ExtensionSize = lpExtensionStatus->dwSize;

	if( g_ExtensionEncryptionManager->cryptoManager.bNeedsRefresh ) {
		if (g_ExtensionEncryptionManager->cryptoManager.refresh != NULL) {
			if (g_ExtensionEncryptionManager->cryptoManager.refresh(g_ExtensionEncryptionManager->cryptoManager.lpCryptoContext, (LPVOID) g_ExtensionEncryptionManager->cryptoManager.lpCryptoParams) != 0) {
				dprintf("[extension_encryption][extension_encryption_decrypt] CryptographicManager refresh failed.");
				LeaveCriticalSection(&g_ExtensionEncryptionManager->cs);
				return FALSE;
			}
		}
	}

	for(DWORD i = 0; i != ExtensionSize; i += diff) {
		if ((ExtensionSize - i) < BUFFER_SIZE) {
			diff = ExtensionSize - i;
		}
		ret = ReadProcessMemory(GetCurrentProcess(), (unsigned char*)ExtensionLoc + i, lpTempBufferRead, diff, &ByteCounter);
		if (!ret || ByteCounter != diff) {
			dprintf("[extension_encryption][extension_encryption_decrypt] ReadProcessMemory failed with error 0x%x", GetLastError());
			break;
		}
		if (!g_ExtensionEncryptionManager->cryptoManager.decrypt(lpTempBufferRead, diff, lpTempBufferWrite, BUFFER_SIZE)) {
			dprintf("[extension_encryption][extension_encryption_decrypt] CryptographicManager decrypt failed.");
			ret = FALSE;
			break;
		}
		ret = WriteProcessMemory(GetCurrentProcess(), (unsigned char*)ExtensionLoc + i, lpTempBufferWrite, diff, &ByteCounter);
		if (!ret || ByteCounter != diff) {
			dprintf("[extension_encryption][extension_encryption_decrypt] WriteProcessMemory failed with error 0x%x", GetLastError());
			break;
		}
	}

	lpExtensionStatus->dwLastUsedTime = GetTickCount();
	lpExtensionStatus->bEncrypted = FALSE;
	LeaveCriticalSection(&g_ExtensionEncryptionManager->cs);
	return ret;
}

void extension_encryption_encrypt_unused() {

	EnterCriticalSection(&g_ExtensionEncryptionManager->cs);
	ExtensionEncryptionStatus** extension_statuses = g_ExtensionEncryptionManager->extensionStatuses;
	DWORD current_time = GetTickCount();
	for (DWORD i = 0; i < g_ExtensionEncryptionManager->dwExtensionsCount; i++) {
		ExtensionEncryptionStatus* status = extension_statuses[i];
		if (status != NULL && status->bEncryptable && !status->bEncrypted) {
			if (current_time - status->dwLastUsedTime > ENCRYPTION_UNUSED_COOLDOWN_MS) {
				g_ExtensionEncryptionManager->encrypt(status);
			}
		}
	}
	LeaveCriticalSection(&g_ExtensionEncryptionManager->cs);
}