#pragma once

typedef struct _WIFI_CALLBACK_CTX
{
	LPVOID lpCtx;
	VOID (*pStartInterfaceHandler)(LPVOID lpCtx, GUID* pGuid, LPCWSTR lpDescription, LPCWSTR lpState);
	VOID (*pProfileHandler)(LPVOID lpCtx, LPCWSTR lpProfileName, LPCWSTR lpProfileXml);
	VOID (*pEndInterfaceHandler)(LPVOID lpCtx);
} WIFI_CALLBACK_CTX, *PWIFI_CALLBACK_CTX;
