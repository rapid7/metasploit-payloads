#include "kull_m_crypto_system.h"

static HMODULE hCryptDll = NULL;
static HMODULE hAdvApi32 = NULL;

typedef BOOL(WINAPI *PRtlGenRandom)(OUT LPBYTE output, IN DWORD length);
static PRtlGenRandom pRtlGenRandom = NULL;

BOOL WINAPI kullRtlGenRandom(OUT LPBYTE output, IN DWORD length)
{
	if (!pRtlGenRandom)
	{
		hAdvApi32 = hAdvApi32 == NULL ? LoadLibraryA("AdvAPI32.dll") : hAdvApi32;

		if (hAdvApi32 == NULL)
		{
			return FALSE;
		}

		pRtlGenRandom = (PRtlGenRandom)GetProcAddress(hAdvApi32, "SystemFunction036");

		if (pRtlGenRandom == NULL)
		{
			return FALSE;
		}
	}
	PRINT_ERROR(L"Address of RtlGenRandom: %p", pRtlGenRandom);
	return pRtlGenRandom(output, length);
}

typedef NTSTATUS (WINAPI *PCDLocateCheckSum)(LONG type, PKERB_CHECKSUM * pCheckSum);
static PCDLocateCheckSum pCDLocateCheckSum = NULL;

NTSTATUS WINAPI kullCDLocateCheckSum(LONG type, PKERB_CHECKSUM * pCheckSum)
{
	if (!pCDLocateCheckSum)
	{
		hCryptDll = hCryptDll == NULL ? LoadLibraryA("cryptdll.dll") : hCryptDll;

		if (hCryptDll == NULL)
		{
			return STATUS_UNSUCCESSFUL;
		}

		pCDLocateCheckSum = (PCDLocateCheckSum)GetProcAddress(hCryptDll, "CDLocateCheckSum");

		if (pCDLocateCheckSum == NULL)
		{
			return STATUS_UNSUCCESSFUL;
		}
	}

	return pCDLocateCheckSum(type, pCheckSum);
}


typedef NTSTATUS(WINAPI *PCDLocateCSystem)(LONG type, PKERB_ECRYPT * pCSystem);
static PCDLocateCSystem pCDLocateCSystem = NULL;

NTSTATUS WINAPI kullCDLocateCSystem(LONG type, PKERB_ECRYPT * pCSystem)
{
	if (!pCDLocateCSystem)
	{
		hCryptDll = hCryptDll == NULL ? LoadLibraryA("cryptdll.dll") : hCryptDll;

		if (hCryptDll == NULL)
		{
			return STATUS_UNSUCCESSFUL;
		}

		pCDLocateCSystem = (PCDLocateCSystem)GetProcAddress(hCryptDll, "CDLocateCSystem");

		if (pCDLocateCSystem == NULL)
		{
			return STATUS_UNSUCCESSFUL;
		}
	}
	return pCDLocateCSystem(type, pCSystem);
}