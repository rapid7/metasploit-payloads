#define _CRT_SECURE_NO_DEPRECATE 1
#include "../../common/common.h"
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <aclapi.h>
#include <accctrl.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <lm.h>
#include <wchar.h>
#include "incognito.h"

BOOL get_domain_from_token(HANDLE token, wchar_t *domainBuffer, DWORD domainBufferSize)
{
	LPVOID TokenUserInfo[BUF_SIZE];
	wchar_t username[BUF_SIZE] = L"", domainname[BUF_SIZE] = L"";
	DWORD user_length = BUF_SIZE;
	DWORD domain_length = BUF_SIZE;
	DWORD sid_type = 0, returned_tokinfo_length;

	if (!GetTokenInformation(token, TokenUser, TokenUserInfo, BUF_SIZE,
			&returned_tokinfo_length))
	{
		return FALSE;
	}

	LookupAccountSidW(NULL, ((TOKEN_USER*)TokenUserInfo)->User.Sid, username,
		&user_length, domainname, &domain_length, (PSID_NAME_USE)&sid_type);

	wcscpy_s(domainBuffer, domainBufferSize, domainname);

	return TRUE;
}

BOOL get_domain_username_from_token(HANDLE token, wchar_t *full_name_to_return)
{
	LPVOID TokenUserInfo[BUF_SIZE];
	wchar_t username[BUF_SIZE] = L"", domainname[BUF_SIZE] = L"";
	DWORD user_length = BUF_SIZE;
	DWORD domain_length = BUF_SIZE;
	DWORD sid_type = 0;
	DWORD returned_tokinfo_length;

	if (!GetTokenInformation(token, TokenUser, TokenUserInfo, BUF_SIZE,
			&returned_tokinfo_length))
	{
		return FALSE;
	}

	LookupAccountSidW(NULL, ((TOKEN_USER*)TokenUserInfo)->User.Sid, username,
		&user_length, domainname, &domain_length, (PSID_NAME_USE)&sid_type);

 	// Make full name in DOMAIN\USERNAME format
	_snwprintf(full_name_to_return, BUF_SIZE, L"%s\\%s", domainname, username);

	return TRUE;
}

BOOL get_domain_groups_from_token(HANDLE token,
	wchar_t **group_name_array[], DWORD *num_groups)
{
	LPVOID TokenGroupsInfo[BUF_SIZE];
	wchar_t groupname[BUF_SIZE] = L"", domainname[BUF_SIZE] = L"";
	DWORD i, group_length = BUF_SIZE;
	DWORD domain_length = BUF_SIZE;
	DWORD sid_type = 0;
	DWORD returned_tokinfo_length;

	if (!GetTokenInformation(token, TokenGroups, TokenGroupsInfo, BUF_SIZE,
			&returned_tokinfo_length))
	{
		return FALSE;
	}

	*group_name_array = calloc(((TOKEN_GROUPS*)TokenGroupsInfo)->GroupCount,
		sizeof(wchar_t *));
	*num_groups = ((TOKEN_GROUPS*)TokenGroupsInfo)->GroupCount;

	for (i=0;i<*num_groups;i++)
	{
		if ((((TOKEN_GROUPS*)TokenGroupsInfo)->Groups[i].Attributes &
				SE_GROUP_ENABLED) != 0)
		{
			group_length = BUF_SIZE;
			domain_length = BUF_SIZE; // fix bug with insufficient buffer size due to reusing last length value
			LookupAccountSidW(NULL, ((TOKEN_GROUPS*)TokenGroupsInfo)->Groups[i].Sid, groupname, &group_length, domainname, &domain_length, (PSID_NAME_USE)&sid_type);
			(*group_name_array)[i] = calloc(BUF_SIZE, sizeof(wchar_t));
			// Make full name in DOMAIN\GROUPNAME format
			_snwprintf((*group_name_array)[i], BUF_SIZE, L"%s\\%s", domainname, groupname);
		}
		else
		{
			(*group_name_array)[i] = calloc(BUF_SIZE, sizeof(wchar_t));
			_snwprintf((*group_name_array)[i], BUF_SIZE, L"%s\\%s", domainname, groupname);
		}
	}

	return TRUE;
}

BOOL is_delegation_token(HANDLE token)
{
	HANDLE temp_token;
	BOOL ret;
	LPVOID TokenImpersonationInfo[BUF_SIZE];
	DWORD returned_tokinfo_length;

	if (GetTokenInformation(token, TokenImpersonationLevel,
			TokenImpersonationInfo, BUF_SIZE, &returned_tokinfo_length))
	{
		return (*((SECURITY_IMPERSONATION_LEVEL*)TokenImpersonationInfo) ==
			SecurityDelegation);
	}

	ret = DuplicateTokenEx(token, TOKEN_ALL_ACCESS, NULL, SecurityDelegation,
		TokenImpersonation, &temp_token);
	CloseHandle(temp_token);
	return ret;
}

BOOL is_impersonation_token(HANDLE token)
{
	HANDLE temp_token;
	BOOL ret;
	LPVOID TokenImpersonationInfo[BUF_SIZE];
	DWORD returned_tokinfo_length;

	if (GetTokenInformation(token, TokenImpersonationLevel,
		TokenImpersonationInfo, BUF_SIZE, &returned_tokinfo_length))
	{
		return (*((SECURITY_IMPERSONATION_LEVEL*)TokenImpersonationInfo) >=
			SecurityImpersonation);
	}

	ret = DuplicateTokenEx(token, TOKEN_ALL_ACCESS, NULL,
		SecurityImpersonation, TokenImpersonation, &temp_token);
	CloseHandle(temp_token);
	return ret;
}

BOOL is_token(HANDLE token, wchar_t *requested_name)
{
	DWORD i, num_groups=0;
	wchar_t *full_name, **group_name_array = NULL;
	BOOL ret = FALSE;

	// If token is NULL then return
	if (!token)
		return FALSE;

	full_name = calloc(BUF_SIZE, sizeof(wchar_t));
	get_domain_username_from_token(token, full_name);
	if (!_wcsicmp(requested_name, full_name))
	{
		ret = TRUE;
	}

	get_domain_groups_from_token(token, &group_name_array, &num_groups);

	for (i=0;i<num_groups;i++)
	{
		if (!_wcsicmp(requested_name, group_name_array[i]))
		{
			ret = TRUE;
		}
		free(group_name_array[i]);
	}

	// Cleanup
	free(group_name_array);
	free(full_name);

	return ret;
}

BOOL is_local_system()
{
	HANDLE token;
	wchar_t full_name[BUF_SIZE];

	// If there is a thread token use that, otherwise use current process token
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, TRUE, &token))
	{
		OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &token);
	}

	get_domain_username_from_token(token, full_name);
	CloseHandle(token);

	return !_wcsicmp(L"NT AUTHORITY\\SYSTEM", full_name);
}

BOOL has_impersonate_priv(HANDLE hToken)
{
	LUID luid;
	LPVOID TokenPrivilegesInfo[BUF_SIZE];
	DWORD returned_privileges_length, returned_name_length, i;
	wchar_t privilege_name[BUF_SIZE];

	if (!LookupPrivilegeValue(NULL, SE_IMPERSONATE_NAME, &luid))
	{
		goto exit;
	}

	if (GetTokenInformation(hToken, TokenPrivileges, TokenPrivilegesInfo, BUF_SIZE, &returned_privileges_length))
	{
		for (i=0;i<((TOKEN_PRIVILEGES*)TokenPrivilegesInfo)->PrivilegeCount;i++)
		{
			returned_name_length = BUF_SIZE;
			LookupPrivilegeNameW(NULL, &(((TOKEN_PRIVILEGES*)TokenPrivilegesInfo)->Privileges[i].Luid), privilege_name, &returned_name_length);
			if (wcscmp(privilege_name, L"SeImpersonatePrivilege") == 0)
				return TRUE;
		}
	}

 exit:
	if (hToken)
	{
		CloseHandle(hToken);
	}

	return FALSE;
}

BOOL has_assignprimarytoken_priv(HANDLE hToken)
{
	LUID luid;
	LPVOID TokenPrivilegesInfo[BUF_SIZE];
	DWORD returned_privileges_length, returned_name_length, i;
	wchar_t privilege_name[BUF_SIZE];

	if (!LookupPrivilegeValue(NULL, SE_IMPERSONATE_NAME, &luid))
	{
		goto exit;
	}

	if (GetTokenInformation(hToken, TokenPrivileges, TokenPrivilegesInfo,
			BUF_SIZE, &returned_privileges_length))
	{
		for (i=0; i < ((TOKEN_PRIVILEGES*)TokenPrivilegesInfo)->PrivilegeCount; i++)
		{
			returned_name_length = BUF_SIZE;
			LookupPrivilegeNameW(NULL,
				&(((TOKEN_PRIVILEGES*)TokenPrivilegesInfo)->Privileges[i].Luid),
				privilege_name, &returned_name_length);
			if (wcscmp(privilege_name, L"SeAssignPrimaryTokenPrivilege") == 0) {
				return TRUE;
			}
		}
	}

 exit:
	if (hToken) {
		CloseHandle(hToken);
	}

	return FALSE;
}
