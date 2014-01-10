/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kuhl_m_net.h"

const KUHL_M_C kuhl_m_c_net[] = {
	{kuhl_m_net_user,		L"user",		L""},
	{kuhl_m_net_localgroup,	L"localgroup",	L""},
	{kuhl_m_net_group,		L"group",		L""},
};
const KUHL_M kuhl_m_net = {
	L"net",	L"", NULL,
	sizeof(kuhl_m_c_net) / sizeof(KUHL_M_C), kuhl_m_c_net, NULL, NULL
};

/*#include "../modules/kull_m_net.h"
#include "../modules/kull_m_token.h"
NTSTATUS kuhl_m_standard_test(int argc, wchar_t * argv[])
{
PDOMAIN_CONTROLLER_INFO pDCInfos;
	USER_INFO_1 userInfo = {L"", L"", 0, USER_PRIV_USER, NULL, NULL, UF_SCRIPT | UF_DONT_EXPIRE_PASSWD | UF_NORMAL_ACCOUNT, NULL,};
	PPOLICY_DNS_DOMAIN_INFO pDomainInfo;
	PSID pSid;
	PWSTR name, domain;
	DWORD parm_err;
	
	if(kull_m_net_getCurrentDomainInfo(&pDomainInfo))
	{
		kprintf(L"Domain   : %wZ/%wZ\n", &pDomainInfo->DnsDomainName, &pDomainInfo->Name);
		if(kull_m_net_CreateWellKnownSid(WinAccountDomainAdminsSid, pDomainInfo->Sid, &pSid))
		{
			if(kull_m_token_getNameDomainFromSID(pSid, &name, &domain, NULL))
			{
				LocalFree(domain);
				kprintf(L"DA group : %s\n", name);

				if(DsGetDcName(NULL, NULL, NULL, NULL, DS_DIRECTORY_SERVICE_PREFERRED | DS_WRITABLE_REQUIRED, &pDCInfos) == ERROR_SUCCESS)
				{
					domain = pDCInfos->DomainControllerName + 2;
					kprintf(L"DC       : %s\n", domain);
					if(NetUserAdd(domain, 1, (LPBYTE) &userInfo, &parm_err) == NERR_Success)
					{
						W00T(L"User !\n");
						if(NetGroupAddUser(domain, name, userInfo.usri1_name) == NERR_Success)
							W00T(L"Group !\n");
					}
					NetApiBufferFree(pDCInfos);
				}
				LocalFree(name);
				
			} else PRINT_ERROR_AUTO(L"kull_m_token_getNameDomainFromSID");
			LocalFree(pSid);
		}
		else PRINT_ERROR_AUTO(L"kull_m_local_domain_user_CreateWellKnownSid");

		LsaFreeMemory(pDomainInfo);
	}
	return STATUS_SUCCESS;
}*/

NTSTATUS kuhl_m_net_user(int argc, wchar_t * argv[])
{
	PCWCHAR szServer, szName;
	PBYTE pBuff;
	DWORD res;
	kull_m_string_args_byName(argc, argv, L"server", &szServer, NULL);
	kull_m_string_args_byName(argc, argv, L"name", &szName, NULL);
	
	if(kull_m_string_args_byName(argc, argv, L"view", NULL, NULL))
	{
		res = NetUserGetInfo(szServer, szName, 2, &pBuff);
		if(res == NERR_Success)
		{
			kprintf(L"\nname       \t");
			if(((PUSER_INFO_2) pBuff)->usri2_full_name)
				kprintf(L"%s", ((PUSER_INFO_2) pBuff)->usri2_full_name);

			kprintf(L"\ncomment    \t");
			if(((PUSER_INFO_2) pBuff)->usri2_comment)
				kprintf(L"%s", ((PUSER_INFO_2) pBuff)->usri2_comment);

			kprintf(L"\nusr_comment\t");
			if(((PUSER_INFO_2) pBuff)->usri2_usr_comment)
				kprintf(L"%s", ((PUSER_INFO_2) pBuff)->usri2_usr_comment);

			kprintf(L"\nfull_name  \t");
			if(((PUSER_INFO_2) pBuff)->usri2_full_name)
				kprintf(L"%s", ((PUSER_INFO_2) pBuff)->usri2_full_name);

			kprintf(L"\npriv       \t");
			res = ((PUSER_INFO_2) pBuff)->usri2_priv;
			switch(res)
			{
			case USER_PRIV_GUEST:
				kprintf(L"GUEST");
				break;
			case USER_PRIV_USER:
				kprintf(L"GUEST");
				break;
			case USER_PRIV_ADMIN:
				kprintf(L"ADMIN");
				break;
			default:
				kprintf(L"? (%u)", res);
			}
			
			kprintf(L"\nauth_flags \t");
			res = ((PUSER_INFO_2) pBuff)->usri2_auth_flags;
			if(res & AF_OP_PRINT)
				kprintf(L"PRINT ");
			if(res & AF_OP_COMM)
				kprintf(L"COMM ");
			if(res & AF_OP_SERVER)
				kprintf(L"SERVER ");
			if(res & AF_OP_ACCOUNTS)
				kprintf(L"ACCOUNTS ");
			kprintf(L"(%08x)", res);

			NetApiBufferFree(pBuff);
		}
	}
	else kuhl_m_net_generic_enum(0, szServer);








	return ERROR_SUCCESS;

	/*
		VIEW
		CREATE
		DELETE
		CHANGE PASS
		UNLOCK
		ENABLE
		DISABLE
		ALL TIME
		EXPIRE NEVER
		DELEGATE
		WORKSTATION *
	*/
}

NTSTATUS kuhl_m_net_group(int argc, wchar_t * argv[])
{
	kuhl_m_net_generic_enum(1, NULL);
	return ERROR_SUCCESS;
}

NTSTATUS kuhl_m_net_localgroup(int argc, wchar_t * argv[])
{
	kuhl_m_net_generic_enum(2, NULL);
	return ERROR_SUCCESS;
}

void kuhl_m_net_generic_enum(DWORD type, LPCWSTR server)
{
	PBYTE pBuff;
	DWORD i, res, eRead, eTotal;
	DWORD resumeIndex = 0;
	DWORD_PTR resumeHandle = 0;
	do
	{
		switch(type)
		{
		case 0:
			res = NetUserEnum(server, 0, 0, &pBuff, MAX_PREFERRED_LENGTH, &eRead, &eTotal, &resumeIndex);
			break;

		case 1:
			res = NetGroupEnum(server, 0, &pBuff, MAX_PREFERRED_LENGTH, &eRead, &eTotal, &resumeHandle);
			break;

		case 2:
			res = NetLocalGroupEnum(server, 0, &pBuff, MAX_PREFERRED_LENGTH, &eRead, &eTotal, &resumeHandle);
			break;
		}
		
		if((res == NERR_Success) || (res == ERROR_MORE_DATA))
		{
			for(i = 0; i < eRead; i++)
				kprintf(L" * %s\n", ((PCWSTR *) pBuff)[i]);
			NetApiBufferFree(pBuff);
		}
		else
		{
			switch(res)
			{
			case ERROR_ACCESS_DENIED :
				PRINT_ERROR(L"ERROR_ACCESS_DENIED\n");
				break;
			case ERROR_INVALID_LEVEL:
				PRINT_ERROR(L"ERROR_INVALID_LEVEL\n");
				break;
			case NERR_BufTooSmall:
				PRINT_ERROR(L"NERR_BufTooSmall\n");
				break;
			case NERR_InvalidComputer:
				PRINT_ERROR(L"NERR_InvalidComputer\n");
				break;
			default:
				PRINT_ERROR(L"NetxxxEnum (%u) : %u\n", type, res);
			}
		}
	} while (res == ERROR_MORE_DATA);
}