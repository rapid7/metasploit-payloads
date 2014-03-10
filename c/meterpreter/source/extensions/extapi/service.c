/*!
 * @file service.c
 * @brief Definitions for service management functions
 */
#include "extapi.h"
#include "service.h"

#ifdef _WIN32
#include <Sddl.h>


HMODULE hAdvapi32 = NULL;

/*! @brief Typedef for the OpenSCManagerA function. */
typedef SC_HANDLE(WINAPI * POPENSCMANAGERA)(LPCSTR lpMachineName, LPCSTR lpDatabaseName, DWORD dwDesiredAccess);
static POPENSCMANAGERA pOpenSCManagerA = NULL;

/*! @brief Typedef for the CloseServiceHandle function. */
typedef BOOL(WINAPI * PCLOSESERVICEHANDLE)(SC_HANDLE hSCObject);
static PCLOSESERVICEHANDLE pCloseServiceHandle = NULL;

/*! @brief Typedef for the EnumServicesStatusExA function. */
typedef BOOL(WINAPI * PENUMSERVICESSTATUSEXA)(
	SC_HANDLE hSCManager,
	SC_ENUM_TYPE InfoLevel,
	DWORD dwServiceType,
	DWORD dwServiceState,
	LPBYTE lpServices,
	DWORD cbBufSize,
	LPDWORD pcbBytesNeeded,
	LPDWORD lpServicesReturned,
	LPDWORD lpResumeHandle,
	LPCSTR pszGroupName
	);
static PENUMSERVICESSTATUSEXA pEnumServicesStatusExA = NULL;

/*! @brief Typedef for the OpenServiceA function. */
typedef SC_HANDLE(WINAPI * POPENSERVICEA)(SC_HANDLE hSCManager, LPCSTR lpServiceName, DWORD dwDesiredAcces);
static POPENSERVICEA pOpenServiceA = NULL;

/*! @brief Typedef for the QueryServiceObjectSecurity function. */
typedef BOOL(WINAPI * PQUERYSERVICEOBJECTSECURITY)(
	SC_HANDLE hService,
	SECURITY_INFORMATION dwSecurityInformation,
	PSECURITY_DESCRIPTOR lpSecurityDescriptor,
	DWORD cbBufSize,
	LPDWORD pcbBytesNeeded
	);
static PQUERYSERVICEOBJECTSECURITY pQueryServiceObjectSecurity = NULL;

/*! @brief Typedef for the QueryServiceConfigA function. */
typedef BOOL(WINAPI * PQUERYSERVICECONFIGA)(
	SC_HANDLE hService,
	LPQUERY_SERVICE_CONFIGA lpServiceConfig,
	DWORD dbBufSize,
	LPDWORD pcbBytesNeeded
	);
static PQUERYSERVICECONFIGA pQueryServiceConfigA = NULL;

/*! @brief Typedef for the ConvertSecurityDescriptorToStringSecurityDescriptorA function. */
typedef BOOL(WINAPI * PCSDTSSDA)(
	PSECURITY_DESCRIPTOR SecurityDescriptor,
	DWORD RequestedStringSDRevision,
	SECURITY_INFORMATION SecurityInformation,
	LPCSTR *StringSecurityDescriptor,
	PULONG StringSecurityDescriptorLen
	);
static PCSDTSSDA pCSDTSSDA = NULL;

VOID add_enumerated_service(Packet *pResponse, LPCSTR cpName, LPCSTR cpDisplayName, DWORD dwProcessId, DWORD dwStatus, BOOL bInteractive);
DWORD query_service(LPCSTR cpServiceName, Packet *pResponse);
DWORD get_service_config(SC_HANDLE scService, Packet *pResponse);
DWORD get_service_dacl(SC_HANDLE scService, Packet *pResponse);
#endif

DWORD enumerate_services(Packet *response);

VOID initialise_service()
{
	do
	{
		dprintf("[EXTAPI SERVICE] Loading advapi32.dll");
		if ((hAdvapi32 = LoadLibraryA("advapi32.dll")) == NULL)
		{
			dprintf("[EXTAPI SERVICE] Unable to load advapi32.dll");
			break;
		}

		dprintf("[EXTAPI SERVICE] Searching for OpenSCManagerA");
		if ((pOpenSCManagerA = (POPENSCMANAGERA)GetProcAddress(hAdvapi32, "OpenSCManagerA")) == NULL)
		{
			dprintf("[EXTAPI SERVICE] Unable to locate OpenSCManagerA in advapi32.dll");
		}

		dprintf("[EXTAPI SERVICE] Searching for CloseServiceHandle");
		if ((pCloseServiceHandle = (PCLOSESERVICEHANDLE)GetProcAddress(hAdvapi32, "CloseServiceHandle")) == NULL)
		{
			dprintf("[EXTAPI SERVICE] Unable to locate CloseServiceHandle in advapi32.dll. Continuing anyway.");
		}

		dprintf("[EXTAPI SERVICE] Searching for EnumServicesStatusExA");
		if ((pEnumServicesStatusExA = (PENUMSERVICESSTATUSEXA)GetProcAddress(hAdvapi32, "EnumServicesStatusExA")) == NULL)
		{
			dprintf("[EXTAPI SERVICE] Unable to locate EnumServicesStatusExA in advapi32.dll.");
		}

		dprintf("[EXTAPI SERVICE] Searching for CloseServiceHandle");
		if ((pCloseServiceHandle = (PCLOSESERVICEHANDLE)GetProcAddress(hAdvapi32, "CloseServiceHandle")) == NULL)
		{
			dprintf("[EXTAPI SERVICE] Unable to locate CloseServiceHandle in advapi32.dll. Continuing anyway.");
		}

		dprintf("[EXTAPI SERVICE] Searching for OpenServiceA");
		if ((pOpenServiceA = (POPENSERVICEA)GetProcAddress(hAdvapi32, "OpenServiceA")) == NULL)
		{
			dprintf("[EXTAPI SERVICE] Unable to locate OpenServiceA in advapi32.dll.");
		}

		dprintf("[EXTAPI SERVICE] Searching for QueryServiceConfigA");
		if ((pQueryServiceConfigA = (PQUERYSERVICECONFIGA)GetProcAddress(hAdvapi32, "QueryServiceConfigA")) == NULL)
		{
			dprintf("[EXTAPI SERVICE] Unable to locate QueryServiceConfigA in advapi32.dll.");
		}

		dprintf("[EXTAPI SERVICE] Searching for QueryServiceObjectSecurity");
		if ((pQueryServiceObjectSecurity = (PQUERYSERVICEOBJECTSECURITY)GetProcAddress(hAdvapi32, "QueryServiceObjectSecurity")) == NULL)
		{
			dprintf("[EXTAPI SERVICE] Unable to locate QueryServiceObjectSecurity in advapi32.dll.");
		}

		dprintf("[EXTAPI SERVICE] Searching for ConvertSecurityDescriptorToStringSecurityDescriptorA");
		if ((pCSDTSSDA = (PCSDTSSDA)GetProcAddress(hAdvapi32, "ConvertSecurityDescriptorToStringSecurityDescriptorA")) == NULL)
		{
			dprintf("[EXTAPI SERVICE] Unable to locate ConvertSecurityDescriptorToStringSecurityDescriptorA in advapi32.dll.");
		}
	} while (0);
}

/*!
 * @brief Handle the request for service enumeration.
 * @param remote Pointer to the \c Remote making the request.
 * @param packet Pointer to the request \c Packet.
 * @returns Indication of sucess or failure.
 */
DWORD request_service_enum(Remote *remote, Packet *packet)
{
	DWORD dwResult = ERROR_SUCCESS;
	Packet * response = packet_create_response(packet);

	do
	{
		if (!response)
		{
			dprintf("[EXTAPI SERVICE] Unable to create response packet");
			dwResult = ERROR_OUTOFMEMORY;
			break;
		}

		dprintf("[EXTAPI SERVICE] Beginning service enumeration");
		dwResult = enumerate_services(response);

	} while (0);

	dprintf("[EXTAPI SERVICE] Transmitting response back to caller.");
	if (response)
	{
		packet_transmit_response(dwResult, remote, response);
	}

	return dwResult;
}

/*!
 * @brief Handle the request for a service query.
 * @param remote Pointer to the \c Remote making the request.
 * @param packet Pointer to the request \c Packet.
 * @remark The \c packet must contain the name of the service to query.
 * @returns Indication of sucess or failure.
 * @retval ERROR_SUCCESS Query succeeded.
 * @retval ERROR_OUTOFMEMORY Memory allocation failed.
 * @retval ERROR_BAD_ARGUMENTS Service name was missing from \c packet.
 */
DWORD request_service_query(Remote *remote, Packet *packet)
{
	LPSTR lpServiceName = NULL;
	DWORD dwResult = ERROR_SUCCESS;
	Packet * response = packet_create_response(packet);

	do
	{
		if (!response)
		{
			dprintf("[EXTAPI SERVICE] Unable to create response packet");
			dwResult = ERROR_OUTOFMEMORY;
			break;
		}

		lpServiceName = packet_get_tlv_value_string(packet, TLV_TYPE_EXT_SERVICE_ENUM_NAME);
		if (!lpServiceName)
		{
			BREAK_WITH_ERROR("[EXTAPI SERVICE] Missing service name parameter", ERROR_BAD_ARGUMENTS);
		}

		dprintf("[EXTAPI SERVICE] Beginning service enumeration");
		dwResult = query_service(lpServiceName, response);

	} while (0);

	dprintf("[EXTAPI SERVICE] Transmitting response back to caller.");
	if (response)
	{
		packet_transmit_response(dwResult, remote, response);
	}

	return dwResult;
}

/*!
 * @brief Perform the request for a service query.
 * @param cpServiceName Name of the serivce to perform the query on.
 * @param pRacket Pointer to the response \c Packet.
 * @returns Indication of sucess or failure.
 * @retval ERROR_SUCCESS Query succeeded.
 */
DWORD query_service(LPCSTR cpServiceName, Packet *pResponse)
{
#ifdef _WIN32
	// currently we only support Windoze
	DWORD dwResult = ERROR_SUCCESS;
	SC_HANDLE scManager = NULL;
	SC_HANDLE scService = NULL;

	do
	{
		if (hAdvapi32 == NULL
			|| pOpenSCManagerA == NULL
			|| pCloseServiceHandle == NULL
			|| pOpenServiceA == NULL)
		{
			BREAK_WITH_ERROR("[EXTAPI SERVICE] Unable to query services, required functions not found", ERROR_INVALID_PARAMETER);
		}

		dprintf("[EXTAPI SERVICE] Opening the Service Control manager");
		if ((scManager = pOpenSCManagerA(NULL, SERVICES_ACTIVE_DATABASEA, SC_MANAGER_CONNECT | GENERIC_READ)) == NULL)
		{
			BREAK_ON_ERROR("[EXTAPI SERVICE] Unable to open the service control manager");
		}

		dprintf("[EXTAPI SERVICE] Opening the Service: %s", cpServiceName);
		if ((scService = pOpenServiceA(scManager, cpServiceName, SC_MANAGER_CONNECT | GENERIC_READ)) == NULL)
		{
			dwResult = GetLastError();
			dprintf("[EXTAPI SERVICE] Unable to open the service: %s (%u)", cpServiceName, dwResult);
			break;
		}

		get_service_config(scService, pResponse);
		get_service_dacl(scService, pResponse);

	} while (0);

	if (scService && pCloseServiceHandle)
	{
		pCloseServiceHandle(scService);
	}

	if (scManager && pCloseServiceHandle)
	{
		pCloseServiceHandle(scManager);
	}

	if (hAdvapi32)
	{
		FreeLibrary(hAdvapi32);
	}

	return dwResult;
#else
	return ERROR_NOT_SUPPORTED;
#endif
}

/*!
 * @brief Perform the service enumeration.
 * @param pRacket Pointer to the response \c Packet.
 * @returns Indication of sucess or failure.
 * @retval ERROR_SUCCESS Query succeeded.
 */
DWORD enumerate_services(Packet *pResponse)
{
#ifdef _WIN32
	// currently we only support Windoze

	DWORD dwResult = ERROR_SUCCESS;
	SC_HANDLE scManager = NULL;
	ENUM_SERVICE_STATUS_PROCESSA* pSsInfo = NULL;
	DWORD dwBytesNeeded = 0;
	DWORD dwServicesReturned = 0;
	DWORD dwResumeHandle = 0;
	DWORD dwServiceIndex = 0;
	BOOL bResult;

	do
	{
		if (hAdvapi32 == NULL
			|| pOpenSCManagerA == NULL
			|| pCloseServiceHandle == NULL
			|| pEnumServicesStatusExA == NULL)
		{
			BREAK_WITH_ERROR("[EXTAPI SERVICE] Unable to enumerate services, required functions not found", ERROR_INVALID_PARAMETER);
		}

		// TODO: add support for other machine names so that this instance can query other machines on the network.
		dprintf("[EXTAPI SERVICE] Opening the Service Control manager");
		if ((scManager = pOpenSCManagerA(NULL, SERVICES_ACTIVE_DATABASEA, SC_MANAGER_CONNECT | GENERIC_READ)) == NULL)
		{
			BREAK_ON_ERROR("[EXTAPI SERVICE] Unable to open the service control manager");
		}

		bResult = pEnumServicesStatusExA(scManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0,
			&dwBytesNeeded, &dwServicesReturned, &dwResumeHandle, NULL);

		if (!bResult && dwBytesNeeded)
		{
			pSsInfo = (ENUM_SERVICE_STATUS_PROCESSA*)malloc(dwBytesNeeded);

			if (!pSsInfo)
			{
				BREAK_ON_ERROR("[EXTAPI SERVICE] Out of memory");
			}

			bResult = pEnumServicesStatusExA(scManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, (LPBYTE)pSsInfo, dwBytesNeeded,
				&dwBytesNeeded, &dwServicesReturned, &dwResumeHandle, NULL);
		}

		if (!bResult)
		{
			BREAK_ON_ERROR("[EXTAPI SERVICE] Failed to enumerate services");
		}

		dprintf("[EXTAPI SERVICE] %s with %u entries returned", (bResult ? "succeeded" : "failed"), dwServicesReturned);

		for (dwServiceIndex = 0; dwServiceIndex < dwServicesReturned; ++dwServiceIndex)
		{
			add_enumerated_service(pResponse, pSsInfo[dwServiceIndex].lpServiceName, pSsInfo[dwServiceIndex].lpDisplayName,
				pSsInfo[dwServiceIndex].ServiceStatusProcess.dwProcessId, pSsInfo[dwServiceIndex].ServiceStatusProcess.dwCurrentState,
				pSsInfo[dwServiceIndex].ServiceStatusProcess.dwServiceType & SERVICE_INTERACTIVE_PROCESS);
		}

	} while (0);

	if (pSsInfo)
	{
		free(pSsInfo);
	}

	if (scManager && pCloseServiceHandle)
	{
		pCloseServiceHandle(scManager);
	}

	if (hAdvapi32)
	{
		FreeLibrary(hAdvapi32);
	}

	return dwResult;
#else
	return ERROR_NOT_SUPPORTED;
#endif
}

#ifdef _WIN32
/*!
 * @brief Add an enumeration result to the given response packet.
 * @param pRacket Pointer to the response \c Packet.
 * @param cpName Name of the service.
 * @param cpDisplayName Display name of the service.
 * @param dwProcessId ID of the service process.
 * @param dwStatus Status of the service (running, paused, etc).
 * @param bInteractive Indicates if the service can interact with the desktop.
 */
VOID add_enumerated_service(Packet *pResponse, LPCSTR cpName, LPCSTR cpDisplayName, DWORD dwProcessId, DWORD dwStatus, BOOL bInteractive)
{
	Tlv entries[5] = { 0 };
	dprintf("[EXTAPI SERVICE] Adding Name: %s", cpName);
	entries[0].header.type = TLV_TYPE_EXT_SERVICE_ENUM_NAME;
	entries[0].header.length = (DWORD)strlen(cpName) + 1;
	entries[0].buffer = (PUCHAR)cpName;

	dprintf("[EXTAPI SERVICE] Adding Display Name: %s", cpDisplayName);
	entries[1].header.type = TLV_TYPE_EXT_SERVICE_ENUM_DISPLAYNAME;
	entries[1].header.length = (DWORD)strlen(cpDisplayName) + 1;
	entries[1].buffer = (PUCHAR)cpDisplayName;

	dprintf("[EXTAPI SERVICE] Adding PID: %u", dwProcessId);
	dwProcessId = htonl(dwProcessId);
	entries[2].header.type = TLV_TYPE_EXT_SERVICE_ENUM_PID;
	entries[2].header.length = sizeof(DWORD);
	entries[2].buffer = (PUCHAR)&dwProcessId;

	dprintf("[EXTAPI SERVICE] Adding Status: %u", dwStatus);
	dwStatus = htonl(dwStatus);
	entries[3].header.type = TLV_TYPE_EXT_SERVICE_ENUM_STATUS;
	entries[3].header.length = sizeof(DWORD);
	entries[3].buffer = (PUCHAR)&dwStatus;

	dprintf("[EXTAPI SERVICE] Adding Status: %s", (bInteractive ? "TRUE" : "FALSE"));
	entries[4].header.type = TLV_TYPE_EXT_SERVICE_ENUM_INTERACTIVE;
	entries[4].header.length = sizeof(BOOL);
	entries[4].buffer = (PUCHAR)&bInteractive;

	dprintf("[EXTAPI SERVICE] Adding group to response");
	packet_add_tlv_group(pResponse, TLV_TYPE_EXT_SERVICE_ENUM_GROUP, entries, 5);
}

/*!
 * @brief Query the configuration of the given service.
 * @details On successful query the results of the query are added to the response.
 * @param scService Service handle referencing the service to query.
 * @param pResponse Pointer to the response \c Packet to add the result to.
 * @returns Indication of success or failure.
 * @retval ERROR_SUCCESS The service configuration query succeeded.
 */
DWORD get_service_config(SC_HANDLE scService, Packet *pResponse)
{
	DWORD dwResult = ERROR_SUCCESS;
	LPQUERY_SERVICE_CONFIGA lpServiceConfig = NULL;
	DWORD cbBytesNeeded = 0;

	do
	{
		if (pQueryServiceConfigA == NULL)
		{
			BREAK_WITH_ERROR("[EXTAPI SERVICE] Unable to enumerate services, required functions not found", ERROR_INVALID_PARAMETER);
		}

		if (pQueryServiceConfigA(scService, NULL, 0, &cbBytesNeeded))
		{
			BREAK_ON_ERROR("[EXTAPI SERVICE] This query should have failed");
		}

		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			BREAK_ON_ERROR("[EXTAPI SERVICE] Unexpected error from QueryServiceConfigA");
		}

		if ((lpServiceConfig = (LPQUERY_SERVICE_CONFIGA)malloc(cbBytesNeeded)) == NULL)
		{
			BREAK_ON_ERROR("[EXTAPI SERVICE] Out of memory");
		}

		if (!pQueryServiceConfigA(scService, lpServiceConfig, cbBytesNeeded, &cbBytesNeeded))
		{
			BREAK_ON_ERROR("[EXTAPI SERVICE] QueryServiceConfigA failed");
		}

		dprintf("[EXTAPI SERVICE] Start type: %u", lpServiceConfig->dwStartType);
		packet_add_tlv_uint(pResponse, TLV_TYPE_EXT_SERVICE_QUERY_STARTTYPE, lpServiceConfig->dwStartType);
		packet_add_tlv_string(pResponse, TLV_TYPE_EXT_SERVICE_QUERY_DISPLAYNAME, lpServiceConfig->lpDisplayName);
		packet_add_tlv_string(pResponse, TLV_TYPE_EXT_SERVICE_QUERY_STARTNAME, lpServiceConfig->lpServiceStartName);
		packet_add_tlv_string(pResponse, TLV_TYPE_EXT_SERVICE_QUERY_PATH, lpServiceConfig->lpBinaryPathName);
		packet_add_tlv_string(pResponse, TLV_TYPE_EXT_SERVICE_QUERY_LOADORDERGROUP, lpServiceConfig->lpLoadOrderGroup ? lpServiceConfig->lpLoadOrderGroup : "");
		packet_add_tlv_bool(pResponse, TLV_TYPE_EXT_SERVICE_QUERY_INTERACTIVE, lpServiceConfig->dwServiceType & SERVICE_INTERACTIVE_PROCESS);

	} while (0);

	if (lpServiceConfig)
	{
		free(lpServiceConfig);
	}

	return dwResult;
}

/*!
 * @brief Get the DACL of the specified service.
 * @details On successful query the DACL string is added to the response.
 * @param scService Service handle referencing the service to query.
 * @param pResponse Pointer to the response \c Packet to add the result to.
 * @returns Indication of success or failure.
 * @retval ERROR_SUCCESS The service configuration query succeeded.
 */
DWORD get_service_dacl(SC_HANDLE scService, Packet *pResponse)
{
	DWORD dwResult = ERROR_SUCCESS;
	DWORD dwBytesNeeded = 0;
	PSECURITY_DESCRIPTOR pSecurityDescriptor = NULL;
	LPSTR lpDaclString;

	do
	{
		if (pQueryServiceObjectSecurity == NULL || pCSDTSSDA == NULL)
		{
			BREAK_WITH_ERROR("[EXTAPI SERVICE] Unable to get service dacl, required functions not found", ERROR_INVALID_PARAMETER);
		}

		if (pQueryServiceObjectSecurity(scService, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)&pSecurityDescriptor, 0, &dwBytesNeeded))
		{
			BREAK_ON_ERROR("[EXTAPI SERVICE] Call should have failed");
		}

		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			BREAK_ON_ERROR("[EXTAPI SERVICE] Unexpected error getting security");
		}

		if ((pSecurityDescriptor = (PSECURITY_DESCRIPTOR)malloc(dwBytesNeeded)) == NULL)
		{
			BREAK_WITH_ERROR("[EXTAPI SERVICE] Out of memory", ERROR_OUTOFMEMORY);
		}

		if (!pQueryServiceObjectSecurity(scService, DACL_SECURITY_INFORMATION, pSecurityDescriptor, dwBytesNeeded, &dwBytesNeeded))
		{
			BREAK_ON_ERROR("[EXTAPI SERVICE] Unable to query security information for DACL_SECURITY_INFORMATION");
		}

		if (!pCSDTSSDA(pSecurityDescriptor, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &lpDaclString, NULL))
		{
			BREAK_ON_ERROR("[EXTAPI SERVICE] Unable to get DACL string");
		}

		packet_add_tlv_string(pResponse, TLV_TYPE_EXT_SERVICE_QUERY_DACL, lpDaclString);

	} while (0);

	if (lpDaclString)
	{
		LocalFree(lpDaclString);
	}

	if (pSecurityDescriptor)
	{
		free(pSecurityDescriptor);
	}

	return dwResult;
}
#endif