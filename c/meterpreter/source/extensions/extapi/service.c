/*!
 * @file service.c
 * @brief Definitions for service management functions
 */
#include "extapi.h"
#include "service.h"
#include "common_metapi.h"

#include <sddl.h>

/*! @brief The possible list of operations to perform on a service */
typedef enum _ServiceOperation
{
	ServOpStart = 1,
	ServOpPause = 2,
	ServOpResume = 3,
	ServOpStop = 4,
	ServOpRestart = 5
} ServiceOperation;

HMODULE hAdvapi32 = NULL;

/*! @brief Typedef for the OpenSCManagerA function. */
typedef SC_HANDLE(WINAPI * POPENSCMANAGERA)(LPCSTR lpMachineName, LPCSTR lpDatabaseName, DWORD dwDesiredAccess);
static POPENSCMANAGERA pOpenSCManagerA = NULL;

/*! @brief Typedef for the CloseServiceHandle function. */
typedef BOOL(WINAPI * PCLOSESERVICEHANDLE)(SC_HANDLE hSCObject);
static PCLOSESERVICEHANDLE pCloseServiceHandle = NULL;

/*! @brief Typedef for the StartServiceA function. */
typedef BOOL (WINAPI * PSTARTSERVICEA)(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCTSTR *lpServiceArgVectors);
static PSTARTSERVICEA pStartServiceA = NULL;

/*! @brief Typedef for the ControlService function. */
typedef BOOL (WINAPI * PCONTROLSERVICE)(SC_HANDLE hService, DWORD dwControl, LPSERVICE_STATUS lpServiceStatus);
static PCONTROLSERVICE pControlService = NULL;

/*! @brief Typedef for the QueryServiceStatus function. */
typedef BOOL (WINAPI * PQUERYSERVICESTATUS)(SC_HANDLE hService, LPSERVICE_STATUS lpServiceStatus);
static PQUERYSERVICESTATUS pQueryServiceStatus = NULL;

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
DWORD get_service_status(SC_HANDLE scService, Packet *pResponse);
DWORD get_service_dacl(SC_HANDLE scService, Packet *pResponse);

DWORD execute_service_task(LPCSTR lpServiceName, ServiceOperation eServiceOp, Packet *response);
DWORD enumerate_services(Packet *response);

/*!
 * @brief Initialise the service part of the extended api.
 */
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

		dprintf("[EXTAPI SERVICE] Searching for StartServiceA");
		if ((pStartServiceA = (PSTARTSERVICEA)GetProcAddress(hAdvapi32, "StartServiceA")) == NULL)
		{
			dprintf("[EXTAPI SERVICE] Unable to locate StartServiceA in advapi32.dll.");
		}

		dprintf("[EXTAPI SERVICE] Searching for ControlService");
		if ((pControlService = (PCONTROLSERVICE)GetProcAddress(hAdvapi32, "ControlService")) == NULL)
		{
			dprintf("[EXTAPI SERVICE] Unable to locate ControlService in advapi32.dll.");
		}

		dprintf("[EXTAPI SERVICE] Searching for QueryServiceStatus");
		if ((pQueryServiceStatus = (PQUERYSERVICESTATUS)GetProcAddress(hAdvapi32, "QueryServiceStatus")) == NULL)
		{
			dprintf("[EXTAPI SERVICE] Unable to locate QueryServiceStatus in advapi32.dll.");
		}
	} while (0);
}

/*!
 * @brief Handle the request for service control.
 * @param remote Pointer to the \c Remote making the request.
 * @param packet Pointer to the request \c Packet.
 * @returns Indication of sucess or failure.
 */
DWORD request_service_control(Remote *remote, Packet *packet)
{
	LPSTR lpServiceName = NULL;
	ServiceOperation eServiceOp = 0;
	DWORD dwResult = ERROR_SUCCESS;
	Packet * response = met_api->packet.create_response(packet);

	do
	{
		if (!response)
		{
			dprintf("[EXTAPI SERVICE] Unable to create response packet");
			dwResult = ERROR_OUTOFMEMORY;
			break;
		}

		lpServiceName = met_api->packet.get_tlv_value_string(packet, TLV_TYPE_EXT_SERVICE_CTRL_NAME);
		if (!lpServiceName)
		{
			BREAK_WITH_ERROR("[EXTAPI SERVICE] Missing service name parameter", ERROR_INVALID_PARAMETER);
		}

		eServiceOp = (ServiceOperation)met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_EXT_SERVICE_CTRL_OP);
		if (eServiceOp == 0)
		{
			BREAK_WITH_ERROR("[EXTAPI SERVICE] Missing service operation parameter", ERROR_INVALID_PARAMETER);
		}

		dprintf("[EXTAPI SERVICE] Executing service control task");
		dwResult = execute_service_task(lpServiceName, eServiceOp, response);

	} while (0);

	dprintf("[EXTAPI SERVICE] Transmitting response back to caller.");
	if (response)
	{
		met_api->packet.transmit_response(dwResult, remote, response);
	}

	return dwResult;
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
	Packet * response = met_api->packet.create_response(packet);

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
		met_api->packet.transmit_response(dwResult, remote, response);
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
	Packet * response = met_api->packet.create_response(packet);

	do
	{
		if (!response)
		{
			dprintf("[EXTAPI SERVICE] Unable to create response packet");
			dwResult = ERROR_OUTOFMEMORY;
			break;
		}

		lpServiceName = met_api->packet.get_tlv_value_string(packet, TLV_TYPE_EXT_SERVICE_ENUM_NAME);
		if (!lpServiceName)
		{
			BREAK_WITH_ERROR("[EXTAPI SERVICE] Missing service name parameter", ERROR_INVALID_PARAMETER);
		}

		dprintf("[EXTAPI SERVICE] Beginning service enumeration");
		dwResult = query_service(lpServiceName, response);

	} while (0);

	dprintf("[EXTAPI SERVICE] Transmitting response back to caller.");
	if (response)
	{
		met_api->packet.transmit_response(dwResult, remote, response);
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
		get_service_status(scService, pResponse);
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

	return dwResult;
}

/*!
 * @brief Perform the service enumeration.
 * @param pRacket Pointer to the response \c Packet.
 * @returns Indication of sucess or failure.
 * @retval ERROR_SUCCESS Query succeeded.
 */
DWORD enumerate_services(Packet *pResponse)
{
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

	return dwResult;
}

/*!
 * @brief Perform the task/operation on a service.
 * @param cpServiceName Name of the serivce to perform the query on.
 * @param eServiceOp The operationg to perform on the service.
 * @param pRacket Pointer to the response \c Packet.
 * @returns Indication of sucess or failure.
 * @retval ERROR_SUCCESS Operation succeeded.
 */
DWORD execute_service_task(LPCSTR cpServiceName, ServiceOperation eServiceOp, Packet *pResponse)
{
	DWORD dwResult = ERROR_SUCCESS;
	DWORD dwOpenFlags = SC_MANAGER_CONNECT | GENERIC_READ | SERVICE_QUERY_STATUS;
	DWORD dwControlFlag = 0;
	DWORD dwTargetStatus = 0;
	SC_HANDLE scManager = NULL;
	SC_HANDLE scService = NULL;
	SERVICE_STATUS serviceStatus;

	do
	{
		if (hAdvapi32 == NULL
			|| pOpenSCManagerA == NULL
			|| pStartServiceA == NULL
			|| pCloseServiceHandle == NULL
			|| pQueryServiceStatus == NULL
			|| pOpenServiceA == NULL)
		{
			BREAK_WITH_ERROR("[EXTAPI SERVICE] Unable to query services, required functions not found", ERROR_INVALID_PARAMETER);
		}

		dprintf("[EXTAPI SERVICE] Opening the Service Control manager");
		if ((scManager = pOpenSCManagerA(NULL, SERVICES_ACTIVE_DATABASEA, SC_MANAGER_CONNECT | GENERIC_READ)) == NULL)
		{
			BREAK_ON_ERROR("[EXTAPI SERVICE] Unable to open the service control manager");
		}

		switch (eServiceOp)
		{
			case ServOpStart:
				dwOpenFlags |= SERVICE_START;
				break;
			case ServOpStop:
				dwOpenFlags |= SERVICE_STOP;
				break;
			case ServOpPause:
			case ServOpResume:
				dwOpenFlags |= SERVICE_PAUSE_CONTINUE;
				break;
			case ServOpRestart:
				dwOpenFlags |= SERVICE_START | SERVICE_STOP;
		}

		dprintf("[EXTAPI SERVICE] Opening the Service: %s", cpServiceName);
		if ((scService = pOpenServiceA(scManager, cpServiceName, dwOpenFlags)) == NULL)
		{
			dwResult = GetLastError();
			dprintf("[EXTAPI SERVICE] Unable to open the service: %s (%u)", cpServiceName, dwResult);
			break;
		}

		// let's get a clue as to what the service status is before we move on
		if (!pQueryServiceStatus(scService, &serviceStatus))
		{
			dwResult = GetLastError();
			dprintf("[EXTAPI SERVICE] Unable to query the service status: %s (%u)", cpServiceName, dwResult);
			break;
		}

		dwResult = ERROR_SUCCESS;
		if (eServiceOp == ServOpStart)
		{
			// we can't try to start the service if it isn't stopped
			if (serviceStatus.dwCurrentState == SERVICE_STOPPED)
			{
				if (!pStartServiceA(scService, 0, NULL))
				{
					dwResult = GetLastError();
					dprintf("[EXTAPI SERVICE] Unable to start the service: %s (%u)", cpServiceName, dwResult);
					break;
				}
			}
			else if(serviceStatus.dwCurrentState != SERVICE_RUNNING)
			{
				dprintf("[EXTAPI SERVICE] Unable to start the service in its current state: %s %x", cpServiceName, serviceStatus.dwCurrentState);
				dwResult = ERROR_INVALID_OPERATION;
				break;
			}
		}
		else
		{
			switch (eServiceOp)
			{
			case ServOpRestart:
			case ServOpStop:
				dwControlFlag = SERVICE_CONTROL_STOP;
				dwTargetStatus = SERVICE_STOPPED;
				break;
			case ServOpPause:
				dwControlFlag = SERVICE_CONTROL_PAUSE;
				dwTargetStatus = SERVICE_PAUSED;
				break;
			case ServOpResume:
				dwControlFlag = SERVICE_CONTROL_CONTINUE;
				dwTargetStatus = SERVICE_RUNNING;
				break;
			}

			dwResult = ERROR_SUCCESS;

			if (serviceStatus.dwCurrentState == dwTargetStatus)
			{
				dprintf("[EXTAPI SERVICE] Service already in target state: %u on %s (%u)", eServiceOp, cpServiceName, dwResult);
			}
			else if (!pControlService(scService, dwControlFlag, &serviceStatus))
			{
				dwResult = GetLastError();
				dprintf("[EXTAPI SERVICE] Unable to control the service: %u on %s (%u)", eServiceOp, cpServiceName, dwResult);
				break;
			}

			if (eServiceOp == ServOpRestart)
			{
				// At this point the service should either be stopped already or it will be stopping.
				// We have to wait until the service has stopped before we attempt to restart.
				do
				{
					Sleep(500);
					pQueryServiceStatus(scService, &serviceStatus);
				} while (serviceStatus.dwCurrentState != SERVICE_STOPPED);

				// next we try to kick it off again
				if (!pStartServiceA(scService, 0, NULL))
				{
					dwResult = GetLastError();
					dprintf("[EXTAPI SERVICE] Unable to start the service: %s (%u)", cpServiceName, dwResult);
				}
			}
		}

	} while (0);

	if (scService && pCloseServiceHandle)
	{
		pCloseServiceHandle(scService);
	}

	if (scManager && pCloseServiceHandle)
	{
		pCloseServiceHandle(scManager);
	}

	return dwResult;
}

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
	Packet* pGroup = met_api->packet.create_group();

	met_api->packet.add_tlv_string(pGroup, TLV_TYPE_EXT_SERVICE_ENUM_NAME, cpName);
	met_api->packet.add_tlv_string(pGroup, TLV_TYPE_EXT_SERVICE_ENUM_DISPLAYNAME, cpDisplayName);
	met_api->packet.add_tlv_uint(pGroup, TLV_TYPE_EXT_SERVICE_ENUM_PID, dwProcessId);
	met_api->packet.add_tlv_uint(pGroup, TLV_TYPE_EXT_SERVICE_ENUM_STATUS, dwStatus);
	met_api->packet.add_tlv_bool(pGroup, TLV_TYPE_EXT_SERVICE_ENUM_INTERACTIVE, bInteractive);

	met_api->packet.add_group(pResponse, TLV_TYPE_EXT_SERVICE_ENUM_GROUP, pGroup);
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
		met_api->packet.add_tlv_uint(pResponse, TLV_TYPE_EXT_SERVICE_QUERY_STARTTYPE, lpServiceConfig->dwStartType);
		met_api->packet.add_tlv_string(pResponse, TLV_TYPE_EXT_SERVICE_QUERY_DISPLAYNAME, lpServiceConfig->lpDisplayName);
		met_api->packet.add_tlv_string(pResponse, TLV_TYPE_EXT_SERVICE_QUERY_STARTNAME, lpServiceConfig->lpServiceStartName);
		met_api->packet.add_tlv_string(pResponse, TLV_TYPE_EXT_SERVICE_QUERY_PATH, lpServiceConfig->lpBinaryPathName);
		met_api->packet.add_tlv_string(pResponse, TLV_TYPE_EXT_SERVICE_QUERY_LOADORDERGROUP, lpServiceConfig->lpLoadOrderGroup ? lpServiceConfig->lpLoadOrderGroup : "");
		met_api->packet.add_tlv_bool(pResponse, TLV_TYPE_EXT_SERVICE_QUERY_INTERACTIVE, lpServiceConfig->dwServiceType & SERVICE_INTERACTIVE_PROCESS);

	} while (0);

	if (lpServiceConfig)
	{
		free(lpServiceConfig);
	}

	return dwResult;
}

/*!
 * @brief Query the status of a given service handle.
 * @details On successful querying the status is added to the response.
 * @param scService Service handle referencing the service to query.
 * @param pResponse Pointer to the response \c Packet to add the result to.
 * @returns Indication of success or failure.
 * @retval ERROR_SUCCESS The service status query succeeded.
 */
DWORD get_service_status(SC_HANDLE scService, Packet *pResponse)
{
	DWORD dwResult = ERROR_SUCCESS;
	SERVICE_STATUS serviceStatus;

	do
	{
		if (pQueryServiceStatus == NULL)
		{
			BREAK_WITH_ERROR("[EXTAPI SERVICE] Unable to query service status, required functions not found", ERROR_INVALID_PARAMETER);
		}

		// let's get a clue as to what the service status is before we move on
		if (!pQueryServiceStatus(scService, &serviceStatus))
		{
			dwResult = GetLastError();
			dprintf("[EXTAPI SERVICE] Unable to query the service status: %u", dwResult);
			break;
		}

		met_api->packet.add_tlv_uint(pResponse, TLV_TYPE_EXT_SERVICE_QUERY_STATUS, serviceStatus.dwCurrentState);

	} while (0);

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

		met_api->packet.add_tlv_string(pResponse, TLV_TYPE_EXT_SERVICE_QUERY_DACL, lpDaclString);

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
