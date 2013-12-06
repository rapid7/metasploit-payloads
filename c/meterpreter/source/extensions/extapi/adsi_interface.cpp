/*!
 * @file adsi_interface.cpp
 * @brief Definitions for functions that directly interact with ADSI
 *        through the (awful) COM interface.
 */
extern "C" {
#include "extapi.h"
#include <Iads.h>
#include <Adshlp.h>
#include <AdsErr.h>
#include "adsi_interface.h"
}

#pragma comment(lib, "Activeds.lib")

#define VALUE_SIZE 512
#define PATH_SIZE 256

static const IID IID_IDirectorySearch = { 0x109BA8EC, 0x92F0, 0x11D0, { 0xA7, 0x90, 0x00, 0xC0, 0x4F, 0xD8, 0xD5, 0xA8 } };

DWORD domain_user_enum(LPCWSTR lpDomain, Packet* response)
{
	HRESULT hResult;
	WCHAR cbPath[PATH_SIZE];

	swprintf_s(cbPath, PATH_SIZE - 1, L"LDAP://%s", lpDomain);

	if ((hResult = CoInitialize(NULL)) == S_OK)
	{
		IDirectorySearch* pDirSearch = NULL;
		ADS_SEARCH_HANDLE hSearch = NULL;

		do
		{
			// start by trying to create the search object which we can use to run searches
			hResult = ADsOpenObject(cbPath, NULL, NULL, ADS_SECURE_AUTHENTICATION | ADS_READONLY_SERVER, IID_IDirectorySearch, (void**)&pDirSearch);
			if (hResult != S_OK)
			{
				dprintf("[ADSI] Unable to open domain: %x", hResult);
				break;
			}

			// These two arrays need to be matched up so that the appropriate TLV gets the right value.
			//LPWSTR pszAttr[] = { L"samAccountName", L"msDS-User-Account-Control-Computed", L"description",
				//L"Name", L"distinguishedname", L"comment" };
			//DWORD tlvIds[] = { TLV_TYPE_EXT_ADSI_USER_SAM, TLV_TYPE_EXT_ADSI_USER_LOCKOUTTIME, TLV_TYPE_EXT_ADSI_USER_DESC,
				//TLV_TYPE_EXT_ADSI_USER_NAME, TLV_TYPE_EXT_ADSI_USER_DN, TLV_TYPE_EXT_ADSI_USER_COMMENT };
			LPWSTR pszAttr[] = { L"samAccountName", L"description", L"Name", L"distinguishedname", L"comment" };
			DWORD tlvIds[] = { TLV_TYPE_EXT_ADSI_USER_SAM, TLV_TYPE_EXT_ADSI_USER_DESC,
				TLV_TYPE_EXT_ADSI_USER_NAME, TLV_TYPE_EXT_ADSI_USER_DN, TLV_TYPE_EXT_ADSI_USER_COMMENT };
			DWORD dwAttrNameSize = sizeof(pszAttr) / sizeof(LPWSTR);

			// run the search for the values listed above
			hResult = pDirSearch->ExecuteSearch(L"(objectClass=user)", pszAttr, dwAttrNameSize, &hSearch);
			if (hResult != S_OK)
			{
				dprintf("[ADSI] Unable to execute the search");
				break;
			}

			ADS_SEARCH_COLUMN col;
			Tlv* entries = (Tlv*)malloc(dwAttrNameSize * sizeof(Tlv));
			char* values = (char*)malloc(VALUE_SIZE * dwAttrNameSize);

			// now we iterate through the search results
			while (SUCCEEDED((hResult = pDirSearch->GetNextRow(hSearch))))
			{
				if (hResult == S_ADS_NOMORE_ROWS)
				{
					hResult = S_OK;

					// out of results, so bomb out of the loop
					break;
				}

				DWORD dwIndex = 0;
				size_t charsConverted;
				QWORD qwValue;

				// iterate through the columns, adding Tlv entries as we go, but only
				// if we can get the values out.
				for (DWORD colIndex = 0; colIndex < dwAttrNameSize; ++colIndex)
				{
					HRESULT hr = pDirSearch->GetColumn(hSearch, pszAttr[dwIndex], &col);
					if (SUCCEEDED(hr))
					{
						char* valueTarget = values + (dwIndex * VALUE_SIZE);
						entries[dwIndex].buffer = (PUCHAR)valueTarget;
						entries[dwIndex].header.type = tlvIds[dwIndex];

						switch (col.dwADsType)
						{
						case ADSTYPE_LARGE_INTEGER:
							qwValue = col.pADsValues->LargeInteger.QuadPart;
							*((QWORD*)valueTarget) = htonq(qwValue);
							entries[dwIndex].header.length = sizeof(QWORD);
							dprintf("[ADSI] Adding large int value %ul", (QWORD)qwValue);
							break;
						case ADSTYPE_INTEGER:
							*((UINT*)valueTarget) = htonl((UINT)col.pADsValues->Integer);
							entries[dwIndex].header.length = sizeof(UINT);
							dprintf("[ADSI] Adding int value %u", (UINT)col.pADsValues->Integer);
							break;
						default:
							WCHAR* source = col.dwADsType == ADSTYPE_CASE_IGNORE_STRING
								? col.pADsValues->CaseIgnoreString
								: col.pADsValues->CaseExactString;

							wcstombs_s(&charsConverted, valueTarget, VALUE_SIZE, source, VALUE_SIZE - 1);
							dprintf("[ADSI] Adding %s", valueTarget);
							entries[dwIndex].header.length = lstrlenA(valueTarget) + 1;
							break;
						}

						dwIndex++;
						pDirSearch->FreeColumn(&col);
					}
					else
					{
						dprintf("[ADSI] Col read failed: %x", hr);
					}
				}

				if (dwIndex > 0)
				{
					dprintf("[ADSI] Adding group packet of %u values", dwIndex);
					// Throw the user details together in a group, ready to return.
					packet_add_tlv_group(response, TLV_TYPE_EXT_ADSI_USER, entries, dwIndex);
					dprintf("[ADSI] Added group packet of %u values", dwIndex);
				}
				else
				{
					dprintf("[ADSI] User found, but no fields extracted.");
				}
			}

			free(entries);
			free(values);
		} while (0);

		if (hSearch != NULL)
		{
			pDirSearch->CloseSearchHandle(hSearch);
		}

		if (pDirSearch != NULL)
		{
			pDirSearch->Release();
		}

		CoUninitialize();
	}

	return (DWORD)hResult;
}

DWORD domain_computer_enum(LPCWSTR lpDomain, Packet* response)
{
	HRESULT hResult;
	WCHAR cbPath[PATH_SIZE];

	swprintf_s(cbPath, PATH_SIZE - 1, L"LDAP://%s", lpDomain);

	if ((hResult = CoInitialize(NULL)) == S_OK)
	{
		IDirectorySearch* pDirSearch = NULL;
		ADS_SEARCH_HANDLE hSearch = NULL;

		do
		{
			// start by trying to create the search object which we can use to run searches
			hResult = ADsOpenObject(cbPath, NULL, NULL, ADS_SECURE_AUTHENTICATION | ADS_READONLY_SERVER, IID_IDirectorySearch, (void**)&pDirSearch);
			if (hResult != S_OK)
			{
				dprintf("[ADSI] Unable to open domain: %x", hResult);
				break;
			}

			// These two arrays need to be matched up so that the appropriate TLV gets the right value.
			LPWSTR pszAttr[] = { L"description", L"Name", L"distinguishedname", L"comment" };
			DWORD tlvIds[] = { TLV_TYPE_EXT_ADSI_COMP_DESC, TLV_TYPE_EXT_ADSI_COMP_NAME, TLV_TYPE_EXT_ADSI_COMP_DN, TLV_TYPE_EXT_ADSI_COMP_COMMENT };
			DWORD dwAttrNameSize = sizeof(pszAttr) / sizeof(LPWSTR);

			// run the search for the values listed above
			hResult = pDirSearch->ExecuteSearch(L"(objectClass=computer)", pszAttr, dwAttrNameSize, &hSearch);
			if (hResult != S_OK)
			{
				dprintf("[ADSI] Unable to execute the search");
				break;
			}

			ADS_SEARCH_COLUMN col;
			Tlv* entries = (Tlv*)malloc(dwAttrNameSize * sizeof(Tlv));
			char* values = (char*)malloc(VALUE_SIZE * dwAttrNameSize);

			// now we iterate through the search results
			while (SUCCEEDED((hResult = pDirSearch->GetNextRow(hSearch))))
			{
				if (hResult == S_ADS_NOMORE_ROWS)
				{
					hResult = S_OK;

					// out of results, so bomb out of the loop
					break;
				}

				DWORD dwIndex = 0;
				size_t charsConverted;

				// iterate through the columns, adding Tlv entries as we go, but only
				// if we can get the values out.
				for (DWORD colIndex = 0; colIndex < dwAttrNameSize; ++colIndex)
				{
					HRESULT hr = pDirSearch->GetColumn(hSearch, pszAttr[dwIndex], &col);
					if (SUCCEEDED(hr))
					{
						char* valueTarget = values + (dwIndex * VALUE_SIZE);
						WCHAR* source = col.dwADsType == ADSTYPE_CASE_IGNORE_STRING
							? col.pADsValues->CaseIgnoreString
							: col.pADsValues->CaseExactString;

						wcstombs_s(&charsConverted, valueTarget, VALUE_SIZE, source, VALUE_SIZE - 1);
						dprintf("[ADSI] Adding %s", valueTarget);
						entries[dwIndex].header.type = tlvIds[dwIndex];
						entries[dwIndex].header.length = lstrlenA(valueTarget) + 1;
						entries[dwIndex].buffer = (PUCHAR)valueTarget;
						dwIndex++;

						pDirSearch->FreeColumn(&col);
					}
					else
					{
						dprintf("[ADSI] Col read failed: %x", hr);
					}
				}

				if (dwIndex > 0)
				{
					dprintf("[ADSI] Adding group packet of %u values", dwIndex);
					// Throw the computer details together in a group, ready to return.
					packet_add_tlv_group(response, TLV_TYPE_EXT_ADSI_COMP, entries, dwIndex);
					dprintf("[ADSI] Added group packet of %u values", dwIndex);
				}
				else
				{
					dprintf("[ADSI] Computer found, but no fields extracted.");
				}
			}

			free(entries);
			free(values);
		} while (0);

		if (hSearch != NULL)
		{
			pDirSearch->CloseSearchHandle(hSearch);
		}

		if (pDirSearch != NULL)
		{
			pDirSearch->Release();
		}

		CoUninitialize();
	}

	return (DWORD)hResult;
}