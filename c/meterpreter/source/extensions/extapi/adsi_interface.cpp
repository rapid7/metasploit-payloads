/*!
 * @file adsi_interface.cpp
 * @brief Definitions for functions that directly interact with ADSI
 *        through the (awful) COM interface.
 */
extern "C" {
#include "extapi.h"
#include "common_metapi.h"
#include <iads.h>
#include <adshlp.h>
#include <adserr.h>
#include "adsi_interface.h"
}

#define VALUE_SIZE 1024
#define PATH_SIZE 256

typedef BOOL (WINAPI *PCONVERTSIDTOSTRINGSID)(PSID pSid, LPSTR* pStr); 

/*! @brief The GUID of the Directory Search COM object. */
extern const IID IID_IDirectorySearch = { 0x109BA8EC, 0x92F0, 0x11D0, { 0xA7, 0x90, 0x00, 0xC0, 0x4F, 0xD8, 0xD5, 0xA8 } };

static PCONVERTSIDTOSTRINGSID pConvertSidToStringSid = NULL;
static HMODULE hAdvapi32 = NULL;

/*!
 * @brief Render a SID to a string.
 * @param pSid Pointer to the SID to render.
 * @param pStr Pointer to the variable that will receive the string. Free with `LocalFree`.
 * @returns Indication of success or failure.
 */
BOOL ConvertSidToStringSid(PSID pSid, LPSTR* pStr)
{
	if (pConvertSidToStringSid == NULL)
	{
		if (hAdvapi32 == NULL)
		{
			hAdvapi32 = LoadLibraryA("Advapi32.dll");
		}

		pConvertSidToStringSid = hAdvapi32 == NULL ? NULL : (PCONVERTSIDTOSTRINGSID)GetProcAddress(hAdvapi32, "ConvertSidToStringSidA");
	}

	return pConvertSidToStringSid == NULL ? FALSE : pConvertSidToStringSid(pSid, pStr);
}

/*!
 * @brief Render a byte array as a GUID string.
 * @param bytes Pointer to the GUID bytes.
 * @param buffer Pointer to the target buffer.
 * @param bufferSize size of the memory available in \c buffer.
 * @remark Assumes the caller knows what they're doing, and assumes that there are 16 bytes in the array.
 */
void guid_to_string(LPBYTE bytes, char* buffer, DWORD bufferSize)
{
	sprintf_s(buffer, bufferSize, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		bytes[0], bytes[1], bytes[2], bytes[3],
		bytes[4], bytes[5], bytes[6], bytes[7],
		bytes[8], bytes[9], bytes[10], bytes[11],
		bytes[12], bytes[13], bytes[14], bytes[15]);
}

/*!
 * @brief Render a byte array as a string.
 * @param bytes Pointer to the bytes.
 * @param count Number of bytes to write.
 * @param buffer Pointer to the target buffer.
 * @param bufferSize size of the memory available in \c buffer.
 * @param byteFormat optional per-byte format (defaults to \c %02x).
 * @param byteFormatMaxLen optional per-byte format max length (to make sure we allocated enough memory).
 * @param delim optional delimiter to render between bytes (defaults to \c -).
 * @remark Assumes the caller knows what they're doing, and assumes that there are 16 bytes in the array.
 */
char* bytes_to_string(LPBYTE bytes, DWORD count, char* byteFormat = "%02x", DWORD byteFormatMaxLen = 2, char* delim = "-")
{
	dprintf("[EXTAPI ADSI] Stringifying a binary of %u bytes", count);

	if (bytes == NULL || count == 0)
	{
		return NULL;
	}

	size_t delimLen = delim == NULL ? 0 : strlen(delim);
	size_t requiredSize = count * byteFormatMaxLen + (count - 1) * delimLen + 1;
	char* string = (char*)malloc(requiredSize);
	char* csr = string;

	if (string)
	{
		for (DWORD i = 0; i < count; ++i)
		{
			if (i != 0 && delimLen > 0)
			{
				csr += sprintf_s(csr, delimLen + 1, "%s", delim);
			}

			csr += sprintf_s(csr, byteFormatMaxLen + 1, byteFormat, bytes[i]);
		}
	}

	dprintf("[EXTAPI ADSI] Stringified a binary of %u bytes to: %s", count, string);

	return string;
}

/*!
 * @brief Perform a domain query via ADSI.
 * @param lpwDomain Name of the domain that is to be queried.
 * @param lpwFilter The filter to use when reading objects (LDAP style).
 * @param lpwQueryCols Array of column names representing fields to extract.
 * @param queryColCount Number of columns in \c lpwQueryCols.
 * @param maxResults The maximum number of results to return.
 * @param pageSize The size of the page of results to return.
 * @param response The response \c Packet to add the results to.
 */
DWORD domain_query(LPCWSTR lpwDomain, LPWSTR lpwFilter, LPWSTR* lpwQueryCols,
	UINT queryColCount, DWORD maxResults, DWORD pageSize, Packet* response)
{
	HRESULT hResult;
	WCHAR cbPath[PATH_SIZE];

	swprintf_s(cbPath, PATH_SIZE - 1, L"LDAP://%s", lpwDomain);

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

			// set the limit of results so that we don't take forever on large domains
			ADS_SEARCHPREF_INFO prefInfo[4];
			prefInfo[0].dwSearchPref = ADS_SEARCHPREF_SIZE_LIMIT;
			prefInfo[0].vValue.dwType = ADSTYPE_INTEGER;
			prefInfo[0].vValue.Integer = (ADS_INTEGER)maxResults;
			prefInfo[1].dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
			prefInfo[1].vValue.dwType = ADSTYPE_INTEGER;
			prefInfo[1].vValue.Integer = (ADS_INTEGER)pageSize;
			prefInfo[2].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
			prefInfo[2].vValue.dwType = ADSTYPE_INTEGER;
			prefInfo[2].vValue.Integer = ADS_SCOPE_SUBTREE;
			prefInfo[3].dwSearchPref = ADS_SEARCHPREF_CACHE_RESULTS;
			prefInfo[3].vValue.dwType = ADSTYPE_BOOLEAN;
			prefInfo[3].vValue.Boolean = false;

			dprintf("[ADSI] Setting Max results to %u", (ADS_INTEGER)maxResults);
			dprintf("[ADSI] Setting Page size to %u", (ADS_INTEGER)pageSize);
			if (FAILED(hResult = pDirSearch->SetSearchPreference(prefInfo, 4)))
			{
				dprintf("[ADSI] Failed to set search settings %u %x", pageSize, hResult);
			}

			dprintf("[ADSI] Search executing");
			hResult = pDirSearch->ExecuteSearch(lpwFilter, lpwQueryCols, queryColCount, &hSearch);
			if (hResult != S_OK)
			{
				dprintf("[ADSI] Unable to execute the search");
				break;
			}

			// Helper buffer used for conversion from whatever type it is, to int.
			char value[VALUE_SIZE];

			DWORD rowsProcessed = 0;

			// now we iterate through the search results
			while (SUCCEEDED((hResult = pDirSearch->GetNextRow(hSearch))) && (maxResults == 0 || rowsProcessed < maxResults))
			{
				if (hResult == S_ADS_NOMORE_ROWS)
				{
					hResult = S_OK;

					// out of results, so bomb out of the loop
					break;
				}

				DWORD dwIndex = 0;
				ADS_SEARCH_COLUMN col;

				Packet* pGroup = met_api->packet.create_group();

				// iterate through the columns, adding Tlv entries as we go, but only
				// if we can get the values out.
				for (DWORD colIndex = 0; colIndex < queryColCount; ++colIndex)
				{
					// try to do something sane based on the type that's being used to store
					// the value.
					HRESULT hr = pDirSearch->GetColumn(hSearch, lpwQueryCols[dwIndex], &col);
					if (SUCCEEDED(hr))
					{
						switch (col.dwADsType)
						{
							case ADSTYPE_LARGE_INTEGER:
							{
								met_api->packet.add_tlv_qword(pGroup, TLV_TYPE_EXT_ADSI_BIGNUMBER, col.pADsValues->LargeInteger.QuadPart);
								dprintf("[ADSI] Adding large int value %lld", (UINT)col.pADsValues->LargeInteger.QuadPart);
								break;
							}
							case ADSTYPE_INTEGER:
							{
								met_api->packet.add_tlv_uint(pGroup, TLV_TYPE_EXT_ADSI_NUMBER, col.pADsValues->Integer);
								dprintf("[ADSI] Adding int value %u", (UINT)col.pADsValues->Integer);
								break;
							}
							case ADSTYPE_DN_STRING:
							{
								dprintf("[EXTAPI ADSI] DN String: %S", col.pADsValues->DNString);
								met_api->packet.add_tlv_wstring(pGroup, TLV_TYPE_EXT_ADSI_STRING, col.pADsValues->DNString);
								break;
							}
							case ADSTYPE_PRINTABLE_STRING:
							{
								dprintf("[EXTAPI ADSI] Printable String: %S", col.pADsValues->PrintableString);
								met_api->packet.add_tlv_wstring(pGroup, TLV_TYPE_EXT_ADSI_STRING, col.pADsValues->PrintableString);
								break;
							}
							case ADSTYPE_NUMERIC_STRING:
							{
								dprintf("[EXTAPI ADSI] Numeric String: %S", col.pADsValues->NumericString);
								met_api->packet.add_tlv_wstring(pGroup, TLV_TYPE_EXT_ADSI_STRING, col.pADsValues->NumericString);
								break;
							}
							case ADSTYPE_CASE_EXACT_STRING:
							{
								dprintf("[EXTAPI ADSI] Case Extact String: %S", col.pADsValues->CaseExactString);
								met_api->packet.add_tlv_wstring(pGroup, TLV_TYPE_EXT_ADSI_STRING, col.pADsValues->CaseExactString);
								break;
							}
							case ADSTYPE_CASE_IGNORE_STRING:
							{
								dprintf("[EXTAPI ADSI] Case Ignore String: %S", col.pADsValues->CaseIgnoreString);
								met_api->packet.add_tlv_wstring(pGroup, TLV_TYPE_EXT_ADSI_STRING, col.pADsValues->CaseIgnoreString);
								break;
							}
							case ADSTYPE_BOOLEAN:
							{
								dprintf("[EXTAPI ADSI] Boolean");
								met_api->packet.add_tlv_bool(pGroup, TLV_TYPE_EXT_ADSI_BOOL, col.pADsValues->Boolean == 0 ? FALSE : TRUE);
								break;
							}
							case ADSTYPE_OCTET_STRING:
							{
								dprintf("[EXTAPI ADSI] Octet string");
								met_api->packet.add_tlv_raw(pGroup, TLV_TYPE_EXT_ADSI_RAW, col.pADsValues->OctetString.lpValue, col.pADsValues->OctetString.dwLength);
								break;
							}
							case ADSTYPE_UTC_TIME:
							{
								dprintf("[EXTAPI ADSI] UTC time");
								SYSTEMTIME* pt = &col.pADsValues->UTCTime;
								sprintf_s(value, VALUE_SIZE, "%4u-%02u-%02u %02u:%02u:%02u.%03u",
									pt->wYear, pt->wMonth, pt->wDay, pt->wHour, pt->wMinute, pt->wSecond, pt->wMilliseconds);
								met_api->packet.add_tlv_string(pGroup, TLV_TYPE_EXT_ADSI_STRING, value);
								break;
							}
							case ADSTYPE_PROV_SPECIFIC:
							{
								dprintf("[EXTAPI ADSI] Provider specific");
								met_api->packet.add_tlv_raw(pGroup, TLV_TYPE_EXT_ADSI_RAW, col.pADsValues->ProviderSpecific.lpValue, col.pADsValues->ProviderSpecific.dwLength);
								break;
							}
							case ADSTYPE_OBJECT_CLASS:
							{
								met_api->packet.add_tlv_wstring(pGroup, TLV_TYPE_EXT_ADSI_STRING, col.pADsValues->ClassName);
								break;
							}
							case ADSTYPE_CASEIGNORE_LIST:
							{
								// list of strings, yay!
								Packet* pStrings = met_api->packet.create_group();
								PADS_CASEIGNORE_LIST list = col.pADsValues->pCaseIgnoreList;

								dprintf("[EXTAPI ADSI] Case Ignore List");

								while (list != NULL)
								{
									met_api->packet.add_tlv_wstring(pStrings, TLV_TYPE_EXT_ADSI_STRING, list->String);
									list = list->Next;
								}

								met_api->packet.add_group(pGroup, TLV_TYPE_EXT_ADSI_ARRAY, pStrings);
								break;
							}
							case ADSTYPE_PATH:
							{
								PADS_PATH path = col.pADsValues->pPath;
								Packet* pPathGroup = met_api->packet.create_group();

								dprintf("[EXTAPI ADSI] PATH");

								met_api->packet.add_tlv_wstring(pPathGroup, TLV_TYPE_EXT_ADSI_PATH_VOL, path->VolumeName);
								met_api->packet.add_tlv_wstring(pPathGroup, TLV_TYPE_EXT_ADSI_PATH_PATH, path->Path);
								met_api->packet.add_tlv_uint(pPathGroup, TLV_TYPE_EXT_ADSI_PATH_TYPE, path->Type);

								met_api->packet.add_group(pGroup, TLV_TYPE_EXT_ADSI_PATH, pPathGroup);
								break;
							}
							case ADSTYPE_POSTALADDRESS:
							{
								Packet* pAddressGroup = met_api->packet.create_group();
								PADS_POSTALADDRESS addr = col.pADsValues->pPostalAddress;

								for (DWORD i = 0; i < sizeof(addr->PostalAddress) / sizeof(addr->PostalAddress[0]); ++i)
								{
									if (!addr->PostalAddress[i] || lstrlenW(addr->PostalAddress[i]) == 0)
									{
										continue;
									}

									met_api->packet.add_tlv_wstring(pAddressGroup, TLV_TYPE_EXT_ADSI_STRING, addr->PostalAddress[i]);
								}

								dprintf("[EXTAPI ADSI] postal address list");

								met_api->packet.add_group(pGroup, TLV_TYPE_EXT_ADSI_ARRAY, pAddressGroup);
								break;
							}
							case ADSTYPE_TIMESTAMP:
							{
								ADS_TIMESTAMP* pts = &col.pADsValues->Timestamp;
								dprintf("[EXTAPI ADSI] timestamp");
								met_api->packet.add_tlv_uint(pGroup, TLV_TYPE_EXT_ADSI_NUMBER, pts->WholeSeconds);
								break;
							}
							case ADSTYPE_BACKLINK:
							{
								ADS_BACKLINK* pbl = &col.pADsValues->BackLink;
								dprintf("[EXTAPI ADSI] backlink");
								met_api->packet.add_tlv_wstring(pGroup, TLV_TYPE_EXT_ADSI_STRING, pbl->ObjectName);
								break;
							}
							case ADSTYPE_TYPEDNAME:
							{
								PADS_TYPEDNAME ptn = col.pADsValues->pTypedName;
								dprintf("[EXTAPI ADSI] typed name");
								met_api->packet.add_tlv_wstring(pGroup, TLV_TYPE_EXT_ADSI_STRING, ptn->ObjectName);
								break;
							}
							case ADSTYPE_NETADDRESS:
							{
								PADS_NETADDRESS pna = col.pADsValues->pNetAddress;
								// IP address octects won't be bigger than 3 chars (given that we can only have 255 as a max value
								// TODO: handle IPv6?
								char* s = bytes_to_string(pna->Address, pna->AddressLength, "%u", 3, ".");
								if (s)
								{
									met_api->packet.add_tlv_string(pGroup, TLV_TYPE_EXT_ADSI_STRING, s);
									free(s);
								}
								else
								{
									met_api->packet.add_tlv_raw(pGroup, TLV_TYPE_EXT_ADSI_RAW, pna->Address, pna->AddressLength);
								}
								dprintf("[ADSI] %u network address of %u bytes added", pna->AddressType, pna->AddressLength);
								break;
							}
							case ADSTYPE_EMAIL:
							{
								dprintf("[EXTAPI ADSI] email");
								met_api->packet.add_tlv_wstring(pGroup, TLV_TYPE_EXT_ADSI_STRING, col.pADsValues->Email.Address);
								break;
							}
							case ADSTYPE_NT_SECURITY_DESCRIPTOR:
							{
								ADS_NT_SECURITY_DESCRIPTOR* psd = &col.pADsValues->SecurityDescriptor;
								char* s = NULL;
								if(ConvertSidToStringSid((PSID)psd->lpValue, &s))
								{
									dprintf("[EXTAPI ADSI] converted SID: %s", s);
									met_api->packet.add_tlv_string(pGroup, TLV_TYPE_EXT_ADSI_STRING, s);
									LocalFree(s);
								}
								else
								{
									dprintf("[EXTAPI ADSI] byte SID");
									met_api->packet.add_tlv_raw(pGroup, TLV_TYPE_EXT_ADSI_RAW, psd->lpValue, psd->dwLength);
								}
								break;
							}
							case ADSTYPE_DN_WITH_BINARY:
							{
								Packet* pDnGroup = met_api->packet.create_group();
								PADS_DN_WITH_BINARY pdb = col.pADsValues->pDNWithBinary;

								dprintf("[ADSI] DN with string");

								met_api->packet.add_tlv_wstring(pDnGroup, TLV_TYPE_EXT_ADSI_STRING, pdb->pszDNString);
								met_api->packet.add_tlv_raw(pDnGroup, TLV_TYPE_EXT_ADSI_RAW, pdb->lpBinaryValue, pdb->dwLength);
								met_api->packet.add_group(pGroup, TLV_TYPE_EXT_ADSI_DN, pDnGroup);

								break;
							}
							case ADSTYPE_DN_WITH_STRING:
							{
								Packet* pDnGroup = met_api->packet.create_group();
								PADS_DN_WITH_STRING pds = col.pADsValues->pDNWithString;

								dprintf("[ADSI] DN with string");

								met_api->packet.add_tlv_wstring(pDnGroup, TLV_TYPE_EXT_ADSI_STRING, pds->pszDNString);
								met_api->packet.add_tlv_wstring(pDnGroup, TLV_TYPE_EXT_ADSI_STRING, pds->pszStringValue);
								met_api->packet.add_group(pGroup, TLV_TYPE_EXT_ADSI_DN, pDnGroup);

								break;
							}
							case ADSTYPE_FAXNUMBER:
							case ADSTYPE_REPLICAPOINTER:
							default:
							{
								// this is a string of some kind
								dprintf("[ADSI] Unhandled ADSI type %u (%x), adding unknown", col.dwADsType, col.dwADsType);
								sprintf_s(value, VALUE_SIZE, "(unhandled ADSI type %u)", col.dwADsType);
								met_api->packet.add_tlv_string(pGroup, TLV_TYPE_EXT_ADSI_STRING, value);
								break;
							}
						}

						pDirSearch->FreeColumn(&col);
					}
					else
					{
						dprintf("[ADSI] Col read failed: %x", hr);
						met_api->packet.add_tlv_string(pGroup, TLV_TYPE_EXT_ADSI_STRING, "");
					}

					dwIndex++;
				}

				if (dwIndex > 0)
				{
					dprintf("[ADSI] Adding group packet of %u values", dwIndex);
					// Throw the user details together in a group, ready to return.
					met_api->packet.add_group(response, TLV_TYPE_EXT_ADSI_RESULT, pGroup);
					dprintf("[ADSI] Added group packet of %u values", dwIndex);
				}
				else
				{
					dprintf("[ADSI] Item found, but no fields extracted.");
				}

				++rowsProcessed;
			}

			dprintf("[ADSI] Processed %u. Final result: %u (0x%x)", rowsProcessed, hResult, hResult);

			if (SUCCEEDED(hResult))
			{
				hResult = S_OK;
			}
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
	else
	{
		dprintf("[ADSI] Failed to initialize COM");
	}

	return (DWORD)hResult;
}
