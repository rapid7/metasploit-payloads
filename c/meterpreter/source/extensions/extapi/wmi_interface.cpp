/*!
 * @file wmi_interface.h
 * @brief Declarations for functions that deal directly with WMI
 *        via the COM interfaces (hence the .cpp extension).
 */
extern "C" {
#include "extapi.h"
#include <inttypes.h>
#include "wmi_interface.h"
}
#include <WbemCli.h>
#include <comutil.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "comsuppw.lib")

#define PATH_SIZE 512
#define FIELD_SIZE 512
#define ENUM_TIMEOUT 5000

/*! @brief The GUID of the Directory Search COM object. */
//static const IID IID_IDirectorySearch = { 0x109BA8EC, 0x92F0, 0x11D0, { 0xA7, 0x90, 0x00, 0xC0, 0x4F, 0xD8, 0xD5, 0xA8 } };

/*!
 * @brief Perform a WMI query.
 * @param lpwDomain Name of the domain that is to be queried.
 * @param lpwQuery The filter to use when reading objects (LDAP style).
 * @param response The response \c Packet to add the results to.
 */
DWORD wmi_query(LPCWSTR lpwDomain, LPWSTR lpwQuery, Packet* response)
{
	HRESULT hResult;
	WCHAR cbPath[PATH_SIZE];

	swprintf_s(cbPath, PATH_SIZE - 1, L"root\\%s", lpwDomain);

	if ((hResult = CoInitializeEx(NULL, COINIT_MULTITHREADED)) == S_OK)
	{
		IWbemLocator* pLocator = NULL;
		IWbemServices* pServices = NULL;
		IEnumWbemClassObject* pEnumerator = NULL;
		IWbemClassObject* pObj = NULL;
		Tlv* valueTlvs = NULL;
		char* values = NULL;
		VARIANT** fields = NULL;

		do
		{
			if (FAILED(hResult = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, 0)))
			{
				dprintf("[WMI] Failed to initialize security: %x", hResult);
				break;
			}

			if (FAILED(hResult = CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_ALL, IID_PPV_ARGS(&pLocator))))
			{
				dprintf("[WMI] Failed to create WbemLocator: %x", hResult);
				break;
			}

			if (FAILED(hResult = pLocator->ConnectServer(cbPath, NULL, NULL, NULL, WBEM_FLAG_CONNECT_USE_MAX_WAIT, NULL, NULL, &pServices)))
			{
				dprintf("[WMI] Failed to create WbemServices at %S: %x", cbPath, hResult);
				break;
			}

			if (FAILED(hResult = pServices->ExecQuery(L"WQL", lpwQuery, WBEM_FLAG_FORWARD_ONLY, NULL, &pEnumerator)))
			{
				dprintf("[WMI] Failed to create Enumerator for query %S: %x", lpwQuery, hResult);
				break;
			}

			ULONG numFound;
			if (FAILED(hResult = pEnumerator->Next(ENUM_TIMEOUT, 1, &pObj, &numFound)))
			{
				dprintf("[WMI] Failed to get the first query element: %x", lpwQuery, hResult);
				break;
			}

			// get the names of the fields out of the first object before doing anything else.
			LPSAFEARRAY pFieldArray = NULL;
			if (FAILED(hResult = pObj->GetNames(NULL, WBEM_FLAG_ALWAYS, NULL, &pFieldArray)))
			{
				dprintf("[WMI] Failed to get field names: %x", hResult);
				break;
			}

			// lock the array
			if (FAILED(hResult = SafeArrayLock(pFieldArray)))
			{
				dprintf("[WMI] Failed to get array dimension: %x", hResult);
				break;
			}

			do
			{
				dprintf("[WMI] Array dimensions: %u", SafeArrayGetDim(pFieldArray);

				// this array is just one dimension, let's get the bounds of the first dimension
				LONG lBound, uBound;
				if (FAILED(hResult = SafeArrayGetLBound(pFieldArray, 1, &lBound))
					|| FAILED(hResult = SafeArrayGetLBound(pFieldArray, 1, &uBound)))
				{
					dprintf("[WMI] Failed to get array dimensions: %x", hResult);
					break;
				}

				LONG fieldCount = uBound - lBound + 1;
				dprintf("[WMI] Query results in %u fields", fieldCount);

				fields = (VARIANT**)malloc(fieldCount * sizeof(VARIANT**));
				valueTlvs = (Tlv*)malloc(fieldCount * sizeof(Tlv));
				values = (char*)malloc(fieldCount * FIELD_SIZE);
				memset(fields, 0, fieldCount * sizeof(VARIANT**));
				memset(valueTlvs, 0, fieldCount * sizeof(Tlv));
				memset(values, 0, fieldCount * FIELD_SIZE);

				for (LONG i = 0; i < fieldCount; ++i)
				{
					char* fieldName = values + (i * FIELD_SIZE);
					LONG indices[2] = { 0, i };
					SafeArrayPtrOfIndex(pFieldArray, indices, (void**)&fields[i]);
					_bstr_t bstr(fields[i]->bstrVal);
					strncpy_s(fieldName, FIELD_SIZE, (const char*)bstr, FIELD_SIZE - 1);

					valueTlvs[i].header.type = TLV_TYPE_EXT_WMI_FIELD;
					valueTlvs[i].header.length = (UINT)strlen(fieldName) + 1;
					valueTlvs[i].buffer = (PUCHAR)fieldName;

					dprintf("[WMI] Added header field: %s", fieldName);
				}

				// add the field names to the packet
				packet_add_tlv_group(response, TLV_TYPE_EXT_WMI_FIELDS, valueTlvs, fieldCount);

				// with that horrible pain out of the way, let's actually grab the data
				do
				{
					if (FAILED(hResult))
					{
						break;
					}

					memset(valueTlvs, 0, fieldCount * sizeof(Tlv));
					memset(values, 0, fieldCount * FIELD_SIZE);

					for (LONG i = 0; i < fieldCount; ++i)
					{
						char* value = values + (i * FIELD_SIZE);
						valueTlvs[i].header.type = TLV_TYPE_EXT_WMI_VALUE;
						valueTlvs[i].buffer = (PUCHAR)value;

						VARIANT varValue;
						VariantInit(&varValue);

						_bstr_t field(fields[i]->bstrVal);
						if (SUCCEEDED(pObj->Get(field, 0, &varValue, NULL, NULL)))
						{
							_variant_t v(varValue);

							switch (v.vt)
							{
							case VT_BOOL:
								strncpy_s(value, FIELD_SIZE, v.boolVal == VARIANT_TRUE ? "true" : "false", FIELD_SIZE - 1);
								break;
							case VT_INT:
								_snprintf_s(value, FIELD_SIZE, FIELD_SIZE - 1, "%"PRId32, (INT)v);
								break;
							case VT_INT_PTR:
								_snprintf_s(value, FIELD_SIZE, FIELD_SIZE - 1, "%"PRId64, (INT_PTR)v);
								break;
							case VT_UINT:
								_snprintf_s(value, FIELD_SIZE, FIELD_SIZE - 1, "%"PRIu32, (UINT)v);
								break;
							case VT_UINT_PTR:
								_snprintf_s(value, FIELD_SIZE, FIELD_SIZE - 1, "%"PRIu64, (UINT_PTR)v);
								break;
							case VT_BSTR:
							case VT_LPSTR:
							case VT_LPWSTR:
								// not sure if this is correct
								strncpy_s(value, FIELD_SIZE, (char*)(_bstr_t)v.bstrVal, FIELD_SIZE - 1);
								break;
							// TODO more types, such as floats, dates, etc.
							default:
								// ignore the value for other types
								break;
							}
						}

						valueTlvs[i].header.length = (UINT)strlen(value) + 1;
						dprintf("[WMI] Added value for %s: %s", (char*)_bstr_t(fields[i]->bstrVal), value);
					}

					// add the field values to the packet
					packet_add_tlv_group(response, TLV_TYPE_EXT_WMI_VALUES, valueTlvs, fieldCount);

					pObj->Release();
					pObj = NULL;
				} while ((hResult = pEnumerator->Next(ENUM_TIMEOUT, 1, &pObj, &numFound)) != WBEM_S_FALSE);

			} while (0);

			SafeArrayUnlock(pFieldArray);

			if (SUCCEEDED(hResult))
			{
				hResult = S_OK;
			}
		} while (0);

		if (fields)
		{
			free(fields);
		}

		if (values)
		{
			free(values);
		}

		if (valueTlvs)
		{
			free(valueTlvs);
		}

		if (pObj)
		{
			pObj->Release();
		}

		if (pEnumerator)
		{
			pEnumerator->Release();
		}

		if (pServices)
		{
			pServices->Release();
		}

		if (pLocator)
		{
			pLocator->Release();
		}
		CoUninitialize();

		dprintf("[WMI] Things appeard to go well!");
	}
	else
	{
		dprintf("[WMI] Failed to initialize COM");
	}

	return (DWORD)hResult;
}
