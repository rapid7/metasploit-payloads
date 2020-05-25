/*!
 * @file wmi_interface.h
 * @brief Declarations for functions that deal directly with WMI
 *        via the COM interfaces (hence the .cpp extension).
 */
extern "C" {
#include "extapi.h"
#include "common_metapi.h"
#include <inttypes.h>
#include "wmi_interface.h"
}
#include <wbemcli.h>
#include <comutil.h>
#include <comdef.h>

#define FIELD_SIZE 1024
#define ENUM_TIMEOUT 5000

/*! The number of fields to ignore at the start of the query, which we aren't interested in.
 *  For some reason there's one more system field in x64 than there is in x86. */
#ifdef _WIN64
#define SYSTEM_FIELD_COUNT 9
#else
#define SYSTEM_FIELD_COUNT 8
#endif

#ifdef __MINGW32__
// Provide custom implmentations of the BSTR conversion
// functions because comsuppw.lib is a proprietary lib
// that comes with Vis Studio
namespace _com_util
{
	inline BSTR ConvertStringToBSTR(const char* pSrc)
	{
		if(!pSrc)
		{
			return NULL;
		}

		DWORD cwch;
		BSTR wsOut(NULL);

		if(cwch = ::MultiByteToWideChar(CP_ACP, 0, pSrc, -1, NULL, 0))
		{
			cwch--;
			wsOut = ::SysAllocStringLen(NULL, cwch);

			if(wsOut)
			{
				if(!::MultiByteToWideChar(CP_ACP, 0, pSrc, -1, wsOut, cwch))
				{
					if(ERROR_INSUFFICIENT_BUFFER == ::GetLastError())
					{
						return wsOut;
					}
					::SysFreeString(wsOut);//must clean up
					wsOut = NULL;
				}
			}
		}

		return wsOut;
	}

	inline char* ConvertBSTRToString(BSTR pSrc)
	{
		if(!pSrc)
		{
			return NULL;
		}

		//convert even embeded NULL
		DWORD cb,cwch = ::SysStringLen(pSrc);

		char *szOut = NULL;

		if(cb = ::WideCharToMultiByte(CP_ACP, 0, pSrc, cwch + 1, NULL, 0, 0, 0))
		{
			szOut = new char[cb];
			if(szOut)
			{
				szOut[cb - 1]  = '\0';

				if(!::WideCharToMultiByte(CP_ACP, 0, pSrc, cwch + 1, szOut, cb, 0, 0))
				{
					delete []szOut;//clean up if failed;
					szOut = NULL;
				}
			}
		}

		return szOut;
	}
}
#endif

/*!
 * @brief Convert a variant type to a string and write it to the given buffer.
 * @param v The variant to convert.
 * @param buffer Pointer to the buffer to write the value to.
 * @param bufferSize size of the buffer.
 * @returns Pointer to the next location in the buffer.
 * @remarks This attempts to "flatten" a variant, including array types. The implementation is
 *          not 100% complete, but is good enough for the sake of this requirement. Only arrays
 *          of BSTR are currenty supported, more types can be added later if needed. Arbitrary
 *          array depth has been attempted, but no tests have yet found a nested array in the
 *          result set. There's probably bugs in that bit.
 */
char* variant_to_string(const _variant_t& v, char* buffer, DWORD bufferSize)
{
	dprintf("[WMI] preparing to parse variant of type %u (%x), buffer size %u", v.vt, v.vt, bufferSize);

	switch (v.vt)
	{
	case VT_EMPTY:
		strncpy_s(buffer, bufferSize, "(EMPTY)", bufferSize - 1);
		break;
	case VT_NULL:
		strncpy_s(buffer, bufferSize, "(NULL)", bufferSize - 1);
		break;
	case VT_BOOL:
		strncpy_s(buffer, bufferSize, v.boolVal == VARIANT_TRUE ? "true" : "false", bufferSize - 1);
		break;
	case VT_I1:
		_snprintf_s(buffer, bufferSize, bufferSize - 1, "%" PRId8, (CHAR)v);
		break;
	case VT_I2:
		_snprintf_s(buffer, bufferSize, bufferSize - 1, "%" PRId16, (SHORT)v);
		break;
	case VT_INT:
	case VT_I4:
		_snprintf_s(buffer, bufferSize, bufferSize - 1, "%" PRId32, (INT)v);
		break;
	case VT_INT_PTR:
		_snprintf_s(buffer, bufferSize, bufferSize - 1, "%" PRIdPTR, (INT_PTR)v);
		break;
	case VT_I8:
		_snprintf_s(buffer, bufferSize, bufferSize - 1, "%" PRId64, (__int64)v);
		break;
	case VT_UI1:
		_snprintf_s(buffer, bufferSize, bufferSize - 1, "%" PRIu8, (BYTE)v);
		break;
	case VT_UI2:
		_snprintf_s(buffer, bufferSize, bufferSize - 1, "%" PRIu16, (SHORT)v);
		break;
	case VT_UINT:
	case VT_UI4:
		_snprintf_s(buffer, bufferSize, bufferSize - 1, "%" PRIu32, (UINT)v);
		break;
	case VT_UINT_PTR:
		_snprintf_s(buffer, bufferSize, bufferSize - 1, "%" PRIuPTR, (UINT_PTR)v);
		break;
	case VT_UI8:
		_snprintf_s(buffer, bufferSize, bufferSize - 1, "%" PRIu64, (unsigned __int64)v);
		break;
	case VT_BSTR:
	case VT_LPSTR:
	case VT_LPWSTR:
		// not sure if this is correct
		strncpy_s(buffer, bufferSize, (char*)(_bstr_t)v.bstrVal, bufferSize - 1);
		break;
		// TODO more types, such as floats, dates, etc.
	default:
		if ((v.vt & VT_ARRAY) == VT_ARRAY)
		{
			// nested array type, great.
			dprintf("[WMI] array type found!");
			LPSAFEARRAY array = v.parray;
			HRESULT hResult;

			if (FAILED(hResult = SafeArrayLock(array)))
			{
				dprintf("[WMI] Failed to get array dimension: %x", hResult);
				break;
			}
			dprintf("[WMI] Field name array locked.");

			LONG* indices = NULL;
			LONG* bounds = NULL;
			do
			{
				VARTYPE varType;
				SafeArrayGetVartype(array, &varType);
				dprintf("[WMI] Array type %u (%x)", (ULONG)varType, (ULONG)varType);
				dprintf("[WMI] Array dimensions: %u", SafeArrayGetDim(array));

				LONG iterations = 1;
				LONG dim = SafeArrayGetDim(array);
				indices = (LONG*)malloc(dim * sizeof(LONG));
				bounds = (LONG*)malloc(dim * sizeof(LONG) * 2);
				memset(indices, 0, dim * sizeof(LONG));
				memset(bounds, 0, dim * sizeof(LONG) * 2);

				for (LONG i = 0; i < dim; ++i)
				{
					LONG* lBound = bounds + i * 2;
					LONG* uBound = lBound + 1;
					if (FAILED(hResult = SafeArrayGetLBound(array, i + 1, lBound))
						|| FAILED(hResult = SafeArrayGetUBound(array, i + 1, uBound)))
					{
						dprintf("[WMI] Failed to get array dimensions: %x", hResult);
						break;
					}
					dprintf("[WMI] Array bounds: %u to %u", *lBound, *uBound);

					iterations *= *uBound - *lBound;
					indices[i] = *lBound;
				}
				dprintf("[WMI] Array requires %u iterations", iterations);

				// we're going to wrap our array elements in brackets, and separate with pipes
				// because we need some kind of array visualisation and this is the best I could
				// come up with at this time of night. Each dimension nests in a new set of brackets
				while (iterations-- > 0)
				{
					for (LONG i = 0; i < dim; ++i)
					{
						if (indices[i] == 0)
						{
							// save space for the closing bracket as well
							bufferSize -= 2;
							*buffer++ = '{';
							dprintf("[WMI] opening bracket for dimension %u", i);
						}
						else if(*(buffer - 1) != '|')
						{
							--bufferSize;
							*buffer++ = '|';
						}
					}

					dprintf("[WMI] extracting value for iteration %u", iterations);
					switch (varType)
					{
					case VT_BSTR:
						BSTR val;
						if (SUCCEEDED(SafeArrayGetElement(array, indices, (void*)&val)))
						{
							dprintf("[WMI] Value extracted for iteration %u", iterations);
							char* newBuf = variant_to_string(_variant_t(val), buffer, bufferSize);
							bufferSize -= (LONG)(newBuf - buffer + 1);
							buffer = newBuf;
							dprintf("[WMI] Value added", iterations);
						}
						break;
					default:
						dprintf("[WMI] Unsupported nested array type %u", (LONG)varType);
						break;
					}

					++indices[dim - 1];
					for (LONG i = dim - 1; i >= 0; --i)
					{
						if (indices[i] == bounds[i * 2 + 1])
						{
							dprintf("[WMI] closing bracket for dimension %u", i);
							*buffer++ = '}';
							indices[i] = bounds[i * 2];
							if (i > 0)
							{
								++indices[i - 1];
							}
						}
					}
				}
			} while (0);

			if (indices)
			{
				free(indices);
			}
			if (bounds)
			{
				free(bounds);
			}

			SafeArrayUnlock(array);
		}
		else
		{
			dprintf("[WMI] Unhandled type: %u (%x)", v.vt, v.vt);
		}
		// ignore the buffer for other types
		break;
	}

	// return wherever we go to.
	return buffer + strlen(buffer);
}

/*!
 * @brief Perform a WMI query.
 * @param lpwRoot Name of the root object that is to be queried against.
 * @param lpwQuery The filter to use when reading objects (LDAP style).
 * @param response The response \c Packet to add the results to.
 */
DWORD wmi_query(LPCWSTR lpwRoot, LPWSTR lpwQuery, Packet* response)
{
	HRESULT hResult;

	dprintf("[WMI] Initialising COM");
	if ((hResult = CoInitializeEx(NULL, COINIT_MULTITHREADED)) == S_OK)
	{
		dprintf("[WMI] COM initialised");
		IWbemLocator* pLocator = NULL;
		IWbemServices* pServices = NULL;
		IEnumWbemClassObject* pEnumerator = NULL;
		IWbemClassObject* pSuperClass = NULL;
		IWbemClassObject* pObj = NULL;
		VARIANT** fields = NULL;

		do
		{
			if (FAILED(hResult = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, 0)))
			{
				dprintf("[WMI] Failed to initialize security: %x", hResult);
				break;
			}
			dprintf("[WMI] Security initialised");

			if (FAILED(hResult = CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_ALL, IID_PPV_ARGS(&pLocator))))
			{
				dprintf("[WMI] Failed to create WbemLocator: %x", hResult);
				break;
			}
			dprintf("[WMI] WbemLocator created.");

			if (FAILED(hResult = pLocator->ConnectServer(_bstr_t(lpwRoot), NULL, NULL, NULL, WBEM_FLAG_CONNECT_USE_MAX_WAIT, NULL, NULL, &pServices)))
			{
				dprintf("[WMI] Failed to create WbemServices at %S: %x", lpwRoot, hResult);
				break;
			}
			dprintf("[WMI] WbemServices created.");

			if (FAILED(hResult = pServices->ExecQuery(L"WQL", lpwQuery, WBEM_FLAG_FORWARD_ONLY, NULL, &pEnumerator)))
			{
				dprintf("[WMI] Failed to create Enumerator for query %S: %x", lpwQuery, hResult);
				break;
			}
			dprintf("[WMI] Enumerated created.");

			ULONG numFound;
			if (FAILED(hResult = pEnumerator->Next(ENUM_TIMEOUT, 1, &pObj, &numFound)))
			{
				dprintf("[WMI] Failed to get the first query element: %x", lpwQuery, hResult);
				break;
			}
			dprintf("[WMI] First result read. hr=%x p=%p", hResult, pObj);

			if (hResult == WBEM_S_FALSE)
			{
				// this is not an error
				dprintf("[WMI] No results found!");
				break;
			}

			// get the names of the fields out of the first object before doing anything else.
			LPSAFEARRAY pFieldArray = NULL;
			if (FAILED(hResult = pObj->GetNames(NULL, WBEM_FLAG_ALWAYS, NULL, &pFieldArray)))
			{
				dprintf("[WMI] Failed to get field names: %x", hResult);
				break;
			}
			dprintf("[WMI] Field Names extracted. hr=%x p=%p", hResult, pFieldArray);

			// lock the array
			if (FAILED(hResult = SafeArrayLock(pFieldArray)))
			{
				dprintf("[WMI] Failed to get array dimension: %x", hResult);
				break;
			}
			dprintf("[WMI] Field name array locked.");

			do
			{
				dprintf("[WMI] Array dimensions: %u", SafeArrayGetDim(pFieldArray));

				// this array is just one dimension, let's get the bounds of the first dimension
				LONG lBound, uBound;
				if (FAILED(hResult = SafeArrayGetLBound(pFieldArray, 1, &lBound))
					|| FAILED(hResult = SafeArrayGetUBound(pFieldArray, 1, &uBound)))
				{
					dprintf("[WMI] Failed to get array dimensions: %x", hResult);
					break;
				}
				dprintf("[WMI] Bounds: %u to %u", lBound, uBound);

				LONG fieldCount = uBound - lBound - SYSTEM_FIELD_COUNT;
#ifndef _WIN64
				// on x86 the array bounds behave differently as the uBound is actually EXCLUSIVE
				// of the last value and not INCLUSIVE
				fieldCount -= 1;
#endif
				dprintf("[WMI] Query results in %u fields", fieldCount);

				VARIANT** fields = (VARIANT**)malloc(sizeof(VARIANT*) * fieldCount);
				char value[FIELD_SIZE];
				Packet* fieldGroup = met_api->packet.create_group();

				memset(fields, 0, sizeof(VARIANT*) * fieldCount);

				for (LONG i = 0; i < fieldCount; ++i)
				{
					LONG indices[1] = { i + SYSTEM_FIELD_COUNT };
					SafeArrayPtrOfIndex(pFieldArray, indices, (void**)&fields[i]);
					_bstr_t bstr(fields[i]->bstrVal);

					met_api->packet.add_tlv_string(fieldGroup, TLV_TYPE_EXT_WMI_FIELD, (const char*)bstr);

					dprintf("[WMI] Added header field: %s", (const char*)bstr);
				}

				dprintf("[WMI] added all field headers");
				// add the field names to the packet
				met_api->packet.add_group(response, TLV_TYPE_EXT_WMI_FIELDS, fieldGroup);

				dprintf("[WMI] processing values...");
				// with that horrible pain out of the way, let's actually grab the data
				do
				{
					if (FAILED(hResult))
					{
						dprintf("[WMI] Loop exited via %x", hResult);
						break;
					}

					Packet* valueGroup = met_api->packet.create_group();

					for (LONG i = 0; i < fieldCount; ++i)
					{
						memset(value, 0, FIELD_SIZE);

						VARIANT varValue;
						VariantInit(&varValue);

						_bstr_t field(fields[i]->bstrVal);

						dprintf("[WMI] Extracting value for %s", (char*)field);
						if (SUCCEEDED(pObj->Get(field, 0, &varValue, NULL, NULL)))
						{
							variant_to_string(_variant_t(varValue), value, FIELD_SIZE);
						}

						met_api->packet.add_tlv_string(valueGroup, TLV_TYPE_EXT_WMI_VALUE, value);

						dprintf("[WMI] Added value for %s: %s", (char*)_bstr_t(fields[i]->bstrVal), value);
					}

					// add the field values to the packet
					met_api->packet.add_group(response, TLV_TYPE_EXT_WMI_VALUES, valueGroup);

					pObj->Release();
					pObj = NULL;
				} while ((hResult = pEnumerator->Next(ENUM_TIMEOUT, 1, &pObj, &numFound)) != WBEM_S_FALSE);

			} while (0);

			SafeArrayUnlock(pFieldArray);
		} while (0);

		if (fields)
		{
			free(fields);
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

		if (SUCCEEDED(hResult))
		{
			hResult = S_OK;
			dprintf("[WMI] Things appeared to go well!");
		}
	}
	else
	{
		dprintf("[WMI] Failed to initialize COM");
	}

	if (FAILED(hResult))
	{
		// if we failed, we're going to convert the error to a string, add it and still return success, but we'll
		// also include the hresult.
		char errorMessage[1024];
		memset(errorMessage, 0, 1024);
		_com_error comError(hResult);
		_snprintf_s(errorMessage, 1024, 1023, "%s (0x%x)", comError.ErrorMessage(), hResult);
		dprintf("[WMI] returning error -> %s", errorMessage);
		met_api->packet.add_tlv_string(response, TLV_TYPE_EXT_WMI_ERROR, errorMessage);
		hResult = S_OK;
	}

	return (DWORD)hResult;
}
