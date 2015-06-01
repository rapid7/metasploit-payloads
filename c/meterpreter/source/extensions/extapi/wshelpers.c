/*!
 * @file wshelpers.h
 * @brief Declarations for wide-string helper functions.
 */
#include "extapi.h"
#include "wshelpers.h"

/*!
 * @brief Helper function that converts an ASCII string to a wide char string.
 * @param lpValue ASCII string to convert.
 * @param lpwValue Target memory for the converted string.
 * @remark \c lpwValue must be freed by the caller using `free`.
 * @returns Indication of success or failure.
 */
DWORD to_wide_string(LPSTR lpValue, LPWSTR* lpwValue)
{
	size_t charsCopied = 0;
	DWORD valueLength;
	DWORD dwResult;

	do
	{
		if (lpValue == NULL)
		{
			BREAK_WITH_ERROR("[EXTAPI ADSI] Value parameter missing", ERROR_INVALID_PARAMETER);
		}

		valueLength = lstrlenA(lpValue);
		*lpwValue = (LPWSTR)malloc(sizeof(WCHAR)* (lstrlenA(lpValue) + 1));
		if (*lpwValue == NULL)
		{
			BREAK_WITH_ERROR("[EXTAPI ADSI] Unable to allocate memory", ERROR_OUTOFMEMORY);
		}

		mbstowcs_s(&charsCopied, *lpwValue, valueLength + 1, lpValue, valueLength);
		dwResult = ERROR_SUCCESS;
	} while (0);

	return dwResult;
}
