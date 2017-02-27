/*************************************************************************************
*  Author: Jeff Tang <jtang@cylance.com>
*  Copyright (c) 2017 Cylance Inc. All rights reserved.                              *
*                                                                                    *
*  Redistribution and use in source and binary forms, with or without modification,  *
*  are permitted provided that the following conditions are met:                     *
*                                                                                    *
*  1. Redistributions of source code must retain the above copyright notice, this    *
*  list of conditions and the following disclaimer.                                  *
*                                                                                    *
*  2. Redistributions in binary form must reproduce the above copyright notice,      *
*  this list of conditions and the following disclaimer in the documentation and/or  *
*  other materials provided with the distribution.                                   *
*                                                                                    *
*  3. Neither the name of the copyright holder nor the names of its contributors     *
*  may be used to endorse or promote products derived from this software without     *
*  specific prior written permission.                                                *
*                                                                                    *
*  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND   *
*  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED     *
*  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE            *
*  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR  *
*  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES    *
*  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;      *
*  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON    *
*  ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT           *
*  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS     *
*  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.                      *
*                                                                                    *
*************************************************************************************/
#include "apisetmap.h"

_PPEB GetProcessEnvironmentBlock()
{
    ULONG_PTR pPeb;
#ifdef _WIN64
    pPeb = __readgsqword(0x60);
#else
    pPeb = __readfsdword(0x30);
#endif
    return (_PPEB)pPeb;
}

PLDR_DATA_TABLE_ENTRY GetInMemoryOrderModuleList()
{
    return (PLDR_DATA_TABLE_ENTRY)GetProcessEnvironmentBlock()->pLdr->InMemoryOrderModuleList.Flink;
}

PCHAR GetRedirectedName(PCHAR szOriginalModule, PCHAR szRedirectedModule)
{
    PAPI_SET_NAMESPACE_ARRAY_V2 pApiSetMap;
	pApiSetMap = (PAPI_SET_NAMESPACE_ARRAY_V2)GetProcessEnvironmentBlock()->pFreeList;

    if (pApiSetMap->Version == 6)
        return GetRedirectedName_V6(szOriginalModule, szRedirectedModule);
    else if (pApiSetMap->Version == 4)
        return GetRedirectedName_V4(szOriginalModule, szRedirectedModule);
    else if (pApiSetMap->Version == 2)
        return GetRedirectedName_V2(szOriginalModule, szRedirectedModule);
    else
        return NULL;
}

PCHAR GetRedirectedName_V6(PCHAR szOriginalModule, PCHAR szRedirectedModule)
{
    PAPI_SET_NAMESPACE_ARRAY_V6 pApiSetMap;
    PAPI_SET_NAMESPACE_ENTRY_V6 pApiEntry;
    PAPI_SET_VALUE_ENTRY_V6 pApiValue;
    DWORD dwEntryCount;
    DWORD dwSetCount;
    PCHAR szEntry;
    PCHAR szName;
    PCHAR szValue;

	pApiSetMap = (PAPI_SET_NAMESPACE_ARRAY_V6)GetProcessEnvironmentBlock()->pFreeList;

    // Loop through each entry in the ApiSetMap to find the matching redirected module entry
    for (dwEntryCount = 0; dwEntryCount < pApiSetMap->Count; dwEntryCount++)
    {
        pApiEntry = &pApiSetMap->Array[dwEntryCount];
        szEntry = wcstocs_((PWSTR)((PCHAR)pApiSetMap + pApiEntry->NameOffset), pApiEntry->NameLength / 2);

        // Skip this entry if it does not match
        if (strnicmp_(szEntry, szRedirectedModule, pApiEntry->NameLength / 2))
        {
            free_(szEntry);
            continue;
        }

        free_(szEntry);

        // Loop through each value entry and find where name == original module
        for (dwSetCount = pApiEntry->Count - 1; dwSetCount >= 0; dwSetCount--)
        {
            pApiValue = (PAPI_SET_VALUE_ENTRY_V6)((PCHAR)pApiSetMap + pApiEntry->DataOffset + (dwSetCount * sizeof(API_SET_VALUE_ENTRY_V6)));
            szName = wcstocs_((PWSTR)((PCHAR)pApiSetMap + pApiValue->NameOffset), pApiValue->NameLength / 2);
            szValue = wcstocs_((PWSTR)((PCHAR)pApiSetMap + pApiValue->ValueOffset), pApiValue->ValueLength / 2);

            if (pApiValue->NameLength == 0 || stricmp_(szName, szOriginalModule) == 0)
            {
                OUTPUTDBGA("\t\t\t[*] Found a matching entry: ");
                OUTPUTDBGA(szValue);
                OUTPUTDBGA("\n");

                free_(szName);
                return szValue;
            }

            free_(szName);
            free_(szValue);
        }
    }

    return NULL;
}
PCHAR GetRedirectedName_V4(PCHAR szOriginalModule, PCHAR szRedirectedModule)
{
    PAPI_SET_NAMESPACE_ARRAY_V4 pApiSetMap;
    PAPI_SET_NAMESPACE_ENTRY_V4 pApiEntry;
    PAPI_SET_VALUE_ARRAY_V4 pApiArray;
    PAPI_SET_VALUE_ENTRY_V4 pApiValue;
    DWORD dwEntryCount;
    DWORD dwSetCount;
    PCHAR szEntry;
    PCHAR szName;
    PCHAR szValue;

	pApiSetMap = (PAPI_SET_NAMESPACE_ARRAY_V4)GetProcessEnvironmentBlock()->pFreeList;

    for (dwEntryCount = 0; dwEntryCount < pApiSetMap->Count; dwEntryCount++)
    {
        pApiEntry = &pApiSetMap->Array[dwEntryCount];
        szEntry = wcstocs_((PWSTR)((PCHAR)pApiSetMap + pApiEntry->NameOffset), pApiEntry->NameLength / 2);

        // Skip this entry if it does not match
        if (strnicmp_(szEntry, szRedirectedModule + 4, pApiEntry->NameLength / 2))
        {
            free_(szEntry);
            continue;
        }

        free_(szEntry);

        pApiArray = (PAPI_SET_VALUE_ARRAY_V4)((PCHAR)pApiSetMap + pApiEntry->DataOffset);

        for (dwSetCount = pApiArray->Count-1; dwSetCount >= 0; dwSetCount--)
        {
            pApiValue = &pApiArray->Array[dwSetCount];
            szName = wcstocs_((PWSTR)((PCHAR)pApiSetMap + pApiValue->NameOffset), pApiValue->NameLength / 2);
            szValue = wcstocs_((PWSTR)((PCHAR)pApiSetMap + pApiValue->ValueOffset), pApiValue->ValueLength / 2);

            if (pApiValue->NameLength == 0 || stricmp_(szName, szOriginalModule) == 0)
            {
                OUTPUTDBGA("\t\t\t[*] Found a matching entry: ");
                OUTPUTDBGA(szName);
                OUTPUTDBGA("\n");

                free_(szName);
                return szValue;
            }

            free_(szName);
            free_(szValue);
        }
    }

    return NULL;
}

PCHAR GetRedirectedName_V2(PCHAR szOriginalModule, PCHAR szRedirectedModule)
{
    PAPI_SET_NAMESPACE_ARRAY_V2 pApiSetMap;
    PAPI_SET_NAMESPACE_ENTRY_V2 pApiEntry;
    PAPI_SET_VALUE_ARRAY_V2 pApiArray;
    PAPI_SET_VALUE_ENTRY_V2 pApiValue;
    DWORD dwEntryCount;
    DWORD dwSetCount;
    PCHAR szEntry;
    PCHAR szName;
    PCHAR szValue;

	pApiSetMap = (PAPI_SET_NAMESPACE_ARRAY_V2)GetProcessEnvironmentBlock()->pFreeList;

    for (dwEntryCount = 0; dwEntryCount < pApiSetMap->Count; dwEntryCount++)
    {
        pApiEntry = &pApiSetMap->Array[dwEntryCount];
        szEntry = wcstocs_((PWSTR)((PCHAR)pApiSetMap + pApiEntry->NameOffset), pApiEntry->NameLength / 2);

        // Skip this entry if it does not match
        if (strnicmp_(szEntry, szRedirectedModule+4, pApiEntry->NameLength / 2))
        {
            free_(szEntry);
            continue;
        }

        free_(szEntry);

        pApiArray = (PAPI_SET_VALUE_ARRAY_V2)((PCHAR)pApiSetMap + pApiEntry->DataOffset);

        for (dwSetCount = pApiArray->Count-1; dwSetCount >= 0; dwSetCount--)
        {
            pApiValue = &pApiArray->Array[dwSetCount];
            szName = wcstocs_((PWSTR)((PCHAR)pApiSetMap + pApiValue->NameOffset), pApiValue->NameLength / 2);
            szValue = wcstocs_((PWSTR)((PCHAR)pApiSetMap + pApiValue->ValueOffset), pApiValue->ValueLength / 2);

            if (pApiValue->NameLength == 0 || stricmp_(szName, szOriginalModule) == 0)
            {
                OUTPUTDBGA("\t\t\t[*] Found a matching entry: ");
                OUTPUTDBGA(szName);
                OUTPUTDBGA("\n");

                free_(szName);
                return szValue;
            }

            free_(szName);
            free_(szValue);
        }
    }

    return NULL;
}
