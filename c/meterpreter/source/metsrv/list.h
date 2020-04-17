/*!
 * @file list.h
 * @brief Declarations for functions that operate on lists.
 */
#ifndef _METERPRETER_METSRV_LIST_H
#define _METERPRETER_METSRV_LIST_H

#include "common_list.h"

LIST * list_create(VOID);
VOID list_destroy(PLIST pList);
DWORD list_count(PLIST pList);
LPVOID list_get(PLIST pList, DWORD index);
BOOL list_clear(PLIST pList, PCLEARFUNC pFunc);
BOOL list_add(PLIST pList, LPVOID data);
BOOL list_remove(PLIST pList, LPVOID data);
BOOL list_remove_at(PLIST pList, DWORD index);
BOOL list_push(PLIST pList, LPVOID data);
LPVOID list_pop(PLIST pList);
LPVOID list_shift(PLIST pList);
BOOL list_enumerate(PLIST pList, PLISTENUMCALLBACK pCallback, LPVOID pState);

#endif