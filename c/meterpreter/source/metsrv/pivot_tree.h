#ifndef _METERPRETER_METSRV_PIVOT_TREE_H
#define _METERPRETER_METSRV_PIVOT_TREE_H

#include "common_pivot_tree.h"

PivotTree* pivot_tree_create();
DWORD pivot_tree_add(PivotTree* tree, LPBYTE guid, PivotContext* ctx);
PivotContext* pivot_tree_remove(PivotTree* tree, LPBYTE guid);
PivotContext* pivot_tree_find(PivotTree* tree, LPBYTE guid);
void pivot_tree_traverse(PivotTree* tree, PivotTreeTraverseCallback callback, LPVOID state);
void pivot_tree_destroy(PivotTree* tree);


#ifdef DEBUGTRACE
void dbgprint_pivot_tree(PivotTree* tree);
#endif

#endif