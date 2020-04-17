#ifndef _METERPRETER_COMMON_PIVOT_TREE_H
#define _METERPRETER_COMMON_PIVOT_TREE_H

typedef DWORD(*PivotWritePacket)(LPVOID state, LPBYTE rawPacket, DWORD rawPacketLength);
typedef DWORD(*PivotRemove)(LPVOID state);

typedef struct _PivotContext
{
	PivotWritePacket packet_write;
	PivotRemove remove;
	LPVOID state;
} PivotContext;

typedef struct _PivotNode PivotNode;

typedef struct _PivotTree
{
	PivotNode* head;
} PivotTree;

typedef void(*PivotTreeTraverseCallback)(LPBYTE guid, PivotContext* ctx, LPVOID state);

#endif
