#ifndef _METERPRETER_METSRV_EXTENSION_LOADER_H
#define _METERPRETER_METSRV_EXTENSION_LOADER_H
#include "common.h"

typedef struct _BASE_RELOCATION_ENTRY {
	WORD	Offset : 12;  // Specifies where the base relocation is to be applied.
	WORD	Type : 4;   // Indicates the type of base relocation to be applied.
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

BOOL LoadReflectively(IN ULONG_PTR lpBuffer, OUT HMODULE* phModule);
#endif // _METERPRETER_METSRV_EXTENSION_LOADER_H