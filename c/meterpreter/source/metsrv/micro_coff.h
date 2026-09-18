#ifndef _METERPRETER_METSRV_MICRO_COFF_H
#define _METERPRETER_METSRV_MICRO_COFF_H

#include "metsrv.h"

#define MICRO_COFF_MAX_SECTIONS 32

typedef struct _MicroCoffImage
{
	PBYTE base;
	SIZE_T size;
	PBYTE sections[MICRO_COFF_MAX_SECTIONS];
	DWORD section_sizes[MICRO_COFF_MAX_SECTIONS];
	DWORD section_characteristics[MICRO_COFF_MAX_SECTIONS];
	DWORD section_count;
} MicroCoffImage;

DWORD micro_coff_load(const BYTE* object, DWORD object_size, MicroCoffImage** result);
PVOID micro_coff_symbol(MicroCoffImage* image, const BYTE* object, DWORD object_size, const char* name);
BOOL micro_coff_contains(MicroCoffImage* image, LPCVOID address, SIZE_T size);
BOOL micro_coff_string(MicroCoffImage* image, LPCSTR value, SIZE_T maximum_length);
VOID micro_coff_unload(MicroCoffImage* image);

#endif
