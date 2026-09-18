#include "micro_coff.h"

#pragma pack(push, 1)
typedef struct _MicroCoffHeader
{
	WORD machine;
	WORD section_count;
	DWORD timestamp;
	DWORD symbol_offset;
	DWORD symbol_count;
	WORD optional_header_size;
	WORD characteristics;
} MicroCoffHeader;

typedef struct _MicroCoffSectionHeader
{
	BYTE name[8];
	DWORD virtual_size;
	DWORD virtual_address;
	DWORD raw_size;
	DWORD raw_offset;
	DWORD relocation_offset;
	DWORD line_offset;
	WORD relocation_count;
	WORD line_count;
	DWORD characteristics;
} MicroCoffSectionHeader;

typedef struct _MicroCoffRelocation
{
	DWORD offset;
	DWORD symbol_index;
	WORD type;
} MicroCoffRelocation;

typedef struct _MicroCoffSymbol
{
	union
	{
		BYTE name[8];
		DWORD name_words[2];
	} name;
	DWORD value;
	SHORT section_number;
	WORD type;
	BYTE storage_class;
	BYTE auxiliary_count;
} MicroCoffSymbol;
#pragma pack(pop)

static BOOL micro_coff_range(DWORD offset, DWORD size, DWORD total)
{
	return offset <= total && size <= total - offset;
}

static SIZE_T micro_coff_align(SIZE_T value, SIZE_T alignment)
{
	return (value + alignment - 1) & ~(alignment - 1);
}

static const MicroCoffHeader* micro_coff_header(const BYTE* object, DWORD object_size)
{
	const MicroCoffHeader* header;
	DWORD section_headers_size;

	if (object == NULL || object_size < sizeof(MicroCoffHeader))
	{
		return NULL;
	}
	header = (const MicroCoffHeader*)object;
#if defined(_WIN64)
	if (header->machine != IMAGE_FILE_MACHINE_AMD64)
#else
	if (header->machine != IMAGE_FILE_MACHINE_I386)
#endif
	{
		return NULL;
	}
	if (header->section_count == 0 || header->section_count > MICRO_COFF_MAX_SECTIONS || header->optional_header_size != 0)
	{
		return NULL;
	}
	if (header->section_count > (MAXDWORD - sizeof(MicroCoffHeader)) / sizeof(MicroCoffSectionHeader))
	{
		return NULL;
	}
	section_headers_size = header->section_count * sizeof(MicroCoffSectionHeader);
	if (!micro_coff_range(sizeof(MicroCoffHeader), section_headers_size, object_size))
	{
		return NULL;
	}
	if (header->symbol_count > MAXDWORD / sizeof(MicroCoffSymbol) || !micro_coff_range(header->symbol_offset, header->symbol_count * sizeof(MicroCoffSymbol), object_size))
	{
		return NULL;
	}
	return header;
}

static const MicroCoffSectionHeader* micro_coff_sections(const BYTE* object)
{
	return (const MicroCoffSectionHeader*)(object + sizeof(MicroCoffHeader));
}

static const MicroCoffSymbol* micro_coff_symbols(const BYTE* object, const MicroCoffHeader* header)
{
	return (const MicroCoffSymbol*)(object + header->symbol_offset);
}

static const char* micro_coff_symbol_name(const BYTE* object, DWORD object_size, const MicroCoffHeader* header, const MicroCoffSymbol* symbol)
{
	DWORD string_offset;
	DWORD string_size;
	const BYTE* string_table;

	if (symbol->name.name_words[0] != 0)
	{
		return (const char*)symbol->name.name;
	}
	string_offset = symbol->name.name_words[1];
	if (header->symbol_count > MAXDWORD / sizeof(MicroCoffSymbol))
	{
		return NULL;
	}
	string_table = object + header->symbol_offset + header->symbol_count * sizeof(MicroCoffSymbol);
	if (!micro_coff_range((DWORD)(string_table - object), sizeof(DWORD), object_size))
	{
		return NULL;
	}
	string_size = *(const DWORD*)string_table;
	if (string_size < sizeof(DWORD) || !micro_coff_range((DWORD)(string_table - object), string_size, object_size) || string_offset < sizeof(DWORD) || string_offset >= string_size)
	{
		return NULL;
	}
	return (const char*)(string_table + string_offset);
}

static BOOL micro_coff_name_matches(const char* symbol_name, const char* expected, BOOL short_name)
{
	DWORD index;
	DWORD limit = short_name ? 8 : MAXDWORD;
	for (index = 0; index < limit && expected[index] != '\0'; index++)
	{
		if (symbol_name[index] != expected[index])
		{
			return FALSE;
		}
	}
	return expected[index] == '\0' && (index == limit || symbol_name[index] == '\0');
}

static PBYTE micro_coff_symbol_address(MicroCoffImage* image, const MicroCoffSymbol* symbol)
{
	if (symbol->section_number == IMAGE_SYM_ABSOLUTE)
	{
		return (PBYTE)(ULONG_PTR)symbol->value;
	}
	if (symbol->section_number <= 0 || symbol->section_number > (SHORT)image->section_count || symbol->value >= image->section_sizes[symbol->section_number - 1])
	{
		return NULL;
	}
	return image->sections[symbol->section_number - 1] + symbol->value;
}

static DWORD micro_coff_relocate(MicroCoffImage* image, const BYTE* object, DWORD object_size, const MicroCoffHeader* header)
{
	const MicroCoffSectionHeader* sections = micro_coff_sections(object);
	const MicroCoffSymbol* symbols = micro_coff_symbols(object, header);
	DWORD section_index;

	for (section_index = 0; section_index < header->section_count; section_index++)
	{
		const MicroCoffSectionHeader* section = &sections[section_index];
		DWORD relocations_size = section->relocation_count * sizeof(MicroCoffRelocation);
		const MicroCoffRelocation* relocations;
		DWORD relocation_index;

		if (section->relocation_count > MAXDWORD / sizeof(MicroCoffRelocation) || !micro_coff_range(section->relocation_offset, relocations_size, object_size))
		{
			return ERROR_BAD_EXE_FORMAT;
		}
		relocations = (const MicroCoffRelocation*)(object + section->relocation_offset);

		for (relocation_index = 0; relocation_index < section->relocation_count; relocation_index++)
		{
			const MicroCoffRelocation* relocation = &relocations[relocation_index];
			const MicroCoffSymbol* symbol;
			PBYTE symbol_address;
			PBYTE relocation_address;
			LONG_PTR relative;

			if (relocation->symbol_index >= header->symbol_count || relocation->offset >= image->section_sizes[section_index])
			{
				return ERROR_BAD_EXE_FORMAT;
			}
			symbol = &symbols[relocation->symbol_index];
			symbol_address = micro_coff_symbol_address(image, symbol);
			if (symbol_address == NULL)
			{
				return ERROR_PROC_NOT_FOUND;
			}
			relocation_address = image->sections[section_index] + relocation->offset;

#if defined(_WIN64)
			if (relocation->type == IMAGE_REL_AMD64_ADDR64)
			{
				if (image->section_sizes[section_index] < sizeof(ULONGLONG) || relocation->offset > image->section_sizes[section_index] - sizeof(ULONGLONG))
				{
					return ERROR_BAD_EXE_FORMAT;
				}
				*(ULONGLONG*)relocation_address += (ULONGLONG)symbol_address;
			}
			else if (relocation->type >= IMAGE_REL_AMD64_REL32 && relocation->type <= IMAGE_REL_AMD64_REL32_5)
			{
				if (image->section_sizes[section_index] < sizeof(LONG) || relocation->offset > image->section_sizes[section_index] - sizeof(LONG))
				{
					return ERROR_BAD_EXE_FORMAT;
				}
				relative = symbol_address - (relocation_address + sizeof(LONG) + relocation->type - IMAGE_REL_AMD64_REL32);
				if (relative < -0x80000000LL || relative > 0x7fffffffLL)
				{
					return ERROR_BAD_EXE_FORMAT;
				}
				*(LONG*)relocation_address += (LONG)relative;
			}
			else
			{
				return ERROR_NOT_SUPPORTED;
			}
#else
			if (relocation->type == IMAGE_REL_I386_DIR32)
			{
				if (image->section_sizes[section_index] < sizeof(DWORD) || relocation->offset > image->section_sizes[section_index] - sizeof(DWORD))
				{
					return ERROR_BAD_EXE_FORMAT;
				}
				*(DWORD*)relocation_address += (DWORD)(ULONG_PTR)symbol_address;
			}
			else if (relocation->type == IMAGE_REL_I386_REL32)
			{
				if (image->section_sizes[section_index] < sizeof(LONG) || relocation->offset > image->section_sizes[section_index] - sizeof(LONG))
				{
					return ERROR_BAD_EXE_FORMAT;
				}
				relative = symbol_address - (relocation_address + sizeof(LONG));
				*(LONG*)relocation_address += (LONG)relative;
			}
			else
			{
				return ERROR_NOT_SUPPORTED;
			}
#endif
		}
	}
	return ERROR_SUCCESS;
}

DWORD micro_coff_load(const BYTE* object, DWORD object_size, MicroCoffImage** result)
{
	const MicroCoffHeader* header = micro_coff_header(object, object_size);
	const MicroCoffSectionHeader* sections;
	MicroCoffImage* image = NULL;
	SIZE_T image_size = 0;
	DWORD section_index;
	DWORD error = ERROR_BAD_EXE_FORMAT;

	if (result == NULL || header == NULL)
	{
		return ERROR_BAD_EXE_FORMAT;
	}
	*result = NULL;
	sections = micro_coff_sections(object);
	image = (MicroCoffImage*)calloc(1, sizeof(MicroCoffImage));
	if (image == NULL)
	{
		return ERROR_NOT_ENOUGH_MEMORY;
	}
	for (section_index = 0; section_index < header->section_count; section_index++)
	{
		DWORD size = max(sections[section_index].raw_size, sections[section_index].virtual_size);
		if (size == 0)
		{
			size = 1;
		}
		if (image_size > MAXDWORD - micro_coff_align(size, 0x1000))
		{
			goto cleanup;
		}
		image->section_sizes[section_index] = size;
		image->section_characteristics[section_index] = sections[section_index].characteristics;
		image_size += micro_coff_align(size, 0x1000);
	}
	image->base = (PBYTE)met_api->win_api.kernel32.VirtualAlloc(NULL, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (image->base == NULL)
	{
		error = ERROR_NOT_ENOUGH_MEMORY;
		goto cleanup;
	}
	image->size = image_size;
	image->section_count = header->section_count;
	image_size = 0;
	for (section_index = 0; section_index < header->section_count; section_index++)
	{
		image->sections[section_index] = image->base + image_size;
		if (sections[section_index].raw_offset != 0 && sections[section_index].raw_size != 0)
		{
			if (!micro_coff_range(sections[section_index].raw_offset, sections[section_index].raw_size, object_size))
			{
				goto cleanup;
			}
			memcpy(image->sections[section_index], object + sections[section_index].raw_offset, sections[section_index].raw_size);
		}
		image_size += micro_coff_align(image->section_sizes[section_index], 0x1000);
	}

	error = micro_coff_relocate(image, object, object_size, header);
	if (error != ERROR_SUCCESS)
	{
		goto cleanup;
	}
	for (section_index = 0; section_index < header->section_count; section_index++)
	{
		DWORD old_protection;
		DWORD characteristics = image->section_characteristics[section_index];
		DWORD protection = (characteristics & IMAGE_SCN_MEM_EXECUTE) ? PAGE_EXECUTE_READ : ((characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY);
		if (!met_api->win_api.kernel32.VirtualProtect(image->sections[section_index], image->section_sizes[section_index], protection, &old_protection))
		{
			error = GetLastError();
			goto cleanup;
		}
	}
	FlushInstructionCache(GetCurrentProcess(), image->base, image->size);
	*result = image;
	return ERROR_SUCCESS;

cleanup:
	micro_coff_unload(image);
	return error;
}

PVOID micro_coff_symbol(MicroCoffImage* image, const BYTE* object, DWORD object_size, const char* name)
{
	const MicroCoffHeader* header = micro_coff_header(object, object_size);
	const MicroCoffSymbol* symbols;
	DWORD symbol_index;
	if (image == NULL || header == NULL || name == NULL)
	{
		return NULL;
	}
	symbols = micro_coff_symbols(object, header);
	for (symbol_index = 0; symbol_index < header->symbol_count; symbol_index++)
	{
		const MicroCoffSymbol* symbol = &symbols[symbol_index];
		const char* symbol_name = micro_coff_symbol_name(object, object_size, header, symbol);
		if (symbol_name != NULL && (micro_coff_name_matches(symbol_name, name, symbol->name.name_words[0] != 0)
#if !defined(_WIN64)
			|| (symbol->name.name_words[0] == 0 && symbol_name[0] == '_' && micro_coff_name_matches(symbol_name + 1, name, FALSE))
#endif
			))
		{
			return micro_coff_symbol_address(image, symbol);
		}
		symbol_index += symbol->auxiliary_count;
	}
	return NULL;
}

BOOL micro_coff_contains(MicroCoffImage* image, LPCVOID address, SIZE_T size)
{
	SIZE_T offset;
	if (image == NULL || address == NULL || (const BYTE*)address < image->base)
	{
		return FALSE;
	}
	offset = (const BYTE*)address - image->base;
	return offset <= image->size && size <= image->size - offset;
}

BOOL micro_coff_string(MicroCoffImage* image, LPCSTR value, SIZE_T maximum_length)
{
	SIZE_T length;
	if (!micro_coff_contains(image, value, 1))
	{
		return FALSE;
	}
	for (length = 0; length < maximum_length; length++)
	{
		if (!micro_coff_contains(image, value + length, 1))
		{
			return FALSE;
		}
		if (value[length] == '\0')
		{
			return TRUE;
		}
	}
	return FALSE;
}

VOID micro_coff_unload(MicroCoffImage* image)
{
	if (image != NULL)
	{
		if (image->base != NULL)
		{
			DWORD old_protection;
			if (met_api->win_api.kernel32.VirtualProtect(image->base, image->size, PAGE_READWRITE, &old_protection))
			{
				SecureZeroMemory(image->base, image->size);
			}
			met_api->win_api.kernel32.VirtualFree(image->base, 0, MEM_RELEASE);
		}
		free(image);
	}
}
