#ifndef COFFLOADER_H_
#define COFFLOADER_H_
#include <stdio.h>
#include <stdint.h>
#include <windows.h>

/* These seem to be the same sizes across architectures, relocations are different though. Defined both sets of types. */

/* sizeof 20 */
typedef struct coff_file_header
{
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} coff_file_header_t;

/* AMD64  should always be here */
#define MACHINETYPE_AMD64 0x8664

#pragma pack(push, 1)

/* Size of 40 */
typedef struct coff_sect
{
    char Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLineNumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} coff_sect_t;

typedef struct coff_reloc
{
    uint32_t VirtualAddress;
    uint32_t SymbolTableIndex;
    uint16_t Type;
} coff_reloc_t;

typedef struct coff_sym
{
    union
    {
        char Name[8];
        uint32_t value[2];
    } first;
    uint32_t Value;
    uint16_t SectionNumber;
    uint16_t Type;
    uint8_t StorageClass;
    uint8_t NumberOfAuxSymbols;

} coff_sym_t;

uint32_t ProtectionFlags[8] = {
    PAGE_NOACCESS,          // not writeable, not readable, not executable
    PAGE_EXECUTE,           // not writeable, not readable, executable
    PAGE_READONLY,          // not writeable, readable, not executable
    PAGE_EXECUTE_READ,      // not writeable, readable, executable
    PAGE_WRITECOPY,         // writeable, not readable, not executable
    PAGE_EXECUTE_WRITECOPY, // writeable, not readable, executable
    PAGE_READWRITE,         // writeable, readable, not executable
    PAGE_EXECUTE_READWRITE, // writeable, readable, executable
};

#pragma pack(pop)
/* AMD64 Specific types */
#define IMAGE_REL_AMD64_ABSOLUTE 0x0000
#define IMAGE_REL_AMD64_ADDR64 0x0001
#define IMAGE_REL_AMD64_ADDR32 0x0002
#define IMAGE_REL_AMD64_ADDR32NB 0x0003
/* Most common from the looks of it, just 32-bit relative address from the byte following the relocation */
#define IMAGE_REL_AMD64_REL32 0x0004
/* Second most common, 32-bit address without an image base. Not sure what that means... */
#define IMAGE_REL_AMD64_REL32_1 0x0005
#define IMAGE_REL_AMD64_REL32_2 0x0006
#define IMAGE_REL_AMD64_REL32_3 0x0007
#define IMAGE_REL_AMD64_REL32_4 0x0008
#define IMAGE_REL_AMD64_REL32_5 0x0009
#define IMAGE_REL_AMD64_SECTION 0x000A
#define IMAGE_REL_AMD64_SECREL 0x000B
#define IMAGE_REL_AMD64_SECREL7 0x000C
#define IMAGE_REL_AMD64_TOKEN 0x000D
#define IMAGE_REL_AMD64_SREL32 0x000E
#define IMAGE_REL_AMD64_PAIR 0x000F
#define IMAGE_REL_AMD64_SSPAN32 0x0010

/*i386 Relocation types */

#define IMAGE_REL_I386_ABSOLUTE 0x0000
#define IMAGE_REL_I386_DIR16 0x0001
#define IMAGE_REL_I386_REL16 0x0002
#define IMAGE_REL_I386_DIR32 0x0006
#define IMAGE_REL_I386_DIR32NB 0x0007
#define IMAGE_REL_I386_SEG12 0x0009
#define IMAGE_REL_I386_SECTION 0x000A
#define IMAGE_REL_I386_SECREL 0x000B
#define IMAGE_REL_I386_TOKEN 0x000C
#define IMAGE_REL_I386_SECREL7 0x000D
#define IMAGE_REL_I386_REL32 0x0014

/* Section Characteristic Flags */

#define IMAGE_SCN_MEM_WRITE 0x80000000
#define IMAGE_SCN_MEM_READ 0x40000000
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define IMAGE_SCN_ALIGN_16BYTES 0x00500000
#define IMAGE_SCN_MEM_NOT_CACHED 0x04000000
#define IMAGE_SCN_MEM_NOT_PAGED 0x08000000
#define IMAGE_SCN_MEM_SHARED 0x10000000
#define IMAGE_SCN_CNT_CODE 0x00000020
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
#define IMAGE_SCN_MEM_DISCARDABLE 0x02000000

unsigned char *unhexlify(unsigned char *value, int *outlen);
typedef int (*goCallback)(char *, int);
#ifdef BUILD_DLL
/* DLL export */
#define EXPORT __declspec(dllexport)
EXPORT int __cdecl LoadAndRun(char *argsBuffer, uint32_t bufferSize, goCallback callback);
#else
/* EXE import */
#define EXPORT __declspec(dllimport)
#endif

int RunCOFF(char *functionname, unsigned char *coff_data, uint32_t filesize, unsigned char *argumentdata, int argumentSize, goCallback data);
#endif
