/*
 * \file   libpefile.c
  * \brief  Manages disassembly and reassembly of the PE COFF File Format
 */

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include "libpefile.h"
#include "common.h"
#include "common_metapi.h"

/* Min/Max Macros */
#define MIN(_a, _b) ((_a) < (_b) ? (_a) : (_b))
#define MAX(_a, _b) ((_a) > (_b) ? (_a) : (_b))

/* Calculate raw size of image an validates positions and sizes. Returns 0 on error */
static  size_t __pefile_calculate_raw_size(PEFILE *in, PEFILE_WRITE_OPTIONS *options) {
  size_t i = 0;
  size_t ii = 0;
  size_t additional_end, section_end;

  /* Raw size of Headers and padding */
  size_t size = in->dos_header.e_lfanew + sizeof(PE_HEADER) + in->pe_header.SizeOfOptionalHeader
      + in->pe_header.NumberOfSections * sizeof(SECTION_HEADER) + in->header_padding.memsize;

  /* Calculate header size only */
  if (options && options->header_only) {

    /* If additional data is forced we need to add this size too. In this case, only 1 additional data
     *  segment is allowed, and only if it's directly after the raw header (happens when parsing a
     *  truncated pe file with header_only option) */
    if (options->force_additional) {
      if (in->additional_count > 1 || ((in->additional_count > 0) && (in->additional_data == NULL))) {
        return 0;
      } else if (in->additional_count > 0) {
        if (size == in->additional_data[0].position) {
          size += in->additional_data[0].memsize;
        } else {
          return 0;
        }
      }
    }
    return size;
  }

  /* Validate & add all Section sizes */
  if ((in->pe_header.NumberOfSections > 0) && (in->section_header == NULL)) {
    return 0;
  }
  for (i = 0; i < in->pe_header.NumberOfSections; ++i) {
    /* Nested sections */
    for (ii = 0; ii < in->pe_header.NumberOfSections; ++ii) {
      if ((i != ii) && (in->section_header[ii].PointerToRawData <= in->section_header[i].PointerToRawData)
          && ((in->section_header[ii].PointerToRawData + in->section_header[ii].SizeOfRawData)
              >= (in->section_header[i].PointerToRawData + in->section_header[i].SizeOfRawData))) {
        size -= in->section_header[i].SizeOfRawData;
      }
    }
    size += in->section_header[i].SizeOfRawData;
  }

  /* Validate & add all additional data */
  if ((in->additional_count > 0) && (in->additional_data == NULL)) {
    return 0;
  }
  for (i = 0; i < in->additional_count; ++i) {
    size += in->additional_data[i].memsize;
  }

  /* Validate additional data positions */
  for (i = 0; i < in->additional_count; ++i) {
    if ((in->additional_data[i].position + in->additional_data[i].memsize) > size) {
      return 0;

    } else {
      /* If additional data starts or ends inside section something is wrong */
      additional_end = in->additional_data[i].position + in->additional_data[i].memsize;
      for (ii = 0; ii < in->pe_header.NumberOfSections; ++ii) {
        section_end = in->section_header[ii].PointerToRawData + in->section_header[ii].SizeOfRawData;
        if (((in->additional_data[i].position >= in->section_header[ii].PointerToRawData)
            && in->additional_data[i].position < section_end)
            || ((additional_end > in->section_header[ii].PointerToRawData) && additional_end < section_end)) {
          return 0;
        }
      }
    }
  }

  /* Validate Section positions */
  for (i = 0; i < in->pe_header.NumberOfSections; ++i) {
    if ((in->section_header[i].PointerToRawData + in->section_header[i].SizeOfRawData) > size) {
      return 0;
    }
  }

  return size;
}

/* Adds additional data to an pe file structure. Return true on success, false otherwise*/
static  bool __pefile_add_additional_data(unsigned char *mem, size_t position, size_t size, PEFILE *out) {
  DATA_BLOB_EX *newAdditional = NULL;

  out->additional_count++;
  newAdditional = realloc(out->additional_data, out->additional_count * sizeof(DATA_BLOB_EX));

  /* Couldn't allocate memory */
  if (newAdditional == NULL) {
    return false;
  }
  out->additional_data = newAdditional;
  out->additional_data[out->additional_count - 1].position = position;
  out->additional_data[out->additional_count - 1].memsize = size;
  out->additional_data[out->additional_count - 1].mem = malloc(out->additional_data[out->additional_count - 1].memsize);

  /* Couldn't allocate memory */
  if (out->additional_data[out->additional_count - 1].mem == NULL) {
    return false;
  }
  memcpy(out->additional_data[out->additional_count - 1].mem,
      mem + out->additional_data[out->additional_count - 1].position,
      out->additional_data[out->additional_count - 1].memsize);

  return true;
}

bool pefile_read_mem(unsigned char *mem, size_t memsize, PEFILE_READ_OPTIONS *options, PEFILE *out) {
  DOS_HEADER *dHead = NULL;
  PE_HEADER *pHead = NULL;
  OPTIONAL_HEADER_32 *oHead32 = NULL;
  OPTIONAL_HEADER_64 *oHead64 = NULL;
  SECTION_HEADER *firstsHead = NULL;
  unsigned char *dos_stub = NULL;
  size_t dos_stubsize = 0;
  size_t header_raw_end = 0;
  size_t header_padding_end = 0;
  size_t additional_end = 0;
  size_t additional_start = 0;
  size_t gap_start = 0;
  size_t gap_size = 0;
  size_t i = 0;
  size_t ii = 0;

  /* Zero first */
  memset(out, 0, sizeof(PEFILE));

  /* DOS Header  Magic OK & Size OK */
  dHead = (DOS_HEADER*) mem;
  if ((memsize < sizeof(DOS_HEADER)) || (dHead->e_magic != MZ_MAGIC)) {
    return false;
  }

  /* PE Header Magic OK & Size OK) */
  pHead = (PE_HEADER *) (mem + dHead->e_lfanew);
  if ((memsize < dHead->e_lfanew + sizeof(PE_HEADER)) || (pHead->Signature != NT_MAGIC)) {
    return false;
  }

  /* Save DOS Stub */
  /* Sometimes there is no DOS Stub, the PE Header can be inside the DOS Header */
  if (dHead->e_lfanew >= sizeof(DOS_HEADER) && (dHead->e_lfanew - sizeof(DOS_HEADER) > 0)) {
    dos_stub = mem + sizeof(DOS_HEADER);
    dos_stubsize = dHead->e_lfanew - sizeof(DOS_HEADER);
  }

  /* Optional Header Magic OK & Size OK */
  oHead32 = (OPTIONAL_HEADER_32 *) (mem + dHead->e_lfanew + sizeof(PE_HEADER));
  oHead64 = (OPTIONAL_HEADER_64 *) oHead32;
  if (pHead->SizeOfOptionalHeader > 0) {
    if ((memsize < ((size_t) oHead32 - (size_t) mem) + pHead->SizeOfOptionalHeader)
        || ((oHead32->Magic != NT_OPTIONAL_32_MAGIC) && (oHead64->Magic != NT_OPTIONAL_64_MAGIC))) {
      return false;
    }
  }

  /* Section Table. Size Ok? */
  if (memsize
      < (dHead->e_lfanew + sizeof(PE_HEADER) + pHead->SizeOfOptionalHeader
          + pHead->NumberOfSections * sizeof(SECTION_HEADER))) {
    return false;
  } else {
    firstsHead = (SECTION_HEADER *) (mem + dHead->e_lfanew + sizeof(PE_HEADER) + pHead->SizeOfOptionalHeader);
  }

  /* Find real end of Header padding (Packers doing some shit with that ...) */
  /* Raw end and padding end defined in Optional Header*/
  header_raw_end = dHead->e_lfanew + sizeof(PE_HEADER) + pHead->SizeOfOptionalHeader
      + pHead->NumberOfSections * sizeof(SECTION_HEADER);
  if (oHead32->Magic == NT_OPTIONAL_32_MAGIC) {
    header_padding_end = oHead32->SizeOfHeaders;
  } else {
    header_padding_end = oHead64->SizeOfHeaders;
  }

  /* Section starting inside padding */
  for (i = 0; i < pHead->NumberOfSections; ++i) {
    if ((firstsHead[i].SizeOfRawData > 0) && firstsHead[i].PointerToRawData < header_padding_end) {
      /* Section inside Header */
      if (firstsHead[i].PointerToRawData < header_raw_end) {
        return false;
      }
      header_padding_end = firstsHead[i].PointerToRawData;
    }
  }

  /* Header Padding in virtual space */
  if (header_padding_end > memsize) {
    header_padding_end = memsize;
    /* But must go till Section 0 */
  } else if ((pHead->NumberOfSections > 0) && header_padding_end < firstsHead[0].PointerToRawData) {
    header_padding_end = firstsHead[0].PointerToRawData;
  }

  /* Copy DOS & PE Header*/
  memcpy(&out->dos_header, dHead, sizeof(DOS_HEADER));
  memcpy(&out->pe_header, pHead, sizeof(PE_HEADER));

  /* Copy DOS Stub */
  if (dos_stub != NULL) {
    out->dos_stub.mem = malloc(dos_stubsize);
    out->dos_stub.memsize = dos_stubsize;
    memcpy(out->dos_stub.mem, dos_stub, dos_stubsize);
  }

  /* Copy Optional Header */
  if (pHead->SizeOfOptionalHeader > 0) {
    if (oHead32->Magic == NT_OPTIONAL_32_MAGIC) {
      memcpy(&out->optional_header_32, oHead32, MIN(pHead->SizeOfOptionalHeader, sizeof(OPTIONAL_HEADER_32)));

      /* Rare: Gap between Optional Header an Section Table */
      if (pHead->SizeOfOptionalHeader > sizeof(OPTIONAL_HEADER_32)) {
        gap_start = dHead->e_lfanew + sizeof(PE_HEADER) + sizeof(OPTIONAL_HEADER_32);
        gap_size = pHead->SizeOfOptionalHeader - sizeof(OPTIONAL_HEADER_32);
      }
    } else {
      memcpy(&out->optional_header_64, oHead64, MIN(pHead->SizeOfOptionalHeader, sizeof(OPTIONAL_HEADER_64)));

      /* Rare: Gap between Optional Header an Section Table */
      if (pHead->SizeOfOptionalHeader > sizeof(OPTIONAL_HEADER_64)) {
        gap_start = dHead->e_lfanew + sizeof(PE_HEADER) + sizeof(OPTIONAL_HEADER_64);
        gap_size = pHead->SizeOfOptionalHeader - sizeof(OPTIONAL_HEADER_64);
      }
    }

    /* Copy gap data if needed */
    if (gap_start > 0) {
      out->optional_header_gap.memsize = gap_size;
      out->optional_header_gap.mem = malloc(gap_size);

      /* Couldn't allocate memory */
      if (out->optional_header_gap.mem == NULL) {
        pefile_free(out);
        return false;
      }
      memcpy(out->optional_header_gap.mem, mem + gap_start, gap_size);
    }
  }

  /* Copy Section Headers & Sections */
  if (firstsHead != NULL && pHead->NumberOfSections > 0) {
    out->section_header = malloc(pHead->NumberOfSections * sizeof(SECTION_HEADER));

    /* Couldn't allocate memory */
    if (out->section_header == NULL) {
      pefile_free(out);
      return false;
    }
    memcpy(out->section_header, firstsHead, pHead->NumberOfSections * sizeof(SECTION_HEADER));

    /* Only if full analysis */
    if ((options == NULL) || ((options != NULL) && !options->header_only)) {
      /* Copy Sections & Additional Data */
      out->section_data = malloc(pHead->NumberOfSections * sizeof(DATA_BLOBC));
      for (i = 0; i < pHead->NumberOfSections; ++i) {
        if (firstsHead[i].SizeOfRawData) {
          out->section_data[i].memsize = firstsHead[i].SizeOfRawData;
          out->section_data[i].mem = malloc(out->section_data[i].memsize);

          /* Couldn't allocate memory */
          if (out->section_data[i].mem == NULL) {
            pefile_free(out);
            return false;
          }
          memcpy(out->section_data[i].mem, mem + firstsHead[i].PointerToRawData, out->section_data[i].memsize);

          /* Find additional Data between sections */
          additional_start = firstsHead[i].PointerToRawData + firstsHead[i].SizeOfRawData;
          additional_end = memsize;
          for (ii = 0; ii < pHead->NumberOfSections; ++ii) {
            if (i == ii) {
              continue;
            }
            if (firstsHead[ii].PointerToRawData == additional_start) {
              additional_end = additional_start;
              break;
            } else if ((firstsHead[ii].PointerToRawData > additional_start)
                && (firstsHead[ii].PointerToRawData < additional_end)) {
              additional_end = firstsHead[ii].PointerToRawData;
              /* nested sections */
            } else if ((firstsHead[ii].PointerToRawData <= firstsHead[i].PointerToRawData)
                && ((firstsHead[ii].PointerToRawData + firstsHead[ii].SizeOfRawData) >= additional_start)) {
              additional_end = additional_start;
              break;
            }
          }

          /* Additional data found */
          if ((additional_start != additional_end)
              && !__pefile_add_additional_data(mem, additional_start, additional_end - additional_start, out)) {

            /* Something went wrong, terminate */
            pefile_free(out);
            return false;
          }

        }
      }

      /* Force add data (everything after header, useful for truncated pe files
       * which shall be reassembled later */
    } else if (options->force_additional && (memsize - header_padding_end > 0)
        && !__pefile_add_additional_data(mem, header_padding_end, memsize - header_padding_end, out)) {

      /* Something went wrong, terminate */
      pefile_free(out);
      return false;
    }

  } else if ((options != NULL) && !(options->header_only && !options->force_additional)) {
    /* No Sections: Everything else is additional */
    if ((memsize - header_padding_end) > 0
        && !__pefile_add_additional_data(mem, header_padding_end, memsize - header_padding_end, out)) {

      /* Something went wrong, terminate */
      pefile_free(out);
      return false;
    }

  }

  /* Copy real Header Padding */
  out->header_padding.position = header_raw_end; /* Won't be used for building, just a shortcut to real header size */
  if (header_padding_end - header_raw_end > 0) {
    out->header_padding.memsize = header_padding_end - header_raw_end;
    out->header_padding.mem = malloc(out->header_padding.memsize);
    memcpy(out->header_padding.mem, mem + header_raw_end, out->header_padding.memsize);
  }

  return true;
}

void pefile_init(PEFILE *in) {
	memset(in, 0, sizeof(PEFILE));
}

bool pefile_read_file(char *file, PEFILE_READ_OPTIONS *options, PEFILE *out) {
  bool returnVar = false;
  unsigned char *file_mem;
  FILE *fh;

  /* Open file */
  wchar_t *file_w = met_api->string.utf8_to_wchar(file);
  if (_wfopen_s(&fh, file_w, L"rb") == 0) {

    /* Get file size and allocate buffer */
    fseek(fh, 0L, SEEK_END);
    size_t size = ftell(fh);
    size_t read_size = 0;
    rewind(fh);
    file_mem = malloc(size);

    if (file_mem != NULL) {
      /* Load file into buffer */
      read_size = fread(file_mem, size, 1, fh);
      fclose(fh);
      fh = NULL;

      /* Process PE file in memory */
      if (read_size == 1) {
        returnVar = pefile_read_mem(file_mem, size, options, out);
      }
      
      /* free buffer after use */
      free(file_mem);
    }

    /* Close file (if memory allocation has failed) */
    if (fh != NULL) {
      fclose(fh);
    }
  }
  free(file_w);

  return returnVar;
}

bool pefile_write_mem(PEFILE *in, PEFILE_WRITE_OPTIONS *options, unsigned char **mem, size_t *memsize) {
  size_t position = 0;
  size_t i = 0;
  uint64_t checksum = 0;
  uint64_t top = 0xffffffffLL + 0x01;
  size_t gap_start = 0;
  size_t gap_size = 0;

  /* Allocate needed memory */
  *memsize = __pefile_calculate_raw_size(in, options);

  /* Try allocate memory */
  if (*memsize > 0) {
    *mem = malloc(*memsize);

    /* Couldn't allocate memory */
    if (mem == NULL) {
      return false;
    }
  } else {
    return false;
  }

  /* Write DOS Header*/
  memcpy(*mem, &in->dos_header, sizeof(DOS_HEADER));

  /* Write PE Header */
  position = in->dos_header.e_lfanew;
  memcpy(*mem + position, &in->pe_header, sizeof(PE_HEADER));

  /* Write DOS Stub if needed */
  if (in->dos_stub.memsize) {
    position = sizeof(DOS_HEADER);
    memcpy(*mem + position, in->dos_stub.mem, in->dos_stub.memsize);
  }

  /* Write Optional Header if needed */
  if (in->pe_header.SizeOfOptionalHeader > 0) {
    position = in->dos_header.e_lfanew + sizeof(PE_HEADER);
    if (in->optional_header_32.Magic == NT_OPTIONAL_32_MAGIC) {
      memcpy(*mem + position, &in->optional_header_32,
          MIN(in->pe_header.SizeOfOptionalHeader, sizeof(OPTIONAL_HEADER_32)));

      /* Rare: Gap between Optional Header an Section Table */
      if (in->pe_header.SizeOfOptionalHeader > sizeof(OPTIONAL_HEADER_32)) {
        gap_start = in->dos_header.e_lfanew + sizeof(PE_HEADER) + sizeof(OPTIONAL_HEADER_32);
        gap_size = in->pe_header.SizeOfOptionalHeader - sizeof(OPTIONAL_HEADER_32);
      }
    } else if (in->optional_header_64.Magic == NT_OPTIONAL_64_MAGIC) {
      memcpy(*mem + position, &in->optional_header_64,
          MIN(in->pe_header.SizeOfOptionalHeader, sizeof(OPTIONAL_HEADER_64)));

      /* Rare: Gap between Optional Header an Section Table */
      if (in->pe_header.SizeOfOptionalHeader > sizeof(OPTIONAL_HEADER_64)) {
        gap_start = in->dos_header.e_lfanew + sizeof(PE_HEADER) + sizeof(OPTIONAL_HEADER_64);
        gap_size = in->pe_header.SizeOfOptionalHeader - sizeof(OPTIONAL_HEADER_64);
      }
    }

    /* Fill gap if there is saved data */
    if (gap_start && (in->optional_header_gap.mem != NULL)) {
      memcpy(*mem + gap_start, in->optional_header_gap.mem, MIN(gap_size, in->optional_header_gap.memsize));
    }
  }

  /* Writes Section Table if needed */
  if (in->pe_header.NumberOfSections > 0) {
    position = in->dos_header.e_lfanew + sizeof(PE_HEADER) + in->pe_header.SizeOfOptionalHeader;
    memcpy(*mem + position, in->section_header, in->pe_header.NumberOfSections * sizeof(SECTION_HEADER));
  }

  /* Writes Header Padding if needed */
  if ((in->header_padding.mem != NULL) && (in->header_padding.position > 0)) {
    position = in->dos_header.e_lfanew + sizeof(PE_HEADER) + in->pe_header.SizeOfOptionalHeader
        + in->pe_header.NumberOfSections * sizeof(SECTION_HEADER);
    memcpy(*mem + position, in->header_padding.mem, in->header_padding.memsize);
  }

  /* Header Only */
  /* Exception: force_additional override */
  if (options != NULL && options->header_only && !options->force_additional) {
    return true;
  }

  /* Write additional Data */
  if (in->additional_count > 0) {
    for (i = 0; i < in->additional_count; ++i) {
      if (in->additional_data[i].mem != NULL) {
        memcpy(*mem + in->additional_data[i].position, in->additional_data[i].mem, in->additional_data[i].memsize);
      }
    }
  }

  /* Header Only */
  if (options != NULL && options->header_only) {
    return true;
  }

  /* Write Section Data */
  if (in->section_data != NULL) {
    for (i = 0; i < in->pe_header.NumberOfSections; ++i) {
      if (in->section_data[i].mem != NULL) {
        memcpy(*mem + in->section_header[i].PointerToRawData, in->section_data[i].mem,
            MIN(in->section_data[i].memsize, in->section_header[i].SizeOfRawData));
      }
    }
  }

  /* Recalculate checksum if forced & OptionalHeader is large enough*/
  if ((options != NULL)
      && (in->pe_header.SizeOfOptionalHeader > offsetof(OPTIONAL_HEADER_32, CheckSum) + sizeof(uint32_t))
      && options->recaluclate_checksum) {

    /* Position of CheckSum (32/64 Bit position is equal) */
    position = in->dos_header.e_lfanew + sizeof(PE_HEADER) + offsetof(OPTIONAL_HEADER_32, CheckSum);

    /* Calculate checksum for Image */
    for (i = 0; i < *memsize; i += 4) {
      if (i == position) {
        continue;
      }
      checksum = (checksum & 0xffffffff) + *(uint32_t *) (*mem + i) + (checksum >> 32);
      if (checksum > top) {
        checksum = (checksum & 0xffffffff) + (checksum >> 32);
      }
    }
    checksum = (checksum & 0xffff) + (checksum >> 16);
    checksum = (checksum) + (checksum >> 16);
    checksum = checksum & 0xffff;
    checksum += *memsize;

    /* Write checksum*/
    *(uint32_t *) (*mem + position) = (uint32_t)checksum;
  }

  return true;
}

bool pefile_write_file(PEFILE *in, PEFILE_WRITE_OPTIONS *options, char* file) {
  bool returnVar = false;
  unsigned char *mem = NULL;
  unsigned char **mem_ref = (unsigned char **) &mem;
  size_t memsize = 0;

  /* Open file */
  FILE *fh;
  wchar_t *file_w = met_api->string.utf8_to_wchar(file);
  if (_wfopen_s(&fh, file_w, L"wb") == 0) {

    /* Generate PE File memory */
    if (pefile_write_mem(in, options, mem_ref, &memsize)) {

      /* Write to file and verify size */
      returnVar = (fwrite(mem, memsize, 1, fh) == 1) ? true : false;

      /* Free memory */
      free(mem);
    }

    /* Close file */
    fclose(fh);
  }
  free(file_w);

  return returnVar;
}

void pefile_free(PEFILE *in) {
  size_t i = 0;

  /* Free DOS stub */
  if (in->dos_stub.mem != NULL) {
    free(in->dos_stub.mem);
  }

  /* Free Optional Header Gap */
  if (in->optional_header_gap.mem != NULL) {
    free(in->optional_header_gap.mem);
  }

  /* Free Section Header */
  if (in->section_header != NULL) {
    free(in->section_header);
  }

  /* Free Header padding */
  if (in->header_padding.mem != NULL) {
    free(in->header_padding.mem);
  }

  /* Free Section data */
  if (in->section_data != NULL) {
    for (i = 0; i < in->pe_header.NumberOfSections; ++i) {
      if (in->section_data[i].mem != NULL) {
        free(in->section_data[i].mem);
      }
    }
    free(in->section_data);
  }

  /* Free additional data*/
  if (in->additional_count && (in->additional_data != NULL)) {
    for (i = 0; i < in->additional_count; ++i) {
      if (in->additional_data[i].mem != NULL) {
        free(in->additional_data[i].mem);
      }
    }
    free(in->additional_data);
  }

  /* Zero structure */
  memset(in, 0, sizeof(PEFILE));
}

uint16_t get_file_architecture(char * target_executable_path) {
	
	PEFILE mype;
	pefile_init(&mype);

	PEFILE_READ_OPTIONS read_options;
	read_options.header_only = true;
	
	if (pefile_read_file(target_executable_path, &read_options, &mype))
		return mype.pe_header.Machine;
	else
		return 0;
}