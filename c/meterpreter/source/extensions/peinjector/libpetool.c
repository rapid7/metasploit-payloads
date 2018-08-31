/*
 * \file   libpetool.c
  * \brief  Applies complex operations on a given PE FILE
 */

#include <string.h>
#include <stddef.h>
#include "libpetool.h"

/* Min/Max Macros */
#define MIN(_a, _b) ((_a) < (_b) ? (_a) : (_b))
#define MAX(_a, _b) ((_a) > (_b) ? (_a) : (_b))

/* Align value */
static  uint32_t __petool_align(uint32_t value, uint32_t alignment) {
  return (value % alignment > 0) ? value + alignment - (value % alignment) : value;
}

/* Adjusting values in the optional header */
static  void __petool_adjust_optional_header(PEFILE *out) {
  size_t i = 0;
  uint32_t size_of_code = 0;
  uint32_t size_of_initialized_data = 0;
  uint32_t size_of_uninitialized_data = 0;
  bool is_32_bit = false;
  uint32_t sizeofimage;

  /* Default values (PE COFF Specification) */
  size_t section_alignment = NT_SECTION_ALIGNMENT;

  /* Check if 32/64 bit header */
  if (out->optional_header_32.Magic == NT_OPTIONAL_32_MAGIC) {
    is_32_bit = true;
    section_alignment = out->optional_header_32.SectionAlignment;
  } else if (out->optional_header_64.Magic == NT_OPTIONAL_64_MAGIC) {
    is_32_bit = false;
    section_alignment = out->optional_header_64.SectionAlignment;
  } else {

    /* Nothing to adjust */
    return;
  }

  /* Sum up over sections */
  for (i = 0; i < out->pe_header.NumberOfSections; ++i) {
    if (out->section_header[i].Characteristics & IMAGE_SCN_CNT_CODE) {
      size_of_code += out->section_header[i].Misc.VirtualSize;
    }
    if (out->section_header[i].Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
      size_of_initialized_data += out->section_header[i].Misc.VirtualSize;
    }
    if (out->section_header[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
      size_of_uninitialized_data += out->section_header[i].Misc.VirtualSize;
    }
  }

  /* Align SizeOfImage to Section Alignment */
  sizeofimage = __petool_align(
      out->section_header[out->pe_header.NumberOfSections - 1].VirtualAddress
          + out->section_header[out->pe_header.NumberOfSections - 1].Misc.VirtualSize, (uint32_t)section_alignment);

  /* Write new values into required fields */
  if (is_32_bit) {
    out->optional_header_32.SizeOfImage = sizeofimage;
    out->optional_header_32.SizeOfCode = size_of_code;
    out->optional_header_32.SizeOfInitializedData = size_of_initialized_data;
    out->optional_header_32.SizeOfUninitializedData = size_of_uninitialized_data;
  } else {

    out->optional_header_64.SizeOfImage = sizeofimage;
    out->optional_header_64.SizeOfCode = size_of_code;
    out->optional_header_64.SizeOfInitializedData = size_of_initialized_data;
    out->optional_header_64.SizeOfUninitializedData = size_of_uninitialized_data;
  }

}

/* Increases the header padding with the given size */
static  bool __petool_increase_header_padding(size_t size, PEFILE *out) {
  size_t i = 0;
  unsigned char *new_header_padding = NULL;
  size_t header_raw_end = out->dos_header.e_lfanew + sizeof(PE_HEADER) + out->pe_header.SizeOfOptionalHeader
      + out->pe_header.NumberOfSections * sizeof(SECTION_HEADER);

  new_header_padding = realloc(out->header_padding.mem, out->header_padding.memsize + size);
  /* Couldn't reallocate memory */
  if (new_header_padding == NULL) {
    return false;
  }

  /* No way to resize without damaging code execution */
  /* Sorry for this cruel if .. */
  if ((out->pe_header.NumberOfSections > 0) && (out->section_header != NULL)
      && ((out->optional_header_32.Magic == NT_OPTIONAL_32_MAGIC)
          || (out->optional_header_64.Magic == NT_OPTIONAL_64_MAGIC))
      && (header_raw_end + out->header_padding.memsize + size) > out->section_header[0].VirtualAddress) {
    /* Reset header padding */
    out->header_padding.mem = realloc(new_header_padding, out->header_padding.memsize);
    return false;
  }

  /* Increase at head */
  memmove(new_header_padding + size, new_header_padding, out->header_padding.memsize);
  memset(new_header_padding, 0, size);
  out->header_padding.mem = new_header_padding;
  out->header_padding.memsize += size;

  /* Fix SizeOfHeaders */
  if (out->optional_header_32.Magic == NT_OPTIONAL_32_MAGIC) {
    if (out->optional_header_32.SizeOfHeaders < (header_raw_end + out->header_padding.memsize)) {
      out->optional_header_32.SizeOfHeaders = (uint32_t)(header_raw_end + out->header_padding.memsize);
    }
  } else if (out->optional_header_64.Magic == NT_OPTIONAL_64_MAGIC) {
    if (out->optional_header_64.SizeOfHeaders < (header_raw_end + out->header_padding.memsize)) {
      out->optional_header_64.SizeOfHeaders = (uint32_t)(header_raw_end + out->header_padding.memsize);
    }
  }

  /* Fix section positions */
  if ((out->pe_header.NumberOfSections > 0) && (out->section_header != NULL)) {
    for (i = 0; i < out->pe_header.NumberOfSections; ++i) {
      out->section_header[i].PointerToRawData += (uint32_t)size;
    }
  }

  /* Fix additional data positions */
  if ((out->additional_count > 0) && (out->additional_data != NULL)) {
    for (i = 0; i < out->additional_count; ++i) {
      out->additional_data[i].position += size;
    }
  }

  return true;
}

bool petool_resize_section(size_t section_index, size_t new_raw_size, size_t new_virtual_size, bool header_only,
    PEFILE *out) {

  uint32_t old_raw_size = 0;
  uint32_t diff = 0;
  bool shrink = false;
  bool raw_change = false;
  unsigned char *newmem = NULL;
  uint32_t i = 0;

  /* Default values (PE COFF Specification) */
  size_t file_alignment = NT_FILE_ALIGNMENT;

  /* No Section Headers*/
  if (out->section_header == NULL) {
    return false;
  }

  /* Section Index out of bounds */
  if (out->pe_header.NumberOfSections <= section_index) {
    return false;
  }

  /* Virtual Size won't fit */
  if ((out->pe_header.NumberOfSections < (section_index + 1))
      && ((out->section_header[section_index].VirtualAddress + new_virtual_size)
          > out->section_header[section_index + 1].VirtualAddress)) {
    return false;
  }

  /* Nothing to do */
  if (!(raw_change = (new_raw_size != out->section_header[section_index].SizeOfRawData))
      && out->section_header[section_index].Misc.VirtualSize == new_virtual_size) {
    return true;
  }

  /* Try to change raw size of section nested in another section, this won't work ... */
  if (raw_change) {
    for (i = 0; i < out->pe_header.NumberOfSections; ++i) {
      if ((section_index != i)
          && (out->section_header[i].PointerToRawData <= out->section_header[section_index].PointerToRawData)
          && ((out->section_header[i].PointerToRawData + out->section_header[i].SizeOfRawData)
              >= (out->section_header[section_index].PointerToRawData + out->section_header[section_index].SizeOfRawData))) {
        return false;
      }
    }
  }

  /* New Virtual Size */
  out->section_header[section_index].Misc.VirtualSize = (uint32_t)new_virtual_size;

  /* Only needed if RawSize was changed */
  if (raw_change) {

    /* Save old raw size*/
    old_raw_size = out->section_header[section_index].SizeOfRawData;

    /* Try to load specific alignments */
    /* x86 */
    if ((out->optional_header_32.Magic == NT_OPTIONAL_32_MAGIC)
        && (out->pe_header.SizeOfOptionalHeader >= offsetof(OPTIONAL_HEADER_32, MajorOperatingSystemVersion))) {
      file_alignment = out->optional_header_32.FileAlignment;

      /* x64 */
    } else if (out->optional_header_64.Magic == NT_OPTIONAL_64_MAGIC
        && (out->pe_header.SizeOfOptionalHeader >= offsetof(OPTIONAL_HEADER_64, MajorOperatingSystemVersion))) {
      file_alignment = out->optional_header_64.FileAlignment;
    }

    /* Align new raw size */
    new_raw_size = __petool_align((uint32_t)new_raw_size, (uint32_t)file_alignment);

    /* Set new RawSize */
    out->section_header[section_index].SizeOfRawData = (uint32_t)new_raw_size;

    /* Get Size difference  */
    if (new_raw_size > old_raw_size) {
      diff = (uint32_t)(new_raw_size - old_raw_size);
      shrink = false;
    } else {
      diff = (uint32_t)(old_raw_size - new_raw_size);
      shrink = true;
    }

    /* Fix section offsets*/
    for (i = 0; i < out->pe_header.NumberOfSections; ++i) {
      if (out->section_header[i].PointerToRawData
          >= (out->section_header[section_index].PointerToRawData + old_raw_size)) {
        shrink ? (out->section_header[i].PointerToRawData -= diff) : (out->section_header[i].PointerToRawData += diff);
      }
    }

    /* Resize section memory */
    if (!header_only) {
      if (out->section_data == NULL) {
        return false;
      }

      /* Try resize */
      newmem = realloc(out->section_data[section_index].mem, new_raw_size);
      if (newmem == NULL) {
        return false;
      }

      /* Set new Memory */
      out->section_data[section_index].mem = newmem;
      out->section_data[section_index].memsize = new_raw_size;

      /* Fix additional data positions */
      if ((out->additional_count > 0) && (out->additional_data != NULL)) {
        for (i = 0; i < out->additional_count; ++i) {
          if (out->additional_data[i].position
              >= (out->section_header[section_index].PointerToRawData + old_raw_size)) {
            shrink ? (out->additional_data[i].position -= diff) : (out->additional_data[i].position += diff);
          }
        }
      }
    }
  }

  /* Adjust Optional Header*/
  __petool_adjust_optional_header(out);

  return true;
}

bool petool_add_section(char *name, size_t namesize, size_t characteristics, unsigned char *mem, size_t memsize,
bool header_only, PEFILE *out) {
  SECTION_HEADER *new_section_header = NULL;
  DATA_BLOBC *new_section_data = NULL;
  size_t i;
  size_t last_section_rva = 0;
  size_t last_section_virtualsize = 0;
  size_t header_raw_end = out->dos_header.e_lfanew + sizeof(PE_HEADER) + out->pe_header.SizeOfOptionalHeader
      + out->pe_header.NumberOfSections * sizeof(SECTION_HEADER);

  /* Default values (PE COFF Specification) */
  size_t section_alignment = NT_SECTION_ALIGNMENT;
  size_t file_alignment = NT_FILE_ALIGNMENT;
  unsigned char *section_mem = NULL;
  size_t section_memsize = 0;
  size_t section_raw_pointer = 0;
  size_t section_rva;

  /* Try to load specific alignments */
  /* x86 */
  if ((out->optional_header_32.Magic == NT_OPTIONAL_32_MAGIC)
      && (out->pe_header.SizeOfOptionalHeader >= offsetof(OPTIONAL_HEADER_32, MajorOperatingSystemVersion))) {
    section_alignment = out->optional_header_32.SectionAlignment;
    file_alignment = out->optional_header_32.FileAlignment;
    last_section_rva = out->optional_header_32.BaseOfCode;

    /* x64 */
  } else if (out->optional_header_64.Magic == NT_OPTIONAL_64_MAGIC
      && (out->pe_header.SizeOfOptionalHeader >= offsetof(OPTIONAL_HEADER_64, MajorOperatingSystemVersion))) {
    section_alignment = out->optional_header_64.SectionAlignment;
    file_alignment = out->optional_header_64.FileAlignment;
    last_section_rva = out->optional_header_64.BaseOfCode;
  }

  /* Increase header padding till the new header fits */
  while (out->header_padding.memsize < sizeof(SECTION_HEADER)) {
    if (!__petool_increase_header_padding(file_alignment, out)) {

      /* Something went wrong*/
      return false;
    }
  }

  /* Move padding */
  memmove(out->header_padding.mem, out->header_padding.mem + sizeof(SECTION_HEADER),
      out->header_padding.memsize - sizeof(SECTION_HEADER));
  out->header_padding.memsize -= sizeof(SECTION_HEADER);

  /* Try find position of last section */
  if ((out->pe_header.NumberOfSections > 0) && (out->section_header != NULL)) {
    last_section_rva = out->section_header[out->pe_header.NumberOfSections - 1].VirtualAddress;
    last_section_virtualsize = out->section_header[out->pe_header.NumberOfSections - 1].Misc.VirtualSize;

    /* Sections can be nested inside other sections */
    for (i = 0; i < out->pe_header.NumberOfSections; ++i) {
      section_raw_pointer = MAX(section_raw_pointer,
          out->section_header[i].PointerToRawData + out->section_header[i].SizeOfRawData);
    }

  } else {
    section_raw_pointer = header_raw_end + out->header_padding.memsize;
  }

  /* Resize holder structures */
  out->pe_header.NumberOfSections++;
  new_section_header = realloc(out->section_header, out->pe_header.NumberOfSections * sizeof(SECTION_HEADER));
  /* Couldn't allocate memory */
  if (new_section_header == NULL) {
    return false;
  }
  out->section_header = new_section_header;

  if (!header_only) {
    new_section_data = realloc(out->section_data, out->pe_header.NumberOfSections * sizeof(DATA_BLOBC));
    /* Couldn't allocate memory */
    if (new_section_data == NULL) {
      return false;
    }
    out->section_data = new_section_data;
  }

  /* Calculate padded raw size & relative virtual address */
  section_memsize = __petool_align((uint32_t)memsize, (uint32_t)file_alignment);
  section_rva = __petool_align((uint32_t)(last_section_rva + last_section_virtualsize), (uint32_t)section_alignment);

  /* Header only, don't modify data */
  if (!header_only) {
    /* Allocate new section memory */
    section_mem = malloc(section_memsize);
    /* Couldn't allocate memory */
    if (section_mem == NULL) {
      return false;
    }

    /* Copy memory to section memory and clear rest */
    if (mem != NULL) {
      memcpy(section_mem, mem, memsize);
      memset(section_mem + memsize, 0, section_memsize - memsize);
    } else {
      memset(section_mem, 0, section_memsize);
    }

    /* Store section data */
    out->section_data[out->pe_header.NumberOfSections - 1].mem = section_mem;
    out->section_data[out->pe_header.NumberOfSections - 1].memsize = section_memsize;

  }

  /* New Section Header */
  memset(&out->section_header[out->pe_header.NumberOfSections - 1], 0, sizeof(SECTION_HEADER));
  out->section_header[out->pe_header.NumberOfSections - 1].PointerToRawData = (uint32_t)section_raw_pointer;
  out->section_header[out->pe_header.NumberOfSections - 1].SizeOfRawData = (uint32_t)section_memsize;
  out->section_header[out->pe_header.NumberOfSections - 1].VirtualAddress = (uint32_t)section_rva;
  out->section_header[out->pe_header.NumberOfSections - 1].Misc.VirtualSize = (uint32_t)memsize;
  out->section_header[out->pe_header.NumberOfSections - 1].Characteristics = (uint32_t)characteristics;
  if (name != NULL) {
    memcpy(out->section_header[out->pe_header.NumberOfSections - 1].Name, name, MIN(NT_SHORT_NAME_LEN, namesize));
  }

  /* Header only, don't modify data */
  if (!header_only) {
    /* Fix additional data positions */
    if ((out->additional_count > 0) && (out->additional_data != NULL)) {
      for (i = 0; i < out->additional_count; ++i) {
        if (out->additional_data[i].position
            == out->section_header[out->pe_header.NumberOfSections - 1].PointerToRawData) {
          out->additional_data[i].position += out->section_header[out->pe_header.NumberOfSections - 1].SizeOfRawData;
          break;
        }
      }
    }
  }

  /* Adjust Optional Header */
  __petool_adjust_optional_header(out);

  return true;
}
