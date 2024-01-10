/**
 * \file   libpetool.h
 * \brief  Applies complex operations on a given PE FILE
 */

#ifndef LIBPETOOL_H_
#define LIBPETOOL_H_

#include "libpefile.h"

/**
 * Tries to resize an existing section
 *
 * \param section_index    Index of section to resize
 * \param new_raw_size     New RawSize of section
 * \param new_virtual_size New VirtualSize of section
 * \param header_only      Only modifies header
 * \param out              PE File where the section will be resized
 *
 * \return true on success, false otherwise
 */
bool petool_resize_section(size_t section_index, size_t new_raw_size, size_t new_virtual_size, bool header_only,
    PEFILE *out);

/**
 * Tries to insert a new section into a given PE File
 *
 * \param name            Name of new section
 * \param namesize        Size of name
 * \param characteristics Characteristics of new section
 * \param mem             Memory used for new section. If NULL, memsize zeros will be used
 * \param memsize         Memory size of new section
 * \param header_only     Only modifies header
 * \param out             PE File where the section will be added
 *
 * \return true on success, false otherwise
 */
bool petool_add_section(char *name, size_t namesize, size_t characteristics, unsigned char *mem, size_t memsize,
    bool header_only, PEFILE *out);

#endif /* LIBPETOOL_H_ */
