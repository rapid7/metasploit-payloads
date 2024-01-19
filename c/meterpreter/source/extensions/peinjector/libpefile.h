/**
 * \file   libpefile.h
  * \brief  Manages disassembly and reassembly of the PE COFF File Format
 */

#ifndef LIBPEFILE_H_
#define LIBPEFILE_H_

#include <stdbool.h>
#include "headers.h"

/**
 * Hold binary data in pefile structure
 */
typedef struct _DATA_BLOB {
  unsigned char *mem; //!< Pointer to memory
  size_t memsize;     //!< Size of memory
} DATA_BLOBC;

/**
 * Hold binary data and position in pefile structure
 */
typedef struct _DATA_BLOB_EX {
  unsigned char *mem; //!< Pointer to memory
  size_t memsize;     //!< Size of memory
  size_t position;    //!< Position of memory
} DATA_BLOB_EX;

/**
 * PE File Format
 */
typedef struct _PEFILE {
  DOS_HEADER dos_header;                  //!< DOS Header
  PE_HEADER pe_header;                    //!< PE Header
  DATA_BLOBC dos_stub;                     //!< DOS Stub Program
  OPTIONAL_HEADER_32 optional_header_32;  //!< Optional Header, 32 Bit
  OPTIONAL_HEADER_64 optional_header_64;  //!< Optional Header, 64 Bit
  DATA_BLOBC optional_header_gap;          //!< Gap between Optional Header and Section Headers, rare.
  SECTION_HEADER *section_header;         //!< Section Headers
  DATA_BLOBC *section_data;                //!< Section data
  DATA_BLOB_EX header_padding;            //!< Padding between Headers and Section data
  DATA_BLOB_EX *additional_data;          //!< Additional binary data inside PE File
  size_t additional_count;                //!< Additional binary data count
} PEFILE;

/**
 * Options for writing PE files
 */
typedef struct _PEFILE_WRITE_OPTIONS {
  bool recaluclate_checksum;  //!< Recalculate Image Checksum after writing
  bool header_only;           //!< Writes header only
  bool force_additional;      //!< Forces writing of additional data (only in combination with header_only)
} PEFILE_WRITE_OPTIONS;

/**
 * Options for reading PE files
 */
typedef struct _PEFILE_READ_OPTIONS {
  bool header_only;           //!< Analyzes header only
  bool force_additional;      //!< Forces reading of additional data (only in combination with header_only)
} PEFILE_READ_OPTIONS;

/**
* Initializes PEFILE structure
*
*/
void pefile_init(PEFILE *in);

/**
 * Parses PE File data from memory
 *
 * \param mem     Input memory
 * \param memsize Input memory size
 * \param options Options for reading, Ignored if NULL
 * \param out     Output PEFILE structure
 *
 * \return true on success, false otherwise
 */
bool pefile_read_mem(unsigned char *mem, size_t memsize, PEFILE_READ_OPTIONS *options, PEFILE *out);

/**
 * Parses PE File data from files
 *
 * \param file    Input file
 * \param options Options for reading, Ignored if NULL
 * \param out     Output PEFILE structure
 *
 * \return true on success, false otherwise
 */
bool pefile_read_file(char *file, PEFILE_READ_OPTIONS *options, PEFILE *out);

/**
 * Writes PE File data to memory
 *
 * \param in      Input PEFILE structure
 * \param options Options for writing, Ignored if NULL
 * \param mem     Output memory
 * \param memsize Output memory size
 *
 * \return true on success, false otherwise
 */
bool pefile_write_mem(PEFILE *in, PEFILE_WRITE_OPTIONS *options, unsigned char **mem, size_t *memsize);

/**
 * Writes PE File data to files
 *
 * \param in      Input PEFILE structure
 * \param options Options for writing, Ignored if NULL
 * \param file    Output file
 *
 * \return true on success, false otherwise
 */
bool pefile_write_file(PEFILE *in, PEFILE_WRITE_OPTIONS *options, char* file);

/**
 * Clears PEFILE structure
 *
 * \param in      Input PEFILE structure
 */
void pefile_free(PEFILE *in);

/**
* Get PEFILE architecture
*
* \param file    Input file
*/
uint16_t get_file_architecture(char * target_executable_path);

#endif /* LIBPEFILE_H_ */
