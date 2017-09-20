/**
 * \file   libpeinfect.h
  * \brief  Infects a PE File with a given payload
 */

#ifndef LIBPEINFECT_H_
#define LIBPEINFECT_H_

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stddef.h>
#include "libpetool.h"

/**
 * Sentinel size of serialized patch
 */
#define PEINFECT_PATCH_SENTINELSIZE 9

/**
 * Available Injection Methods
 */
typedef enum _PEINFECT_METHOD {
  METHOD_ALIGNMENT = 1 << 0,          //!< Alignment-gap only method
  METHOD_ALIGNMENT_RESIZE = 1 << 1,   //!< Alignment-gap and resize method
  METHOD_NEW_SECTION = 1 << 2,        //!< Insert new section method
  METHOD_CHANGE_FLAGS = 1 << 3,       //!< Change section flags (combined with alignment/alignment-resize)
  METHOD_CROSS_SECTION_JUMP = 1 << 4, //!< Inserts obfuscated jump at entry point and hides payload in another section
  METHOD_ALL = METHOD_ALIGNMENT | METHOD_ALIGNMENT_RESIZE | METHOD_NEW_SECTION | METHOD_CHANGE_FLAGS | METHOD_CROSS_SECTION_JUMP
} PEINFECT_METHOD;

/**
 * PE Infect control structure
 */
typedef struct _PEINFECT {
  unsigned char *shellcode_x86; //!< Holds x86 shellcode
  size_t shellcode_x86size;     //!< Size of x86 shellcode
  unsigned char *shellcode_x64; //!< Holds x64 shellcode
  size_t shellcode_x64size;     //!< Size of x64 shellcode
  char *section_name;           //!< Name of section to insert
  size_t section_namesize;      //!< Size of new section name
  PEINFECT_METHOD methods;      //!< Allowed infection methods
  bool remove_integrity;        //!< Removes integrity checks
  bool rnd_sectionname;         //!< Random section names
  bool try_stealth;             //!< Tries to check if infection could be detected
  bool encrypt;                 //!< Encrypts shellcode before insertion
  uint32_t encrypt_iterations;  //!< Encryption iterations
  uint32_t jump_iterations;     //!< Cross section jump iterations
  uint32_t infect_cnt_x86;      //!< Infection counter x86
  uint32_t infect_cnt_x64;      //!< Infection counter x64
} PEINFECT;

/**
 * PE Infect patch structure
 */
typedef struct _PEINFECT_PATCH {
  unsigned char *mem;           //!< Pointer to memory of current patch part
  size_t memsize;               //!< Size of current patch part
  size_t position;              //!< Position of current patch part
  bool insert;                  //!< If true patch will be inserted, overwritten otherwise
  struct _PEINFECT_PATCH *next; //!< Pointer to next patch part
} PEINFECT_PATCH;

/**
 * Initializes a new PE Infector
 *
 * \param out PE Infector to initialize
 *
 */
void peinfect_init(PEINFECT *out);

/**
 * Sets the section Name to use for a injected section
 *
 * \param section_name     Name of new section if injected
 * \param section_namesize Size of new section name
 * \param random           If true, previous params are ignored and a random section
 *                         name will be used for each injection. (Enabled by default)
 * \param out              PE Infector to configure
 *
 */
void peinfect_set_sectionname(char *section_name, size_t section_namesize, bool random, PEINFECT *out);

/**
 * Gets the section name used for infection
 *
 * \param in               PE Infector
 *
 * \return section name if set, NULL otherwise
 */
char* peinfect_get_sectionname(PEINFECT *in);

/**
 * Sets the methods to use for infection (All are enabled by default, except METHOD_CROSS_SECTION_JUMP)
 *
 * \param methods          Methods to use for infection
 * \param out              PE Infector to configure
 *
 */
void peinfect_set_methods(PEINFECT_METHOD methods, PEINFECT *out);

/**
 * Gets the methods used for infection
 *
 * \param in               PE Infector
 *
 * \return infection methods
 */
PEINFECT_METHOD peinfect_get_methods(PEINFECT *in);

/**
 * Sets the interations for cross section infection. (Limits: Min: 1 Max: 64)
 *
 * \param iterations       Number of iterations to use
 * \param out              PE Infector to configure
 *
 */
void peinfect_set_jumpiterations(uint32_t iterations, PEINFECT *out);

/**
 * Gets the interations for cross section infection
 *
 * \param in               PE Infector
 *
 * \return Number of iterations used
 */
uint32_t peinfect_get_jumpiterations(PEINFECT *in);

/**
 * Sets the interations for encryption. (Limits: Min: 1 Max: 16)
 *
 * \param iterations       Number of iterations to use
 * \param out              PE Infector to configure
 *
 */
void peinfect_set_encryptiterations(uint32_t iterations, PEINFECT *out);

/**
 * Gets the interations for encryption
 *
 * \param in               PE Infector
 *
 * \return Number of iterations used
 */
uint32_t peinfect_get_encryptiterations(PEINFECT *in);

/**
 * Enables encryption of payload (Enabled by default)
 *
 * \param encrypt          Encrypts if true
 * \param out              PE Infector to configure
 *
 */
void peinfect_set_encrypt(bool encrypt, PEINFECT *out);

/**
 * Gets the encryption of payload
 *
 * \param in               PE Infector
 *
 * \return true if set, false otherwise
 */
bool peinfect_get_encrypt(PEINFECT *in);

/**
 * Enables removal of integrity checks (Enabled by default)
 *
 * \param remove_integrity Remove integrity if true
 * \param out              PE Infector to configure
 *
 */
void peinfect_set_removeintegrity(bool remove_integrity, PEINFECT *out);

/**
 * Gets the removal of integrity checks flag
 *
 * \param in               PE Infector
 *
 * \return true if set, false otherwise
 */
bool peinfect_get_removeintegrity(PEINFECT *in);

/**
 * Enables to try to stay stealth (Enabled by default)
 *
 * \param try_stealth      Try to stay stealth if true
 * \param out              PE Infector to configure
 *
 */
void peinfect_set_trystaystealth(bool try_stealth, PEINFECT *out);

/**
 * Gets the try stay stealth flag
 *
 * \param in               PE Infector
 *
 * \return true if set, false otherwise
 */
bool peinfect_get_trystaystealth(PEINFECT *in);

/**
 * Sets shellcode to use
 *
 * \param mem     Pointer to memory containing shellcode
 * \param memsize Size of the shellcode
 * \param x64     If true shellcode will used for x64 PE Files, x86 otherwise
 * \param out     PE Infector which will use the shellcode
 *
 * \return true on success, false otherwise
 */
bool peinfect_set_shellcode(unsigned char *mem, size_t memsize, bool x64, PEINFECT *out);

/**
 * Gets the shellcode used for infection
 *
 * \param in               PE Infector
 * \param x64              returns x64 shellcode if true, x86 otherwise
 *
 * \ return shellcode
 */
unsigned char* peinfect_get_shellcode(PEINFECT *in, bool x64);

/**
 * Infects PE File with preconfigured shellcode
 *
 * \param mem     Pointer to memory containing PE File
 * \param memsize Size of the PE File
 * \param in      Input PEINFECT structure for configuration
 * \param out     infected PE File
 *
 * \return true on success, false otherwise
 */
bool peinfect_infect_full(unsigned char *mem, size_t memsize, PEINFECT *in, PEFILE *out);

/**
 * Infects PE File from disk with preconfigured shellcode
 *
 * \param infile  PE File to infect
 * \param in      Input PEINFECT structure for configuration
 * \param outfile PE File to store
 *
 * \return true on success, false otherwise
 */
bool peinfect_infect_full_file(char *infile, PEINFECT *in, char *outfile);

/**
 * Clears PEINFECT structure
 *
 * \param in Input PEINFECT structure
 */
void peinfect_free(PEINFECT *in);


#endif /* LIBPEINFECT_H_ */
