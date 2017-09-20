/**
 * \file   libpeinfect_obfuscator.h
  * \brief  peinfect obfuscator sub-library
 */

#ifndef LIBPEINFECT_OBFUSCATOR_H_
#define LIBPEINFECT_OBFUSCATOR_H_

#include "libpeinfect.h"

/**
 * Build obfuscated jump to entry point (ep)
 *
 * \param pe               PEFILE to build jump
 * \param jumpsize         Size of generated shellcode
 *
 * \return shellcode if success, NULL otherwise
 */
unsigned char* peinfect_obfuscator_build_ep_jmp(PEFILE *pe, size_t *jmpsize);

/**
 * Encodes payload and attaches obfuscated decoder stub
 *
 * \param payload           Payload to encode
 * \param payloadsize       Size of payload
 * \param encodedsize       Size of generated shellcode
 * \param x64               Enables x64 mode
 *
 * \return shellcode if success, NULL otherwise
 */
unsigned char* peinfect_obfuscator_encrypt_payload(unsigned char *payload, size_t payloadsize, size_t *encodedsize,
    bool x64);

#endif /* LIBPEINFECT_OBFUSCATOR_H_ */
