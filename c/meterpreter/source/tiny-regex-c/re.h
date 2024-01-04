/*
 *
 * Mini regex-module inspired by Rob Pike's regex code described in:
 *
 * http://www.cs.princeton.edu/courses/archive/spr09/cos333/beautiful.html
 *
 *
 *
 * Supports:
 * ---------
 *   '.'        Dot, matches any character
 *   '^'        Start anchor, matches beginning of string
 *   '$'        End anchor, matches end of string
 *   '*'        Asterisk, match zero or more (greedy)
 *   '+'        Plus, match one or more (greedy)
 *   '?'        Question, match zero or one (non-greedy)
 *   '[abc]'    Character class, match if one of {'a', 'b', 'c'}
 *   '[^abc]'   Inverted class, match if NOT one of {'a', 'b', 'c'} -- NOTE: feature is currently broken!
 *   '[a-zA-Z]' Character ranges, the character set of the ranges { a-z | A-Z }
 *   '\s'       Whitespace, \t \f \r \n \v and spaces
 *   '\S'       Non-whitespace
 *   '\w'       Alphanumeric, [a-zA-Z0-9_]
 *   '\W'       Non-alphanumeric
 *   '\d'       Digits, [0-9]
 *   '\D'       Non-digits
 *
 *
 */

#ifndef _TINY_REGEX_C
#define _TINY_REGEX_C

#ifndef RE_DOT_MATCHES_NEWLINE
/* Define to 0 if you DON'T want '.' to match '\r' + '\n' */
#define RE_DOT_MATCHES_NEWLINE 1
#endif

#ifdef __cplusplus
extern "C"{
#endif

// size_t for 32-bit compilation.
#include <stddef.h>

typedef struct regex_t
{
    unsigned char  type;   /* CHAR, STAR, etc.                      */
    union
    {
        unsigned char  ch;   /*      the character itself             */
        unsigned char* ccl;  /*  OR  a pointer to characters in class */
    } u;
} regex_t;

/* Typedef'd pointer to get abstract datatype. */
typedef struct regex_t* re_t;

#define MAX_REGEXP_OBJECTS      255    /* Max number of regex symbols in expression. */
#define MAX_CHAR_CLASS_LEN      255    /* Max length of character-class buffer in.   */

/* Find matches of the compiled pattern inside text. */
int re_matchp(re_t pattern, const char* text, size_t text_length, size_t max_match_length, size_t* matchlength);

/* Compile a regular expression in-place, allowing for multiple needles to be compiled without the usage of a static buffer. Returns ERROR_SUCCESS (0) on success, else 1. */
int re_compile(const char* pattern, size_t pattern_length, re_t compiled_regex, unsigned char* regex_char_buffer);

#ifdef __cplusplus
}
#endif

#endif /* ifndef _TINY_REGEX_C */
