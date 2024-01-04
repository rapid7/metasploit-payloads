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


#include "re.h"
#include <stdio.h>
#include <ctype.h>

/* Definitions: */

enum { UNUSED, DOT, BEGIN, END, QUESTIONMARK, STAR, PLUS, CHAR_RE, CHAR_CLASS, INV_CHAR_CLASS, DIGIT, NOT_DIGIT, ALPHA, NOT_ALPHA, WHITESPACE, NOT_WHITESPACE, /* BRANCH */ };

/* Private function declarations: */
static int matchpattern(regex_t* pattern, const char* text, size_t text_length, size_t text_offset, size_t max_match_size, size_t* matchlength);
static int matchcharclass(char c, const char* str);
static int matchstar(regex_t p, regex_t* pattern, const char* text, size_t text_length, size_t text_offset, size_t max_match_size, size_t* matchlength);
static int matchplus(regex_t p, regex_t* pattern, const char* text, size_t text_length, size_t text_offset, size_t max_match_size, size_t* matchlength);
static int matchone(regex_t p, char c);
static int matchdigit(char c);
static int matchalpha(char c);
static int matchwhitespace(char c);
static int matchmetachar(char c, const char* str);
static int matchrange(char c, const char* str);
static int matchdot(char c);
static int ismetachar(char c);

/* Public functions: */
int re_matchp(re_t pattern, const char* text, size_t text_length, size_t max_match_length, size_t* matchlength)
{
  if (max_match_length == 0) { return -1; }
  *matchlength = 0;

  if (pattern == 0 || text_length == 0) { return -1; }

  if (pattern[0].type == BEGIN)
  {
      return ((matchpattern(&pattern[1], text, text_length, 0, max_match_length, matchlength)) ? 0 : -1);
  }
  
  int idx = -1;

  do
  {
      idx += 1;

      if (matchpattern(pattern, text, text_length, idx, max_match_length, matchlength))
      {
          return idx;
      }
  }
  while ((size_t)idx < text_length);

  return -1;
}

int re_compile(const char* pattern, size_t pattern_length, re_t compiled_regex, unsigned char* regex_char_buffer)
{
    int ccl_bufidx = 1;

    char c;     /* current char in pattern   */
    int i = 0;  /* index into pattern        */
    int j = 0;  /* index into re_compiled    */

    while (i < (int)pattern_length && (j + 1 < MAX_REGEXP_OBJECTS))
    {
        c = pattern[i];

        switch (c)
        {
            /* Meta-characters: */
        case '^': {    compiled_regex[j].type = BEGIN;           } break;
        case '$': {    compiled_regex[j].type = END;             } break;
        case '.': {    compiled_regex[j].type = DOT;             } break;
        case '*': {    compiled_regex[j].type = STAR;            } break;
        case '+': {    compiled_regex[j].type = PLUS;            } break;
        case '?': {    compiled_regex[j].type = QUESTIONMARK;    } break;
            /*    case '|': {    compiled_regex[j].type = BRANCH;          } break; <-- not working properly */

                  /* Escaped character-classes (\s \w ...): */
        case '\\':
        {
            if (i + 1 < (int)pattern_length)
            {
                /* Skip the escape-char '\\' */
                i += 1;
                /* ... and check the next */
                switch (pattern[i])
                {
                    /* Meta-character: */
                case 'd': {    compiled_regex[j].type = DIGIT;            } break;
                case 'D': {    compiled_regex[j].type = NOT_DIGIT;        } break;
                case 'w': {    compiled_regex[j].type = ALPHA;            } break;
                case 'W': {    compiled_regex[j].type = NOT_ALPHA;        } break;
                case 's': {    compiled_regex[j].type = WHITESPACE;       } break;
                case 'S': {    compiled_regex[j].type = NOT_WHITESPACE;   } break;

                    /* Escaped character, e.g. '.' or '$' */
                default:
                {
                    compiled_regex[j].type = CHAR_RE;
                    compiled_regex[j].u.ch = pattern[i];
                } break;
                }
            }
            else
            {
                compiled_regex[j].type = CHAR_RE;
                compiled_regex[j].u.ch = pattern[i];
            }
        } break;

        /* Character class: */
        case '[':
        {
            /* Remember where the char-buffer starts. */
            int buf_begin = ccl_bufidx;

            /* Look-ahead to determine if negated */
            if (pattern[i + 1] == '^')
            {
                compiled_regex[j].type = INV_CHAR_CLASS;
                i += 1; /* Increment i to avoid including '^' in the char-buffer */
                if (i + 1 == (int)pattern_length) /* incomplete pattern, missing non-zero char after '^' */
                {
                    return 1;
                }
            }
            else
            {
                compiled_regex[j].type = CHAR_CLASS;
            }

            /* Copy characters inside [..] to buffer */
            while ((pattern[++i] != ']')
                && (i < (int)pattern_length)) /* Missing ] */
            {
                if (pattern[i] == '\\')
                {
                    if (ccl_bufidx >= MAX_CHAR_CLASS_LEN - 1)
                    {
                        //fputs("exceeded internal buffer!\n", stderr);
                        return 1;
                    }
                    if (i + 1 == (int)pattern_length) /* incomplete pattern, missing non-zero char after '\\' */
                    {
                        return 1;
                    }
                    regex_char_buffer[ccl_bufidx++] = pattern[i++];
                }
                else if (ccl_bufidx >= MAX_CHAR_CLASS_LEN)
                {
                    //fputs("exceeded internal buffer!\n", stderr);
                    return 1;
                }
                regex_char_buffer[ccl_bufidx++] = pattern[i];
            }
            if (ccl_bufidx >= MAX_CHAR_CLASS_LEN)
            {
                /* Catches cases such as [00000000000000000000000000000000000000][ */
                //fputs("exceeded internal buffer!\n", stderr);
                return 1;
            }
            /* Null-terminate string end */
            regex_char_buffer[ccl_bufidx++] = 0;
            compiled_regex[j].u.ccl = &regex_char_buffer[buf_begin];
        } break;

        /* Other characters: */
        default:
        {
            compiled_regex[j].type = CHAR_RE;
            compiled_regex[j].u.ch = c;
        } break;
        }

        i += 1;
        j += 1;
    }
    /* 'UNUSED' is a sentinel used to indicate end-of-pattern */
    compiled_regex[j].type = UNUSED;

    return 0; // ERROR_SUCCESS
}

void re_print(regex_t* pattern)
{
  const char* types[] = { "UNUSED", "DOT", "BEGIN", "END", "QUESTIONMARK", "STAR", "PLUS", "CHAR", "CHAR_CLASS", "INV_CHAR_CLASS", "DIGIT", "NOT_DIGIT", "ALPHA", "NOT_ALPHA", "WHITESPACE", "NOT_WHITESPACE", "BRANCH" };

  int i;
  int j;
  char c;
  for (i = 0; i < MAX_REGEXP_OBJECTS; ++i)
  {
    if (pattern[i].type == UNUSED)
    {
      break;
    }

    printf("type: %s", types[pattern[i].type]);
    if (pattern[i].type == CHAR_CLASS || pattern[i].type == INV_CHAR_CLASS)
    {
      printf(" [");
      for (j = 0; j < MAX_CHAR_CLASS_LEN; ++j)
      {
        c = pattern[i].u.ccl[j];
        if ((c == '\0') || (c == ']'))
        {
          break;
        }
        printf("%c", c);
      }
      printf("]");
    }
    else if (pattern[i].type == CHAR_RE)
    {
      printf(" '%c'", pattern[i].u.ch);
    }
    printf("\n");
  }
}



/* Private functions: */
static int matchdigit(char c)
{
  return isdigit(c);
}
static int matchalpha(char c)
{
  return isalpha(c);
}
static int matchwhitespace(char c)
{
  return isspace(c);
}
static int matchalphanum(char c)
{
  return ((c == '_') || matchalpha(c) || matchdigit(c));
}
static int matchrange(char c, const char* str)
{
  return (    (c != '-')
           && (str[0] != '\0')
           && (str[0] != '-')
           && (str[1] == '-')
           && (str[2] != '\0')
           && (    (c >= str[0])
                && (c <= str[2])));
}
static int matchdot(char c)
{
#if defined(RE_DOT_MATCHES_NEWLINE) && (RE_DOT_MATCHES_NEWLINE == 1)
  (void)c;
  return 1;
#else
  return c != '\n' && c != '\r';
#endif
}
static int ismetachar(char c)
{
  return ((c == 's') || (c == 'S') || (c == 'w') || (c == 'W') || (c == 'd') || (c == 'D'));
}

static int matchmetachar(char c, const char* str)
{
  switch (str[0])
  {
    case 'd': return  matchdigit(c);
    case 'D': return !matchdigit(c);
    case 'w': return  matchalphanum(c);
    case 'W': return !matchalphanum(c);
    case 's': return  matchwhitespace(c);
    case 'S': return !matchwhitespace(c);
    default:  return (c == str[0]);
  }
}

static int matchcharclass(char c, const char* str)
{
  do
  {
    if (matchrange(c, str))
    {
      return 1;
    }
    else if (str[0] == '\\')
    {
      /* Escape-char: increment str-ptr and match on next char */
      str += 1;
      if (matchmetachar(c, str))
      {
        return 1;
      }
      else if ((c == str[0]) && !ismetachar(c))
      {
        return 1;
      }
    }
    else if (c == str[0])
    {
      if (c == '-')
      {
        return ((str[-1] == '\0') || (str[1] == '\0'));
      }
      else
      {
        return 1;
      }
    }
  }
  while (*str++ != '\0');

  return 0;
}

static int matchone(regex_t p, char c)
{
  switch (p.type)
  {
    case DOT:            return matchdot(c);
    case CHAR_CLASS:     return  matchcharclass(c, (const char*)p.u.ccl);
    case INV_CHAR_CLASS: return !matchcharclass(c, (const char*)p.u.ccl);
    case DIGIT:          return  matchdigit(c);
    case NOT_DIGIT:      return !matchdigit(c);
    case ALPHA:          return  matchalphanum(c);
    case NOT_ALPHA:      return !matchalphanum(c);
    case WHITESPACE:     return  matchwhitespace(c);
    case NOT_WHITESPACE: return !matchwhitespace(c);
    default:             return  (p.u.ch == c);
  }
}

static int matchstar(regex_t p, regex_t* pattern, const char* text, size_t text_length, size_t text_offset, size_t max_match_length, size_t* matchlength)
{
  size_t prelen = *matchlength;
  const char* prepoint = text;
  while ((text_offset < text_length) && (max_match_length > *matchlength) && matchone(p, text[text_offset]))
  {
    text_offset++;
    (*matchlength)++;
  }
  while (&text[text_offset] >= prepoint)
  {
    if (matchpattern(pattern, text, text_length, text_offset--, max_match_length, matchlength))
      return 1;
    (*matchlength)--;
  }

  *matchlength = prelen;
  return 0;
}

static int matchplus(regex_t p, regex_t* pattern, const char* text, size_t text_length, size_t text_offset, size_t max_match_length, size_t* matchlength)
{
  const char* prepoint = text;
  while ((text_offset < text_length) && (max_match_length > *matchlength) && matchone(p, text[text_offset]))
  {
    text_offset++;
    (*matchlength)++;
  }
  while (text > prepoint)
  {
    if (matchpattern(pattern, text, text_length, text_offset--, max_match_length, matchlength))
      return 1;
    (*matchlength)--;
  }

  return 0;
}

static int matchquestion(regex_t p, regex_t* pattern, const char* text, size_t text_length, size_t text_offset, size_t max_match_length, size_t* matchlength)
{
  if (p.type == UNUSED)
    return 1;
  if (matchpattern(pattern, text, text_length, text_offset, max_match_length, matchlength))
      return 1;
  if ((text_offset < text_length) && (max_match_length > *matchlength) && matchone(p, text[text_offset++]))
  {
    if (matchpattern(pattern, text, text_length, text_offset, max_match_length, matchlength))
    {
      (*matchlength)++;
      return 1;
    }
  }
  return 0;
}


#if 0

/* Recursive matching */
static int matchpattern(regex_t* pattern, const char* text, int *matchlength)
{
  int pre = *matchlength;
  if ((pattern[0].type == UNUSED) || (pattern[1].type == QUESTIONMARK))
  {
    return matchquestion(pattern[1], &pattern[2], text, matchlength);
  }
  else if (pattern[1].type == STAR)
  {
    return matchstar(pattern[0], &pattern[2], text, matchlength);
  }
  else if (pattern[1].type == PLUS)
  {
    return matchplus(pattern[0], &pattern[2], text, matchlength);
  }
  else if ((pattern[0].type == END) && pattern[1].type == UNUSED)
  {
    return text[0] == '\0';
  }
  else if ((text[0] != '\0') && matchone(pattern[0], text[0]))
  {
    (*matchlength)++;
    return matchpattern(&pattern[1], text+1);
  }
  else
  {
    *matchlength = pre;
    return 0;
  }
}

#else

/* Iterative matching */
static int matchpattern(regex_t* pattern, const char* text, size_t text_length, size_t text_offset, size_t max_match_length, size_t* matchlength)
{
  size_t pre = *matchlength;
  do
  {
    if ((pattern[0].type == UNUSED) || (pattern[1].type == QUESTIONMARK))
    {
      return matchquestion(pattern[0], &pattern[2], text, text_length, text_offset, max_match_length, matchlength);
    }
    else if (pattern[1].type == STAR)
    {
      return matchstar(pattern[0], &pattern[2], text, text_length, text_offset, max_match_length, matchlength);
    }
    else if (pattern[1].type == PLUS)
    {
      return matchplus(pattern[0], &pattern[2], text, text_length, text_offset, max_match_length, matchlength);
    }
    else if ((pattern[0].type == END) && pattern[1].type == UNUSED)
    {
      return (text_offset == text_length - 1);
    }
/*  Branching is not working properly
    else if (pattern[1].type == BRANCH)
    {
      return (matchpattern(pattern, text) || matchpattern(&pattern[2], text));
    }
*/
  (*matchlength)++;
  }
  while ((text_offset < text_length) && (max_match_length > *matchlength) && matchone(*pattern++, text[text_offset++]));

  *matchlength = pre;
  return 0;
}

#endif
