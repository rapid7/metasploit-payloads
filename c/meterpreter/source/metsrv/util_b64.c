#include "util_b64.h"
#include <string.h>
#include <stdlib.h>

static int b64_val(char c)
{
	if (c >= 'A' && c <= 'Z') return c - 'A';
	if (c >= 'a' && c <= 'z') return c - 'a' + 26;
	if (c >= '0' && c <= '9') return c - '0' + 52;
	if (c == '+') return 62;
	if (c == '/') return 63;
	return -1;
}

BYTE* b64_decode(const char* input, size_t* out_len)
{
	if (!input || !out_len) return NULL;

	size_t in_len = strlen(input);
	if (in_len == 0 || (in_len % 4) != 0) return NULL;

	size_t pad = 0;
	if (input[in_len - 1] == '=') pad++;
	if (in_len >= 2 && input[in_len - 2] == '=') pad++;

	size_t decoded_len = (in_len / 4) * 3 - pad;
	BYTE* out = (BYTE*)malloc(decoded_len);
	if (!out) return NULL;

	size_t oi = 0;
	for (size_t i = 0; i < in_len; i += 4)
	{
		int v0 = b64_val(input[i]);
		int v1 = b64_val(input[i + 1]);
		int v2 = (input[i + 2] == '=') ? 0 : b64_val(input[i + 2]);
		int v3 = (input[i + 3] == '=') ? 0 : b64_val(input[i + 3]);
		if (v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0)
		{
			free(out);
			return NULL;
		}
		unsigned int triple = ((unsigned int)v0 << 18)
		                    | ((unsigned int)v1 << 12)
		                    | ((unsigned int)v2 <<  6)
		                    |  (unsigned int)v3;
		if (oi < decoded_len) out[oi++] = (BYTE)((triple >> 16) & 0xFF);
		if (oi < decoded_len) out[oi++] = (BYTE)((triple >>  8) & 0xFF);
		if (oi < decoded_len) out[oi++] = (BYTE)( triple        & 0xFF);
	}

	*out_len = decoded_len;
	return out;
}
