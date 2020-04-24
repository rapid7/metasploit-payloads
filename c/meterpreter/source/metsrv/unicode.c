/*!
 * @file unicode.c
 * @brief Unicode conversion functions
 */

#include "common.h"

wchar_t *utf8_to_wchar(const char *in)
{
	wchar_t *out;
	int len;

	if (in == NULL) {
		return NULL;
	}

	len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, in, -1, NULL, 0);
	if (len <= 0) {
		return NULL;
	}

	out = calloc(len, sizeof(wchar_t));
	if (out == NULL) {
		return NULL;
	}

	if (MultiByteToWideChar(CP_UTF8, 0, in, -1, out, len) == 0) {
		free(out);
		out = NULL;
	}

	return out;
}

char *wchar_to_utf8(const wchar_t *in)
{
	char *out;
	int len;

	if (in == NULL) {
		return NULL;
	}

	len = WideCharToMultiByte(CP_UTF8, 0, in, -1, NULL, 0, NULL, NULL);
	if (len <= 0) {
		return NULL;
	}

	out = calloc(len, sizeof(char));
	if (out == NULL) {
		return NULL;
	}

	if (WideCharToMultiByte(CP_UTF8, 0, in, -1, out, len, NULL, FALSE) == 0) {
		free(out);
		out = NULL;
	}

	return out;
}
