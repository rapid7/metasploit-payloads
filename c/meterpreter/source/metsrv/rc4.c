#include "rc4.h"

BOOL InitRc4(RC4_CTX* Context, unsigned char* Key, size_t len) {
	unsigned char T = 0;
	unsigned int j = 0;

	if (Context == NULL || Key == NULL || len == 0) {
		return FALSE;
	}

	memset(Context, 0x00, sizeof(RC4_CTX));

	for (unsigned int i = 0; i < 256; i++) {
		Context->s[i] = i;
	}

	for (unsigned int i = 0; i < 256; i++) {
		j = (j + Context->s[i] + Key[i % len]) % 256;
		T = Context->s[i];
		Context->s[i] = Context->s[j];
		Context->s[j] = T;
	}

	Context->i = 0;
	Context->j = 0;

	return TRUE;
}

BOOL RC4Cipher(RC4_CTX* Context, unsigned char* buf, size_t len) {
	unsigned char T = 0;
	unsigned int i = Context->i;
	unsigned int j = Context->j;

	for (unsigned int k = 0; k < len;k++) {
		i = (i+1) % 256;
		j = (j + Context->s[i]) % 256;
		T = Context->s[i];
		Context->s[i] = Context->s[j];
		Context->s[j] = T;
		buf[k] ^= Context->s[(Context->s[i] + Context->s[j]) % 256];
	}

	Context->i = i;
	Context->j = j;

	return TRUE;
}