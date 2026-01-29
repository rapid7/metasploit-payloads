#include <windows.h>

typedef struct {
	unsigned int i, j;
	unsigned char s[256];
} RC4_CTX;

BOOL InitRc4(RC4_CTX* Context, unsigned char* Key, size_t len);
BOOL RC4Cipher(RC4_CTX* Context, unsigned char* buf, size_t len);

