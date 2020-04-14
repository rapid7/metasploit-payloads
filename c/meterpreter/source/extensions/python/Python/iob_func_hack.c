#include <stdio.h>

_ACRTIMP_ALT FILE** __cdecl __iob_func()
{
	static FILE* x[3] = { NULL };
	if (x[0] == NULL)
	{
		x[0] = stdin;
		x[1] = stdout;
		x[2] = stderr;
	}

	return x;
}