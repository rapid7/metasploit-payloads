/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globals.h"
#include <io.h>
#include <fcntl.h>

typedef void (*output_writer)(const wchar_t* newOutput);
void kprintf(PCWCHAR format, ...);

VOID kull_m_output_set_writer(output_writer writer);