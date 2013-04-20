#ifndef _METERPRETER_SOURCE_EXTENSION_MIMIKATZ_MIMIKATZ_H
#define _METERPRETER_SOURCE_EXTENSION_MIMIKATZ_MIMIKATZ_H
extern "C" 
{
#include "../../common/common.h"
}
#endif

#include <io.h>
#include <fcntl.h>
#include <iostream>
#include <sstream>
#include "mimikatz.h"
#include "global.h"

#define TLV_TYPE_EXTENSION_MIMIKATZ 0

#define TLV_MIMIKATZ_RESULT \
	MAKE_CUSTOM_TLV(                 \
	TLV_META_TYPE_STRING,      \
	TLV_TYPE_EXTENSION_MIMIKATZ, \
	TLV_EXTENSIONS + 1)