/*!
 * @file args.h
 * @brief Definitions for argument parsing functionality.
 */
#ifndef _METERPRETER_LIB_ARGS_H
#define _METERPRETER_LIB_ARGS_H

#include "linkage.h"

/*! @brief State container for \c args_parse calls. */
typedef struct
{
	DWORD currentIndex;    ///< The index of the argument being parsed.
	PCHAR argument;        ///< Pointer to the current switch's argument.
	CHAR  toggle;          ///< Indicates of this parameter is a toggle parameter.
} ArgumentContext;

LINKAGE DWORD args_parse(UINT argc, CHAR **argv, PCHAR params, 
		ArgumentContext *ctx);

#endif
