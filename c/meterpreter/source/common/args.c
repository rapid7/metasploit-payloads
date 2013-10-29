/*!
 * @file args.c
 * @brief Definitions for argument parsing functionality.
 */
#include "common.h"

/*!
 * @brief Parse an argument vector by a parameter format specifier
 * @details Intended to be called repeatedly until all arguments are parsed.
 *          Each call results in a single argument be parsed.
 * @param argc Number of arguments to in the argument list.
 * @param argv Array of arguments to parse.
 * @param params String of supported parameters. eg \c abc:de: Parameters
 *               followed by a colon expect an associated argumetn
 * @param ctx Pointer to a context used to keep track of parsing.
 * @return Indication of whether parsing was successful.
 * @retval ERROR_NOT_FOUND The specified parameter wasn't found in the
 *                         argument list.
 * @retval ERROR_INVALID_PARAMETER The specified parameter was missing an
                                   associated argument.
 * @retval ERROR_SUCCESS The argument was parsed correctly.
 */
DWORD args_parse(UINT argc, CHAR **argv, PCHAR params, 
		ArgumentContext *ctx)
{
	DWORD index = 0;

	if (!ctx->currentIndex)
		ctx->currentIndex = 1;

	index = ctx->currentIndex;

	// We've hit the end, return out.
	if (index >= argc)
		return ERROR_NOT_FOUND;

	// Is this a toggled parameter?
	if (argv[index][0] == '-')
	{
		PCHAR currentParam = params;
		BOOL hasParam = FALSE;

		// Check to see if this argument expects a parameter
		while (*currentParam)
		{
			if (*currentParam == argv[index][1])
			{
				hasParam = (*(currentParam + 1) == ':') ? TRUE : FALSE;
				break;
			}

			currentParam++;
		}

		// If this param requires an argument yet is not given one, fail.
		if ((hasParam) &&
		    (index + 1 >= argc))
			return ERROR_INVALID_PARAMETER;

		ctx->argument = (hasParam) ? argv[index+1] : NULL;
		ctx->toggle   = argv[index][1]; 

		// Skip past the parameter.
		if (hasParam)
			++index;
	}
	else
		ctx->toggle = 0;

	// Update the index
	ctx->currentIndex = ++index;

	return ERROR_SUCCESS;
}
