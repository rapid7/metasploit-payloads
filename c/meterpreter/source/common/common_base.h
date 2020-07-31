/*!
 * @file common_base.h
 * @brief Declarations of macros and types that apply to almost any Meterpreter component.
 */
#ifndef _METERPRETER_COMMON_BASE_H
#define _METERPRETER_COMMON_BASE_H

#include "common_core.h"

/*! @brief Function pointer type that defines the interface for a dispatch handler. */
typedef DWORD(*DISPATCH_ROUTINE)(Remote *remote, Packet *packet);
typedef BOOL(*INLINE_DISPATCH_ROUTINE)(Remote *remote, Packet *packet, DWORD* result);

/*! @brief Specifies the maximum number of arguments that are checked/handled
 *         in a request/response packet dispatcher.
 */
#define MAX_CHECKED_ARGUMENTS  16

/*! @brief Flag indicating that the command arguments repeat. */
#define ARGUMENT_FLAG_REPEAT   (1 << 28)
/*! @brief Mask indicating the range numbers allowed for command arguments. */
#define ARGUMENT_FLAG_MASK     0x0fffffff

/*! @brief Helper macro that contains the required NULL initialisations for a command handler TLV info. */
#define EMPTY_TLV { 0 }, 0
/*! @brief Helper macro which defines an empty dispatch handler. */
#define EMPTY_DISPATCH_HANDLER NULL, NULL, EMPTY_TLV
/*! @brief Helper macro that defines terminator for command lists. */
#define COMMAND_TERMINATOR { 0, { EMPTY_DISPATCH_HANDLER }, { EMPTY_DISPATCH_HANDLER } }

/*!
 * @brief Helper macro that defines a command instance with a request handler only.
 * @remarks The request handler will be executed on a separate thread.
 */
#define COMMAND_REQ(command_id, reqHandler) { command_id, { reqHandler, NULL, EMPTY_TLV }, { EMPTY_DISPATCH_HANDLER } }
/*!
 * @brief Helper macro that defines a command instance with a response handler only.
 * @remarks The request handler will be executed on a separate thread.
 */
#define COMMAND_REP(command_id, repHandler) { command_id, { EMPTY_DISPATCH_HANDLER }, { repHandler, NULL, EMPTY_TLV } }
/*!
 * @brief Helper macro that defines a command instance with both a request and response handler.
 * @remarks The request handler will be executed on a separate thread.
 */
#define COMMAND_REQ_REP(command_id, reqHandler, repHandler) { command_id, { reqHandler, NULL, EMPTY_TLV }, { repHandler, NULL, EMPTY_TLV } }
/*!
 * @brief Helper macro that defines a command instance with an inline request handler only.
 * @remarks The request handler will be executed on the server thread.
 */
#define COMMAND_INLINE_REQ(command_id, reqHandler) { command_id, { NULL, reqHandler, EMPTY_TLV }, { EMPTY_DISPATCH_HANDLER } }
/*!
 * @brief Helper macro that defines a command instance with an inline response handler only.
 * @remarks The response handler will be executed on the server thread.
 */
#define COMMAND_INLINE_REP(command_id, reqHandler) { command_id, { EMPTY_DISPATCH_HANDLER }, { NULL, reqHandler, EMPTY_TLV } }

/*!
 * @brief Defines a command handler for requests and responses.
 */
typedef struct 
{
	/*! @brief Pointer to the routine that will be called to handle the request/response. */
	DISPATCH_ROUTINE        handler;

	/*!
	 * @brief Pointer to the routine that will be called on the _current thread_.
	 * @remark If this function is specified then it will be invoked on the current server
	 *         thread rather than having a new thread allocated to it for processing.
	 *         The result of this routine will indicate whether the server should continue.
	 *         If this value is specified (ie. non-NULL) then the \c handler value is ignored.
	 */
	INLINE_DISPATCH_ROUTINE inline_handler;

	/*! @brief Array of types that match the expected arguments for this response/request routine. */
	TlvMetaType             argumentTypes[MAX_CHECKED_ARGUMENTS];
	/*! @brief The number of entries in the \c argumentTypes array. */
	DWORD                   numArgumentTypes;
} PacketDispatcher;

/*!
 * @brief Container for a command definition.
 */
typedef struct command
{
	UINT             command_id; ///< Identifier for the command.
	PacketDispatcher request;    ///< Defines the request handler.
	PacketDispatcher response;   ///< Defines the response handler.

	// Internal -- not stored
	struct command   *next;      ///< Pointer to the next command in the command list.
	struct command   *prev;      ///< Pointer to the previous command in the command list.
} Command;

#endif
