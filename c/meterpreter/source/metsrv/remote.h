/*!
 * @file remote.h
 * @brief Declarations of functions and types that interact with a remote endpoint.
 */
#ifndef _METERPRETER_METSRV_REMOTE_H
#define _METERPRETER_METSRV_REMOTE_H

#include "common_thread.h"
#include "common_config.h"
#include "common_pivot_tree.h"

Remote* remote_allocate();
VOID remote_deallocate(Remote *remote);

VOID remote_set_fd(Remote *remote, SOCKET fd);

#endif
