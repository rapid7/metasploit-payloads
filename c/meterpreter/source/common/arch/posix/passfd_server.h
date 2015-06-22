/*!
 * @file passfd_server.h
 * @brief Declarations for functions which allow to share a file descriptor.
 */
#include "common.h"

LONG passfd(SOCKET orig_fd,  LPSTR sock_path);
