/*!
 * @file remote.c
 * @brief Definitions of functions and types that interact with a remote endpoint.
 */
#include "metsrv.h"
#include "packet_encryption.h"

/*!
 * @brief Instantiate a remote context from a file descriptor.
 * @details This function takes a file descriptor and wraps it in \c Remote
 *          context which makes it easier to interact with the endpoint.
 * @returns Pointer to the created \c Remote instance.
 * @retval NULL Indicates a memory allocation failure or a lock creation failure.
 * @retval Non-NULL Successful creation of the context.
 */
Remote* remote_allocate()
{
	Remote* remote = (Remote*)calloc(1, sizeof(Remote));
	LOCK* lock = lock_create();

	do
	{
		if (remote == NULL || lock == NULL)
		{
			break;
		}

		remote->lock = lock;
		remote->enc_ctx = NULL;
		remote->pivot_sessions = pivot_tree_create();
		remote->pivot_listeners = pivot_tree_create();

		dprintf("[REMOTE] remote created %p", remote);
		return remote;
	} while (0);

	if (lock)
	{
		lock_destroy(lock);
	}

	if (remote->pivot_sessions)
	{
		pivot_tree_destroy(remote->pivot_sessions);
	}

	if (remote->pivot_listeners)
	{
		pivot_tree_destroy(remote->pivot_listeners);
	}

	free(remote);

	vdprintf("[REMOTE] here 3");
	return NULL;
}

/*!
 * @brief Deallocate a remote context.
 * @param remote Pointer to the \c Remote instance to deallocate.
 */
VOID remote_deallocate(Remote * remote)
{
	free_encryption_context(remote);
	pivot_tree_destroy(remote->pivot_sessions);
	pivot_tree_destroy(remote->pivot_listeners);

	if (remote->lock)
	{
		lock_destroy(remote->lock);
	}

	free(remote->orig_config);

	// Wipe our structure from memory
	memset(remote, 0, sizeof(Remote));

	free(remote);
}
