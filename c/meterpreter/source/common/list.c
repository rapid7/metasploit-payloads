/*!
 * @file list.c
 * @brief Definitions for functions that operate on lists.
 * @details An implementation of a simple thread safe double linked list structure. Can be used as either
 *          a stack (via pop/push), a queue (via push/shift) or an array (via get/add/insert/remove). If
 *          performing a group of actions on a list based on results from list actions, acquire the list 
 *          lock before the group of actions and release lock when done.
 */
#include "common.h"

/*!
 * @brief Create a thread-safe double linked list.
 * @returns A new instance of a linked list.
 * @retval NULL Indicates a memory allocation failure.
 */
LIST * list_create(VOID)
{
	LIST * list = (LIST*)malloc(sizeof(LIST));
	if (list != NULL)
	{
		list->start = NULL;
		list->end = NULL;
		list->count = 0;
		list->lock = lock_create();

		if (list->lock == NULL)
		{
			list_destroy(list);
			return NULL;
		}
	}
	return list;
}

/*!
 * @brief Destroy an existing linked list.
 * @details This destroys all nodes and the list itself but not the data held in the
 *          linked list. This is the responsibility of the caller to destroy.
 * @param list The \c LIST instance to destroy.
 */
VOID list_destroy(LIST * list)
{
	NODE * current_node;
	NODE * next_node;

	if (list != NULL)
	{
		lock_acquire(list->lock);

		current_node = list->start;

		while (current_node != NULL)
		{
			next_node = current_node->next;

			current_node->next = NULL;

			current_node->prev = NULL;

			free(current_node);

			current_node = next_node;
		}

		list->count = 0;

		lock_release(list->lock);

		lock_destroy(list->lock);

		free(list);
	}
}

/*!
 * @brief Get the number of items in the list.
 * @param list The \c LIST to get a count of.
 * @returns The number of elements in the list.
 * @remark If using this coung value to itterate through the list with `list_get`, acquire
 *         the lists lock before the `list_count/list_get` block and release it afterwards.
 */
DWORD list_count(LIST * list)
{
	DWORD count = 0;

	if (list != NULL)
	{
		lock_acquire(list->lock);

		count = list->count;

		lock_release(list->lock);
	}

	return count;
}

/*!
 * @brief Get the data value held in the list and a specified index.
 * @param list Pointer to the \c LIST to get the element from.
 * @param index Index of the element to get;
 * @returns Pointer to the item in the list.
 * @retval NULL Indicates the element doesn't exist in the list.
 * @remark This will perform a linear search from the beginning of the list.
 */
LPVOID list_get(LIST * list, DWORD index)
{
	LPVOID data = NULL;
	NODE * current_node = NULL;

	if (list == NULL)
		return NULL;

	lock_acquire(list->lock);

	if (list->count <= index)
	{
		lock_release(list->lock);
		return NULL;
	}

	current_node = list->start;

	while (current_node != NULL)
	{
		if (index == 0)
		{
			break;
		}

		current_node = current_node->next;

		index--;
	}

	if (current_node != NULL)
	{
		data = current_node->data;
	}

	lock_release(list->lock);

	return data;
}

/*!
 * @brief Add a data item onto the end of the list.
 * @param list Pointer to the \c LIST to add the item to.
 * @param data The data that is to be added to the list.
 * @returns Indication of success or failure.
 * @sa list_push
 */
BOOL list_add(LIST * list, LPVOID data)
{
	return list_push(list, data);
}

/*!
 * @brief Internal function to remove a node from a list.
 * @param list Pointer to the \c LIST containing \c node.
 * @param node Pointer to the \c NOTE to remove.
 * @returns Indication of success or failure.
 * @remark Assumes caller has aquired the appropriate lock first.
 */
BOOL list_remove_node(LIST * list, NODE * node)
{
	if (list == NULL || node == NULL)
	{
		return FALSE;
	}

	if (list->count - 1 == 0)
	{
		list->start = NULL;
		list->end = NULL;
	}
	else
	{
		if (list->start == node)
		{
			list->start = list->start->next;
			list->start->prev = NULL;
		}
		else if (list->end == node)
		{
			list->end = list->end->prev;
			list->end->next = NULL;
		}
		else
		{
			node->next->prev = node->prev;
			node->prev->next = node->next;
		}
	}

	list->count -= 1;

	node->next = NULL;

	node->prev = NULL;

	free(node);

	return TRUE;
}

/*!
 * @brief Remove a given data item from the list.
 * @param list Pointer to the \c LIST to remove the item from.
 * @param data The data that is to be removed from the list.
 * @remark Assumes data items are unqique as only the first occurrence is removed. 
 * @returns Indication of success or failure.
 * @sa list_remove_node
 */
BOOL list_remove(LIST * list, LPVOID data)
{
	BOOL result = FALSE;
	NODE * current_node = NULL;

	if (list == NULL || data == NULL)
	{
		return FALSE;
	}

	lock_acquire(list->lock);

	current_node = list->start;

	while (current_node != NULL)
	{
		if (current_node->data == data)
		{
			break;
		}

		current_node = current_node->next;
	}

	result = list_remove_node(list, current_node);

	lock_release(list->lock);

	return result;
}

/*!
 * @brief Remove a list item at the specified index.
 * @param list Pointer to the \c LIST to remove the item from.
 * @param index Index of the item to remove.
 * @returns Indication of success or failure.
 */
BOOL list_delete(LIST * list, DWORD index)
{
	BOOL result = FALSE;
	LPVOID data = NULL;
	NODE * current_node = NULL;

	if (list == NULL)
	{
		return FALSE;
	}

	lock_acquire(list->lock);

	if (list->count > index)
	{
		current_node = list->start;

		while (current_node != NULL)
		{
			if (index == 0)
			{
				result = list_remove_node(list, current_node);
				break;
			}

			current_node = current_node->next;

			index--;
		}
	}

	lock_release(list->lock);

	return result;
}

/*!
 * @brief Push a data item onto the end of the list.
 * @param list Pointer to the \c LIST to append the data to.
 * @param data Pointer to the data to append.
 * @returns Indication of success or failure.
 */
BOOL list_push(LIST * list, LPVOID data)
{
	NODE * node = NULL;

	if (list == NULL)
		return FALSE;

	node = (NODE*)malloc(sizeof(NODE));
	if (node == NULL)
	{
		return FALSE;
	}

	node->data = data;
	node->next = NULL;
	node->prev = NULL;

	lock_acquire(list->lock);

	if (list->end != NULL)
	{
		list->end->next = node;

		node->prev = list->end;

		list->end = node;
	}
	else
	{
		list->start = node;
		list->end = node;
	}

	list->count += 1;

	lock_release(list->lock);

	return TRUE;
}

/*!
 * @brief Pop a data value off the end of the list.
 * @param list Pointer to the \c LIST to pop the value from.
 * @returns The popped value.
 * @retval NULL Indicates no data in the list.
 */
LPVOID list_pop(LIST * list)
{
	LPVOID data = NULL;

	if (list == NULL)
	{
		return NULL;
	}

	lock_acquire(list->lock);

	if (list->end != NULL)
	{
		data = list->end->data;

		list_remove_node(list, list->end);
	}

	lock_release(list->lock);

	return data;
}

/*!
 * @brief Pop a data value off the start of the list.
 * @param list Pointer to the \c LIST to shift the value from.
 * @returns The shifted value.
 * @retval NULL Indicates no data in the list.
 */
LPVOID list_shift(LIST * list)
{
	LPVOID data = NULL;

	if (list == NULL)
	{
		return NULL;
	}

	lock_acquire(list->lock);

	if (list->start != NULL)
	{
		data = list->start->data;

		list_remove_node(list, list->start);
	}

	lock_release(list->lock);

	return data;
}
