#include "common.h"
#include "pivot_tree.h"

typedef struct _PivotNode
{
	BYTE guid[sizeof(GUID)];
	PivotContext* ctx;

	struct _PivotNode* left;
	struct _PivotNode* right;
} PivotNode;

PivotTree* pivot_tree_create()
{
	return (PivotTree*)calloc(1, sizeof(PivotTree));
}

DWORD pivot_tree_add_node(PivotNode* parent, PivotNode* node)
{
	int cmp = memcmp(parent->guid, node->guid, sizeof(parent->guid));

	if (cmp < 0)
	{
		if (parent->left == NULL)
		{
			parent->left = node;
			return ERROR_SUCCESS;
		}

		return pivot_tree_add_node(parent->left, node);
	}

	if (parent->right == NULL)
	{
		parent->right = node;
		return ERROR_SUCCESS;
	}

	return pivot_tree_add_node(parent->right, node);
}

DWORD pivot_tree_add(PivotTree* tree, LPBYTE guid, PivotContext* ctx)
{
	PivotNode* node = (PivotNode*)calloc(1, sizeof(PivotNode));

	memcpy(node->guid, guid, sizeof(node->guid));
	node->ctx = ctx;

	if (tree->head == NULL)
	{
		tree->head = node;
		return ERROR_SUCCESS;
	}

	return pivot_tree_add_node(tree->head, node);
}

PivotNode* pivot_tree_largest_node(PivotNode* node)
{
	if (node == NULL)
	{
		return NULL;
	}

	if (node->right == NULL)
	{
		return node;
	}
	return pivot_tree_largest_node(node->right);
}

DWORD pivot_tree_remove_node(PivotNode* parent, LPBYTE guid)
{
	int cmp = memcmp(parent->guid, guid, sizeof(parent->guid));
	if (cmp < 0 && parent->left != NULL)
	{
		int cmp = memcmp(parent->left->guid, guid, sizeof(parent->guid));
		if (cmp == 0)
		{
			PivotNode* remove = parent->left;
			PivotNode* left = remove->left;
			PivotNode* largest = pivot_tree_largest_node(left);

			if (largest != NULL)
			{
				largest->right = remove->right;
				parent->left = left;
			}
			else
			{
				parent->left = remove->right;
			}

			free(remove);
			return ERROR_SUCCESS;
		}

		return pivot_tree_remove_node(parent->left, guid);
	}

	if (cmp > 0 && parent->right != NULL)
	{
		int cmp = memcmp(parent->right->guid, guid, sizeof(parent->guid));
		if (cmp == 0)
		{
			PivotNode* remove = parent->right;
			PivotNode* left = remove->left;
			PivotNode* largest = pivot_tree_largest_node(left);

			if (largest != NULL)
			{
				largest->right = remove->right;
				parent->right = left;
			}
			else
			{
				parent->right = remove->right;
			}

			free(remove);
			return ERROR_SUCCESS;
		}

		return pivot_tree_remove_node(parent->left, guid);
	}

	return ERROR_SUCCESS;
}

DWORD pivot_tree_remove(PivotTree* tree, LPBYTE guid)
{
	if (tree->head == NULL)
	{
		return ERROR_SUCCESS;
	}

	int cmp = memcmp(tree->head->guid, guid, sizeof(tree->head->guid));

	if (cmp == 0)
	{
		PivotNode* remove = tree->head;
		PivotNode* left = tree->head->left;
		PivotNode* largest = pivot_tree_largest_node(left);

		if (largest != NULL)
		{
			largest->right = tree->head->right;
			tree->head = left;
		}
		else
		{
			tree->head = tree->head->right;
		}

		free(remove);
		return ERROR_SUCCESS;
	}

	return pivot_tree_remove_node(tree->head, guid);
}

PivotContext* pivot_tree_find_node(PivotNode* node, LPBYTE guid)
{
	if (node == NULL)
	{
		return NULL;
	}

	int cmp = memcmp(guid, node->guid, sizeof(guid));
	if (cmp == 0)
	{
		return node->ctx;
	}

	if (cmp < 0)
	{
		return pivot_tree_find_node(node->left, guid);
	}

	return pivot_tree_find_node(node->right, guid);
}

PivotContext* pivot_tree_find(PivotTree* tree, LPBYTE guid)
{
	return pivot_tree_find_node(tree->head, guid);
}

void pivot_tree_traverse_node(PivotNode* node, PivotTreeTraverseCallback callback, LPVOID state)
{
	if (node != NULL)
	{
		pivot_tree_traverse_node(node->left, callback, state);
		callback(node->guid, node->ctx, state);
		pivot_tree_traverse_node(node->right, callback, state);
	}
}

void pivot_tree_traverse(PivotTree* tree, PivotTreeTraverseCallback callback, LPVOID state)
{
	pivot_tree_traverse_node(tree->head, callback, state);
}

void pivot_tree_destroy_node(PivotNode* node)
{
	if (node != NULL)
	{
		pivot_tree_destroy_node(node->left);
		pivot_tree_destroy_node(node->right);
		free(node);
	}
}

void pivot_tree_destroy(PivotTree* tree)
{
	pivot_tree_destroy_node(tree->head);
	free(tree);
}