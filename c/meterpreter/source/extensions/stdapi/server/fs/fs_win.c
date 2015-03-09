#include <sys/stat.h>

#include "fs_local.h"
#include "precomp.h"

char * fs_expand_path(const char *regular)
{
	DWORD expandedFilePathSize = 32768;
	LPSTR expandedFilePath;

	/*
	 * Expand the file path
	 */
	expandedFilePath = malloc(expandedFilePathSize);
	if (expandedFilePath == NULL) {
		return NULL;
	}

	/*
	 * Expand the file path being accessed. ExpandEnvironmentStrings
	 * NULL-terminates the result;
	 */
	if (ExpandEnvironmentStrings(regular, expandedFilePath,
	    expandedFilePathSize - 2) == 0) {
		free(expandedFilePath);
		return NULL;
	}

	return expandedFilePath;
}

int fs_ls(const char *directory, fs_ls_cb_t cb, void *arg)
{
	DWORD result = 0;
	LPSTR expanded = NULL;
	LPSTR baseDirectory = NULL;
	char tempDirectory[FS_MAX_PATH];
	WIN32_FIND_DATA data;
	HANDLE ctx = NULL;

	_snprintf(tempDirectory, sizeof(tempDirectory), "%s", directory);

	/*
	 * If there is not wildcard mask on the directory, create a version of the
	 * directory with a mask appended
	 */
	if (strrchr(directory, '*') == NULL) {
		_snprintf(tempDirectory, sizeof(tempDirectory), "%s\\*",
				directory);

		baseDirectory = _strdup(directory);
		if (baseDirectory == NULL) {
			result = ERROR_NOT_ENOUGH_MEMORY;
			goto out;
		}

	} else {
		/*
		 * Otherwise, if it does have an asterisk, we need to scan back
		 * and find the base directory.  If there is no slash, it means
		 * we're listing the cwd.
		 */
		PCHAR slash = strrchr(directory, '\\');
		if (slash) {
			*slash = 0;
			baseDirectory = _strdup(directory);
			if (baseDirectory == NULL) {
				result = ERROR_NOT_ENOUGH_MEMORY;
				goto out;
			}
			*slash = '\\';
		}
	}

	expanded = fs_expand_path(tempDirectory);
	if (expanded == NULL) {
		result = ERROR_NOT_ENOUGH_MEMORY;
		goto out;
	}

	/*
	 * Start the find operation
	 */
	ctx = FindFirstFile(expanded, &data);
	do {
		if (ctx == INVALID_HANDLE_VALUE) {
			result = GetLastError();
			break;
		}

		cb(arg, data.cFileName, baseDirectory);

	} while (FindNextFile(ctx, &data));

	/*
	 * Clean up resources
	 */
	FindClose(ctx);
	free(expanded);
out:
	free(tempDirectory);
	free(baseDirectory);
	return result;
}

int fs_chdir(const char *directory)
{
	if (SetCurrentDirectory(directory) == 0) {
		return GetLastError();
	}
	return ERROR_SUCCESS;
}

int fs_delete_dir(const char *directory)
{
	if (RemoveDirectory(directory) == 0) {
		return GetLastError();
	}
	return ERROR_SUCCESS;
}

int fs_delete_file(const char *path)
{
	if (DeleteFile(path) == 0) {
		return GetLastError();
	}
	return ERROR_SUCCESS;
}

int fs_getwd(char *directory, size_t len)
{
	if (GetCurrentDirectory(len, directory) == 0) {
		return GetLastError();
	}
	return ERROR_SUCCESS;
}

int fs_move(const char *oldpath, const char *newpath)
{
	if (MoveFile(oldpath, newpath) == 0) {
		return GetLastError();
	}
	return ERROR_SUCCESS;
}

int fs_mkdir(const char *directory)
{
	if (CreateDirectory(directory, NULL) == 0) {
		return GetLastError();
	}
	return ERROR_SUCCESS;
}

int fs_fopen(const char *path, const char *mode, FILE **f)
{
	char *expanded = NULL;
	int rc = ERROR_SUCCESS;

	if (path == NULL || f == NULL) {
		return ERROR_INVALID_PARAMETER;
	}

	if ((expanded = fs_expand_path(path)) == NULL) {
		return ERROR_NOT_ENOUGH_MEMORY;
	}

	*f = fopen(expanded, mode);
	if (*f == NULL) {
		rc = GetLastError();
	}

	free(expanded);
	return rc;
}

int fs_stat(char *filename, struct meterp_stat *buf)
{
	struct stat sbuf;

	if (stat(filename, &sbuf) == -1) {
		return GetLastError();
	}

	buf->st_dev   = sbuf.st_dev;
	buf->st_ino   = sbuf.st_ino;
	buf->st_mode  = sbuf.st_mode;
	buf->st_nlink = sbuf.st_nlink;
	buf->st_uid   = sbuf.st_uid;
	buf->st_gid   = sbuf.st_gid;
	buf->st_rdev  = sbuf.st_rdev;
	buf->st_size  = sbuf.st_size;
	buf->st_atime = sbuf.st_atime;
	buf->st_mtime = sbuf.st_mtime;
	buf->st_ctime = sbuf.st_ctime;

	return ERROR_SUCCESS;
}
