#include <sys/stat.h>

#include "fs_local.h"
#include "precomp.h"

char * fs_expand_path(const char *regular)
{
	wchar_t expanded_path[FS_MAX_PATH];
	wchar_t *regular_w;

	regular_w = utf8_to_wchar(regular);
	if (regular_w == NULL) {
		return NULL;
	}

	if (ExpandEnvironmentStringsW(regular_w, expanded_path, FS_MAX_PATH) == 0) {
		free(regular_w);
		return NULL;
	}

	free(regular_w);

	return wchar_to_utf8(expanded_path);
}

int fs_ls(const char *directory, fs_ls_cb_t cb, void *arg)
{
	DWORD result = 0;
	LPSTR expanded = NULL;
	LPSTR baseDirectory = NULL;
	char tempDirectory[FS_MAX_PATH];

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

	WIN32_FIND_DATAW data;
	wchar_t *path_w = utf8_to_wchar(expanded);
	if (path_w == NULL) {
		result = GetLastError();
		goto out;
	}

	HANDLE ctx = FindFirstFileW(path_w, &data);
	if (ctx == NULL) {
		result = GetLastError();
		goto out;
	}

	do {
		if (ctx == INVALID_HANDLE_VALUE) {
			result = GetLastError();
			break;
		}

		char *filename = wchar_to_utf8(data.cFileName);
		char *short_filename = wchar_to_utf8(data.cAlternateFileName);
		char path[FS_MAX_PATH];

		if (baseDirectory) {
			_snprintf(path, sizeof(path), "%s\\%s", baseDirectory, filename);
		} else {
			_snprintf(path, sizeof(path), "%s", filename);
		}

		cb(arg, filename, short_filename, path);

		free(filename);
		free(short_filename);

	} while (FindNextFileW(ctx, &data));

	/*
	 * Clean up resources
	 */
	FindClose(ctx);
	free(expanded);
out:
	free(baseDirectory);
	free(path_w);
	return result;
}

int fs_chdir(const char *directory)
{
	int rc = ERROR_SUCCESS;
	wchar_t *dir_w = utf8_to_wchar(directory);

	if (dir_w == NULL) {
		rc = GetLastError();
		goto out;
	}

	if (SetCurrentDirectoryW(dir_w) == 0) {
		rc = GetLastError();
	}

out:
	free(dir_w);
	return rc;
}

int fs_delete_dir(const char *directory)
{
	int rc = ERROR_SUCCESS;
	wchar_t *dir_w = utf8_to_wchar(directory);

	if (dir_w == NULL) {
		rc = GetLastError();
		goto out;
	}

	if (RemoveDirectoryW(dir_w) == 0) {
		rc = GetLastError();
	}

out:
	free(dir_w);
	return rc;
}

int fs_delete_file(const char *path)
{
	int rc = ERROR_SUCCESS;
	wchar_t *path_w = utf8_to_wchar(path);

	if (path_w == NULL) {
		rc = GetLastError();
		goto out;
	}

	if (DeleteFileW(path_w) == 0) {
		rc = GetLastError();
	}

out:
	free(path_w);
	return rc;
}

int fs_getwd(char **dir)
{
	int rc = ERROR_SUCCESS;
	wchar_t dir_w[FS_MAX_PATH];

	if (GetCurrentDirectoryW(FS_MAX_PATH, dir_w) == 0) {
		rc = GetLastError();
		goto out;
	}

	*dir = wchar_to_utf8(dir_w);
	if (*dir == NULL) {
		rc = GetLastError();
	}

out:
	return rc;
}

int fs_move(const char *oldpath, const char *newpath)
{
	int rc = ERROR_SUCCESS;
	wchar_t *old_w = utf8_to_wchar(oldpath);
	wchar_t *new_w = utf8_to_wchar(newpath);

	if ((old_w == NULL) || (new_w == NULL)) {
		rc = GetLastError();
		goto out;
	}

	if (MoveFileW(old_w, new_w) == 0) {
		rc = GetLastError();
	}

out:
	free(old_w);
	free(new_w);
	return rc;
}

int fs_copy(const char *oldpath, const char *newpath)
{
	int rc = ERROR_SUCCESS;
	wchar_t *old_w = utf8_to_wchar(oldpath);
	wchar_t *new_w = utf8_to_wchar(newpath);

	if ((old_w == NULL) || (new_w == NULL)) {
		rc = GetLastError();
		goto out;
	}

	if (CopyFileW(old_w, new_w, 0) == 0) {
		rc = GetLastError();
	}

out:
	free(old_w);
	free(new_w);
	return rc;
}

int fs_mkdir(const char *directory)
{
	int rc = ERROR_SUCCESS;
	wchar_t *dir_w = utf8_to_wchar(directory);

	if (dir_w == NULL) {
		rc = GetLastError();
		goto out;
	}

	if (CreateDirectoryW(dir_w, NULL) == 0) {
		rc = GetLastError();
	}

out:
	free(dir_w);
	return rc;
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

	wchar_t *path_w = utf8_to_wchar(expanded);
	wchar_t *mode_w = utf8_to_wchar(mode);

	if ((path_w == NULL) || (mode_w == NULL)) {
		rc = ERROR_NOT_ENOUGH_MEMORY;
		goto out;
	}

	*f = _wfopen(path_w, mode_w);
	if (*f == NULL) {
		rc = GetLastError();
	}

out:
	free(expanded);
	free(path_w);
	free(mode_w);
	return rc;
}

#define Py_SAFE_DOWNCASTM(VALUE, WIDE, NARROW) (NARROW)(VALUE)

static int
attributes_to_mode(DWORD attr)
{
	int m = 0;
	if (attr & FILE_ATTRIBUTE_DIRECTORY)
		m |= _S_IFDIR | 0111; /* IFEXEC for user,group,other */
	else
		m |= _S_IFREG;
	if (attr & FILE_ATTRIBUTE_READONLY)
		m |= 0444;
	else
		m |= 0666;
	return m;
}

static __int64 secs_between_epochs = 11644473600;

static BOOL
attributes_from_dir_w(LPCWSTR pszFile, LPWIN32_FILE_ATTRIBUTE_DATA pfad)
{
	HANDLE hFindFile;
	WIN32_FIND_DATAW FileData;
	hFindFile = FindFirstFileW(pszFile, &FileData);
	if (hFindFile == INVALID_HANDLE_VALUE)
		return FALSE;
	FindClose(hFindFile);
	pfad->dwFileAttributes = FileData.dwFileAttributes;
	pfad->ftCreationTime = FileData.ftCreationTime;
	pfad->ftLastAccessTime = FileData.ftLastAccessTime;
	pfad->ftLastWriteTime = FileData.ftLastWriteTime;
	pfad->nFileSizeHigh = FileData.nFileSizeHigh;
	pfad->nFileSizeLow = FileData.nFileSizeLow;
	return TRUE;
}

static void
FILE_TIME_to_time_t_nsec(FILETIME *in_ptr, time_t *time_out)
{
	__int64 in;
	memcpy(&in, in_ptr, sizeof(in));
	*time_out = Py_SAFE_DOWNCASTM((in / 10000000) - secs_between_epochs, __int64, time_t);
}

static int attribute_data_to_stat(WIN32_FILE_ATTRIBUTE_DATA *info, struct meterp_stat *result)
{
	memset(result, 0, sizeof(*result));
	result->st_mode = attributes_to_mode(info->dwFileAttributes);
	result->st_size = (((__int64)info->nFileSizeHigh) << 32) + info->nFileSizeLow;
	FILE_TIME_to_time_t_nsec(&info->ftCreationTime, &result->st_ctime);
	FILE_TIME_to_time_t_nsec(&info->ftLastWriteTime, &result->st_mtime);
	FILE_TIME_to_time_t_nsec(&info->ftLastAccessTime, &result->st_atime);

	return 0;
}

static int win32_wstatM(const wchar_t* path, struct meterp_stat *result)
{
	int code;
	const wchar_t *dot;
	WIN32_FILE_ATTRIBUTE_DATA info;
	if (!GetFileAttributesExW(path, GetFileExInfoStandard, &info)) {
		if (GetLastError() != ERROR_SHARING_VIOLATION) {
			return -1;
		}
		else {
			if (!attributes_from_dir_w(path, &info)) {
				return -1;
			}
		}
	}
	code = attribute_data_to_stat(&info, result);
	if (code < 0)
		return code;
	/* Set IFEXEC if it is an .exe, .bat, ... */
	dot = wcsrchr(path, '.');
	if (dot) {
		if (_wcsicmp(dot, L".bat") == 0 ||
			_wcsicmp(dot, L".cmd") == 0 ||
			_wcsicmp(dot, L".exe") == 0 ||
			_wcsicmp(dot, L".com") == 0)
			result->st_mode |= 0111;
	}
	return code;
}

int fs_stat(char *filename, struct meterp_stat *buf)
{
	struct meterp_stat sbuf;

	wchar_t *filename_w = utf8_to_wchar(filename);
	if (filename_w == NULL) {
		return -1;
	}

	if (win32_wstatM(filename_w, &sbuf) == -1) {
		return GetLastError();
	}

	free(filename_w);

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
