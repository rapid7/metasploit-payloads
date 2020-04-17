#include <sys/stat.h>

#include "fs_local.h"
#include "precomp.h"
#include "common_metapi.h"

BOOL DeleteFolderWR(LPCWSTR szPath)
{
	WIN32_FIND_DATAW findFileData;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	DWORD dwError, dwAttrs;
	BOOL bRes;
	int nLength;
	wchar_t cPath[MAX_PATH], cCurrentFile[MAX_PATH];

	if (szPath == NULL) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	if (szPath[0] == L'\\' || szPath[0] == L'\0' || szPath[0] == L'.' || lstrcmpiW(szPath, L"..") == 0) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	dwAttrs = GetFileAttributesW(szPath);
	if (dwAttrs == INVALID_FILE_ATTRIBUTES) {
		return FALSE;
	}

	if (~dwAttrs & FILE_ATTRIBUTE_DIRECTORY) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	SetLastError(0);

	bRes = RemoveDirectoryW(szPath);
	if (bRes == TRUE)
		return TRUE;

	if (bRes == FALSE  && GetLastError() != ERROR_DIR_NOT_EMPTY)
		return FALSE;

	nLength = lstrlenW(szPath);

	if (nLength + lstrlenW(L"\\*.*") + 1> MAX_PATH)
		return FALSE;

	if (szPath[nLength - 1] == L'\\')
		wsprintfW(cPath, L"%s*.*", szPath);
	else
		wsprintfW(cPath, L"%s\\*.*", szPath);

	hFind = FindFirstFileW(cPath, &findFileData);
	if (hFind == INVALID_HANDLE_VALUE)
		return FALSE;

	lstrcpyW(cPath, szPath);

	if (cPath[nLength - 1] == L'\\')
		cPath[nLength - 1] = L'\0';

	do
	{
		if (lstrcmpiW(findFileData.cFileName, L".") == 0 || lstrcmpiW(findFileData.cFileName, L"..") == 0)
			continue;

		if (lstrlenW(cPath) + lstrlenW(L"\\") + lstrlenW(findFileData.cFileName) + 1 > MAX_PATH)
			continue;

		wsprintfW(cCurrentFile, L"%s\\%s", cPath, findFileData.cFileName);
		if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_READONLY)
			{
				findFileData.dwFileAttributes &= ~FILE_ATTRIBUTE_READONLY;
				SetFileAttributesW(cCurrentFile, findFileData.dwFileAttributes);
			}

			if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
				bRes = RemoveDirectoryW(cCurrentFile);
			else
				bRes = DeleteFolderWR(cCurrentFile);
		}
		else
		{

			if ((findFileData.dwFileAttributes & FILE_ATTRIBUTE_READONLY) ||
				(findFileData.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM))
				SetFileAttributesW(cCurrentFile, FILE_ATTRIBUTE_NORMAL);

			DeleteFileW(cCurrentFile);
		}
	} while (FindNextFileW(hFind, &findFileData));

	dwError = GetLastError();

	if (hFind != INVALID_HANDLE_VALUE)
		FindClose(hFind);

	if (dwError != ERROR_NO_MORE_FILES)
		return FALSE;

	bRes = RemoveDirectoryW(szPath);

	return bRes;
}

char * fs_expand_path(const char *regular)
{
	wchar_t expanded_path[FS_MAX_PATH];
	wchar_t *regular_w;

	regular_w = met_api->string.utf8_to_wchar(regular);
	if (regular_w == NULL) {
		return NULL;
	}

	if (ExpandEnvironmentStringsW(regular_w, expanded_path, FS_MAX_PATH) == 0) {
		free(regular_w);
		return NULL;
	}

	free(regular_w);

	return met_api->string.wchar_to_utf8(expanded_path);
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
	wchar_t *path_w = met_api->string.utf8_to_wchar(expanded);
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

		char *filename = met_api->string.wchar_to_utf8(data.cFileName);
		char *short_filename = met_api->string.wchar_to_utf8(data.cAlternateFileName);
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
	wchar_t *dir_w = met_api->string.utf8_to_wchar(directory);

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
	wchar_t *dir_w = met_api->string.utf8_to_wchar(directory);

	if (dir_w == NULL) {
		rc = GetLastError();
		goto out;
	}

	if (DeleteFolderWR(dir_w) == 0) {
		rc = GetLastError();
	}

out:
	free(dir_w);
	return rc;
}

int fs_delete_file(const char *path)
{
	int rc = ERROR_SUCCESS;
	wchar_t *path_w = met_api->string.utf8_to_wchar(path);

	if (path_w == NULL) {
		rc = GetLastError();
		goto out;
	}

	DWORD attrs = GetFileAttributesW(path_w);
	if ((attrs != INVALID_FILE_ATTRIBUTES) && (attrs & FILE_ATTRIBUTE_READONLY)) {
		attrs &= ~FILE_ATTRIBUTE_READONLY;
		SetFileAttributesW(path_w, attrs);
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

	*dir = met_api->string.wchar_to_utf8(dir_w);
	if (*dir == NULL) {
		rc = GetLastError();
	}

out:
	return rc;
}

int fs_move(const char *oldpath, const char *newpath)
{
	int rc = ERROR_SUCCESS;
	wchar_t *old_w = met_api->string.utf8_to_wchar(oldpath);
	wchar_t *new_w = met_api->string.utf8_to_wchar(newpath);

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
	wchar_t *old_w = met_api->string.utf8_to_wchar(oldpath);
	wchar_t *new_w = met_api->string.utf8_to_wchar(newpath);

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
	wchar_t *dir_w = met_api->string.utf8_to_wchar(directory);

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

	wchar_t *path_w = met_api->string.utf8_to_wchar(expanded);
	wchar_t *mode_w = met_api->string.utf8_to_wchar(mode);

	if ((path_w == NULL) || (mode_w == NULL)) {
		rc = ERROR_NOT_ENOUGH_MEMORY;
		goto out;
	}
	wchar_t Mode[5];
	memset(Mode, 0, sizeof(Mode));
	Mode[0] = mode_w[0];
	Mode[1] = L'b';
	*f = _wfopen(path_w, Mode);
	if (*f == NULL) {
		rc = GetLastError();
	}

out:
	free(expanded);
	free(path_w);
	free(mode_w);
	return rc;
}

static int
attributes_to_mode(DWORD attr)
{
	int m = 0;
	if (attr & FILE_ATTRIBUTE_DIRECTORY) {
		m |= _S_IFDIR | 0111; /* IFEXEC for user,group,other */
	} else {
		m |= _S_IFREG;
	}
	if (attr & FILE_ATTRIBUTE_READONLY) {
		m |= 0444;
	} else {
		m |= 0666;
	}
	return m;
}

static int
attributes_from_dir_w(LPCWSTR pszFile, LPWIN32_FILE_ATTRIBUTE_DATA pfad)
{
	HANDLE hFindFile;
	WIN32_FIND_DATAW FileData;
	hFindFile = FindFirstFileW(pszFile, &FileData);
	if (hFindFile == INVALID_HANDLE_VALUE) {
		return -1;
	}
	FindClose(hFindFile);
	pfad->dwFileAttributes = FileData.dwFileAttributes;
	pfad->ftCreationTime = FileData.ftCreationTime;
	pfad->ftLastAccessTime = FileData.ftLastAccessTime;
	pfad->ftLastWriteTime = FileData.ftLastWriteTime;
	pfad->nFileSizeHigh = FileData.nFileSizeHigh;
	pfad->nFileSizeLow = FileData.nFileSizeLow;
	return 0;
}

static void
FILE_TIME_to_nsec(FILETIME *in_ptr, uint64_t *time_out)
{
	int64_t in;
	const int64_t secs_between_epochs = 11644473600;
	memcpy(&in, in_ptr, sizeof(in));
	*time_out = (in / 10000000) - secs_between_epochs;
}

static int
attribute_data_to_stat(WIN32_FILE_ATTRIBUTE_DATA *info, struct meterp_stat *result)
{
	memset(result, 0, sizeof(*result));
	result->st_mode = attributes_to_mode(info->dwFileAttributes);
	result->st_size = (((__int64)info->nFileSizeHigh) << 32) + info->nFileSizeLow;
	FILE_TIME_to_nsec(&info->ftCreationTime, &result->st_ctime);
	FILE_TIME_to_nsec(&info->ftLastWriteTime, &result->st_mtime);
	FILE_TIME_to_nsec(&info->ftLastAccessTime, &result->st_atime);

	return 0;
}

/*
 * The CRT of Windows has a number of flaws wrt. its stat() implementation:
 * - time stamps are restricted to second resolution
 * - file modification times suffer from forth-and-back conversions between
 *    UTC and local time
 * Therefore, we implement our own stat, based on the Win32 API directly.
 *
 * This is based on the Python 2 implementation from:
 * https://github.com/python/cpython/commit/14694662d530d0d1823e1d86f2e5b2e4ec600e86#diff-a6f29e907cbb5fffd44d453bcd7b77d5R741
 */
static int
win32_wstat(const wchar_t* path, struct meterp_stat *result)
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
	if (code < 0) {
		return code;
	}
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
	wchar_t *filename_w = met_api->string.utf8_to_wchar(filename);
	if (filename_w == NULL) {
		return -1;
	}

	if (win32_wstat(filename_w, buf) == -1) {
		return GetLastError();
	}

	free(filename_w);

	return ERROR_SUCCESS;
}
