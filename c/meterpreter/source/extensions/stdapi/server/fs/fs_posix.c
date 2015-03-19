#include <sys/stat.h>
#include <sys/types.h>

#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "precomp.h"
#include "fs_local.h"

int fs_ls(const char *directory, fs_ls_cb_t cb, void *arg)
{
	struct meterp_stat s;
	struct dirent *data;
	char path[FS_MAX_PATH];

	DIR *ctx = opendir(directory);
	if (ctx == NULL) {
		return errno;
	}

	while ((data = readdir(ctx))) {

		snprintf(path, sizeof(path), "%s/%s", directory, data->d_name);

		cb(arg, data->d_name, NULL, path);
	}

	closedir(ctx);
	return ERROR_SUCCESS;
}

int fs_chdir(const char *directory)
{
	if (chdir(directory) == -1) {
		return errno;
	}
	return ERROR_SUCCESS;
}

int fs_delete_file(const char *path)
{
	if (unlink(path) == -1) {
		return errno;
	}
	return ERROR_SUCCESS;
}

int fs_delete_dir(const char *directory)
{
	if (rmdir(directory) == -1) {
		return errno;
	}
	return ERROR_SUCCESS;
}

char * fs_expand_path(const char *regular)
{
	return strdup(regular);
}

int fs_getwd(char **directory)
{
	char dir[FS_MAX_PATH];
	if (getcwd(dir, sizeof(dir)) == NULL) {
		return errno;
	}
	*directory = strdup(dir);
	return *directory == NULL ? ERROR_NOT_ENOUGH_MEMORY : ERROR_SUCCESS;
}

int fs_mkdir(const char *directory)
{
	if (mkdir(directory, 0777) == -1) {
		return errno;
	}
	return ERROR_SUCCESS;
}

int fs_fopen(const char *path, const char *mode, FILE **f)
{
	int rc = 0;

	if (path == NULL || f == NULL) {
		return ERROR_INVALID_PARAMETER;
	}

	*f = fopen(path, mode);
	if (*f == NULL) {
		rc = errno;
	}

	return rc;
}

int fs_move(const char *oldpath, const char *newpath)
{
	if (rename(oldpath, newpath) == -1) {
		return errno;
	}
	return ERROR_SUCCESS;
}

int fs_stat(char *filename, struct meterp_stat *buf)
{
	struct stat sbuf;

	if (stat(filename, &sbuf) == -1) {
		return errno;
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
