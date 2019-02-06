#ifndef _FS_LOCAL_H
#define _FS_LOCAL_H

#include <stdint.h>
#include <stdio.h>

#define FS_SEPARATOR "\\"
#define FS_MAX_PATH  32768

#pragma pack(push, 1)

/*
 * Stat structures on Windows and various Unixes are all slightly different.
 * Use this as a means of standardization so the client has some hope of
 * understanding what the stat'd file really is.
 */
struct meterp_stat {
    uint32_t st_dev;
    uint32_t st_mode;
    uint32_t st_nlink;
    uint32_t st_uid;
    uint32_t st_gid;
    uint32_t st_rdev;
    uint64_t st_ino;
    uint64_t st_size;
    uint64_t st_atime;
    uint64_t st_mtime;
    uint64_t st_ctime;
};

#pragma pack(pop)

typedef void (*fs_ls_cb_t)(void *arg, char *name, char *short_name, char *path);

int fs_chdir(const char *directory);

int fs_delete_dir(const char *directory);

int fs_delete_file(const char *path);

/*
 * Returns an expanded file path that must be freed
 */
char * fs_expand_path(const char *regular);

int fs_fopen(const char *path, const char *mode, FILE **f);

int fs_ls(const char *directory, fs_ls_cb_t cb, void *arg);

int fs_getwd(char **directory);

int fs_mkdir(const char *directory);

int fs_move(const char *oldpath, const char *newpath);

int fs_copy(const char *oldpath, const char *newpath);

/*
 * Fills the platform-independent meterp_stat buf with data from the
 * platform-dependent stat()
 */
int fs_stat(char *filename, struct meterp_stat *buf);

#endif
