#ifndef _METERPRETER_SOURCE_EXTENSION_STDAPI_STDAPI_SERVER_FS_FS_H
#define _METERPRETER_SOURCE_EXTENSION_STDAPI_STDAPI_SERVER_FS_FS_H

LPSTR fs_expand_path(LPCSTR regular);

/*
 * File system interaction
 */
DWORD request_fs_ls(Remote *remote, Packet *packet);
DWORD request_fs_getwd(Remote *remote, Packet *packet);
DWORD request_fs_chdir(Remote *remote, Packet *packet);
DWORD request_fs_mkdir(Remote *remote, Packet *packet);
DWORD request_fs_delete_dir(Remote *remote, Packet *packet);
DWORD request_fs_delete_file(Remote *remote, Packet *packet);
DWORD request_fs_separator(Remote *remote, Packet *packet);
DWORD request_fs_stat(Remote *remote, Packet *packet);
DWORD request_fs_file_expand_path(Remote *remote, Packet *packet);
DWORD request_fs_search( Remote * remote, Packet * packet );
DWORD request_fs_md5(Remote *remote, Packet *packet);
DWORD request_fs_sha1(Remote *remote, Packet *packet);
DWORD request_fs_file_move(Remote *remote, Packet *packet);
DWORD request_fs_file_copy(Remote *remote, Packet *packet);
DWORD request_fs_mount_show(Remote *remote, Packet *packet);

/*
 * Channel allocation
 */
DWORD request_fs_file_channel_open(Remote *remote, Packet *packet);

#endif
