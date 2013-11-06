#ifndef _METERPRETER_SOURCE_EXTENSION_INCOGNITO_LIST_TOKENS_H
#define _METERPRETER_SOURCE_EXTENSION_INCOGNITO_LIST_TOKENS_H

// Token struct definitions
typedef struct
{
	char username[256];
	HANDLE token;
} SavedToken;

#define MAX_USERNAME 256

typedef struct
{
	char username[MAX_USERNAME];
	int token_num;
	BOOL delegation_available;
	BOOL impersonation_available;
} unique_user_token;

typedef enum
{
	BY_USER,
	BY_GROUP
} TOKEN_ORDER;

typedef struct
{
	BOOL SE_ASSIGNPRIMARYTOKEN_PRIVILEGE;
	BOOL SE_CREATE_TOKEN_PRIVILEGE; 
	BOOL SE_TCB_PRIVILEGE; 
	BOOL SE_TAKE_OWNERSHIP_PRIVILEGE; 
	BOOL SE_BACKUP_PRIVILEGE; 
	BOOL SE_RESTORE_PRIVILEGE; 
	BOOL SE_DEBUG_PRIVILEGE; 
	BOOL SE_IMPERSONATE_PRIVILEGE; 
	BOOL SE_RELABEL_PRIVILEGE; 
	BOOL SE_LOAD_DRIVER_PRIVILEGE; 
} TOKEN_PRIVS;

SavedToken *get_token_list(DWORD *num_tokens_enum, TOKEN_PRIVS *token_privs);
void process_user_token(HANDLE, unique_user_token*, DWORD*, TOKEN_ORDER);

#endif