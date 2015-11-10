#ifndef _METERPRETER_SOURCE_EXTENSION_EXTAPI_PRIV_SERVER_NTDS_JET_H
#define _METERPRETER_SOURCE_EXTENSION_EXTAPI_PRIV_SERVER_NTDS_JET_H
#include <esent.h>
#pragma comment(lib, "esent")

/*! @brief Typedef for the jetState struct. */
struct jetState{
	TCHAR ntdsPath[255];
	JET_INSTANCE jetEngine;
	JET_SESID jetSession;
	JET_DBID jetDatabase;
	JET_TABLEID jetTable;
};

/*! @brief Typedef for the ntdsColumns struct. */
struct ntdsColumns{
	JET_COLUMNDEF accountName;
	JET_COLUMNDEF accountType;
	JET_COLUMNDEF accountExpiry;
	JET_COLUMNDEF accountDescription;
	JET_COLUMNDEF accountControl;
	JET_COLUMNDEF encryptionKey;
	JET_COLUMNDEF lastLogon;
	JET_COLUMNDEF lastPasswordChange;
	JET_COLUMNDEF lmHash;
	JET_COLUMNDEF lmHistory;
	JET_COLUMNDEF logonCount;
	JET_COLUMNDEF ntHash;
	JET_COLUMNDEF ntHistory;
	JET_COLUMNDEF accountSID;
};

#define ACCOUNT_NAME_SIZE 128
#define ACCOUNT_DESC_SIZE 1024

/*! @brief Typedef for the ntdsAccount struct. */
struct ntdsAccount{
	char accountName[ACCOUNT_NAME_SIZE];
	char accountDescription[ACCOUNT_DESC_SIZE];
	DWORD accountRID;
	BOOL accountDisabled;
	BOOL accountLocked;
	BOOL noPassword;
	BOOL passNoExpire;
	BOOL passExpired;
	int logonCount;
	int numNTHistory;
	int numLMHistory;
	char expiryDate[30];
	char logonDate[30];
	char logonTime[30];
	char passChangeDate[30];
	char passChangeTime[30];
	char lmHash[33];
	char ntHash[33];
	char lmHistory[792];
	char ntHistory[792];
	unsigned char accountSID[28];
};


// UserAccountControl Flags
#define NTDS_ACCOUNT_DISABLED         0x00000002
#define NTDS_ACCOUNT_LOCKED           0x00000010
#define NTDS_ACCOUNT_NO_PASS          0x00000020
#define NTDS_ACCOUNT_PASS_NO_EXPIRE   0x00010000
#define NTDS_ACCOUNT_PASS_EXPIRED     0x00800000

JET_ERR engine_shutdown(struct jetState *ntdsState);
JET_ERR engine_startup(struct jetState *ntdsState);
JET_ERR find_first(struct jetState *ntdsState);
JET_ERR get_column_info(struct jetState *ntdsState, struct ntdsColumns *accountColumns);
JET_ERR get_PEK(struct jetState *ntdsState, struct ntdsColumns *accountColumns, struct encryptedPEK *pekEncrypted);
JET_ERR next_user(struct jetState *ntdsState, struct ntdsColumns *accountColumns);
JET_ERR open_database(struct jetState *ntdsState);
JET_ERR read_user(struct jetState *ntdsState, struct ntdsColumns *accountColumns, struct decryptedPEK *pekDecrypted, struct ntdsAccount *userAccount);
JET_ERR read_table(struct jetState *ntdsState, struct ntdsColumns *accountColumns, struct decryptedPEK *pekDecrypted);
JET_ERR read_user_hash_history(struct jetState *ntdsState, struct ntdsColumns *accountColumns, struct decryptedPEK *pekDecrypted, struct ntdsAccount *userAccount);
JET_ERR read_user_lm_hash(struct jetState *ntdsState, struct ntdsColumns *accountColumns, struct decryptedPEK *pekDecrypted, struct ntdsAccount *userAccount);
JET_ERR read_user_nt_hash(struct jetState *ntdsState, struct ntdsColumns *accountColumns, struct decryptedPEK *pekDecrypted, struct ntdsAccount *userAccount);
JET_ERR read_user_dates(struct jetState *ntdsState, struct ntdsColumns *accountColumns, struct decryptedPEK *pekDecrypted, struct ntdsAccount *userAccount);
void get_instance_name(char *name);
#endif
