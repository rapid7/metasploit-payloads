#ifndef _METERPRETER_SOURCE_EXTENSION_PRIV_PRIV_SERVER_NTDS_JET_H
#define _METERPRETER_SOURCE_EXTENSION_PRIV_PRIV_SERVER_NTDS_JET_H
#include <esent.h>
#pragma comment(lib, "esent")

typedef struct {
	TCHAR ntdsPath[255];
	JET_INSTANCE jetEngine;
	JET_SESID jetSession;
	JET_DBID jetDatabase;
	JET_TABLEID jetTable;
	BOOL eof;
}jetState;

typedef struct {
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
}ntdsColumns;

typedef struct{
	wchar_t accountName[20];
	wchar_t accountDescription[1024];
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
	unsigned char accountSID[24];
}ntdsAccount;


// UserAccountControl Flags
#define NTDS_ACCOUNT_DISABLED         0x00000002
#define NTDS_ACCOUNT_LOCKED           0x00000010
#define NTDS_ACCOUNT_NO_PASS          0x00000020
#define NTDS_ACCOUNT_PASS_NO_EXPIRE   0x00010000
#define NTDS_ACCOUNT_PASS_EXPIRED     0x00800000

JET_ERR engine_shutdown(jetState *ntdsState);
JET_ERR engine_startup(jetState *ntdsState);
JET_ERR find_first(jetState *ntdsState);
JET_ERR get_column_info(jetState *ntdsState, ntdsColumns *accountColumns);
JET_ERR get_PEK(jetState *ntdsState, ntdsColumns *accountColumns, encryptedPEK *pekEncrypted);
JET_ERR next_user(jetState *ntdsState, ntdsColumns *accountColumns);
JET_ERR open_database(jetState *ntdsState);
JET_ERR read_table(jetState *ntdsState, ntdsColumns *accountColumns, decryptedPEK *pekDecrypted);

#endif