/*!
* @file ntds_jet.c
* @brief Definitions for NTDS Jet Engine functions
*/
#include "precomp.h"

/*!
* @brief Shuts down the Jet Instance and frees the jetState struct.
* @param ntdsState Pointer to a jetsState struct which contains all the state data for the Jet Instance.
* @returns Indication of sucess or failure.
*/
JET_ERR engine_shutdown(jetState *ntdsState){
	JET_ERR shutdownStatus;
	shutdownStatus = JetCloseDatabase(ntdsState->jetSession, ntdsState->jetDatabase, (JET_GRBIT)NULL);
	if (shutdownStatus != JET_errSuccess){
		return shutdownStatus;
	}
	shutdownStatus = JetDetachDatabase(ntdsState->jetSession, ntdsState->ntdsPath);
	if (shutdownStatus != JET_errSuccess){
		return shutdownStatus;
	}
	shutdownStatus = JetEndSession(ntdsState->jetSession, (JET_GRBIT)NULL);
	if (shutdownStatus != JET_errSuccess){
		return shutdownStatus;
	}
	shutdownStatus = JetTerm(ntdsState->jetEngine);
	free(ntdsState);
	return shutdownStatus;
}

/*!
* @brief Starts up the Jet Instance and initialises it.
* @param ntdsState Pointer to a jetsState struct which contains all the state data for the Jet Instance.
* @returns Indication of sucess or failure.
*/
JET_ERR engine_startup(jetState *ntdsState){
	JET_ERR jetError;
	// Set the Page Size to the highest possibile limit
	jetError = JetSetSystemParameter(&ntdsState->jetEngine, JET_sesidNil, JET_paramDatabasePageSize, 8192, NULL);
	if (jetError != JET_errSuccess){
		return jetError;
	}
	// Create our Jet Instance
	jetError = JetCreateInstance(&ntdsState->jetEngine, "NTDS");
	if (jetError != JET_errSuccess){
		return jetError;
	}
	// Disable crash recovery and transaction logs
	jetError = JetSetSystemParameter(&ntdsState->jetEngine, JET_sesidNil, JET_paramRecovery, (JET_API_PTR)NULL, "Off");
	if (jetError != JET_errSuccess){
		return jetError;
	}
	// Initialise the Jet instance
	jetError = JetInit(&ntdsState->jetEngine);
	if (jetError != JET_errSuccess){
		return jetError;
	}
	return JET_errSuccess;
}

/*!
* @brief Moves the database cursor to the first record in the 'datatable' table
* @param ntdsState Pointer to a jetsState struct which contains all the state data for the Jet Instance.
* @returns Indication of sucess or failure.
*/
JET_ERR find_first(jetState *ntdsState){
	JET_ERR cursorStatus;
	cursorStatus = JetMove(ntdsState->jetSession, ntdsState->jetTable, JET_MoveFirst, (JET_GRBIT)NULL);
	return cursorStatus;
}

/*!
* @brief Collect the Column Definitions for all relevant columns in 'datatable'
* @param ntdsState Pointer to a jetsState struct which contains all the state data for the Jet Instance.
* @param accountColumns Pointer to an ntdsState struct which will hold all of our column definitions.
* @returns Indication of sucess or failure.
*/
JET_ERR get_column_info(jetState *ntdsState, ntdsColumns *accountColumns){
	JET_ERR columnError;
	struct {
		char *name;
		JET_COLUMNDEF *column;
	}columns[] = {
		{ "ATTm590045", &accountColumns->accountName },
		{ "ATTj590126", &accountColumns->accountType },
		{ "ATTq589983", &accountColumns->accountExpiry },
		{ "ATTk590689", &accountColumns->encryptionKey },
		{ "ATTq589876", &accountColumns->lastLogon },
		{ "ATTk589879", &accountColumns->lmHash },
		{ "ATTk589984", &accountColumns->lmHistory },
		{ "ATTj589993", &accountColumns->logonCount },
		{ "ATTk589914", &accountColumns->ntHash },
		{ "ATTk589918", &accountColumns->ntHistory },
		{ "ATTm13", &accountColumns->accountDescription },
		{ "ATTj589832", &accountColumns->accountControl },
		{ "ATTq589920", &accountColumns->lastPasswordChange },
		{ "ATTr589970", &accountColumns->accountSID }
	};
	int countColumns = sizeof(columns) / sizeof(columns[0]);
	for (int i = 0; i < countColumns; i++){
		columnError = JetGetTableColumnInfo(ntdsState->jetSession, ntdsState->jetTable, columns[i].name, columns[i].column, sizeof(JET_COLUMNDEF), JET_ColInfo);
		if (columnError != JET_errSuccess){
			return columnError;
		}
	}
	return JET_errSuccess;
}

/*!
* @brief Finds the Password Encryption Key(PEK) record in 'datatable'
* @param ntdsState Pointer to a jetsState struct which contains all the state data for the Jet Instance.
* @param accountColumns Pointer to an ntdsState struct which will hold all of our column definitions.
* @param pekEncrypted Pointer to an encryptedPEK struct to hold our encrypted PEK
* @returns Indication of sucess or failure.
*/
JET_ERR get_PEK(jetState *ntdsState, ntdsColumns *accountColumns, encryptedPEK *pekEncrypted){
	JET_ERR cursorStatus;
	JET_ERR readStatus;
	unsigned char *encryptionKey[76];

	cursorStatus = JetMove(ntdsState->jetSession, ntdsState->jetTable, JET_MoveFirst, (JET_GRBIT)NULL);
	if (cursorStatus != JET_errSuccess){
		return cursorStatus;
	}
	do{
		//Attempt to retrieve the Password Encryption Key
		unsigned long columnSize = 0;
		readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->encryptionKey.columnid, encryptionKey, 76, &columnSize, 0, NULL);
		if (readStatus == JET_errSuccess){
			memcpy(pekEncrypted, &encryptionKey, 76);
			puts("Found the Password Encryption Key");
			return readStatus;
		}
		cursorStatus = JetMove(ntdsState->jetSession, ntdsState->jetTable, JET_MoveNext, (JET_GRBIT)NULL);
	} while (cursorStatus == JET_errSuccess);
	return readStatus;
}

/*!
* @brief Moves the database cursor to the next User record in 'datatable'
* @param ntdsState Pointer to a jetsState struct which contains all the state data for the Jet Instance.
* @param accountColumns Pointer to an ntdsState struct which will hold all of our column definitions.
* @returns Indication of sucess or failure.
*/
JET_ERR next_user(jetState *ntdsState, ntdsColumns *accountColumns){
	JET_ERR cursorStatus;
	JET_ERR readStatus;
	JET_ERR finalStatus = JET_errSuccess;
	DWORD accountType = 0;
	unsigned long columnSize = 0;
	do{
		cursorStatus = JetMove(ntdsState->jetSession, ntdsState->jetTable, JET_MoveNext, (JET_GRBIT)NULL);
		if (cursorStatus != JET_errSuccess){
			finalStatus = cursorStatus;
			break;
		}
		//Retrieve the account type for this row
		readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->accountType.columnid, &accountType, sizeof(accountType), &columnSize, 0, NULL);
		// Unless this is a User Account, then we skip it
		if (readStatus == JET_wrnColumnNull){
			continue;
		}
		else if (readStatus != JET_errSuccess){
			finalStatus = readStatus;
			break;
		}
	} while (accountType != 0x30000000);
	return finalStatus;
}

/*!
* @brief Attach our Jet Instance to the ntds.dit file and open the 'datatable' table for reading.
* @param ntdsState Pointer to a jetsState struct which contains all the state data for the Jet Instance.
* @returns Indication of sucess or failure.
*/
JET_ERR open_database(jetState *ntdsState){
	JET_ERR attachStatus = JetAttachDatabase(ntdsState->jetSession, ntdsState->ntdsPath, JET_bitDbReadOnly);
	if (attachStatus != JET_errSuccess){
		return attachStatus;
	}
	JET_ERR openStatus = JetOpenDatabase(ntdsState->jetSession, ntdsState->ntdsPath, NULL, &ntdsState->jetDatabase, JET_bitDbReadOnly);
	if (openStatus != JET_errSuccess){
		return openStatus;
	}
	return JET_errSuccess;
}

/*!
* @brief Read the current user record into an ntdsAccount struct.
* @param ntdsState Pointer to a jetsState struct which contains all the state data for the Jet Instance.
* @param accountColumns Pointer to an ntdsState struct which will hold all of our column definitions.
* @param pekDecrypted Pointer to a decryptedPEK structure that holds our decrypted PEK
* @param userAccount Pointer to an ntdsAccount struct that will hold all of our User data
* @returns Indication of sucess or failure.
*/
JET_ERR read_user(jetState *ntdsState, ntdsColumns *accountColumns, decryptedPEK *pekDecrypted, ntdsAccount *userAccount){
	JET_ERR readStatus = JET_errSuccess;
	//Define our temp values here
	FILETIME accountExpiry;
	SYSTEMTIME accountExpiry2;
	FILETIME lastLogon;
	SYSTEMTIME lastLogon2;
	FILETIME lastPass;
	SYSTEMTIME lastPass2;
	DWORD accountControl = 0;
	unsigned long columnSize = 0;
	encryptedHash *encryptedLM = calloc(1,sizeof(encryptedHash));
	encryptedHash *encryptedNT = calloc(1, sizeof(encryptedHash));

	// Grab the SID here
	readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->accountSID.columnid, &userAccount->accountSID, sizeof(userAccount->accountName), &columnSize, 0, NULL);
	if (readStatus != JET_errSuccess){
		return readStatus;
	}
	// Derive the RID from the SID
	int ridIndex = columnSize - sizeof(DWORD);
	DWORD *ridLoc = (DWORD *)&userAccount->accountSID[ridIndex];
	userAccount->accountRID = htonl(*ridLoc);

	// Grab the samAccountName here
	readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->accountName.columnid, &userAccount->accountName, sizeof(userAccount->accountName), &columnSize, 0, NULL);
	if (readStatus != JET_errSuccess){
		return readStatus;
	}
	// Grab the account expiration date/time here
	readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->accountExpiry.columnid, &accountExpiry, sizeof(accountExpiry), &columnSize, 0, NULL);
	if (readStatus != JET_errSuccess){
		return readStatus;
	}
	//Convert the FILETIME to a SYSTEMTIME so we can get a human readable date
	FileTimeToSystemTime(&accountExpiry, &accountExpiry2);
	int dateResult = GetDateFormat(LOCALE_SYSTEM_DEFAULT, DATE_LONGDATE, &accountExpiry2, NULL, userAccount->expiryDate, 255);
	// Getting Human Readable will fail if account never expires. Just set the expiryDate string to 'never'
	if (dateResult == 0){
		strncpy(userAccount->expiryDate, "Never", 6);
	}
	// Grab the last logon date and time
	readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->lastLogon.columnid, &lastLogon, sizeof(lastLogon), &columnSize, 0, NULL);
	if (readStatus != JET_errSuccess){
		return readStatus;
	}
	//Convert the FILETIME to a SYSTEMTIME so we can get a human readable date
	FileTimeToSystemTime(&lastLogon, &lastLogon2);
	dateResult = GetDateFormat(LOCALE_SYSTEM_DEFAULT, DATE_LONGDATE, &lastLogon2, NULL, userAccount->logonDate, 255);
	// Getting Human Readable will fail if account has never logged in, much like the expiry date
	if (dateResult == 0){
		strncpy(userAccount->logonDate, "Never", 6);
	}
	dateResult = GetTimeFormat(LOCALE_SYSTEM_DEFAULT, 0, &lastLogon2, NULL, userAccount->logonTime, 255);
	if (dateResult == 0){
		strncpy(userAccount->logonTime, "Never", 6);
	}
	// Grab the last password change date and time
	readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->lastPasswordChange.columnid, &lastPass, sizeof(lastPass), &columnSize, 0, NULL);
	if (readStatus != JET_errSuccess){
		return readStatus;
	}
	//Convert the FILETIME to a SYSTEMTIME so we can get a human readable date
	FileTimeToSystemTime(&lastPass, &lastPass2);
	dateResult = GetDateFormat(LOCALE_SYSTEM_DEFAULT, DATE_LONGDATE, &lastPass2, NULL, userAccount->passChangeDate, 255);
	// Getting Human Readable will fail if account has never logged in, much like the expiry date
	if (dateResult == 0){
		strncpy(userAccount->passChangeDate, "Never", 6);
	}
	dateResult = GetTimeFormat(LOCALE_SYSTEM_DEFAULT, 0, &lastPass2, NULL, userAccount->passChangeTime, 255);
	if (dateResult == 0){
		strncpy(userAccount->passChangeTime, "Never", 6);
	}
	// Grab the Account Description here
	readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->accountDescription.columnid, &userAccount->accountDescription, sizeof(userAccount->accountDescription), &columnSize, 0, NULL);
	if (readStatus == JET_wrnColumnNull){
		memset(userAccount->accountDescription, 0, sizeof(userAccount->accountDescription));
	}
	else if (readStatus != JET_errSuccess){
		return readStatus;
	}
	// Grab the UserAccountControl flags here
	readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->accountControl.columnid, &accountControl, sizeof(accountControl), &columnSize, 0, NULL);
	if (readStatus != JET_errSuccess){
		return readStatus;
	}
	userAccount->accountDisabled = !!(accountControl & NTDS_ACCOUNT_DISABLED);
	userAccount->accountLocked = !!(accountControl & NTDS_ACCOUNT_LOCKED);
	userAccount->noPassword = !!(accountControl & NTDS_ACCOUNT_NO_PASS);
	userAccount->passExpired = !!(accountControl & NTDS_ACCOUNT_PASS_EXPIRED);
	userAccount->passNoExpire = !!(accountControl & NTDS_ACCOUNT_PASS_NO_EXPIRE);

	// Grab the Logon Count here
	readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->logonCount.columnid, &userAccount->logonCount, sizeof(userAccount->logonCount), &columnSize, 0, NULL);
	if (readStatus != JET_errSuccess){
		return readStatus;
	}
	// Grab the NT Hash
	readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->ntHash.columnid, encryptedNT, sizeof(encryptedHash), &columnSize, 0, NULL);
	if (readStatus != JET_errSuccess){
		if (readStatus == JET_wrnColumnNull){
			memcpy(&userAccount->ntHash, &BLANK_NT_HASH, 32);
		}
		else{
			return readStatus;
		}
	}
	else{
		decrypt_hash(encryptedNT, pekDecrypted, userAccount->ntHash, userAccount->accountRID);
	}
	// Grab the LM Hash
	readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->lmHash.columnid, encryptedLM, sizeof(encryptedHash), &columnSize, 0, NULL);
	if (readStatus != JET_errSuccess){
		if (readStatus == JET_wrnColumnNull){
			memcpy(&userAccount->lmHash, &BLANK_LM_HASH, 32);
		}
		else{
			return readStatus;
		}
	}
	else{
		decrypt_hash(encryptedLM, pekDecrypted, userAccount->lmHash, userAccount->accountRID);
	}
	// Grab the NT Hash History
	readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->ntHistory.columnid, NULL, 0, &columnSize, 0, NULL);
	if (readStatus == JET_wrnBufferTruncated){
		LPBYTE encNTHist = (LPBYTE)calloc(1,columnSize);
		readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->ntHistory.columnid, encNTHist, columnSize, &columnSize, 0, NULL);
		decrypt_hash_history(encNTHist, columnSize, pekDecrypted, userAccount->accountRID, userAccount->ntHistory, &userAccount->numNTHistory);
		free(encNTHist);
		// If there's no NT history, there's no LM history
		// Grab the LM History
		readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->lmHistory.columnid, NULL, 0, &columnSize, 0, NULL);
		if (readStatus == JET_wrnBufferTruncated){
			LPBYTE encLMHist = (LPBYTE)calloc(1,columnSize);
			readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->lmHistory.columnid, encLMHist, columnSize, &columnSize, 0, NULL);
			decrypt_hash_history(encLMHist, columnSize, pekDecrypted, userAccount->accountRID, userAccount->lmHistory, &userAccount->numLMHistory);
			free(encLMHist);
		}
		else {
			return readStatus;
		}
	}
	return JET_errSuccess;
}
