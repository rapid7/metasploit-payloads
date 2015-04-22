#include "ntds_jet.h"

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
	return shutdownStatus;
}

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

JET_ERR get_column_info(jetState *ntdsState, ntdsColumns *accountColumns){
	JET_ERR columnError;
	const char attributeNames[][25] = {
		"ATTm590045",
		"ATTj590126",
		"ATTq589983",
		"ATTk590689",
		"ATTq589876",
		"ATTk589879",
		"ATTk589984",
		"ATTj589993",
		"ATTk589914",
		"ATTk589918",
		"ATTm13",
		"ATTj589832",
		"ATTq589920",
		"ATTr589970"
	};
	JET_COLUMNDEF *columnDefs[] = {
		&accountColumns->accountName,
		&accountColumns->accountType,
		&accountColumns->accountExpiry,
		&accountColumns->encryptionKey,
		&accountColumns->lastLogon,
		&accountColumns->lmHash,
		&accountColumns->lmHistory,
		&accountColumns->logonCount,
		&accountColumns->ntHash,
		&accountColumns->ntHistory,
		&accountColumns->accountDescription,
		&accountColumns->accountControl,
		&accountColumns->lastPasswordChange,
		&accountColumns->accountSID,
	};
	for (int i = 0; i < 14; i++){
		columnError = JetGetTableColumnInfo(ntdsState->jetSession, ntdsState->jetTable, attributeNames[i], columnDefs[i], sizeof(JET_COLUMNDEF), JET_ColInfo);
		if (columnError != JET_errSuccess){
			return columnError;
		}
	}
	return JET_errSuccess;
}

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

JET_ERR read_table(jetState *ntdsState, ntdsColumns *accountColumns, decryptedPEK *pekDecrypted){
	JET_ERR cursorStatus;
	JET_ERR readStatus;

	cursorStatus = JetMove(ntdsState->jetSession, ntdsState->jetTable, JET_MoveFirst, (JET_GRBIT)NULL);
	if (cursorStatus != JET_errSuccess){
		return cursorStatus;
	}
	do{
		// Create a User Account Struct to hold our data
		ntdsAccount *userAccount = malloc(sizeof(ntdsAccount));
		memset(userAccount, 0, sizeof(ntdsAccount));

		//Define our temp values here
		DWORD accountType = 0;
		FILETIME accountExpiry;
		SYSTEMTIME accountExpiry2;
		FILETIME lastLogon;
		SYSTEMTIME lastLogon2;
		FILETIME lastPass;
		SYSTEMTIME lastPass2;
		DWORD accountControl = 0;
		unsigned long columnSize = 0;
		encryptedHash *encryptedLM = malloc(sizeof(encryptedHash));
		encryptedHash *encryptedNT = malloc(sizeof(encryptedHash));
		memset(encryptedLM, 0, sizeof(encryptedHash));
		memset(encryptedNT, 0, sizeof(encryptedHash));

		//Retrieve the account type for this row
		readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->accountType.columnid, &accountType, sizeof(accountType), &columnSize, 0, NULL);
		// Unless this is a User Account, then we skip it
		if (readStatus == JET_wrnColumnNull || accountType != 0x30000000){
			cursorStatus = JetMove(ntdsState->jetSession, ntdsState->jetTable, JET_MoveNext, (JET_GRBIT)NULL);
			continue;
		}
		// If any other error has occured we've screwed up and need to fix it for now
		if (readStatus != JET_errSuccess){
			exit(readStatus);
		}
		// Grab the SID here
		readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->accountSID.columnid, &userAccount->accountSID, sizeof(userAccount->accountName), &columnSize, 0, NULL);
		if (readStatus != JET_errSuccess){
			exit(readStatus);
		}
		// Derive the RID from the SID
		int ridIndex = columnSize - sizeof(DWORD);
		DWORD *ridLoc = (DWORD *)&userAccount->accountSID[ridIndex];
		userAccount->accountRID = htonl(*ridLoc);

		// Grab the samAccountName here
		readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->accountName.columnid, &userAccount->accountName, sizeof(userAccount->accountName), &columnSize, 0, NULL);
		if (readStatus != JET_errSuccess){
			exit(readStatus);
		}
		// Grab the account expiration date/time here
		readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->accountExpiry.columnid, &accountExpiry, sizeof(accountExpiry), &columnSize, 0, NULL);
		if (readStatus != JET_errSuccess){
			exit(readStatus);
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
			exit(readStatus);
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
			exit(readStatus);
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
			exit(readStatus);
		}
		// Grab the UserAccountControl flags here
		readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->accountControl.columnid, &accountControl, sizeof(accountControl), &columnSize, 0, NULL);
		if (readStatus != JET_errSuccess){
			exit(readStatus);
		}
		if (accountControl & NTDS_ACCOUNT_DISABLED){
			userAccount->accountDisabled = TRUE;
		}
		if (accountControl & NTDS_ACCOUNT_LOCKED){
			userAccount->accountLocked = TRUE;
		}
		if (accountControl & NTDS_ACCOUNT_NO_PASS){
			userAccount->noPassword = TRUE;
		}
		if (accountControl & NTDS_ACCOUNT_PASS_EXPIRED){
			userAccount->passExpired = TRUE;
		}
		if (accountControl & NTDS_ACCOUNT_PASS_NO_EXPIRE){
			userAccount->passNoExpire = TRUE;
		}
		// Grab the Logon Count here
		readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->logonCount.columnid, &userAccount->logonCount, sizeof(userAccount->logonCount), &columnSize, 0, NULL);
		if (readStatus != JET_errSuccess){
			exit(readStatus);
		}
		// Grab the NT Hash
		readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->ntHash.columnid, encryptedNT, sizeof(encryptedHash), &columnSize, 0, NULL);
		if (readStatus != JET_errSuccess){
			if (readStatus == JET_wrnColumnNull){
				memcpy(&userAccount->ntHash, &BLANK_NT_HASH, 32);
			}
			else{
				exit(readStatus);
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
				exit(readStatus);
			}
		}
		else{
			decrypt_hash(encryptedLM, pekDecrypted, userAccount->lmHash, userAccount->accountRID);
		}
		// Grab the NT Hash History
		readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->ntHistory.columnid, NULL, 0, &columnSize, 0, NULL);
		if (readStatus == JET_wrnBufferTruncated){
			LPBYTE encNTHist = (LPBYTE)malloc(columnSize);
			readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->ntHistory.columnid, encNTHist, columnSize, &columnSize, 0, NULL);
			decrypt_hash_history(encNTHist, columnSize, pekDecrypted, userAccount->accountRID, &userAccount->ntHistory, &userAccount->numNTHistory);
			// If there's no NT history, there's no LM history
			// Grab the LM History
			readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->lmHistory.columnid, NULL, 0, &columnSize, 0, NULL);
			if (readStatus == JET_wrnBufferTruncated){
				LPBYTE encLMHist = (LPBYTE)malloc(columnSize);
				readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->lmHistory.columnid, encLMHist, columnSize, &columnSize, 0, NULL);
				decrypt_hash_history(encLMHist, columnSize, pekDecrypted, userAccount->accountRID, &userAccount->lmHistory, &userAccount->numLMHistory);
			}
			else {
				return readStatus;
			}
		}
		dump_account(userAccount);
		cursorStatus = JetMove(ntdsState->jetSession, ntdsState->jetTable, JET_MoveNext, (JET_GRBIT)NULL);
	} while (cursorStatus == JET_errSuccess);
	if (cursorStatus != JET_errNoCurrentRecord){
		return cursorStatus;
	}
	return JET_errSuccess;
}