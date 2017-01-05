package com.metasploit.meterpreter.android;

import android.content.Context;
import android.os.PowerManager;
import com.metasploit.meterpreter.AndroidMeterpreter;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class android_wakelock implements Command {

    private PowerManager.WakeLock wakeLock = null;

    @Override
    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        final Context context = AndroidMeterpreter.getContext();
        if (context == null) {
            return ERROR_FAILURE;
        }
        int flags = request.getIntValue(TLVType.TLV_TYPE_FLAGS);
        if (wakeLock == null) {
            if (flags != 0) {
                PowerManager powerManager = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
                wakeLock = powerManager.newWakeLock(flags, android_wakelock.class.getSimpleName());
                wakeLock.acquire();
            }
        } else {
            if (flags == 0) {
                wakeLock.release();
                wakeLock = null;
            }
        }
        return ERROR_SUCCESS;
    }
}
