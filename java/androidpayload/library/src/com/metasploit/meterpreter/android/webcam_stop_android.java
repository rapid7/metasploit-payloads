
package com.metasploit.meterpreter.android;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;
import com.metasploit.meterpreter.stdapi.stdapi_webcam_audio_record;

public class webcam_stop_android extends stdapi_webcam_audio_record implements Command {

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {

        if (webcam_start_android.camera != null) {
            webcam_start_android.camera.stopPreview();
            webcam_start_android.camera.release();
            webcam_start_android.camera = null;
        }

        return ERROR_SUCCESS;
    }
}
