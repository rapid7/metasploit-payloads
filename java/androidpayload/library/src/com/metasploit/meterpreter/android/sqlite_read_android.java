package com.metasploit.meterpreter.android;

import android.database.Cursor;
import android.net.Uri;

import com.metasploit.meterpreter.AndroidMeterpreter;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;

public class sqlite_read_android implements Command {

    private static final int TLV_EXTENSIONS = 20000;

    @Override
    public int execute(Meterpreter meterpreter, TLVPacket request,
                       TLVPacket response) throws Exception {
        return ERROR_SUCCESS;
    }

}
