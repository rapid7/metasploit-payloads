package com.metasploit.meterpreter.stdapi;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

import java.awt.Robot;
import java.awt.event.InputEvent;

public class stdapi_ui_send_mouse_V1_4 extends stdapi_ui_send_mouse implements Command {

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        int action = request.getIntValue(TLVType.TLV_TYPE_MOUSE_ACTION);
        int x = request.getIntValue(TLVType.TLV_TYPE_MOUSE_X);
        int y = request.getIntValue(TLVType.TLV_TYPE_MOUSE_Y);

        Robot robot = new Robot();
        if (x != -1 && y != -1) {
            robot.mouseMove(x, y);
        }
        switch (action) {
            case 1:
                robot.mousePress(InputEvent.BUTTON1_MASK);
                robot.mouseRelease(InputEvent.BUTTON1_MASK);
                break;
            case 2:
                robot.mousePress(InputEvent.BUTTON1_MASK);
                break;
            case 3:
                robot.mouseRelease(InputEvent.BUTTON1_MASK);
                break;
            case 4:
                robot.mousePress(InputEvent.BUTTON3_MASK);
                robot.mouseRelease(InputEvent.BUTTON3_MASK);
                break;
            case 5:
                robot.mousePress(InputEvent.BUTTON3_MASK);
                break;
            case 6:
                robot.mouseRelease(InputEvent.BUTTON3_MASK);
                break;
            case 7:
                robot.mousePress(InputEvent.BUTTON1_MASK);
                robot.mouseRelease(InputEvent.BUTTON1_MASK);
                robot.mousePress(InputEvent.BUTTON1_MASK);
                robot.mouseRelease(InputEvent.BUTTON1_MASK);
                break;
        }

        return ERROR_SUCCESS;
    }
}
