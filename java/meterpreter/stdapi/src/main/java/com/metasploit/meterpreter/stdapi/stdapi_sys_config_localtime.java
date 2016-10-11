package com.metasploit.meterpreter.stdapi;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

import java.text.Format;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class stdapi_sys_config_localtime implements Command {
    private static final Format formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z", Locale.ENGLISH);
    private static final Format tzformatter = new SimpleDateFormat("Z", Locale.ENGLISH);
    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        Date date = new Date();
        String localTime = formatter.format(date) + " (UTC" + tzformatter.format(date) + ")";
        response.addOverflow(TLVType.TLV_TYPE_LOCAL_DATETIME, localTime);
        return ERROR_SUCCESS;
    }
}
