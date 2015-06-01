#set( $symbol_pound = '#' )
#set( $symbol_dollar = '$' )
#set( $symbol_escape = '\' )
package ${package};

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;

/**
 * Example of a very simple command. This command will print a greeting to the
 * victim's console and return it.
 */
public class ${pluginName}_greet_world implements Command {

	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
		String greeting = "Hello, world!";
		System.out.println(greeting);
		response.add(TLVType.TLV_TYPE_STRING, greeting);
		return ERROR_SUCCESS;
	}
}
