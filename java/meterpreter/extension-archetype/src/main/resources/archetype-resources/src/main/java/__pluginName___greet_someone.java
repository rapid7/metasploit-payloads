#set( $symbol_pound = '#' )
#set( $symbol_dollar = '$' )
#set( $symbol_escape = '\' )
package ${package};

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;

/**
 * Example how to implement a command differently for different target Java
 * versions. This command will build a dynamic greeting, print it to the
 * victim's console and return it.
 *
 * There are two implementations of this class. This base class uses
 * {@link StringBuffer} for building the greeting. The version for Java 1.5 and
 * above, {@link ${pluginName}_greet_someone_V1_5}, uses
 * {@link String${symbol_pound}format(String, Object[])} API which was added in Java 1.5. This
 * example is constructed since the new formatting API does not really justify a
 * separate version of the command.
 */
public class ${pluginName}_greet_someone implements Command {

	public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
		String greetee = request.getStringValue(TLVType.TLV_TYPE_GREETEE);
		String greeting = buildGreeting(greetee);
		System.out.println(greeting);
		response.add(TLVType.TLV_TYPE_STRING, greeting);
		return ERROR_SUCCESS;
	}

	protected String buildGreeting(String greetee) {
		StringBuffer sb = new StringBuffer(greetee.length() + 8);
		sb.append("Hello, ");
		sb.append(greetee);
		sb.append('!');
		return sb.toString();
	}
}
