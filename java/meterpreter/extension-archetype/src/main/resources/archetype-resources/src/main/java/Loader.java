#set( $symbol_pound = '#' )
#set( $symbol_dollar = '$' )
#set( $symbol_escape = '\' )
package ${package};

import com.metasploit.meterpreter.CommandManager;
import com.metasploit.meterpreter.ExtensionLoader;

/**
 * Loader class to register all the commands of this extension.
 */
public class Loader implements ExtensionLoader {

	public void load(CommandManager mgr) throws Exception {
		mgr.registerCommand("${pluginName}_greet_world", ${pluginName}_greet_world.class);
		mgr.registerCommand("${pluginName}_greet_someone", ${pluginName}_greet_someone.class);
	}
}
