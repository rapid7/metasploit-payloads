#set( $symbol_pound = '#' )
#set( $symbol_dollar = '$' )
#set( $symbol_escape = '\' )
package ${package};

/**
 * Implementation of {@link ${pluginName}_greet_someone} for Java 1.5 and above, using
 * {@link String${symbol_pound}format(String, Object[])} API.
 */
public class ${pluginName}_greet_someone_V1_5 extends ${pluginName}_greet_someone {

	protected String buildGreeting(String greetee) {
		return String.format("Hello, %s!", new Object[] { greetee });
	}
}
