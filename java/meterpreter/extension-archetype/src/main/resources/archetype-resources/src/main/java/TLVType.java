#set( $symbol_pound = '#' )
#set( $symbol_dollar = '$' )
#set( $symbol_escape = '\' )
package ${package};

import com.metasploit.meterpreter.TLVPacket;

/**
 * TLV types for this extension. Add new types you need here.
 */
public interface TLVType extends com.metasploit.meterpreter.TLVType {

	public static final int TLV_EXTENSIONS = 20000;

	public static final int TLV_TYPE_GREETEE = TLVPacket.TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 1);
}
