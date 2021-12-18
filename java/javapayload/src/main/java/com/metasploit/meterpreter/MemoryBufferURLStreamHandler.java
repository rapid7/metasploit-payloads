package com.metasploit.meterpreter;

import java.io.IOException;
import java.io.Serializable;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.util.ArrayList;
import java.util.List;

/**
 * An {@link URLStreamHandler} for a {@link MemoryBufferURLConnection}
 *
 * @author mihi
 */
public class MemoryBufferURLStreamHandler extends URLStreamHandler implements Serializable {

    private List files = new ArrayList();

    @Override
    protected URLConnection openConnection(URL u) throws IOException {
        return new MemoryBufferURLConnection(u);
    }

    public List getFiles() {
        return files;
    }
}
