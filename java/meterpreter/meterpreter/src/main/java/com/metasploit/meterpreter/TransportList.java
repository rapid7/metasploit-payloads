package com.metasploit.meterpreter;

public class TransportList {
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

