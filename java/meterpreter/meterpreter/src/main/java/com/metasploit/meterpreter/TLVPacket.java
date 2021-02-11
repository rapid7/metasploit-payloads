package com.metasploit.meterpreter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * A packet consisting of multiple TLV values. Having the same type more than once is an error.
 *
 * @author mihi
 */
public class TLVPacket {

    // constants
    public static final int PACKET_TYPE_REQUEST = 0;
    public static final int PACKET_TYPE_RESPONSE = 1;

    public static final int TLV_META_TYPE_NONE = 0;

    public static final int TLV_META_TYPE_STRING = (1 << 16);
    public static final int TLV_META_TYPE_UINT = (1 << 17);
    public static final int TLV_META_TYPE_RAW = (1 << 18);
    public static final int TLV_META_TYPE_BOOL = (1 << 19);
    public static final int TLV_META_TYPE_QWORD = (1 << 20);
    public static final int TLV_META_TYPE_COMPRESSED = (1 << 29);
    public static final int TLV_META_TYPE_GROUP = (1 << 30);
    public static final int TLV_META_TYPE_COMPLEX = (1 << 31);

    // not defined in original
    public static final int TLV_META_TYPE_MASK = (1 << 31) + (1 << 30) + (1 << 29) + (1 << 19) + (1 << 18) + (1 << 17) + (1 << 16);

    /**
     * A list of {@link Integer} values that represent the order of the TLV value types for serializing the current package.
     */
    private List/* <Integer> */typeOrder = new ArrayList();

    /**
     * A list of objects that represent the values stored in the package.
     */
    private List/* <Integer> */valueList = new ArrayList();

    /**
     * A map, mapping the types (as {@link Integer} objects) to an {@link ArrayList} of {@link Integer} values that respresent the index into the valueList array.
     */
    private Map/* <Integer,ArrayList> */valueMap = new HashMap();

    /**
     * A list of additionals types/values to be added to the end of the packet. Here packet types may appear more than once, but they cannot be read again with this class.
     */
    private List/* <Integer/Object> */overflowList = new ArrayList();

    /**
     * Construct a new empty TLV packet.
     */
    public TLVPacket() {
    }

    /**
     * Read a TLV packet from an input stream.
     *
     * @param in        Input stream to read from
     * @param remaining length of the packet to read in bytes
     * @throws IOException if an error occurs
     */
    public TLVPacket(DataInputStream in, int remaining) throws IOException {
        while (remaining > 0) {
            int len = in.readInt();
            int type = in.readInt();
            if (len > remaining) {
                break;
            }
            byte[] data = new byte[len - 8];
            remaining -= len;
            Object value;
            if ((type & TLV_META_TYPE_COMPRESSED) != 0) {
                in.readFully(data);
                value = data;
            } else if ((type & TLV_META_TYPE_STRING) != 0) {
                in.readFully(data);
                String string = new String(data, "UTF-8");
                if (!string.endsWith("\0")) {
                    throw new IOException("C string is not 0 terminated: " + string);
                }
                string = string.substring(0, string.length() - 1);
                if (string.indexOf('\0') != -1) {
                    throw new IOException("Embedded null detected: " + string);
                }
                value = string;
            } else if ((type & TLV_META_TYPE_QWORD) != 0 && len == 16) {
                value = in.readLong();
            } else if ((type & TLV_META_TYPE_UINT) != 0 && len == 12) {
                value = in.readInt();
            } else if ((type & TLV_META_TYPE_BOOL) != 0 && len == 9) {
                value = in.readBoolean();
            } else if ((type & TLV_META_TYPE_RAW) != 0) {
                in.readFully(data);
                value = data;
            } else if ((type & TLV_META_TYPE_GROUP) != 0) {
                in.readFully(data);
                DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data));
                value = new TLVPacket(dis, data.length);
                dis.close();
            } else if ((type & TLV_META_TYPE_COMPLEX) != 0) {
                in.readFully(data);
                value = data;
            } else {
                throw new IOException("Unsupported type: " + type + "/" + len);
            }
            add(type, value);
        }
        if (remaining != 0) {
            throw new IOException("Incomplete packets detected");
        }
    }

    /**
     * Add a TLV value to this object.
     */
    public void add(int type, Object value) throws IOException {
        ArrayList indices = null;
        Integer typeObj = new Integer(type);
        typeOrder.add(typeObj);

        if (valueMap.containsKey(typeObj)) {
            indices = (ArrayList) valueMap.get(typeObj);
        } else {
            indices = new ArrayList();
            valueMap.put(typeObj, indices);
        }

        // add the index of the new element to the list of indices for the object
        indices.add(new Integer(valueList.size()));

        // add the value to the list of values that make up the object
        valueList.add(value);
    }

    /**
     * Add an element to the overflow list.
     */
    public void addOverflow(int type, Object value) throws IOException {
        overflowList.add(new Integer(type));
        overflowList.add(value);
    }

    /**
     * Add a TLV value to this object.
     */
    public void add(int type, long value) throws IOException {
        add(type, new Long(value));
    }

    /**
     * Add a TLV value to this object.
     */
    public void add(int type, int value) throws IOException {
        add(type, new Integer(value));
    }

    /**
     * Add a TLV value to this object.
     */
    public void add(int type, boolean value) throws IOException {
        add(type, Boolean.valueOf(value));
    }

    /**
     * Get the types and their order in this packet, as an immutable list.
     */
    public List getTypeOrder() {
        return Collections.unmodifiableList(typeOrder);
    }

    /**
     * Get the value associated to a type.
     */
    public Object getValue(int type) {
        ArrayList indices = (ArrayList) valueMap.get(new Integer(type));
        if (indices == null) {
            throw new IllegalArgumentException("Cannot find type " + type);
        }
        // the indices variable is an ArrayList so by default return the first to
        // preserve existing behaviour.
        return valueList.get(((Integer) indices.get(0)).intValue());
    }

    /**
     * Get the list of values associated to a type.
     */
    public List getValues(int type) {
        ArrayList values = new ArrayList();
        ArrayList indices = (ArrayList) valueMap.get(new Integer(type));
        if (indices == null) {
            throw new IllegalArgumentException("Cannot find type " + type);
        }

        for (int i = 0; i < indices.size(); ++i) {
            values.add(valueList.get(((Integer) indices.get(i)).intValue()));
        }
        return values;
    }

    /**
     * Get the value associated to a type.
     */
    public Object getValue(int type, Object defaultValue) {
        ArrayList indices = (ArrayList) valueMap.get(new Integer(type));
        if (indices == null) {
            return defaultValue;
        }
        // the indices variable is an ArrayList so by default return the first to
        // preserve existing behaviour.
        return valueList.get(((Integer) indices.get(0)).intValue());
    }

    /**
     * Get the value associated to a type as a {@link String}.
     */
    public String getStringValue(int type) {
        return (String) getValue(type);
    }

    /**
     * Get the value associated to a type as a {@link String}, or a default value if the value does not exist.
     */
    public String getStringValue(int type, String defaultValue) {
        return (String) getValue(type, defaultValue);
    }

    /**
     * Get the value associated to a type as an int.
     */
    public long getLongValue(int type) {
        return ((Long) getValue(type)).longValue();
    }

    /**
     * Get the value associated to a type as an int.
     */
    public int getIntValue(int type) {
        return ((Integer) getValue(type)).intValue();
    }

    /**
     * Get the value associated to a type as a boolean.
     */
    public boolean getBooleanValue(int type) {
        return ((Boolean) getValue(type)).booleanValue();
    }

    /**
     * Get the value associated to a type as a byte array.
     */
    public byte[] getRawValue(int type) {
        return (byte[]) getValue(type);
    }

    /**
     * Get the value associated to a type as a byte array.
     */
    public byte[] getRawValue(int type, byte[] defaultValue) {
        return (byte[]) getValue(type, defaultValue);
    }

    public TLVPacket createResponse() throws IOException {
        TLVPacket response = new TLVPacket();
        response.add(TLVType.TLV_TYPE_COMMAND_ID, this.getIntValue(TLVType.TLV_TYPE_COMMAND_ID));
        response.add(TLVType.TLV_TYPE_REQUEST_ID, this.getStringValue(TLVType.TLV_TYPE_REQUEST_ID, null));
        return response;
    }

    /**
     * Write all the values to an output stream.
     */
    public void write(DataOutputStream out) throws IOException {
        for (Iterator it = typeOrder.iterator(); it.hasNext(); ) {
            Integer typeKey = (Integer) it.next();
            int type = typeKey.intValue();
            Object value = getValue(type);
            write(out, type, value);
        }
        for (Iterator it = overflowList.iterator(); it.hasNext(); ) {
            Integer typeKey = (Integer) it.next();
            int type = typeKey.intValue();
            Object value = it.next();
            write(out, type, value);
        }
    }

    /**
     * Write a single value to an output stream.
     */
    private static void write(DataOutputStream out, int type, Object value) throws IOException {
        byte[] data;
        if ((type & TLV_META_TYPE_STRING) != 0) {
            data = ((String) value + "\0").getBytes("UTF-8");
        } else if ((type & TLV_META_TYPE_QWORD) != 0) {
            out.writeInt(16);
            out.writeInt(type);
            out.writeLong(((Long) value).longValue());
            return;
        } else if ((type & TLV_META_TYPE_UINT) != 0) {
            out.writeInt(12);
            out.writeInt(type);
            out.writeInt(((Integer) value).intValue());
            return;
        } else if ((type & TLV_META_TYPE_BOOL) != 0) {
            out.writeInt(9);
            out.writeInt(type);
            out.writeBoolean(((Boolean) value).booleanValue());
            return;
        } else if ((type & TLV_META_TYPE_RAW) != 0) {
            data = (byte[]) value;
        } else if ((type & TLV_META_TYPE_GROUP) != 0) {
            data = ((TLVPacket) value).toByteArray();
        } else if ((type & TLV_META_TYPE_COMPLEX) != 0) {
            data = (byte[]) value;
        } else {
            throw new IOException("Unsupported type: " + type);
        }
        out.writeInt(8 + data.length);
        out.writeInt(type);
        out.write(data);
    }

    /**
     * Convert all the values to a byte array.
     */
    public byte[] toByteArray() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        write(new DataOutputStream(baos));
        return baos.toByteArray();
    }
}
