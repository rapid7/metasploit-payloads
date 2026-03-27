package com.metasploit;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
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

    public static final int ENC_NONE = 0;
    public static final int ENC_AES256 = 1;
    public static final int ENC_AES128 = 2;

    private static final SecureRandom secureRandom = new SecureRandom();

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
            throw new IOException("Incomplete packets detected (" + remaining + " remaining bytes)");
        }
    }

    public TLVPacket(byte[] packetBytes) throws IOException {
        this(new DataInputStream(new ByteArrayInputStream(packetBytes)), packetBytes.length);
    }

    public static TLVPacket fromEncoded(byte[] packetBytes, byte[] aesKey) throws IOException {
        return fromEncoded(new DataInputStream(new ByteArrayInputStream(packetBytes)), aesKey);
    }

    public static TLVPacket fromEncoded(DataInputStream in, byte[] aesKey) throws IOException {
        byte[] header = new byte[32];
        in.readFully(header);
        byte[] clonedHeader = header.clone();

        byte[] xorKey = new byte[4];
        arrayCopy(header, 0, xorKey, 0, 4);

        // XOR the whole header first
        xorBytes(xorKey, header, 0);


        // extract the length
        int bodyLen = readInt(header, 24) - 8;

        byte[] body = new byte[bodyLen];
        in.readFully(body);

        // create a complete packet and xor the whole thing. We do this because we can't
        // be sure that the content of the body is 4-byte aligned with the xor key, so we
        // do the whole lot to make sure it behaves
        byte[] packet = new byte[clonedHeader.length + body.length];
        arrayCopy(clonedHeader, 0, packet, 0, clonedHeader.length);
        arrayCopy(body, 0, packet, clonedHeader.length, body.length);
        xorBytes(xorKey, packet, 0);

        arrayCopy(packet, 32, body, 0, body.length);
        int encFlag = readInt(packet, 20);
        if (encFlag != ENC_NONE && aesKey != null) {
            try
            {
                body = aesDecrypt(body, aesKey);
            }
            catch(GeneralSecurityException e)
            {
                // if things go back we're basically screwed.
                throw new IOException("AES decryption failed: " + e.getMessage());
            }
        }

        ByteArrayInputStream byteStream = new ByteArrayInputStream(body, 0, body.length);
        DataInputStream inputStream = new DataInputStream(byteStream);
        TLVPacket tlvPacket = new TLVPacket(inputStream, body.length);
        inputStream.close();

        return tlvPacket;
    }

    private static byte[] aesDecrypt(byte[] encryptedData, byte[] aesKey) throws GeneralSecurityException {
        byte[] iv = new byte[16];
        byte[] encrypted = new byte[encryptedData.length - iv.length];
        arrayCopy(encryptedData, 0, iv, 0, iv.length);
        arrayCopy(encryptedData, iv.length, encrypted, 0, encrypted.length);

        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        synchronized(cipher) {
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            return cipher.doFinal(encrypted);
        }
    }

    private static byte[] aesEncrypt(byte[] data, byte[] aesKey) throws GeneralSecurityException {
        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);

        byte[] encrypted = null;
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        synchronized(cipher) {
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            encrypted = cipher.doFinal(data);
        }

        data = new byte[encrypted.length + iv.length];
        arrayCopy(iv, 0, data, 0, iv.length);
        arrayCopy(encrypted, 0, data, iv.length, encrypted.length);
        return data;
    }

    private static void arrayCopy(byte[] src, int srcPos, byte[] dest, int destPos, int length) {
        if (length > 0) {
            System.arraycopy(src, srcPos + 0, dest, destPos + 0, length);
        }
    }

    private static void xorBytes(byte[] xorKey, byte[] bytes, int offset) {
        for (int i = 0; i < bytes.length - offset; ++i) {
            bytes[i + offset] ^= xorKey[i % 4];
        }
    }

    private static int readInt(byte[] source, int offset) {
        return (0xFF & source[offset]) << 24 |
                (0xFF & source[1 + offset]) << 16 |
                (0xFF & source[2 + offset]) << 8 |
                (0xFF & source[3 + offset]);
    }

    private static void writeInt(byte[] dest, int offset, int value) {
        dest[offset] = (byte)((value >> 24) & 0xFF);
        dest[offset + 1] = (byte)((value >> 16) & 0xFF);
        dest[offset + 2] = (byte)((value >> 8) & 0xFF);
        dest[offset + 3] = (byte)(value & 0xFF);
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
            return values;
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

    public byte[] toEncoded(int type, byte[] aesKey, byte[] sessionGUID) throws IOException {
        byte[] data = this.toByteArray();

        int encType = ENC_NONE;
        if (aesKey != null) {
            encType = (aesKey.length == 32 ? ENC_AES256 : ENC_AES128);
            try {
                data = aesEncrypt(data, aesKey);
            } catch (GeneralSecurityException e) {
                throw new IOException("AES encryption failed: " + e.getMessage());
            }
        }

        byte[] packet = new byte[32 + data.length];
        byte[] xorKey = {
            (byte)(0xFF & (int)((Math.random() * 255) + 1)),
            (byte)(0xFF & (int)((Math.random() * 255) + 1)),
            (byte)(0xFF & (int)((Math.random() * 255) + 1)),
            (byte)(0xFF & (int)((Math.random() * 255) + 1))
        };
        arrayCopy(xorKey, 0, packet, 0, 4);
        if (sessionGUID != null) {
            // Include the session guid in the outgoing message
            arrayCopy(sessionGUID, 0, packet, 4, sessionGUID.length);
        }

        writeInt(packet, 20, encType);

        // Write the length/type
        writeInt(packet, 24, data.length + 8);
        writeInt(packet, 28, type);

        // finally write the data
        arrayCopy(data, 0, packet, 32, data.length);

        // Xor the packet bytes
        xorBytes(xorKey, packet, 4);
        return packet;
    }
}
