using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;

namespace MSF.Powershell.Meterpreter
{
    public class Tlv : IDisposable
    {
        private MemoryStream _stream = null;

        public byte[] ToRequest(CommandId commandId)
        {
            var tlvBytes = this.Bytes;
            if (tlvBytes == null)
            {
                return null;
            }

            var header = default(byte[]);
            using (var headerStream = new MemoryStream())
            {
                var packetType = ToBytes((int)PacketType.Request);

                headerStream.Write(packetType, 0, packetType.Length);
                Append(headerStream, TlvType.CommandId, commandId);
                var requestId = Core.RandomString(8);
                Append(headerStream, TlvType.RequestId, ToBytes(requestId));

                header = headerStream.ToArray();
            }

            using (var packetStream = new MemoryStream())
            {
                var blankHeader = new byte[24];
                var size = header.Length + tlvBytes.Length + 4;
                var sizeBytes = ToBytes(size);

                System.Diagnostics.Debug.Write(string.Format("[PSH BINDING] Size value will be set to {0}", size));
                packetStream.Write(blankHeader, 0, blankHeader.Length);
                packetStream.Write(sizeBytes, 0, sizeBytes.Length);
                packetStream.Write(header, 0, header.Length);
                packetStream.Write(tlvBytes, 0, tlvBytes.Length);

                return packetStream.ToArray();
            }
        }

        public static Dictionary<TlvType, List<object>> FromResponse(byte[] response, int start = 0, int length = 0)
        {
            var dict = new Dictionary<TlvType, List<object>>();

            var offset = start;

            if (length == 0)
            {
                length = response.Length;
            }

            System.Diagnostics.Debug.Write(string.Format("[PSH BINDING] Parsing from {0} to {1} of {2}", start, start + length, response.Length));

            while (offset < start + length)
            {
                var size = BytesToInt(response, offset);
                var tlvType = BytesToTlvType(response, offset + 4);
                System.Diagnostics.Debug.Write(string.Format("[PSH BINDING] Type {0} found that's {1} bytes", tlvType, size));

                if (!dict.ContainsKey(tlvType))
                {
                    dict.Add(tlvType, new List<object>());
                }

                var metaType = TlvTypeToMetaType(tlvType);
                System.Diagnostics.Debug.Write(string.Format("[PSH BINDING] Type {0} detected as meta type {1}", tlvType, metaType));
                switch (metaType)
                {
                    case MetaType.String:
                        {
                            var value = BytesToString(response, size - 8, offset + 8);
                            System.Diagnostics.Debug.Write(string.Format("[PSH BINDING] Type {0} value is: {1}", tlvType, value));
                            dict[tlvType].Add(value);
                            break;
                        }
                    case MetaType.Uint:
                        {
                            var value = BytesToInt(response, offset + 8);
                            System.Diagnostics.Debug.Write(string.Format("[PSH BINDING] Type {0} value is: {1}", tlvType, value));
                            dict[tlvType].Add(value);
                            break;
                        }
                    case MetaType.Qword:
                        {
                            var value = BytesToQword(response, offset + 8);
                            System.Diagnostics.Debug.Write(string.Format("[PSH BINDING] Type {0} value is: {1}", tlvType, value));
                            dict[tlvType].Add(value);
                            break;
                        }
                    case MetaType.Bool:
                        {
                            var value = BytesToBool(response, offset + 8);
                            System.Diagnostics.Debug.Write(string.Format("[PSH BINDING] Type {0} value is: {1}", tlvType, value));
                            dict[tlvType].Add(value);
                            break;
                        }
                    case MetaType.Raw:
                        {
                            var value = new byte[size - 8];
                            Array.Copy(response, offset + 8, value, 0, value.Length);
                            System.Diagnostics.Debug.Write(string.Format("[PSH BINDING] Type {0} value is: {1} bytes long", tlvType, value.Length));
                            dict[tlvType].Add(value);
                            break;
                        }
                    case MetaType.Group:
                        {
                            System.Diagnostics.Debug.Write(string.Format("[PSH BINDING] Type {0} is a group, parsing...", tlvType));
                            var value = FromResponse(response, offset + 8, size);
                            System.Diagnostics.Debug.Write(string.Format("[PSH BINDING] Type {0} parsed, value is a dictionary of {1} elements", tlvType, value.Count));
                            dict[tlvType].Add(value);
                            break;
                        }
                    default:
                        {
                            System.Diagnostics.Debug.Write(string.Format("[PSH BINDING] Unexpected type {0}", tlvType));
                            break;
                        }
                }

                offset += size;
                System.Diagnostics.Debug.Write(string.Format("[PSH BINDING] Offset updated to {0}", offset));
            }

            return dict;
        }

        public static T GetValue<T>(Dictionary<TlvType, List<object>> tlvDict, TlvType tlvType, T defaultVal = default(T))
        {
            if (tlvDict.ContainsKey(tlvType) && tlvDict[tlvType].Count > 0)
            {
                return (T)tlvDict[tlvType][0];
            }

            return defaultVal;
        }

        public byte[] Bytes
        {
            get
            {
                if (_stream != null)
                {
                    return _stream.ToArray();
                }
                return null;
            }
        }

        public Tlv()
        {
            _stream = new MemoryStream();
        }

        public void Pack(TlvType t, bool b)
        {
            ValidateMetaType(MetaType.Bool, t);
            Append(t, b ? new byte[] { 1 } : new byte[] { 0 });
        }

        public void Pack(TlvType t, uint i)
        {
            ValidateMetaType(MetaType.Uint, t);
            Append(t, ToBytes(i));
        }

        public void Pack(TlvType t, int i)
        {
            ValidateMetaType(MetaType.Uint, t);
            Append(t, ToBytes(i));
        }

        public void Pack(TlvType t, Int64 i)
        {
            ValidateMetaType(MetaType.Qword, t);
            Append(t, ToBytes(i));
        }

        public void Pack(TlvType t, string s)
        {
            ValidateMetaType(MetaType.String, t);
            Append(t, ToBytes(s));
        }

        public void Pack(TlvType t, Tlv tlv)
        {
            ValidateMetaType(MetaType.Group, t);
            var tlvBytes = tlv.Bytes;
            if (tlvBytes != null)
            {
                Append(t, tlv.Bytes);
            }
        }

        public void Pack(TlvType t, byte[] value)
        {
            ValidateMetaType(MetaType.Raw, t);
            Append(t, value);
        }

        public void Dispose()
        {
            if (_stream != null)
            {
                _stream.Dispose();
                _stream = null;
            }
        }

        private void Append(TlvType t, byte[] value)
        {
            Append(_stream, t, value);
        }

        private static void Append(MemoryStream stream, TlvType t, CommandId commandId)
        {
            System.Diagnostics.Debug.Write(string.Format("[PSH BINDING] Adding type {0} ({1}) of {2} ({3})", t, (uint)t, commandId, (uint)commandId));
            var type = ToBytes((int)t);
            var value = ToBytes((uint)commandId);
            var length = ToBytes(value.Length + type.Length + 4);
            stream.Write(length, 0, length.Length);
            stream.Write(type, 0, type.Length);
            stream.Write(value, 0, value.Length);
        }

        private static void Append(MemoryStream stream, TlvType t, byte[] value)
        {
            System.Diagnostics.Debug.Write(string.Format("[PSH BINDING] Adding type {0} of {1} bytes", t, value.Length));
            var type = ToBytes((int)t);
            var length = ToBytes(value.Length + type.Length + 4);
            stream.Write(length, 0, length.Length);
            stream.Write(type, 0, type.Length);
            stream.Write(value, 0, value.Length);
        }

        private static void ValidateMetaType(MetaType expected, TlvType actual)
        {
            if ((MetaType)((TlvType)expected & actual) != expected)
            {
                throw new ArgumentException("Invalid Meta type given");
            }
        }

        private static PacketType BytesToPacketType(byte[] bytes, int offset = 0)
        {
            return (PacketType)BytesToInt(bytes, offset);
        }

        private static TlvType BytesToTlvType(byte[] bytes, int offset = 0)
        {
            return (TlvType)BytesToInt(bytes, offset);
        }

        private static bool BytesToBool(byte[] bytes, int offset = 0)
        {
            return bytes[offset] == 1;
        }

        private static int BytesToInt(byte[] bytes, int offset = 0)
        {
            return IPAddress.NetworkToHostOrder(BitConverter.ToInt32(bytes, offset));
        }

        private static Int64 BytesToQword(byte[] bytes, int offset = 0)
        {
            return IPAddress.NetworkToHostOrder(BitConverter.ToInt64(bytes, offset));
        }

        private static string BytesToString(byte[] bytes, int length, int offset = 0)
        {
            // discard the trailing null byte
            return Encoding.UTF8.GetString(bytes, offset, length - 1);
        }

        private static byte[] ToBytes(Int64 i)
        {
            return BitConverter.GetBytes(IPAddress.HostToNetworkOrder(i));
        }

        private static byte[] ToBytes(int i)
        {
            return BitConverter.GetBytes(IPAddress.HostToNetworkOrder(i));
        }

        private static byte[] ToBytes(uint i)
        {
            return BitConverter.GetBytes(IPAddress.HostToNetworkOrder((int)i));
        }

        private static byte[] ToBytes(string s)
        {
            return Encoding.UTF8.GetBytes(s + "\x00");
        }

        private static MetaType TlvTypeToMetaType(TlvType tlvType)
        {
            return (MetaType)((int)tlvType & (int)MetaType.All);
        }
    }
}
