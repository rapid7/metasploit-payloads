﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;

namespace MSF.Powershell.Meterpreter
{
    public class Tlv : IDisposable
    {
        private MemoryStream _stream = null;

        public byte[] ToRequest(string methodName)
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
                Append(headerStream, TlvType.Method, ToBytes(methodName));
                Append(headerStream, TlvType.RequestId, ToBytes(Core.RandomString(8)));

                header = headerStream.ToArray();
            }

            using (var packetStream = new MemoryStream())
            {
                var xorKey = ToBytes(0);
                var size = ToBytes(header.Length + tlvBytes.Length + 4);

                packetStream.Write(xorKey, 0, xorKey.Length);
                packetStream.Write(size, 0, size.Length);
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

            while (offset < length)
            {
                var size = BytesToInt(response, offset);
                var tlvType = BytesToTlvType(response, offset + 4);
                System.Diagnostics.Debug.Write(string.Format("Type {0} found that's {1} bytes", tlvType, size));

                if (!dict.ContainsKey(tlvType))
                {
                    dict.Add(tlvType, new List<object>());
                }

                switch (TlvTypeToMetaType(tlvType))
                {
                    case MetaType.String:
                        {
                            var value = BytesToString(response, size - 8, offset + 8);
                            System.Diagnostics.Debug.Write(string.Format("Type {0} value is: {1}", tlvType, value));
                            dict[tlvType].Add(value);
                            break;
                        }
                    case MetaType.Uint:
                        {
                            var value = BytesToInt(response, offset + 8);
                            System.Diagnostics.Debug.Write(string.Format("Type {0} value is: {1}", tlvType, value));
                            dict[tlvType].Add(value);
                            break;
                        }
                    case MetaType.Qword:
                        {
                            var value = BytesToQword(response, offset + 8);
                            System.Diagnostics.Debug.Write(string.Format("Type {0} value is: {1}", tlvType, value));
                            dict[tlvType].Add(value);
                            break;
                        }
                    case MetaType.Bool:
                        {
                            var value = BytesToBool(response, offset + 8);
                            System.Diagnostics.Debug.Write(string.Format("Type {0} value is: {1}", tlvType, value));
                            dict[tlvType].Add(value);
                            break;
                        }
                    case MetaType.Group:
                        {
                            var value = FromResponse(response, offset + 8, size);
                            System.Diagnostics.Debug.Write(string.Format("Type {0} value is a dictionary of {1} elements", tlvType, value.Count));
                            dict[tlvType].Add(value);
                            break;
                        }
                }

                offset += size;
            }

            return dict;
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
            return BitConverter.GetBytes(IPAddress.HostToNetworkOrder(i));
        }

        private static byte[] ToBytes(string s)
        {
            return Encoding.UTF8.GetBytes(s + "\x00");
        }

        private static MetaType TlvTypeToMetaType(TlvType tlvType)
        {
            return (MetaType)((int)MetaType.All & (int)tlvType);
        }
    }
}