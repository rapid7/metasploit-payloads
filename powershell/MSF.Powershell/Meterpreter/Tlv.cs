using System;
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
    }
}
