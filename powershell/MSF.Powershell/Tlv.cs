using System;
using System.IO;
using System.Net;
using System.Text;

namespace MSF.Powershell
{
    public class Tlv
    {
        private MemoryStream _stream = null;

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
            var value = Encoding.UTF8.GetBytes(s + "\x00");
            Append(t, value);
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

        private void Append(TlvType t, byte[] value)
        {
            var type = ToBytes((int)t);
            var length = ToBytes(value.Length);
            _stream.Write(length, 0, length.Length);
            _stream.Write(type, 0, type.Length);
            _stream.Write(value, 0, value.Length);
        }

        private void ValidateMetaType(MetaType expected, TlvType actual)
        {
            if ((MetaType)((TlvType)expected & actual) != expected)
            {
                throw new ArgumentException("Invalid Meta type given");
            }
        }

        private byte[] ToBytes(Int64 i)
        {
            return BitConverter.GetBytes(IPAddress.HostToNetworkOrder(i));
        }

        private byte[] ToBytes(int i)
        {
            return BitConverter.GetBytes(IPAddress.HostToNetworkOrder(i));
        }

        private byte[] ToBytes(uint i)
        {
            return BitConverter.GetBytes(IPAddress.HostToNetworkOrder(i));
        }
    }
}
