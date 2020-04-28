using System;
using System.Collections.Generic;

namespace MSF.Powershell.Meterpreter
{
    public static class Transport
    {
        public class TransportInstance
        {
            public string Url { get; set; }
            public int CommTimeout { get; set; }
            public int RetryTotal { get; set; }
            public int RetryWait { get; set; }
            public string UserAgent { get; set; }
            public string ProxyHost { get; set; }
            public string ProxyUser { get; set; }
            public string ProxyPass { get; set; }
            public string CertHash { get; set; }
        }

        public class SessionDefinition
        {
            public DateTime SessionExpiry { get; private set; }
            public List<TransportInstance> Transports { get; private set; }

            public SessionDefinition(DateTime sessionExpiry)
            {
                SessionExpiry = sessionExpiry;
                Transports = new List<TransportInstance>();
            }
        }

        public static SessionDefinition List()
        {
            Tlv tlv = new Tlv();

            var result = Core.InvokeMeterpreterBinding(true, tlv.ToRequest(CommandId.CoreTransportList));

            if (result != null)
            {
                System.Diagnostics.Debug.Write("[PSH BINDING] List result returned");
                var responseTlv = Tlv.FromResponse(result);
                if (responseTlv[TlvType.Result].Count > 0 &&
                    (int)responseTlv[TlvType.Result][0] == 0)
                {
                    System.Diagnostics.Debug.Write("[PSH BINDING] List succeeded");
                    var expirySeconds = Tlv.GetValue<int>(responseTlv, TlvType.TransSessExp);
                    var session = new SessionDefinition(DateTime.Now.AddSeconds(expirySeconds));

                    foreach (var transportObj in responseTlv[TlvType.TransGroup])
                    {
                        var transportDict = (Dictionary<TlvType, List<object>>)transportObj;

                        var transport = new TransportInstance
                        {
                            Url = Tlv.GetValue<string>(transportDict, TlvType.TransUrl, string.Empty),
                            CommTimeout = Tlv.GetValue<int>(transportDict, TlvType.TransCommTimeout),
                            RetryTotal = Tlv.GetValue<int>(transportDict, TlvType.TransRetryTotal),
                            RetryWait = Tlv.GetValue<int>(transportDict, TlvType.TransRetryWait),
                            UserAgent = Tlv.GetValue<string>(transportDict, TlvType.TransUa, string.Empty),
                            ProxyHost = Tlv.GetValue<string>(transportDict, TlvType.TransProxyHost, string.Empty),
                            ProxyUser = Tlv.GetValue<string>(transportDict, TlvType.TransProxyUser, string.Empty),
                            ProxyPass = Tlv.GetValue<string>(transportDict, TlvType.TransProxyPass, string.Empty),
                        };
                        var hash = Tlv.GetValue<byte[]>(transportDict, TlvType.TransCertHash);
                        if (hash != null && hash.Length > 0)
                        {
                            transport.CertHash = BitConverter.ToString(hash).Replace("-", "");
                        }

                        session.Transports.Add(transport);
                    }

                    return session;
                }
                System.Diagnostics.Debug.Write("[PSH BINDING] List failed");
            }
            else
            {
                System.Diagnostics.Debug.Write("[PSH BINDING] List result was null");
            }

            return null;
        }

        private static string ToUriString(byte[] b)
        {
            return System.Convert.ToBase64String(b).Replace("+", "-").Replace("/", "_").Replace("=", "");
        }

        private static int GetUnixTime()
        {
            return (int)(DateTime.UtcNow - DateTime.Parse("1/1/1970")).TotalSeconds;
        }

        private static byte[] GenerateRandomBytes(int count)
        {
            var b = new byte[count];
            var c = new System.Security.Cryptography.RNGCryptoServiceProvider();
            c.GetNonZeroBytes(b);
            return b;
        }

        private static string GenerateRandomUri()
        {
            return ToUriString(GenerateRandomBytes(12));
        }

        private static string GenerateUuid()
        {
            var arch = IntPtr.Size == 4 ? 1 : 2;
            var uuid = GenerateRandomBytes(16);
            uuid[10] = (byte)(uuid[8] ^ 1);
            uuid[11] = (byte)(uuid[9] ^ arch);
            var tx = BitConverter.ToInt32(new byte[] { uuid[9], uuid[8], uuid[9], uuid[8] }, 0);
            var t = BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder(tx ^ GetUnixTime()));
            uuid[12] = t[0];
            uuid[13] = t[1];
            uuid[14] = t[2];
            uuid[15] = t[3];
            return ToUriString(uuid);
        }

        private static int Check8(string s)
        {
            var sum = 0;
            foreach (var c in System.Text.Encoding.ASCII.GetBytes(s))
            {
                sum += (int)c;
            }
            return sum % 0x100;
        }

        public static string GenerateTransportUri()
        {
            var uuid = GenerateUuid();
            var sum = 98;

            for (var i = 1; i <= 1000; ++i)
            {
                var t = uuid + GenerateRandomUri();
                if (sum == Check8(t))
                {
                    return string.Format("/{0}/", t);
                }
            }

            return null;
        }

        public static bool Add(TransportInstance transport, int sessionExpiry = 0)
        {
            Tlv tlv = new Tlv();
            tlv.Pack(TlvType.TransUrl, transport.Url);

            if (sessionExpiry > 0)
            {
                tlv.Pack(TlvType.TransSessExp, sessionExpiry);
            }
            if (transport.CommTimeout > 0)
            {
                tlv.Pack(TlvType.TransCommTimeout, transport.CommTimeout);
            }
            if (transport.RetryTotal > 0)
            {
                tlv.Pack(TlvType.TransRetryTotal, transport.RetryTotal);
            }
            if (transport.RetryWait > 0)
            {
                tlv.Pack(TlvType.TransRetryWait, transport.RetryWait);
            }
            if (!string.IsNullOrEmpty(transport.UserAgent))
            {
                tlv.Pack(TlvType.TransUa, transport.UserAgent);
            }
            if (!string.IsNullOrEmpty(transport.ProxyHost))
            {
                tlv.Pack(TlvType.TransUa, transport.ProxyHost);
            }
            if (!string.IsNullOrEmpty(transport.ProxyUser))
            {
                tlv.Pack(TlvType.TransUa, transport.ProxyUser);
            }
            if (!string.IsNullOrEmpty(transport.ProxyPass))
            {
                tlv.Pack(TlvType.TransUa, transport.ProxyPass);
            }
            if (!string.IsNullOrEmpty(transport.CertHash))
            {
                var hash = new byte[transport.CertHash.Length / 2];
                for (var i = 0; i < hash.Length; ++i )
                {
                    hash[i] = Convert.ToByte(transport.CertHash.Substring(i * 2, 2), 16);
                }
                tlv.Pack(TlvType.TransCertHash, hash);
            }

            var result = Core.InvokeMeterpreterBinding(true, tlv.ToRequest(CommandId.CoreTransportAdd));

            if (result != null)
            {
                System.Diagnostics.Debug.Write("[PSH BINDING] List result returned");
                var responseTlv = Tlv.FromResponse(result);
                if (responseTlv[TlvType.Result].Count > 0 &&
                    (int)responseTlv[TlvType.Result][0] == 0)
                {
                    return true;
                }
            }

            return false;
        }
    }
}
