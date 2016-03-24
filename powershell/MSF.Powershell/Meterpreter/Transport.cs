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
            public byte[] CertHash { get; set; }
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

            var result = Core.InvokeMeterpreterBinding(true, tlv.ToRequest("core_transport_list"));

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
                            CertHash = Tlv.GetValue<byte[]>(transportDict, TlvType.TransCertHash)
                        };
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
            if (transport.CertHash != null && transport.CertHash.Length > 0)
            {
                tlv.Pack(TlvType.TransCertHash, transport.CertHash);
            }

            var result = Core.InvokeMeterpreterBinding(true, tlv.ToRequest("core_transport_add"));

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
