namespace MSF.Powershell.Meterpreter
{
    public static class User
    {
        private const string SystemSID = "S-1-5-18";

        public static string GetUid()
        {
            System.Diagnostics.Debug.Write("[PSH BINDING] Invoking binding call GetUid");

            Tlv tlv = new Tlv();

            var result = Core.InvokeMeterpreterBinding(true, tlv.ToRequest(CommandId.StdapiSysConfigGetuid));

            if (result != null)
            {
                var responseTlv = Tlv.FromResponse(result);
                if (responseTlv[TlvType.Result].Count > 0 &&
                    (int)responseTlv[TlvType.Result][0] == 0)
                {
                    return Tlv.GetValue<string>(responseTlv, TlvType.UserName);
                }
            }

            return null;
        }

        public static string GetSid()
        {
            System.Diagnostics.Debug.Write("[PSH BINDING] Invoking binding call GetSid");

            Tlv tlv = new Tlv();

            var result = Core.InvokeMeterpreterBinding(true, tlv.ToRequest(CommandId.StdapiSysConfigGetsid));

            if (result != null)
            {
                var responseTlv = Tlv.FromResponse(result);
                if (responseTlv[TlvType.Result].Count > 0 &&
                    (int)responseTlv[TlvType.Result][0] == 0)
                {
                    return Tlv.GetValue<string>(responseTlv, TlvType.Sid);
                }
            }

            return null;

        }

        public static bool IsSystem()
        {
            System.Diagnostics.Debug.Write("[PSH BINDING] Invoking binding call IsSystem");

            return SystemSID == GetSid();
        }
    }
}
