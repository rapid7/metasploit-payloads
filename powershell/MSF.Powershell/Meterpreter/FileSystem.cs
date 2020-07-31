using System;
using System.Collections.Generic;

namespace MSF.Powershell.Meterpreter
{
    public static class FileSystem
    {
        public enum MountType
        {
            Unknown = 0,
            RootDir = 1,
            Removable = 2,
            Fixed = 3,
            Remote = 4,
            CdRom = 5,
            RamDisk = 6
        }

        public class Mount
        {
            public string Name { get; set; }
            public MountType Type { get; set; }
            public Int64 SpaceUser { get; set; }
            public Int64 SpaceTotal { get; set; }
            public Int64 SpaceFree { get; set; }
            public string UncPath { get; set; }
        }

        public static List<Mount> ShowMount()
        {
            Tlv tlv = new Tlv();

            var result = Core.InvokeMeterpreterBinding(true, tlv.ToRequest(CommandId.StdapiFsMountShow));

            if (result != null)
            {
                System.Diagnostics.Debug.Write("[PSH BINDING] ShowMount result returned");
                var responseTlv = Tlv.FromResponse(result);
                if (responseTlv[TlvType.Result].Count > 0 &&
                    (int)responseTlv[TlvType.Result][0] == 0)
                {
                    System.Diagnostics.Debug.Write("[PSH BINDING] ShowMount succeeded");
                    var mounts = new List<Mount>();

                    foreach (var mountObj in responseTlv[TlvType.Mount])
                    {
                        var mountDict = (Dictionary<TlvType, List<object>>)mountObj;
                        var mount = new Mount
                        {
                            Name = Tlv.GetValue<string>(mountDict, TlvType.MountName, string.Empty),
                            Type = Tlv.GetValue<MountType>(mountDict, TlvType.MountType, MountType.Unknown),
                            SpaceUser = Tlv.GetValue<Int64>(mountDict, TlvType.MountSpaceUser),
                            SpaceTotal = Tlv.GetValue<Int64>(mountDict, TlvType.MountSpaceTotal),
                            SpaceFree = Tlv.GetValue<Int64>(mountDict, TlvType.MountSpaceFree),
                            UncPath = Tlv.GetValue<string>(mountDict, TlvType.MountUncPath, string.Empty)
                        };
                        mounts.Add(mount);
                    }

                    return mounts;
                }
                System.Diagnostics.Debug.Write("[PSH BINDING] ShowMount failed");
            }
            else
            {
                System.Diagnostics.Debug.Write("[PSH BINDING] ShowMount result was null");
            }

            return null;
        }
    }
}
