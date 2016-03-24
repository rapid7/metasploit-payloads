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
            public string Name { get; private set; }
            public MountType Type { get; private set; }
            public Int64 SpaceUser { get; private set; }
            public Int64 SpaceTotal { get; private set; }
            public Int64 SpaceFree { get; private set; }
            public string UncPath { get; private set; }

            public Mount(string name, MountType type, Int64 spaceUser, Int64 spaceTotal, Int64 spaceFree, string uncPath)
            {
                Name = name;
                Type = type;
                SpaceUser = spaceUser;
                SpaceTotal = spaceTotal;
                SpaceFree = spaceFree;
                UncPath = uncPath;
            }
        }

        public static List<Mount> ShowMount()
        {
            Tlv tlv = new Tlv();

            var result = Core.InvokeMeterpreterBinding(true, tlv.ToRequest("stdapi_fs_mount_show"));

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
                        System.Diagnostics.Debug.Write("[PSH BINDING] ShowMount succeeded");
                        var mountDict = (Dictionary<TlvType, List<object>>)mountObj;
                        var name = Tlv.GetValue<string>(mountDict, TlvType.MountName, string.Empty);
                        var type = Tlv.GetValue<MountType>(mountDict, TlvType.MountType, MountType.Unknown);
                        var spaceUser = Tlv.GetValue<Int64>(mountDict, TlvType.MountSpaceUser);
                        var spaceTotal = Tlv.GetValue<Int64>(mountDict, TlvType.MountSpaceTotal);
                        var spaceFree = Tlv.GetValue<Int64>(mountDict, TlvType.MountSpaceFree);
                        var uncPath = Tlv.GetValue<string>(mountDict, TlvType.MountUncPath, string.Empty);
                        mounts.Add(new Mount(name, type, spaceUser, spaceTotal, spaceFree, uncPath));
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
