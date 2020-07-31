using System;

namespace MSF.Powershell.Meterpreter
{
    public enum PacketType
    {
        Request = 0,
        Response = 1,
        PlainRequest = 10,
        PlainResponse = 11
    };

    [Flags]
    public enum MetaType
    {
        None = 0,
        String = 1 << 16,
        Uint = 1 << 17,
        Raw = 1 << 18,
        Bool = 1 << 19,
        Qword = 1 << 20,
        Compressed = 1 << 21,

        Group = 1 << 30,
        Complex = 1 << 31,

        All = String | Uint | Raw | Bool | Qword | Compressed | Group | Complex
    };

    public enum ExtensionBase
    {
        Stdapi = 0,
        Incognito = 20000,
        Priv = 20000,
        Kiwi = 20000
    };

    public enum TlvType
    {
        // Actual types
        Any = MetaType.None,
        CommandId = MetaType.Uint | 1,
        RequestId = MetaType.String | 2,
        Exception = MetaType.Group | 3,
        Result = MetaType.Uint | 4,

        String = MetaType.String | 10,
        Uint = MetaType.Uint | 11,
        Bool = MetaType.Bool | 12,

        Length = MetaType.Uint | 25,
        Data = MetaType.Raw | 26,
        Flags = MetaType.Uint | 27,

        ChannelId = MetaType.Uint | 50,
        ChannelType = MetaType.String | 51,
        ChannelData = MetaType.Raw | 52,
        ChannelDataGroup = MetaType.Group | 53,
        ChannelClass = MetaType.Uint | 54,
        ChannelParentId = MetaType.Uint | 55,

        SeekWhence = MetaType.Uint | 70,
        SeekOffset = MetaType.Uint | 71,
        SeekPos = MetaType.Uint | 72,

        ExceptionCode = MetaType.Uint | 300,
        ExceptionString = MetaType.String | 301,

        LibraryPath = MetaType.String | 400,
        TargetPath = MetaType.String | 401,
        MigratePid = MetaType.Uint | 402,
        MigrateLen = MetaType.Uint | 403,

        TransType = MetaType.Uint | 430,
        TransUrl = MetaType.String | 431,
        TransUa = MetaType.String | 432,
        TransCommTimeout = MetaType.Uint | 433,
        TransSessExp = MetaType.Uint | 434,
        TransCertHash = MetaType.Raw | 435,
        TransProxyHost = MetaType.String | 436,
        TransProxyUser = MetaType.String | 437,
        TransProxyPass = MetaType.String | 438,
        TransRetryTotal = MetaType.Uint | 439,
        TransRetryWait = MetaType.Uint | 440,
        TransHeaders = MetaType.String | 441,
        TransGroup = MetaType.Group | 442,

        MachineId = MetaType.String | 460,
        Uuid = MetaType.Raw | 461,

        CipherName = MetaType.String | 500,
        CipherParameters = MetaType.Group | 501,

        PeerHost = MetaType.String | 1500,
        PeerPort = MetaType.Uint | 1501,
        LocalHost = MetaType.String | 1502,
        LocalPort = MetaType.Uint | 1503,

        // STDAPI stuff
        ComputerName = MetaType.String | (ExtensionBase.Stdapi + 1040),
        OsName = MetaType.String | (ExtensionBase.Stdapi + 1041),
        UserName = MetaType.String | (ExtensionBase.Stdapi + 1042),
        Architecture = MetaType.String | (ExtensionBase.Stdapi + 1043),
        LangSystem = MetaType.String | (ExtensionBase.Stdapi + 1044),
        Sid = MetaType.String | (ExtensionBase.Stdapi + 1045),
        Domain = MetaType.String | (ExtensionBase.Stdapi + 1046),
        LoggedOnUserCount = MetaType.Uint | (ExtensionBase.Stdapi + 1047),

        Mount = MetaType.Group | (ExtensionBase.Stdapi + 1207),
        MountName = MetaType.String | (ExtensionBase.Stdapi + 1208),
        MountType = MetaType.Uint | (ExtensionBase.Stdapi + 1209),
        MountSpaceUser = MetaType.Qword | (ExtensionBase.Stdapi + 1210),
        MountSpaceTotal = MetaType.Qword | (ExtensionBase.Stdapi + 1211),
        MountSpaceFree = MetaType.Qword | (ExtensionBase.Stdapi + 1212),
        MountUncPath = MetaType.String | (ExtensionBase.Stdapi + 1213),

        Pid = MetaType.Uint | (ExtensionBase.Stdapi + 2300),
        ProcessName = MetaType.String | (ExtensionBase.Stdapi + 2301),
        ProcessPath = MetaType.String | (ExtensionBase.Stdapi + 2302),
        ProcessGroup = MetaType.Group | (ExtensionBase.Stdapi + 2303),
        ProcessArch = MetaType.Uint | (ExtensionBase.Stdapi + 2306),
        ParentPid = MetaType.Uint | (ExtensionBase.Stdapi + 2307),
        ProcessSession = MetaType.Uint | (ExtensionBase.Stdapi + 2308),

        // PRIV stuff
        ElevateTechnique = MetaType.Uint | (ExtensionBase.Priv + 200),
        ElevateServiceName = MetaType.String | (ExtensionBase.Priv + 201),

        // KIWI stuff
        KiwiCmd = MetaType.String | (ExtensionBase.Kiwi + 100),
        KiwiCmdResult = MetaType.String | (ExtensionBase.Kiwi + 101),

        // INCOGNITO stuff
        IncognitoListTokensDelegation = MetaType.String | (ExtensionBase.Incognito + 2),
        IncognitoListTokensImpersonation = MetaType.String | (ExtensionBase.Incognito + 3),
        IncognitoListTokensTokenOrder = MetaType.Uint | (ExtensionBase.Incognito + 4),
        IncognitoImpersonateToken = MetaType.String | (ExtensionBase.Incognito + 5),
        IncognitoGenericResponse = MetaType.String | (ExtensionBase.Incognito + 6),
        IncognitoUserName = MetaType.String | (ExtensionBase.Incognito + 7),
        IncognitoPassword = MetaType.String | (ExtensionBase.Incognito + 8),
        IncognitoServerName = MetaType.String | (ExtensionBase.Incognito + 9),
        IncognitoGroupName = MetaType.String | (ExtensionBase.Incognito + 10)
    };
}
