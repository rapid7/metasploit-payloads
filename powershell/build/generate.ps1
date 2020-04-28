function Generate-MetasploitPowershell {
    <#
    .SYNOPSIS
        Generates the source and include files that are built in to the Metasploit
        Powershell extension. These files contain the body of the MSF.Powershell.Runner
        class in .NET that allow for the extension to interact with the interpreter.

    .PARAMETER BuildDir
        Specifies the 'build' folder the powershelll project. By default, the current
        folder is used, however if this is invoked outside of the specified folder then
        the location of the folder containing this script has to be specified.

    .PARAMETER Debug
        Indicates that the debug build should be used instead of the release build (for testing).

    .INPUTS
        None.

    .OPUTPUTS
        Writes some content to screen to inform the user of success or failure.

    .EXAMPLE
        PS C:\metasploit-payloads\powershell\build\> Generate-MetasploitPowershell -Debug
        PS C:\> Generate-MetasploitPowershell -BuildDir C:\metasploit-payloads\powershell\build\
    #>

    param(
        [ValidateScript({ Test-Path -Path $_ })]
        [String]
        $BuildDir = $(Get-Location),

        [Switch]
        $Debug
    )

    $Build = 'Release'
    If ($Debug) {
        $Build = 'Debug'
    }

    $SourceAssembly = [System.IO.Path]::Combine($BuildDir, '..', 'MSF.Powershell', 'bin', $Build, 'MSF.Powershell.dll')
    Write-Host [+] Building source using binary at $SourceAssembly ...
    If (-not (Test-Path -LiteralPath $SourceAssembly)) {
        Write-Host [!] Unable to find $SourceAssembly
        Write-Host [!] Make sure that BuildDir and Build are set correctly, and that the target binary has been built.
        Exit
    }

    # We will assume that if the SourceAssembly path is correct, that we have the right folder and we
    # can just generate a path based on the current folder for the target and it'll be ok.
    $TargetPath = [System.IO.Path]::Combine($BuildDir, '..', '..', 'c', 'meterpreter', 'source', 'extensions', 'powershell')

    # Time to generate some source
    $AssemblyContent = [System.IO.File]::ReadAllBytes($SourceAssembly)

    # Start with the include file
    $SizeVar = 'PSHRUNNER_DLL_LEN'
    $HeaderContent = New-Object System.Collections.ArrayList
    [void] $HeaderContent.Add("/*!`n")
    [void] $HeaderContent.Add(" * @file powershell_runner.h`n")
    [void] $HeaderContent.Add(" * @brief This file was generated at $([DateTime]::UtcNow) UTC, do not modify directly.`n")
    [void] $HeaderContent.Add(" */`n`n")
    [void] $HeaderContent.Add("#ifndef _METERPRETER_SOURCE_EXTENSION_POWERSHELL_RUNNER_H`n")
    [void] $HeaderContent.Add("#define _METERPRETER_SOURCE_EXTENSION_POWERSHELL_RUNNER_H`n`n")
    [void] $HeaderContent.Add("#define $SizeVar $($AssemblyContent.Length)`n`n")
    [void] $HeaderContent.Add("extern unsigned char PowerShellRunnerDll[$SizeVar];`n`n")
    [void] $HeaderContent.Add("#endif`n`n")

    $RunnerHeaderPath = [System.IO.Path]::Combine($TargetPath, 'powershell_runner.h')
    [System.IO.File]::WriteAllText($RunnerHeaderPath, $HeaderContent)
    Write-Host [+] $RunnerHeaderPath written.

    # Now the body of the source
    $SourceContent = New-Object System.Collections.ArrayList
    [void] $SourceContent.Add("/*!`n")
    [void] $SourceContent.Add(" * @file powershell_runner.cpp`n")
    [void] $SourceContent.Add(" * @brief This file is generated, do not modify directly.`n")
    [void] $SourceContent.Add(" */`n`n")
    [void] $SourceContent.Add("#include `"powershell_runner.h`"`n`n")
    [void] $SourceContent.Add("#pragma message(`"Compiling PowerShellRunner into app. Size: $($AssemblyContent.Length)`")`n`n")
    [void] $SourceContent.Add("unsigned char PowerShellRunnerDll[$SizeVar] =`n")
    [void] $SourceContent.Add("{`n")

    # Do the magic to convert the bytes into an array of literal bytes.
    For ($i = 0; $i -lt $AssemblyContent.Length; $i++) {
        If (($i % 12) -eq 0) {
            [void] $SourceContent.Add("`t")
        }
        [void] $SourceContent.Add("0x$($AssemblyContent[$i].ToString('X2')),")
        If (($i % 12) -eq 11) {
            [void] $SourceContent.Add("`n")
        }
    }

    [void] $SourceContent.Add("`n};`n`n")

    $RunnerCppPath = [System.IO.Path]::Combine($TargetPath, 'powershell_runner.cpp')
    [System.IO.File]::WriteAllText($RunnerCppPath, $SourceContent)
    Write-Host [+] $RunnerCppPath written.
    Write-Host [+] Powershell Assembly content written. .NET Binary is $AssemblyContent.Length bytes.
}

