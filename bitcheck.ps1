# Secondary script that enumerates information regarding bitlocker/tpm status and mbam policy application

param([String] $target,
[String] $targetlist,
[Switch] $enum,
[Switch] $fix)

class SessionHandler
{
    [String] $target
    [String] $psexec
    [Hashtable] $results

    SessionHandler([String] $target)
    {
        [String] $this.target = $target
        [String] $this.psexec = ($PSScriptRoot + "PSExec.exe")

        if( ! (Test-Path -Path $this.psexec))
        {
            [Console]::WriteLine("Unable to find PsExec binary in $PSScriptRoot")
            exit
        }
    }

    [Bool] Bind()
    {
        if(Test-Connection $this.target)
        {
            [Console]::WriteLine("$($this.target) is binded successfully")
            return $true
        }
        else
        {
            [Console]::WriteLine("Unable to bind $($this.target)")
            return $false
        }
    }

    [String] GetHostname()
    {
        $this.hostname = & "$($this.psexec)" -accepteula -nobanner "\\$($this.target)" hostname 2>$null
        return $this.hostname
    }
    
    [String] GetTPMStatus()
    {
        $tpm_presence = $(& "$($this.psexec)" "\\$($this.target)" powershell get-tpm | findstr "TpmPresent" 2>$null).split(":")
        $tpm_activation = $(& "$($this.psexec)" "\\$($this.target)" powershell get-tpm | findstr "TpmReady" 2>$null).split(":")

        if($tpm_presence[1].trim() -eq 'true' -and $tpm_activation[1].trim() -eq 'true')
        {
            return 'Ready'
        }
        else
        {
            return 'Not ready'
        }
    }

    [String] GetRegistryKeys()
    {

    }

    [String] Get
    [Void] Enum()
    {

    }
}

$session = [SessionHandler]::new($target)
$session.Bind()