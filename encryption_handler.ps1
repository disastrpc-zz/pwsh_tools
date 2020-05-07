
# Takes params from the script invocation
param([string]$target,
[string]$targetlist,
[switch]$report,
[switch]$encrypt,
[string]$biospass)

$VER = '1.0'
$helper = [Helper]::new()

# Utility class to help with formatting
class Helper
{
    [string]$global:WARN = '[*]'
    [string]$global:OK = '[+]'
    [string]$global:ERR = '[-]'
    
    # Static method to set the UI foreground color to specified value
    static [void] SetColour([string]$colour)
    {
        $global:curr = $global:host.UI.RawUI.ForegroundColor
        $global:host.UI.RawUI.ForegroundColor = $colour
    }

    # Reset foreground to default val
    static [void] Reset()
    {
        $global:host.UI.RawUI.ForegroundColor = $global:curr
    }
}


# Class contains methods that allow the SessionHandler object to connect to remote systems
class SessionHandler
{
    [string]$target
    [string]$target_path
    [string]$ipv4
    [string]$hostname
    [string]$model
    [bool]$encryption_status
    [bool]$tpm_on
    [bool]$tpm_status

    [Helper]$global:helper = [Helper]::new()

    # Constructor attempts to gather information from system such as hostname, model and TPM status
    SessionHandler([string]$target)
    {
        $this.target = $target

        [console]::WriteLine([string]::Format("{0} Gathering information for {1}...", $(Timestamp), $this.target))
        # Regular expression to check to see if target format matches IP address
        if($this.target -match "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
        {
            # if match then execute 'hostname' on target system
            [console]::WriteLine([string]::Format("{0} IP Address detected, resolving hostname for {1}...", $(Timestamp), $this.target))
            $this.hostname = .\PsExec.exe -accepteula -nobanner "\\$($this.target)" hostname 2>$null
            $this.ipv4 = $target
        }
        else
        {   
            # if hostname provided attempt to query DNS server for IP address
            [console]::WriteLine([string]::Format("{0} Hostname detected, querying DNS for IP address...", $(Timestamp), $this.target))
            $this.ipv4 = [System.Net.Dns]::GetHostAddresses($this.target)
            $this.hostname = $target
        }

        # call GetTPMPresence and GetTPMActivation and assign to object property
        $this.tpm_on = $this.GetTPMPresence()
        $this.tpm_status = $this.GetTPMActivation()

        # Call WMIC on target PC in order to retrieve model number for computer
        $model_arr = $(.\PsExec.exe -accepteula -nobanner "\\$($this.target)" cmd /c wmic computersystem get model 2>$null).trim()
        $this.model = $model_arr[2]

        $this.target_path = $this.BuildTargetPath()
    }

    # Synchronous IP range scanner to avoid causing too much traffic
    [void] ScanIPRange([string]$start, [string]$stop)
    {

    }
    
    # Builds UNC path to C$ network share 
    hidden [string] BuildTargetPath()
    {
        $t1 = "\\$($this.target)\"
        $t2 = '\C$\Temp'
        $path = Join-Path $t1 $t2

        return $path
    }
    
    # Handles transferring of packaged installation files to target
    [void] TransferFiles()
    {
        [console]::WriteLine([string]::Format("{0} Transferring 'ddc.zip' to {1}...",$(Timestamp),$this.target))

        # xcopy the files using UNC path
        xcopy dcc.zip $this.target_path /i /y
        
        # then invoke powershell Expand-Archive to invoke
        .\PsExec.exe "\\$($this.target)" powershell Expand-Archive -Path "$($this.target_path)\dcc.zip" -DestinationPath "$($this.target_path)\dcc\" 2>$null
        if($LASTEXITCODE -ne 0){[Helper]::SetColour('DarkRed'); [console]::WriteLine([string]::Format("{0} Error extracting files. Code: {1}",$(Timestamp), $LASTEXITCODE)); [Helper]::Reset(); exit}

        # Cleanup install files from system
        .\PsExec.exe "\\$($this.target)" cmd /c del /F /Q "$($this.target_path)\dcc.zip" 2>$null
        if($LASTEXITCODE -ne 0){[Helper]::SetColour('DarkRed'); [console]::WriteLine([string]::Format("{0} Error cleaning up files. Code: {1}",$(Timestamp), $LASTEXITCODE)); [Helper]::Reset(); exit}
       
        [Helper]::SetColour("DarkGreen")
        [console]::WriteLine([string]::Format("{0} File transfer, extraction and cleanup complete", $(Timestamp)))
        [Helper]::Reset()
    }

    # Query target to check if TPM is visible to the operating system
    [bool] GetTPMPresence()
    {
        $query = $(.\PsExec.exe "\\$($this.target)" powershell get-tpm | findstr "TpmPresent" 2>$null).split(":")
        if($LASTEXITCODE -ne 0){[Helper]::SetColour('DarkRed'); [console]::WriteLine([string]::Format("{0} Error getting status. Code: {1}",$(Timestamp), $LASTEXITCODE)); [Helper]::Reset(); exit}
        if($query[1].trim() -eq 'true')
        {
            return $true
        }
        else
        {
            return $false
        }
    }
    
    # Query target to check if TPM is provisioned and compliant
    [bool] GetTPMActivation()
    {
        $query = $(.\PsExec.exe "\\$($this.target)" powershell get-tpm | findstr "TpmReady" 2>$null).split(":")
        if($LASTEXITCODE -ne 0){[Helper]::SetColour('DarkRed'); [console]::WriteLine([string]::Format("{0} Error getting status. Code: {1}",$(Timestamp), $LASTEXITCODE)); [Helper]::Reset(); exit}

        if($query[1].trim() -eq 'true')
        {
            return $true
        }
        else
        {
            return $false
        }
    }

    # Waits for session's computer to restart
    [void] WaitForRestart()
    {
        $c1 = 1
        $c2 = 1
        
        # first loop checks for the PC to shutdown before attempting to query again to avoid false positives
        do {Start-Sleep(5)} until( ! (Test-Connection -TargetName $this.target -Count 1 -Quiet) -or $c2 -gt 20)
        
        # second loop waits for ping responses to come back up
        while($c1 -le 20)
        {
            if(Test-Connection -Targetname $this.target -Count 1 -Quiet)
            {
                break
            }

            Start-Sleep(5)
            $c1++
        }
    }

    # Installs Dell Command and Configure and enables TPM chip on target machine
    [void] EnableTPM($bpass)
    {
        [console]::WriteLine([string]::Format("{0} Running installer at '{1}\dcc\Command_Configure.msi'",$(Timestamp),$this.target_path))
        
        # Installs .msi file at $target_path in quiet mode
        .\PsExec.exe "\\$($this.target)" cmd /c msiexec /i "$($this.target_path)\dcc\Command_Configure.msi" /passive /qn 2>$null
        if($LASTEXITCODE -eq 0)
        {
            [Helper]::SetColour('DarkGreen');
            [console]::WriteLine([string]::Format("{0} Files successfully installed",$(Timestamp)))
            [Helper]::Reset()
        }
        else
        {
            [Helper]::SetColour("DarkRed")
            [console]::WriteLine([string]::Format("{0} Error running installer, error code: {1}",$(Timestamp), $LastExitCode))
            [Helper]::Reset()
            exit
        }

        # invoke cctk.exe in system with --setuppwd switch to set BIOS password
        [console]::WriteLine([string]::Format("{0} Setting administrator password...",$(Timestamp)))
        .\PsExec.exe "\\$($this.target)" "C:\Program Files (x86)\Dell\Command Configure\X86_64\cctk.exe" "--setuppwd=$bpass" 2>$null
        if($LASTEXITCODE -eq 0)
        {
            [Helper]::SetColour('DarkGreen');
            [console]::WriteLine([string]::Format("{0} Set BIOS administrator password",$(Timestamp)))
            [Helper]::Reset()
        }
        # if exit code is 114 115 or 116 we can assume password has already been set on operating system
        elseif($LASTEXITCODE -in 114,115,116)
        {
            [Helper]::SetColour('DarkYellow');
            [console]::WriteLine([string]::Format("{0} BIOS password already set, skipping...",$(Timestamp)))
            [Helper]::Reset()
        }
        else
        {
            [Helper]::SetColour("DarkRed")
            [console]::WriteLine([string]::Format("{0} Error running installer, error code: {1}",$(Timestamp), $LastExitCode))
            [Helper]::Reset()
            exit
        }

        [console]::WriteLine([string]::Format("{0} Attempting to enable TPM chip...",$(Timestamp)))
        # attempt to turn on TPM chip so its visible to OS
        .\PsExec.exe "\\$($this.target)" cmd /c "C:\Program Files (x86)\Dell\Command Configure\X86_64\cctk.exe" "--tpm=on" "--valsetuppwd=$bpass" 2>$null
        if($LASTEXITCODE -eq 0)
        {
            [Helper]::SetColour('DarkGreen');
            [console]::WriteLine([string]::Format("{0} TPM is on",$(Timestamp)))
            [Helper]::Reset()
        }
        else
        {
            [Helper]::SetColour("DarkRed"); 
            [console]::WriteLine([string]::Format("{0} Error enabling TPM chip. Code: {1}",$(Timestamp), $LastExitCode))
            [Helper]::Reset();
            exit
        }

        [console]::WriteLine([string]::Format("{0} Attempting to provision TPM chip...",$(Timestamp)))
        .\PsExec.exe "\\$($this.target)" "C:\Program Files (x86)\Dell\Command Configure\X86_64\cctk.exe" "--tpmactivation=activate" "--valsetuppwd=$bpass" 2>$null
        if($LASTEXITCODE -eq 0)
        {
            [Helper]::SetColour('DarkGreen');
            [console]::WriteLine([string]::Format("{0} TPM chip is compliant and ready",$(Timestamp)))
            [Helper]::Reset()
        }
        else
        {
            [Helper]::SetColour("DarkRed"); 
            [console]::WriteLine([string]::Format("{0} Error provisioning TPM, error code: {1}",$(Timestamp), $LastExitCode))
            [Helper]::Reset()
            exit
        }

        [console]::WriteLine([string]::Format("{0} Rebooting system... ",$(Timestamp)))
        
        # Reboot system then wait for restart
        .\PsExec.exe "\\$($this.target)" cmd /c shutdown /r /t 0 2>$null
        $this.WaitForRestart()
        [console]::WriteLine([string]::Format("{0} {1} reboot successful",$(Timestamp),$this.target))
        
        # Attempt cleanup of CCTK
        [console]::WriteLine([string]::Format("{0} Cleaning up...",$(Timestamp)))
        .\PsExec.exe "\\$($this.target)" cmd /c del /s /Q "C:\Program Files (x86)\Dell\" 2>$null
     
        if($LASTEXITCODE -eq 0)
        {
            [console]::WriteLine([string]::Format("{0} Cleanup successful",$(Timestamp)))
        }
        else
        {
            [console]::WriteLine([string]::Format("{0} Cleanup failed with error code: {1}",$(Timestamp), $LASTEXITCODE))
        }
        
    }

}

# Simple function to return timestamp for logging
function Timestamp()
{
    $ts = Get-Date -Format "[MM/dd HH:mm]"
    return $ts
}

# takes $session object and formats its properties to display as report
function FormatReport([SessionHandler]$session)
{
    [console]::WriteLine("{0} System Information:",$(Timestamp))

    if($session.tpm_on){[string] $tpm_on = 'True'} else {$tpm_on = 'False'}
    if($session.tpm_status){[string] $tpm_active = 'True'} else {$tpm_active = 'False'}

    [console]::WriteLine([string]::Format("{0} Hostname:`t`t`t{1}`n{0} IPv4:`t`t`t{2}`n{0} Model:`t`t`t{3}`n{0} TPM On:`t`t`t{4}`n{0} TPM Active:`t`t{5}",
                                        $(Timestamp),
                                        $session.hostname,
                                        $session.ipv4,
                                        $session.model,
                                        $tpm_on,
                                        $tpm_active))
}

function Main()
{

    if($encrypt){$mode = 'encryption'}
    elseif($report){$mode = 'reporting'}

    [Helper]::SetColour("DarkYellow")
    [console]::WriteLine([string]::Format("-= Bitlocker Remote Automation Handler - Version {0} =-",$VER))
    [Helper]::Reset()
    [console]::WriteLine("Tool used to remotely query and configure TPM and Non-TPM enabled systems`nBy Jared Freed")
    [console]::WriteLine([string]::Format("{0} Starting tool in {1} mode",$(Timestamp), $mode))
    [Helper]::SetColour("DarkRed")
    # Check for correct min PS version
    if($PSVersionTable.PSVersion.Major -lt 6)
    {
        [console]::WriteLine([string]::Format("{0} Minimum required PowerShell version is '6', your version is '{1}'",$(Timestamp),$PSVersionTable.PSVersion.Major))
        [Helper]::Reset()
        exit
    }

    if( ! ($target) -and ! ($target_list))
    {
        [console]::WriteLine([string]::Format("{0} Please provide a target or a target list using the '-target' or '-targetlist' switches respectively",$(Timestamp)))
        [Helper]::Reset()
        exit
    }
    elseif($target -and $target_list)
    {
        [console]::WriteLine([string]::Format("{0} Target must be a single host or a path to a host file, not both",$(Timestamp)))
        [Helper]::Reset()
        exit
    }

    if( ! ($report) -and ! ($encrypt))
    {
        [console]::WriteLine([string]::Format("{0} Please specify an action using the '-encrypt' or '-report' switches",$(Timestamp)))
        [Helper]::Reset()
        exit
    }
    elseif($report -and $encrypt)
    {
        [console]::WriteLine([string]::Format("{0} Only one action is allowed per invocation",$(Timestamp)))
        [Helper]::Reset()
        exit
    }
    elseif($encrypt -and ! ($biospass))
    {
        [console]::WriteLine([string]::Format("{0} BIOS password must be supplied, re-run script using the '-biospass' switch",$(Timestamp)))
        [Helper]::Reset()
        exit
    }

    [Helper]::Reset()


    # Check for PSExec and the dcc.zip file containing Dell Command and Configure
    if( ! (Test-Path -Path "$PSScriptRoot\PsExec.exe"))
    {
        [console]::WriteLine([string]::Format("{0} PSExec is not found. Please ensure the 'PsExec.exe' executable is in the same directory as the script and named accordingly",$(Timestamp)))
        exit
    }

    if( ! (Test-Path -Path "$PSScriptRoot\dcc.zip"))
    {
        [console]::WriteLine([string]::Format("{0} Missing installation files. Please ensure the 'dcc.zip' file is in the same directory as the script and named accordingly",$(Timestamp)))
        exit
    }

    [SessionHandler]$session = [SessionHandler]::new($target)

    if($encrypt)
    {
        FormatReport($session)
        $session.TransferFiles()
        $session.EnableTPM($biospass)
        [Helper]::SetColour("DarkGreen")
        [console]::WriteLine([string]::Format("{0} Process has finished successfully on {1}",$(Timestamp),$session.target))
        [Helper]::Reset()
    }
    elseif($report)
    {
        FormatReport($session)
    }

    [Helper]::Reset()
}

Main
