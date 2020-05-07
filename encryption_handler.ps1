# Bitlocker Remote Handler

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
    
    # Set foreground colour to val
    static [void] SetColour([string]$colour)
    {
        $global:curr = $global:host.UI.RawUI.ForegroundColor
        $global:host.UI.RawUI.ForegroundColor = $colour
    }

    # Reset foreground colour
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

    # Constructor attempts to gather information about the target on creation, this means that each SessionHandler object will already know everything it needs before starting operations.
    SessionHandler([string]$target)
    {
        $this.target = $target

        [console]::WriteLine([string]::Format("{0} Gathering information for {1}...", $(Timestamp), $this.target))

        # Regular expression to check to see if target format matches IP address
        if($this.target -match "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
        {
            [console]::WriteLine([string]::Format("{0} IP Address detected, resolving hostname for {1}...", $(Timestamp), $this.target))

            # Gather hostname by invoking 'hostname' command
            $this.hostname = .\PsExec.exe -accepteula -nobanner "\\$($this.target)" hostname 2>$null
            $this.ipv4 = $target
        }
        else
        {  
            # Query DNS for Ipv4 address if hostname is detected         
            [console]::WriteLine([string]::Format("{0} Hostname detected, querying DNS for IP address...", $(Timestamp), $this.target))
            $this.ipv4 = [System.Net.Dns]::GetHostAddresses($this.target)
            $this.hostname = $target
        }

        # call tpm query methods to gather tpm information
        $this.tpm_on = $this.GetTPMPresence()
        $this.tpm_status = $this.GetTPMActivation()

        # invoke WIMIC to gather model 
        $model_arr = $(.\PsExec.exe -accepteula -nobanner "\\$($this.target)" cmd /c wmic computersystem get model 2>$null).trim()
        $this.model = $model_arr[2]

        # Builds UNC path to C$ share
        $this.target_path = $this.BuildTargetPath()
    }

    # Builds path to target's C$ share in order to perform file operations
    hidden [string] BuildTargetPath()
    {
        $t1 = "\\$($this.target)\"
        $t2 = '\C$\Temp'
        $path = Join-Path $t1 $t2

        return $path
    }

    # Handles transfer and extraction of installer files and performs cleanup
    [void] TransferFiles()
    {
        [console]::WriteLine([string]::Format("{0} Transferring 'ddc.zip' to {1}...",$(Timestamp),$this.target))

        # xcopy zip file over
        xcopy dcc.zip $this.target_path /i /y
        # then invoke powershell's expand-archive cmdlet to extract
        .\PsExec.exe "\\$($this.target)" powershell Expand-Archive -Path "$($this.target_path)\dcc.zip" -DestinationPath "$($this.target_path)\dcc\" 2>$null
        if($LASTEXITCODE -ne 0){[Helper]::SetColour('DarkRed'); [console]::WriteLine([string]::Format("{0} Error extracting files. Code: {1}",$(Timestamp), $LASTEXITCODE)); [Helper]::Reset(); exit}


       
        [Helper]::SetColour("DarkGreen")
        [console]::WriteLine([string]::Format("{0} File transfer, extraction and cleanup complete", $(Timestamp)))
        [Helper]::Reset()

        [console]::WriteLine([string]::Format("{0} Running installer at '{1}\dcc\Command_Configure.msi'",$(Timestamp),$this.target_path))

        # Execute .msi installer 
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
    }

    # GetTPMPresence() and GetTPMActivaton() both invoke the get-tpm cmdlet on the target system and format the output to include the presence and status information only
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

    # Waits for the session's target to reboot
    [void] WaitForRestart()
    {
        $c1 = 1
        $c2 = 1

        # first loop waits for system to restart in order to avoid false positives
        do {Start-Sleep(5)} until( ! (Test-Connection -TargetName $this.target -Count 1 -Quiet) -or $c2 -gt 20)
        
        # second loop querys target and breaks once connection is successful 
        # both loops default to 5 second intervals between pings
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

    # performs BIOS operations using Dell's CCTK.exe 
    [void] EnableTPM($bpass)
    {

        [console]::WriteLine([string]::Format("{0} Setting administrator password...",$(Timestamp)))

        # invoke cctk.exe to attempt to set BIOS password
        .\PsExec.exe "\\$($this.target)" "C:\Program Files (x86)\Dell\Command Configure\X86_64\cctk.exe" "--setuppwd=$bpass" 2>$null
        if($LASTEXITCODE -eq 0)
        {
            [Helper]::SetColour('DarkGreen');
            [console]::WriteLine([string]::Format("{0} Set BIOS administrator password",$(Timestamp)))
            [Helper]::Reset()
        }
        # exit codes available in the Dell website point to these returned when the --valsetuppwd switch is required to change the existing password 
        # to a new one, this means it is safe to assume that if any of these are returned the BIOS password is already set and we can skip it.
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

        # Invoke cctk.exe with the --tpm=on and the user supplied BIOS password
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
            [console]::WriteLine([string]::Format("{0} Error running installer, error code: {1}",$(Timestamp), $LastExitCode))
            [Helper]::Reset();
            exit
        }

        [console]::WriteLine([string]::Format("{0} Attempting to provision TPM chip...",$(Timestamp)))

        # Invoke cctk.exe with the --tpmactivation=activate switch to activate chip
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
            [console]::WriteLine([string]::Format("{0} Error activating TPM, error code: {1}",$(Timestamp), $LastExitCode))
            [Helper]::Reset()
            exit
        }

        # Clean up after myself
        [console]::WriteLine([string]::Format("{0} Cleaning up...",$(Timestamp)))
        .\PsExec.exe "\\$($this.target)" cmd /c del /F /Q "$($this.target_path)\dcc.zip" 2>$null
        if($LASTEXITCODE -ne 0){[Helper]::SetColour('DarkYellow'); [console]::WriteLine([string]::Format("{0} Unable to clean up 'dcc.zip'. Code: {1}",$(Timestamp), $LASTEXITCODE)); [Helper]::Reset(); exit}
        .\PsExec.exe "\\$($this.target)" cmd /c del /F /Q /s "$($this.target_path)\dcc\" 2>$null
        if($LASTEXITCODE -ne 0){[Helper]::SetColour('DarkYellow'); [console]::WriteLine([string]::Format("{0} Unable to clean up '\dcc\'. Code: {1}",$(Timestamp), $LASTEXITCODE)); [Helper]::Reset(); exit}
        .\PsExec.exe "\\$($this.target)" cmd /c del /F /Q /s "C:\Program Files (x86)\Dell\Command Configure\" 2>$null
        if($LASTEXITCODE -ne 0){[Helper]::SetColour('DarkYellow'); [console]::WriteLine([string]::Format("{0} Unable to clean up 'Command and Configure'. Code: {1}",$(Timestamp), $LASTEXITCODE)); [Helper]::Reset(); exit}

        # Attempt to reboot system and wait for it to restart
        [console]::WriteLine([string]::Format("{0} Rebooting system... ",$(Timestamp)))
        .\PsExec.exe "\\$($this.target)" cmd /c shutdown /r /t 0 2>$null
        $this.WaitForRestart()
        [console]::WriteLine([string]::Format("{0} {1} reboot successful",$(Timestamp),$this.target))
    }

}

# Generate timestamp for use in string formatting
function Timestamp()
{
    $ts = Get-Date -Format "[MM/dd HH:mm]"
    return $ts
}

# Takes a SessionHandler object and formats its members to console output
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

# Main function handles program flow
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

    # these logic statements ensure correct param combinations are supplied on the command line switches
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
    [Helper]::SetColour("DarkRed")

    # Check for PSExec and the dcc.zip file containing Dell Command and Configure
    if( ! (Test-Path -Path "$PSScriptRoot\PsExec.exe"))
    {
        [console]::WriteLine([string]::Format("{0} PSExec is not found. Please ensure the 'PsExec.exe' executable is in the same directory as the script and named accordingly",$(Timestamp)))
        [Helper]::Reset()
        exit
    }
    if( ! (Test-Path -Path "$PSScriptRoot\dcc.zip"))
    {
        [console]::WriteLine([string]::Format("{0} Missing installation files. Please ensure the 'dcc.zip' file is in the same directory as the script and named accordingly",$(Timestamp)))
        [Helper]::Reset()
        exit
    }

    [Helper]::Reset()

    # create SessionHandler object
    [SessionHandler]$session = [SessionHandler]::new($target)

    if($encrypt)
    {
        [console]::WriteLine([string]::Format("{0} TPM visibility is '{1}' on target {2}",$(Timestamp),$session.tpm_on,$session.target))

        # If TPM is not on proceed with script
        if( ! ($session.tpm_on))
        {
            [console]::WriteLine([string]::Format("{0} Attempting TPM activation",$(Timestamp)))

            # Run session methods to initiate TPM activation process
            $session.TransferFiles()
            $session.EnableTPM($biospass)
            [Helper]::SetColour("DarkGreen")
            [console]::WriteLine([string]::Format("{0} Process has finished successfully on {1}",$(Timestamp),$session.target))
            [Helper]::Reset()   
        }
        # if tpm is visible check if its active too
        elseif($session.tpm_on)
        {
            if( ! ($session.tpm_active))
            {
                [Helper]::SetColour("DarkYellow")
                [console]::WriteLine([string]::Format("{0} TPM status is on but not provisioned",$(Timestamp)))
                [Helper]::Reset()   
            }
            elseif($session.tpm_active)
            {    
                [Helper]::SetColour("DarkGreen")        
                [console]::WriteLine([string]::Format("{0} TPM status is on and compliant, skipping...",$(Timestamp)))
                [Helper]::Reset()   
            }
        }
    }

    # Report switch only generated report with object
    elseif($report)
    {
        FormatReport($session)
    }

    [Helper]::Reset()
}

Main
