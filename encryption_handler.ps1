
# Class contains methods that allow the SessionHandler object to connect to remote systems
class SessionHandler
{

    [string]$target
    [string]$target_path
    [Helper]$global:helper = [Helper]::new()

    # Constructor checks for required programs before instantiating the object
    SessionHandler([string]$target)
    {
        if( ! (Test-Path -Path "$PSScriptRoot\PsExec.exe"))
        {
            [console]::WriteLine([string]::Format("{0} PSExec is not installed. Please ensure the 'PsExec.exe' executable is in the same directory as the script and named accordingly.", $this.helper.ERR))
            ex
        }

        if( ! (Test-Path -Path "$PSScriptRoot\dcc.zip"))
        {
            [console]::WriteLine([string]::Format("{0} Missing installation files. Please ensure the 'dcc.zip' file is in the same directory as the script and named accordingly.", $this.helper.ERR))
            ex
        }
        
        $this.target = $target
        $this.target_path = $this.BuildTargetPath()

    }

    hidden [string] BuildTargetPath()
    {
        $t1 = "\\$($this.target)\"
        $t2 = '\C$\Temp'
        $path = Join-Path $t1 $t2

        return $path
    }

    [void]TransferFiles()
    {
        [console]::WriteLine([string]::Format("{0} Transferring 'ddc.zip' to {1}...", $this.helper.WARN, $this.target))

        xcopy dcc.zip $this.target_path /i /y
        .\PsExec.exe "\\$($this.target)" powershell Expand-Archive -Path "$($this.target_path)\dcc.zip" -DestinationPath "$($this.target_path)\dcc\" 2>$null
        .\PsExec.exe "\\$($this.target)" cmd /c del /F /Q "$($this.target_path)\dcc.zip" 2>$null
       
        [console]::WriteLine([string]::Format("{0} File transfer, extraction and cleanup complete", $this.helper.OK, $this.target))
    }

    [void]ActivateTPM()
    {
        [console]::WriteLine([string]::Format("{0} Activating TPM on {1}", $this.helper.WARN, $this.target))
        
    }

}

# Utility class to help with formatting
class Helper
{
    [string]$WARN = '[*]'
    [string]$OK = '[+]'
    [string]$ERR = '[-]'
}

# Wrap exit command inside function
function ex{exit}

[SessionHandler]$session = [SessionHandler]::new('10.1.220.4')
$session.TransferFiles()