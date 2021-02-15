<#
.SYNOPSIS
    The script intended to fix Bitlocker related issues. If the script cannot handle the error... That's sad :(

.DESCRIPTION
    - First a check goes against Protection Status, if the state is On the script ends without performing any action
    - If the protection state is off the script checks if the TPM has the necessary protectors. If the protectors are missing, adds them
    - In case of an encrypted volume the script will resume the protection, in case of a decrypted volume the encryption will be started
    - If the encryption fails a catch block will check if the tpm is in ready state. In case of false result, tpm will be initialized and protection will be resumed. In case of error the error will be catched and written into the eventviewer
    - As a last step the script checks if the tpm state and writes the result to the log
    - If the script cannot handle the bitlocker activation error ir will write out manual check needed

.PARAMETER DemoParam1
    

.PARAMETER DemoParam2
    

.EXAMPLE
   

.EXAMPLE
    

.NOTES
    Author: David Molnar
    Last Edit: 5/21/2020 
    Version 1.0 - Initial release

#>

#Variables used in script
$LogSource = "BitlockerFixNoInvoke"
$keyprotector = (Get-BitLockerVolume C:).keyprotector
$protection = (Get-BitLockerVolume C:).protectionstatus
$volumestatus = (Get-BitLockerVolume C:).volumestatus
$tpmon = (Get-WmiObject -Namespace root/cimv2/security/microsofttpm -ClassName win32_tpm).IsActivated_InitialValue
$tpmownd = (Get-WmiObject -Namespace root/cimv2/security/microsofttpm -ClassName win32_tpm).IsOwned_InitialValue
#$tpmen = (Get-WmiObject -Namespace root/cimv2/security/microsofttpm -ClassName win32_tpm).IsEnabled_InitialValue
$tpminit = (Initialize-tpm).tpmready
#$autoProvisioning = (Get-Tpm).AutoProvisioning



#Create Tracelog
$global:LOGFILE = "C:\Windows\BitlockerFix.LOG"
$global:bVerbose = $True


function Write-TraceLog
{                                       
    [CmdletBinding()]
    PARAM(
     [Parameter(Mandatory=$True)]                     
	    [String]$Message,                     
	    [String]$LogPath = $LOGFILE, 
     [validateset('Info','Error','Warn')]   
	    [string]$severity,                     
	    [string]$component = $((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name),
        [long]$logsize = 5 * 1024 * 1024,
        [switch]$Info
	)                

    $Verbose = [bool]($PSCmdlet.MyInvocation.BoundParameters['Verbose'])
    Switch ($severity)
    {
        'Error' {$sev = 3}
        'Warn'  {$sev = 2}
        default {$sev = 1}
    }

    If (($Verbose -and $bVerbose) -or ($Verbose -eq $false)) {
	    $TimeZoneBias = Get-WmiObject -Query "Select Bias from Win32_TimeZone"                     
	    $WhatTimeItIs= Get-Date -Format "HH:mm:ss.fff"                     
	    $Dizzate= Get-Date -Format "MM-dd-yyyy"                     
	
	    "<![LOG[$Message]LOG]!><time=$([char]34)$WhatTimeItIs$($TimeZoneBias.bias)$([char]34) date=$([char]34)$Dizzate$([char]34) component=$([char]34)$component$([char]34) context=$([char]34)$([char]34) type=$([char]34)$sev$([char]34) thread=$([char]34)$([char]34) file=$([char]34)$([char]34)>"| Out-File -FilePath $LogPath -Append -NoClobber -Encoding default
    }

    If ($bVerbose) {write-host $Message}

    $LogPath = $LogPath.ToUpper()
    $i = Get-Item -Path $LogPath
    #$i.Length
    If ($i.Length -gt $logsize)
    {
        $backuplog = $LogPath.Replace(".LOG", ".LO_")
        If (Test-Path $backuplog)
        {
            Remove-Item $backuplog
        }
        Move-Item -Path $LogPath -Destination $backuplog
    } 

} 

#Fix Start
Write-TraceLog -Message "Starting Script" -severity Info -component "Installation"


if ($protection -eq "On") {
    Write-TraceLog -Message "Protection is already on"  -severity Info -component "Protection Check" 
   $return = "ProtectionAlreadyOn"
}
elseif (($tpmon -eq $True) -and ($protection -eq "Off")){
    try {
        if ("TPM" -notin $keyprotector.KeyProtectorType) {
            Add-BitLockerKeyProtector C: -TpmProtector -ErrorAction Stop | Out-null
            Write-TraceLog -Message "Added TPM Protector" -severity Info -component "KeyProtectors"
        }
        if ("RecoveryPassword" -notin $keyprotector.KeyProtectorType) { 
            Add-BitLockerKeyProtector C: -RecoveryPasswordProtector -ErrorAction Stop | Out-null
            Write-TraceLog -Message "Added RecoveryKey Protector" -severity Info -component "KeyProtectors"
        }
            if ($volumestatus -like "*Encrypted") {
                Resume-BitLocker -MountPoint C: -ErrorAction Stop 
                Write-TraceLog -Message "Protection has been turned on" -severity Info -component "TurnOnProtection"
                $return = "ProtectionOn"
            }
            elseif ($volumestatus -eq 'FullyDecrypted') {
            $startencryption = & 'C:\Windows\System32\manage-bde.exe' -on C:
                if ($volumestatus -eq 'EncryptionInProgress') {
                    Write-TraceLog -Message "$startencryption" -severity Info -component "TurnOnProtection"
                    $return = "EncryptionInProgress"
                }
                elseif ("NOTE: Encryption will begin after the hardware test succeeds." -in $startencryption) {
                    Write-TraceLog -Message "Encryption will begin after the hardware test succeeds" -severity Info -component "TurnOnProtection"
                    $return = "NeedRestart"
                }
                else {
                        Write-EventLog -LogName Application -Source $LogSource -EntryType Error -EventId 112 -Message "$startencryption"
                        Write-TraceLog -Message "$startencryption" -severity Error -component "TurnOnProtection"
                        $return = "EncryptionError"
                }
            }
    }
    catch {
        if ($tpminit -eq $False) {
            Write-TraceLog -Message "TPM not ready, start initialization" -severity Info -component "TPMActions"
            $tpminit = Initialize-Tpm
                if ($tpminit -eq $False) {
                    Write-TraceLog -Message "TPM not ready, initialization failed" -severity Error -component "TPMActions"
                    $return = "TPMInitFailed"
                }
                else {
                    Write-TraceLog -Message "TPM ready, initialization succeeded, enabling protectors" -severity Info -component "TurnOnProtection"
                    Resume-BitLocker C:
                    $protection = (Get-BitLockerVolume C:).protectionstatus
                        if ($protection -eq "On") {
                            Write-TraceLog -Message "Protection has been turned on" -severity Info -component "TurnOnProtection"
                            $return = "ProtectionOn"
                        }    
                        else {
                            Write-TraceLog -Message "Protection could not be turned on: $Error" -severity Error -component "TurnOnProtection"
                            $return = "ResumeProtectionError"
                        }
                }
        }
        else {
            Write-TraceLog -Message "Protection could not be turned on: $Error" -severity Error -component "TurnOnProtection"
            $return = "ResumeProtectionError"
        }


    }    
}
elseif (($tpmon -eq $False) -or (!$tpmon)) {
        Write-TraceLog -Message "TPM is disabled" -severity Warn -component "TPMState"
        $return = "TPMDisabled"
            if ($tpmownd -eq $True) {
                Write-TraceLog -Message "TPM is owned" -severity Warn -component "TPMState"
            }
            elseif (!$tpmownd) {
                Write-TraceLog -Message "No TPM info" -severity Warn -component "TPMState"
            }
            else {
                Write-TraceLog -Message "TPM is not owned" -severity Warn -component "TPMState"
            }
}
else {
        Write-TraceLog -Message "No solution can be applied, check the computer for further investigation" -severity Error -component "Installation"
    $return = "NeedManualCheck"
}

$return | Out-Null