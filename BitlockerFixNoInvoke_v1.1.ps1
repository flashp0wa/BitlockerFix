<#
.SYNOPSIS
    The script intended to fix Bitlocker related issues. If the script cannot handle the error... That's sad :(

.DESCRIPTION
    A more detailed description of why and how the function works... will come here for sure, if I will not be so lazy to write it. If by any chance I forgot to fill in later (and since You are reading this I forgot) please let me know.

.PARAMETER DemoParam1
    

.PARAMETER DemoParam2
    

.EXAMPLE
   

.EXAMPLE
    

.NOTES
    Author: David Molnar
    Last Edit: 4/29/2020 
    Version 1.1 - Initial release

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

$hostname = hostname


#Create EventLog
New-EventLog -LogName Application -Source $LogSource -ErrorAction SilentlyContinue

<#EventID Legend
    111 Success
    112 Error
    113 Warning
    114 Unknown Issue
#>


#Fix Start

if ($protection -eq "On") {
    Write-EventLog -LogName Application -Source $LogSource -EntryType Information -EventId 111 -Message "Protection is already on"
   $return = "ProtectionAlreadyOn"
}
elseif (($tpmon -eq $True) -and ($protection -eq "Off")){
    try {
        if ("TPM" -notin $keyprotector.KeyProtectorType) {
            Add-BitLockerKeyProtector C: -TpmProtector -ErrorAction Stop | Out-null
            Write-EventLog -LogName Application -Source $LogSource -EntryType Information -EventId 111 -Message "Added TPM Protector"
        }
        if ("RecoveryPassword" -notin $keyprotector.KeyProtectorType) { 
            Add-BitLockerKeyProtector C: -RecoveryPasswordProtector -ErrorAction Stop | Out-null
            Write-EventLog -LogName Application -Source $LogSource -EntryType Information -EventId 111 -Message "Added RecoveryKey Protector"
        }
            if ($volumestatus -like "*Encrypted") {
                Resume-BitLocker -MountPoint C: -ErrorAction Stop
                Write-EventLog -LogName Application -Source $LogSource -EntryType Information -EventId 111 -Message "Protection has been turned on"
                $return = "ProtectionOn"
            }
            elseif ($volumestatus -eq 'FullyDecrypted') {
            $startencryption = & 'C:\Windows\System32\manage-bde.exe' -on C:
                if ($volumestatus -eq 'EncryptionInProgress') {
                    Write-EventLog -LogName Application -Source $LogSource -EntryType Information -EventId 111 -Message "$startencryption"
                    $return = "EncryptionInProgress"
                }
                elseif ("NOTE: Encryption will begin after the hardware test succeeds." -in $startencryption) {
                    Write-EventLog -LogName Application -Source $LogSource -EntryType Information -EventId 111 -Message "Encryption will begin after the hardware test succeeds"
                    $return = "NeedRestart"
                }
                else {
                        Write-EventLog -LogName Application -Source $LogSource -EntryType Error -EventId 112 -Message "$startencryption"
                        $return = "EncryptionError"
                }
            }
    }
    catch {
        if ($tpminit -eq $False) {
            Write-EventLog -LogName Application -Source $LogSource -EntryType Error -EventId 111 -Message "TPM not ready, start initialization "
            & C:\WINDOWS\system32\TpmInit.exe
                if ($tpminit -eq $False) {
                    Write-EventLog -LogName Application -Source $LogSource -EntryType Error -EventId 113 -Message "TPM not ready, initialization failed"
                    $return = "TPMInitFailed"
                }
                else {
                    Write-EventLog -LogName Application -Source $LogSource -EntryType Error -EventId 111 -Message "TPM ready, initialization succeded, enabling protectors"
                    Resume-BitLocker C:
                    $protection = (Get-BitLockerVolume C:).protectionstatus
                        if ($protection -eq "On") {
                            Write-EventLog -LogName Application -Source $LogSource -EntryType Information -EventId 111 -Message "Protection has been turned on"
                            $return = "ProtectionOn"
                        }    
                        else {
                            Write-EventLog -LogName Application -Source $LogSource -EntryType Error -EventId 112 -Message "Protection could not be turned on: $Error"
                            $return = "ResumeProtectionError"
                        }
                }
        }
        else {
            Write-EventLog -LogName Application -Source $LogSource -EntryType Error -EventId 112 -Message "Protection could not be turned on: $Error"
            $return = "ResumeProtectionError"
        }


    }    
}
elseif (($tpmon -eq $False) -or (!$tpmon)) {
        Write-EventLog -LogName Application -Source $LogSource -EntryType Warning -EventId 113 -Message "TPM is disabled"
        $return = "TPMDisabled"
            if ($tpmownd -eq $True) {
                Write-EventLog -LogName Application -Source $LogSource -EntryType Warning -EventId 113 -Message "TPM is owned"
            }
            elseif (!$tpmownd) {
                Write-EventLog -LogName Application -Source $LogSource -EntryType Warning -EventId 113 -Message "No TPM info"
            }
            else {
                Write-EventLog -LogName Application -Source $LogSource -EntryType Warning -EventId 111 -Message "TPM is not owned"
            }
}
else {
        Write-EventLog -LogName Application -Source $LogSource -EntryType Error -EventId 114 -Message "No solution can be applied, check the computer for further investigation"
    $return = "NeedManualCheck"
}
#Log-o-copy

if (($return -eq "NeedManualCheck") -or ($return -eq "TPMDisabled") -or ($return -eq "ResumeProtectionError") -or ($return -eq "EncryptionError")) {
    Write-EventLog -LogName Application -Source $LogSource -EntryType Information -EventId 111 -Message "Log saved to remotepath"
    $path = "\\crassccm01\msdeploy$\Bitlocker_Fix_Log\BitlockerFix_${return}_${hostname}.txt"
        (Get-EventLog -LogName Application -Source $LogSource).message | Out-File -filepath $path -Force
}

$return | Out-Null