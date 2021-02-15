#Created by David Molnar
#Create Date 4/14/2020 


#Variables used in script

$PSScriptRoot
$keyprotector = (Get-BitLockerVolume C:).keyprotector
$protection = (Get-BitLockerVolume C:).protectionstatus
$tpmon = (Get-WmiObject -Namespace root/cimv2/security/microsofttpm -ClassName win32_tpm).IsActivated_InitialValue
$return = $null



#Check if keyprotectors are available

if (($keyprotector -notcontains "Tpm" -or "RecoveryPassword" -or !$keyprotector -or $protection -eq "Off") -and $tpmon -eq $True ) {
        $return = $true
}        
else {
        $return = $False
    }

    return $return