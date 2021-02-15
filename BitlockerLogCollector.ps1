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
    Last Edit: 5/3/2020 
    Version 1.1 - Initial release

#>

$hostname = hostname

New-Item -Path "\\crassccm01\msdeploy$\Bitlocker_Fix_Log\EventLogs" -Name $hostname -ItemType Directory
Copy-Item -Path "$env:SystemRoot\System32\Winevt\Logs\Microsoft-Windows-BitLocker%4BitLocker Management.evtx" -Destination "\\crassccm01\msdeploy$\Bitlocker_Fix_Log\EventLogs\${hostname}" -Force