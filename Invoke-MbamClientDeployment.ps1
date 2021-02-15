###############################################################################
#
# Copyright (c) Microsoft Corporation.  All rights reserved.
#
# MBAM Client Deployment
#
# Version: 2.5.1
#
# Purpose: Configure BitLocker drive encryption.
#          Record recovery keys with MBAM Server.
#
# Usage:   Invoke-MbamClientDeployment
#              -RecoveryServiceEndpoint <URL> 
#              [-StatusReportingServiceEndpoint <URL>]
#              [-EncryptionMethod $EncryptionMethod]
#              [-EncryptAndEscrowDataVolumes]
#              [-WaitForEncryptionToComplete]
#              [-IgnoreEscrowOwnerAuthFailure]
#              [-IgnoreEscrowRecoveryKeyFailure]
#              [-IgnoreReportStatusFailure]
#              [-DoNotResumeSuspendedEncryption]
#
###############################################################################

# This param statement collects values from the command line that will be passed 
# directly to the function 'Invoke-MbamClientDeployment'.  If changes are made to 
# this parameter list, the 'Invoke-MbamClientDeployment' parameter list must 
# also be modified.

Param(
    [Parameter(HelpMessage="URL of MBAM recovery service endpoint")][string]$RecoveryServiceEndpoint = $null,
    [Parameter(HelpMessage="URL of MBAM reporting service endpoint")][string]$StatusReportingServiceEndpoint = $null,
    [Parameter(HelpMessage="Default is AES128")][string]$EncryptionMethod = "AES128",
    [switch]$EncryptAndEscrowDataVolumes,
    [switch]$WaitForEncryptionToComplete,
    [switch]$IgnoreEscrowOwnerAuthFailure,
    [switch]$IgnoreEscrowRecoveryKeyFailure,
    [switch]$IgnoreReportStatusFailure,
    [switch]$DoNotResumeSuspendedEncryption
    )

Set-StrictMode -Version 1

# Enum type: EncryptionMethod
# The enum values are consistent with the values used by 
# Win32_EncryptableVolume.Encrypt() WMI method.
if (-not ("EncryptionMethod" -as [type]))
{
    Add-Type -TypeDefinition @"
        public enum EncryptionMethod
        {
            UNSPECIFIED = 0,
            AES128_DIFFUSER,
            AES256_DIFFUSER,
            AES128,
            AES256
        }
"@
}

# Enum type: MbamVolumeType
# The enum values are consistent with the values used by Mbam_Volume WMI instances.
if (-not ("MbamVolumeType" -as [type]))
{
    Add-Type -TypeDefinition @"
        public enum MbamVolumeType
        {
            UNKNOWN = 0,
            OS_DRIVE,
            FIXED_DATA_DRIVE,
            REMOVABLE_DATA_DRIVE,
            VIRTUAL_FIXED_DATA_VOLUME
        }
"@
}

# Enum type: ProtectoryType
# The enum values are consistent with the values used by 
# Win32_EncryptableVolume.GetKeyProtectorType() WMI method.
if (-not ("ProtectorType"  -as [type]))
{
    Add-Type -TypeDefinition @"
        public enum ProtectorType
        {
            UNKNOWN_NO_PROTECTOR = 0,
            TPM_PROTECTOR,
            EXTERNALKEY_PROTECTOR, 
            NUMERICALPASSWORD_PROTECTOR,
            TPMPIN_PROTECTOR,
            TPMKEY_PROTECTOR,
            TPMPINKEY_PROTECTOR,
            PUBLICKEY_PROTECTOR,
            PASSPHRASE_PROTECTOR,
            TPMCERTIFICATE_PROTECTOR,
            SID_PROTECTOR,
            DRA_PROTECTOR = 200
        }
"@
}

# Enum type: ProtectionStatus
# The enum values are consistent with the values used by 
# Win32_EncryptableVolume.GetProtectionStatus() WMI method.
if (-not ("ProtectionStatus"  -as [type]))
{
    Add-Type -TypeDefinition @"
        public enum ProtectionStatus
        {
            UNPROTECTED = 0,
            PROTECTED,
            UNKNOWN
        }
"@
}

# Enum type: ConversionStatus
# The enum values are consistent with the values used by 
# Win32_EncryptableVolume.GetConversionStatus() WMI method.
if (-not ("ConversionStatus"  -as [type]))
{
    Add-Type -TypeDefinition @"
        public enum ConversionStatus
        {
            FULLY_DECRYPTED = 0,
            FULLY_ENCRYPTED,
            ENCRYPTION_IN_PROGRESS,
            DECRYPTION_IN_PROGRESS,
            ENCRYPTION_PAUSED,
            DECRYPTION_PAUSED
        }
"@
}

# WMI constants
if (-not (Test-Path variable:local:TpmWmiNamespace))
{
    Set-Variable TpmWmiNamespace -Option ReadOnly -Scope local "root\CIMV2\Security\MicrosoftTpm"
}

if (-not (Test-Path variable:local:BitLockerWmiNamespace))
{
    Set-Variable BitLockerWmiNamespace -Option ReadOnly -Scope local "root\CIMV2\Security\MicrosoftVolumeEncryption"
}

if (-not (Test-Path variable:local:MbamWmiNamespace))
{
    Set-Variable MbamWmiNamespace -Option ReadOnly -Scope local "root\Microsoft\MBAM"
}

# Retry constants for escrowing TPM owner-auth and volume recovery key to MBAM server.
# Mumber of tries: 3
# Retry interval: 30 seconds
if (-not (Test-Path variable:local:NumEscrowTries))
{
    Set-Variable NumEscrowTries -Option ReadOnly -Scope local 3
}

if (-not (Test-Path variable:local:EscrowRetryInterval))
{
    Set-Variable EscrowRetryInterval -Option ReadOnly -Scope local 30 # in seconds
}


# HRESULT Constants
if (-not (Test-Path variable:local:S_OK))
{
    Set-Variable S_OK                                                   -Option ReadOnly -Scope local ([uint32]"0x0")
    Set-Variable MBAM_E_TPM_NOT_PRESENT                                 -Option ReadOnly -Scope local ([uint32]"0x80040200")
    Set-Variable MBAM_E_TPM_INCORRECT_STATE                             -Option ReadOnly -Scope local ([uint32]"0x80040201")
    Set-Variable MBAM_E_TPM_AUTO_PROVISIONING_PENDING                   -Option ReadOnly -Scope local ([uint32]"0x80040202")
    Set-Variable MBAM_E_TPM_OWNERAUTH_READFAIL                          -Option ReadOnly -Scope local ([uint32]"0x80040203")
    Set-Variable MBAM_E_REBOOT_REQUIRED                                 -Option ReadOnly -Scope local ([uint32]"0x80040204")
    Set-Variable MBAM_E_SHUTDOWN_REQUIRED                               -Option ReadOnly -Scope local ([uint32]"0x80040205")
    Set-Variable FVE_E_LOCKED_VOLUME                                    -Option ReadOnly -Scope local ([uint32]"0x80310000")
    Set-Variable FVE_E_NOT_ACTIVATED                                    -Option ReadOnly -Scope local ([uint32]"0x80310008")
    Set-Variable FVE_E_PROTECTOR_NOT_FOUND                              -Option ReadOnly -Scope local ([uint32]"0x80310033")
    Set-Variable FVE_E_VOLUME_TOO_SMALL                                 -Option ReadOnly -Scope local ([uint32]"0x8031006F")
    Set-Variable WS_E_INVALID_FORMAT                                    -Option ReadOnly -Scope local ([uint32]"0x803D0000")
    Set-Variable WS_E_ENDPOINT_ACCESS_DENIED                            -Option ReadOnly -Scope local ([uint32]"0x803D0005")
    Set-Variable WS_E_ENDPOINT_NOT_FOUND                                -Option ReadOnly -Scope local ([uint32]"0x803D000D")
    Set-Variable WS_E_ENDPOINT_FAILURE                                  -Option ReadOnly -Scope local ([uint32]"0x803D000F")
    Set-Variable WS_E_ENDPOINT_UNREACHABLE                              -Option ReadOnly -Scope local ([uint32]"0x803D0010")
    Set-Variable WS_E_ENDPOINT_TOO_BUSY                                 -Option ReadOnly -Scope local ([uint32]"0x803D0012")
    Set-Variable WS_E_ENDPOINT_FAULT_RECEIVED                           -Option ReadOnly -Scope local ([uint32]"0x803D0013")
    Set-Variable WS_E_INVALID_ENDPOINT_URL                              -Option ReadOnly -Scope local ([uint32]"0x803D0020")
}

# Exit code constants
if (-not (Test-Path variable:local:BDEHDCFG_E_BDECFG_READY_FOR_BITLOCKER))
{
    Set-Variable BDEHDCFG_E_BDECFG_READY_FOR_BITLOCKER                  -Option ReadOnly -Scope local ([int32]"0xC0A00002")
}

# HRESULT to error message mapping
if (-not (Test-Path variable:local:HresultToString))
{
    Set-Variable HresultToString -Option ReadOnly -Scope local @{
        $S_OK = "The method was successful.";
        $MBAM_E_TPM_NOT_PRESENT = "TPM is not present in the machine or disabled in BIOS configuration.";
        $MBAM_E_TPM_INCORRECT_STATE = "TPM is not in the correct state (enabled, activated and owner installation allowed).";
        $MBAM_E_TPM_AUTO_PROVISIONING_PENDING = "MBAM cannot take the ownership of TPM because auto-provisioning is pending. Try again after the auto-provisioning is completed.";
        $MBAM_E_TPM_OWNERAUTH_READFAIL = "MBAM cannot read the TPM owner authorization value. The value may have been removed after a successful escrow. On Windows 7, MBAM cannot read the value if the TPM is owned by others.";
        $MBAM_E_REBOOT_REQUIRED = "The computer must be restarted to set TPM in the correct state. Physical presence may be required.";
        $MBAM_E_SHUTDOWN_REQUIRED = "The computer must be shutdown and turned back on to set TPM in the correct state. Physical presence may be required.";
        $FVE_E_LOCKED_VOLUME = "The volume is locked.";
        $FVE_E_NOT_ACTIVATED = "BitLocker is not enabled on the volume. Add a key protector to enable BitLocker.";
        $FVE_E_PROTECTOR_NOT_FOUND = "Numerical Password protector was not found for the volume.";
        $FVE_E_VOLUME_TOO_SMALL = "The drive is too small to be protected using BitLocker Drive Encryption.";
        $WS_E_INVALID_FORMAT = "The input data was not in the expected format or did not have the expected value.";
        $WS_E_ENDPOINT_ACCESS_DENIED = "Access was denied by the remote endpoint.";
        $WS_E_ENDPOINT_NOT_FOUND = "The remote endpoint does not exist or could not be located.";
        $WS_E_ENDPOINT_FAILURE = "The remote endpoint could not process the request.";
        $WS_E_ENDPOINT_UNREACHABLE = "The remote endpoint was not reachable.";
        $WS_E_ENDPOINT_TOO_BUSY = "The remote endpoint is unable to process the request due to being overloaded.";
        $WS_E_ENDPOINT_FAULT_RECEIVED = "A message containing a fault was received from the remote endpoint. Ensure that you are connecting to the connect service endpoint."
        $WS_E_INVALID_ENDPOINT_URL = "The endpoint address URL is not valid. The URL must start with 'http' or 'https'.";
        $BDEHDCFG_E_BDECFG_READY_FOR_BITLOCKER = "This computer's hard drive is properly configured for BitLocker. It is not necessary to run BitLocker Setup."
    }
}

Function GetMbamWmiErrorMessage($HResult)
{
<#
    .SYNOPSIS
        Convert an HRESULT into a string.

    .DESCRIPTION
        Attempts to convert an HRESULT into a string. If not able, the HRESULT
        is returned as a HEX formatted string.

    .PARAMETER HResult
        HResult to convert.
#>

    if ($hResult)
    {
        [uint32]$hResult = $hResult;
        [string]$hexval = "0x{0:x}" -f $hResult

        if ($HresultToString.Contains($hResult))
        {
            return " HRESULT: $hexval - " + ($HresultToString[$hResult]);
        }
        else
        {
            return " HRESULT: $hexval"
        }
    }
    else
    {
        return [string]""
    }
}

Function ReportStatus()
{
<#
    .SYNOPSIS
        Report the encryption and compliance status.

    .DESCRIPTION
        Report the encryption and compliance status to the provided MBAM reporting service endpoint.

    .PARAMETER ReportingServiceEndpoint
        MBAM reporting service endpoint.

    .PARAMETER IgnoreError
        If set, it will just write a warning instead of throwing an exception on WMI method error.

    .RETURNVALUE
        HRESULT returned by the Mbam_Machine.ReportStatus() WMI method being called.
#>

    Param(
        [Parameter(Mandatory=$True)][string]$ReportingServiceEndpoint, 
        [switch]$IgnoreError
        )

    Write-Debug "ReportStatus ReportingServiceEndpoint=$ReportingServiceEndpoint $IgnoreError=$IgnoreError"

    # Call WMI method Mbam_Machine.ReportStatus()
    [psobject]$mbamMachine = Get-WmiObject -Query ("SELECT * FROM Mbam_Machine") -Namespace $MbamWmiNamespace

    if ($mbamMachine -eq $Null)
    {
        Throw "WMI query to Mbam_Machine failed."
    }

    Try
    {
        [psobject]$obj = $mbamMachine.ReportStatus($ReportingServiceEndpoint)
    }
    Catch [system.object]
    {
        Throw "Failed to execute WMI Mbam_Machine.ReportStatus. Make sure MBAM client is 2.5 SP1 or greater."
    }

    [uint32]$hResult = $obj.ReturnValue

    if (($hResult -ne $S_OK))
    {
        [string]$message = ("Failed to report the encryption and compliance status. " + (GetMbamWmiErrorMessage $hResult))

        # If the error can be ignored just write a warning, otherwise write an error and throw.
        if ($IgnoreError)
        {
            Write-Host $message
        }
        else
        {
            Throw $message
        }
    }

    Write-Debug "ReportStatus: Return $hResult"
    return $hResult;
}

Function PrepareTpmAndEscrowOwnerAuth()
{
<#
    .SYNOPSIS
        Prepare TPM and escrow TPM owner-auth.

    .DESCRIPTION
        Prepare TPM and escrow TPM owner-auth to the provided MBAM recovery service endpoint.
        It will try to set TPM to the correct state (enabled, activated and TPM owner installation allowed) if not so.
        It will take the ownership of TPM if it is not owned and not configured to be auto-provisioned.
        It will fail if TPM is not owned but configured to be auto-provisioned.

    .PARAMETER RecoveryServiceEndpoint
        MBAM recovery service endpoint.

    .PARAMETER IgnoreEscrowOwnerAuthFailure
        If set, it will just write a warning instead of throwing an exception on TPM owner-auth escrow errors.
        The TPM preparation errors will block encryption and are hence considered fatal.

    .RETURNVALUE
        HRESULT returned by the Mbam_Machine.PrepareTpmAndEscrowOwnerAuth() WMI method being called.
#>

    Param(
        [Parameter(Mandatory=$True)][string]$RecoveryServiceEndpoint, 
        [switch]$IgnoreEscrowOwnerAuthFailure
        )

    Write-Debug "PrepareTpmAndEscrowOwnerAuth RecoveryServiceEndpoint=$RecoveryServiceEndpoint IgnoreEscrowOwnerAuthFailure=$IgnoreEscrowOwnerAuthFailure"

    # Call WMI method Mbam_Machine.PrepareTpmAndEscrowOwnerAuth()
    [psobject]$mbamMachine = Get-WmiObject -Query ("SELECT * FROM Mbam_Machine") -Namespace $MbamWmiNamespace

    if ($mbamMachine -eq $Null)
    {
        Throw "WMI query to Mbam_Machine failed."
    }

    [int]$numTried = 0
    [uint32]$hResult = $S_OK

    do
    {
        [psobject]$obj = $mbamMachine.PrepareTpmAndEscrowOwnerAuth($RecoveryServiceEndpoint)

        if ($obj -eq $null)
        {
            Throw "Failed to execute WMI Mbam_Machine.PrepareTpmAndEscrowOwnerAuth. Make sure MBAM client is 2.5 SP1 or greater."
        }

        ++$numTried
        $hResult = $obj.ReturnValue

        if ($hResult -ne $S_OK)
        {
            if (($hResult -eq $MBAM_E_TPM_NOT_PRESENT) -or ($hResult -eq $MBAM_E_TPM_INCORRECT_STATE) -or ($hResult -eq $MBAM_E_TPM_AUTO_PROVISIONING_PENDING)) # TPM preparation errors
            {
                Throw "Failed to prepare TPM for encryption." + (GetMbamWmiErrorMessage $hResult)
            }
            elseif ($numTried -lt $NumEscrowTries) 
            {
                Write-Host ("Failed to escrow TPM owner-auth to $RecoveryServiceEndpoint." + (GetMbamWmiErrorMessage $hResult))
                Write-Host ("Retry after $EscrowRetryInterval seconds...")
                Start-Sleep -s $EscrowRetryInterval 
            }
        }
    }
    while (($hResult -ne $S_OK) -and ($numTried -lt $NumEscrowTries))
            
    if ($hResult -ne $S_OK)
    {
        $message = ("Failed to escrow TPM owner-auth to $RecoveryServiceEndpoint after $NumEscrowTries tries. Last error - " + (GetMbamWmiErrorMessage $hResult))
        if ($IgnoreEscrowOwnerAuthFailure)
        {
            Write-Host $message
            Write-Host "The TPM owner-auth escrow failures are configured to be ignored."
        }
        else
        {
            Throw $message
        }
    }

    Write-Debug "PrepareTpmAndEscrowOwnerAuth: Return $hResult"
    return $hResult;
}

Function EscrowVolumeRecoveryInfo()
{
<#
    .SYNOPSIS
        Escrow volume recovery information.

    .DESCRIPTION
        Escrow volume recovery information to the provided MBAM recovery service endpoint.

    .PARAMETER RecoveryServiceEndpoint
        MBAM recovery service endpoint.

    .PARAMETER DeviceId
        Device ID of the volume whose recovery info will be escrowed.

    .PARAMETER IgnoreError
        If set, it will just write a warning instead of throwing an exception on WMI method error.

    .RETURNVALUE
        HRESULT returned by the Machine_Volume.EscrowRecoveryInfo() WMI method being called.
#>

    Param(
        [Parameter(Mandatory=$True)][string]$RecoveryServiceEndpoint, 
        [Parameter(Mandatory=$True)][string]$DeviceId, 
        [switch]$IgnoreError
        )

    Write-Debug("EscrowVolumeRecoveryInfo RecoveryServiceEndpoint=$RecoveryServiceEndpoint " +
        "DeviceId=$DeviceId IgnoreError=$IgnoreError")

    # Call WMI method Machine_Volume.EscrowRecoveryInfo() on the device

    [string]$id = (EscapeWmiString $DeviceId)
    [psobject]$mbamVolume = Get-WmiObject -Query ("SELECT * FROM Mbam_Volume WHERE DeviceId = '$id'") -Namespace $MbamWmiNamespace

    if ($mbamVolume -eq $Null)
    {
        Throw "Mbam_Volume WMI lookup failed to find device $DeviceId."
    }

    # To overcome possible connectivity issues, try to connect to the MBAM service serveral times in case of error.

    [int]$numTried = 0
    [uint32]$hResult = $S_OK

    do
    {
        [psobject]$obj = $mbamVolume.EscrowRecoveryKey($RecoveryServiceEndpoint)

        if ($obj -eq $null)
        {
            Throw "Failed to execute WMI Mbam_Volume.EscrowRecoveryKey. Make sure MBAM client is 2.5 SP1 or greater."
        }

        ++$numTried
        $hResult = $obj.ReturnValue

        if (($hResult -ne $S_OK) -and ($numTried -lt $NumEscrowTries))
        {
            $driveLetter = $mbamVolume.DriveLetter
            Write-Host ("Failed to escrow the recovery information of volume $driveLetter (Device ID: $DeviceId) to $RecoveryServiceEndpoint." + (GetMbamWmiErrorMessage $hResult))
            Write-Host ("Retry after $EscrowRetryInterval seconds...")
            Start-Sleep -s $EscrowRetryInterval 
        }
    }
    while (($hResult -ne $S_OK) -and ($numTried -lt $NumEscrowTries))
        
    if ($hResult -ne $S_OK)
    {
        $driveLetter = $mbamVolume.DriveLetter
        $message = ("Failed to escrow the recovery information of volume $driverLetter (Device ID: $DeviceId) to $RecoveryServiceEndpoint after $NumEscrowTries tries. Last error - " + (GetMbamWmiErrorMessage $hResult))
        if ($IgnoreError)
        {
            Write-Host $message
            Write-Host "The volume recovery information escrow failures are configured to be ignored."
        }
        else
        {
            throw $message
        }
    }

    Write-Debug "EscrowVolumeRecoveryInfo: Return $hResult"
    return $hResult;
}

Function IsProtectorPresent()
{
<#
    .SYNOPSIS
        Check if a specified type of key protector is present in the specified volume.

    .DESCRIPTION
        Check if a specified type of key protector is present in the specified volume.

    .PARAMETER DeviceId
        DeviceId of the volume to check.

    .PARAMETER ProtectorType
        Key protector type to check. If not specified, all protector types will be checked.

    .RETURNVALUE
        True if a specified type of protector is present, False otherwise.
#>

    Param(
        [Parameter(Mandatory=$True)][string]$DeviceId,
        [ProtectorType]$ProtectorType
        )

    Write-Debug "IsProtectorPresent DeviceId=$DeviceId ProtectorType=$ProtectorType"

    # If protector type is not specified, any protector will be looked up.
    if ($ProtectorType -eq $null)
    {
        $ProtectorType = [ProtectorType]::UNKNOWN_NO_PROTECTOR
    }

    [psobject]$volume = GetEncryptableVolume -DeviceId $deviceId
    [psobject]$keyProtectorsObj = $volume.GetKeyProtectors(($ProtectorType -as [int]))

    [uint32]$hResult = $keyProtectorsObj.ReturnValue
    [string[]]$protectors = $keyProtectorsObj.VolumeKeyProtectorID

    if (($hResult -ne $S_OK))
    {
        Throw "Failed to determine whether device $DeviceId has a $ProtectorType protector."
    }

    [uint32]$retval = ($protectors.Count -gt 0)

    Write-Debug "IsProtectorPresent: Return $retval"
    return $retval
}

Function IsTpmProtectorPresent()
{
<#
    .SYNOPSIS
        Check if any TPM key protector is present in the specified volume.

    .DESCRIPTION
        Check if any TPM key protector is present in the specified volume.

    .PARAMETER DeviceId
        The DeviceId of the volume to check.

    .RETURNVALUE
        True if any TPM key protector is present, False otherwise.
#>

    Param([Parameter(Mandatory=$True)][string]$DeviceId)
    Write-Debug "IsTpmProtectorPresent DeviceId=$DeviceId"

    [bool]$retval = `
        (IsProtectorPresent -DeviceId $DeviceId -ProtectorType ([ProtectorType]::TPM_PROTECTOR)) -or `
        (IsProtectorPresent -DeviceId $DeviceId -ProtectorType ([ProtectorType]::TPMPIN_PROTECTOR)) -or `
        (IsProtectorPresent -DeviceId $DeviceId -ProtectorType ([ProtectorType]::TPMKEY_PROTECTOR)) -or `
        (IsProtectorPresent -DeviceId $DeviceId -ProtectorType ([ProtectorType]::TPMPINKEY_PROTECTOR))

    Write-Debug "IsTpmProtectorPresent: Return $retval"
    return $retval
}

Function IsAutoUnlockProtectorPresent()
{
<#
    .SYNOPSIS
        Check if Auto-unlock key protector is present in the specified volume.

    .DESCRIPTION
        Check if Auto-unlock key protector is present in the specified volume.

    .PARAMETER DeviceId
        DeviceId of the volume to check.

    .RETURNVALUE
    True if Auto-unlock key protector is present, False otherwise.
#>

    Param([Parameter(Mandatory=$True)][string]$DeviceId)
    Write-Debug "IsAutoUnlockProtectorPresent DeviceId=$DeviceId"

    [psobject]$volume = GetEncryptableVolume -DeviceId $deviceId
    [psobject]$obj = $volume.IsAutoUnlockEnabled()
    [uint32]$hresult = $obj.ReturnValue
    [bool]$retval = $obj.IsAutoUnlockEnabled
    
    if (($hresult -ne $S_OK))
    {
        Throw "Failed to get the Auto-unlock protector enablement status of volume $DeviceId." + (GetMbamWmiErrorMessage $hResult)
    }

    Write-Debug "IsAutoUnlockProtectorPresent: Return $retval"
    return $retval
}

Function IsEncryptionNeeded()
{
<#
    .SYNOPSIS
        Check if encryption is needed for the given drive.

    .DESCRIPTION
        It returns $True if 
            1) the volume is decrypted or being decrypted, or
            2) the volume is encryption paused and the -DoNotResumeSuspendedEncryption flag is not set,
            3) the volume is encrypted but the protectors are not enabled.
        It throws an exception if the protection status of the volume cannot be determined.

    .PARAMETER DeviceId
        The device ID of the volume to check.

    .PARAMETER DoNotResumeSuspendedEncryption
        If present, suspended encryption will not be resumed.

    .RETURNVALUE
        True if a volume protector is turned on, False otherwise.
#>

    Param(
        [Parameter(Mandatory=$True)][string]$DeviceId,
        [switch]$DoNotResumeSuspendedEncryption
        )
    Write-Debug("IsEncryptionNeeded DeviceId=$DeviceId DoNotResumeSuspendedEncryption=$DoNotResumeSuspendedEncryption")

    [psobject]$volume = GetEncryptableVolume -DeviceId $deviceId
    [psobject]$conversionStatusObj = $volume.GetConversionStatus()
    [uint32]$hResult = $conversionStatusObj.ReturnValue
    [ConversionStatus]$conversionStatus = $conversionStatusObj.ConversionStatus
    
    if (($hResult -ne $S_OK))
    {
        Throw "Failed to get the conversion status of volume $DeviceId." + (GetMbamWmiErrorMessage $hResult)
    }

    [bool]$retval = $False

    if ($conversionStatus -eq [ConversionStatus]::FULLY_DECRYPTED)
    {lk
        Write-Host "Device $DeviceId is fully decrypted. Encryption will be started."
        $retval = $True
    }
    elseif ($conversionStatus -eq [ConversionStatus]::DECRYPTION_IN_PROGRESS)
    {
        Write-Host "Device $DeviceId has decryption in progress. Encryption will be started."
        $retval = $True
    }
    elseif ($conversionStatus -eq [ConversionStatus]::FULLY_ENCRYPTED)
    {
        if ((GetProtectionStatus -DeviceId $deviceId) -eq [ProtectionStatus]::UNPROTECTED)
        {
            Write-Host "Device $DeviceId is already encrypted but not protected. The key protectors will be enabled."
            $retval = $True
        }
        else
        {
            Write-Host "Device $DeviceId is already encrypted and protected."
        }
    }
    elseif ($conversionStatus -eq [ConversionStatus]::ENCRYPTION_IN_PROGRESS)
    {
        Write-Host "Device $DeviceId is already encrypting."
    }
    elseif ($conversionStatus -eq [ConversionStatus]::ENCRYPTION_PAUSED)
    {
        if ($DoNotResumeSuspendedEncryption)
        {
            Write-Host "Device $DeviceId has encryption paused. State will not be changed."
        }
        else
        {
            Write-Host "Device $DeviceId has encryption paused. Encryption will be resumed."
            $retval = $True
        }
    }
    elseif ($conversionStatus -eq [ConversionStatus]::DECRYPTION_PAUSED)
    {
        Write-Host "Device $DeviceId has decryption paused. State will not be changed."
    }
    else
    {
        Write-Host ("Conversion status of volume $DeviceId is " + ($conversionStatus -as [string]))
    }

    Write-Debug "IsEncryptionNeeded: Return $retval"
    return $retval;
}

Function AddNumericalPasswordProtectorToVolume()
{
<#
    .SYNOPSIS
        Add Numerical Password key protector to the specified volume.

    .DESCRIPTION
        Add Numerical Password key protector to the specified volume.

    .PARAMETER DeviceId
        Device ID of the volume to check.
#>

    Param([Parameter(Mandatory=$True)][string]$DeviceId)
    Write-Debug "AddNumericalPasswordProtectorToVolume DeviceId=$DeviceId"

    [psobject]$volume = GetEncryptableVolume -DeviceId $deviceId
    [uint32]$hResult = $volume.ProtectKeyWithNumericalPassword().ReturnValue

    if (($hResult -ne $S_OK))
    {
        [string]$message = ("Failed to add Numerical Password protector to device $DeviceId." + (GetMbamWmiErrorMessage $hResult))

        if ($hResult -eq $FVE_E_VOLUME_TOO_SMALL)
        {
            $message = "Device $DeviceId is too small to be protected using BitLocker Drive Encryption."
        }

        Throw $message
    }

    Write-Debug "AddNumericalPasswordProtectorToVolume: Returned from function"
}

Function GetOsDeviceId()
{
<#
    .SYNOPSIS
        Gets the device ID of OS drive.

    .DESCRIPTION
        Gets the device ID of the OS drive. An exception is thrown on failure.

    .RETURNVALUE
        As string containing the OS device id.
#>

    Write-Debug "GetOsDeviceId"

    [int]$volumeType = [MbamVolumeType]::OS_DRIVE
    [psobject]$volume = Get-WmiObject -Query ("SELECT * FROM Mbam_Volume WHERE BitLockerManagementVolumeType = '$volumeType'") -Namespace $MbamWmiNamespace

    if ($volume -eq $null)
    {
        Throw "Failed to find the OS device."
    }
    
    [string]$deviceId = $volume.DeviceId
    return $deviceId
}

Function AddTpmProtectorToOsVolume()
{
<#
    .SYNOPSIS
        Add key protector to OS volume.

    .DESCRIPTION
        Add TPM key protector to OS volume if it has compatible TPM.
#>

    Write-Debug "AddTpmProtectorToOsVolume"

    [string]$deviceId = GetOsDeviceId
    [psobject]$volume = GetEncryptableVolume -DeviceId $deviceId
    [uint32]$hResult = $volume.ProtectKeyWithTPM().ReturnValue

    if (($hResult -ne $S_OK))
    {
        Throw "Failed to add TPM protector to OS device $deviceId." + (GetMbamWmiErrorMessage $hResult)
    }

    Write-Debug "AddTpmProtectorToOsVolume: Returning from function"
}

Function AddAutoUnlockProtectorToDataVolume()
{
<#
    .SYNOPSIS
        Add key protector to the specified data volume.

    .DESCRIPTION
        Add an external key protector to the specified data volume and enable auto-unlock.

    .PARAMETER DeviceId
        The DeviceId of the data volume to add protector to.
#>

    Param([Parameter(Mandatory=$True)][string]$DeviceId)
    Write-Debug "AddAutoUnlockProtectorToDataVolume DeviceId=$DeviceId"

    [bool]$enabled = IsAutoUnlockProtectorPresent -DeviceId $deviceId

    if ($enabled) # return immediately if auto-unlock already enabled
    {
        Write-Host "AddAutoUnlockProtectorToDataVolume: Auto-unlock is already enabled on data volume $DeviceId."
        return
    }

    # Call Win32_EncryptableVolume.ProtectKeyWithExternalKey() WMI method to add an external key protector.
    [psobject]$volume = GetEncryptableVolume -DeviceId $deviceId
    [psobject]$obj = $volume.ProtectKeyWithExternalKey()
    [uint32]$hResult = $obj.ReturnValue
    $protectorID = $obj.VolumeKeyProtectorID

    if (($hResult -ne $S_OK))
    {
        Throw "Failed to add an external key protector to data volume $DeviceId." + (GetMbamWmiErrorMessage $hResult)
    }

    # Call Win32_encryptablevolume.EnableAutoUnlock() WMI method to enable auto-unlock.
    [uint32]$hResult = $volume.EnableAutoUnlock($protectorID).ReturnValue

    if (($hResult -ne $S_OK))
    {
        Throw "Failed to enable auto-unlock on data volume $DeviceId." + (GetMbamWmiErrorMessage $hResult)
    }

    Write-Debug "AddAutoUnlockProtectorToDataVolume: Returning from function"
}

Function StartEncrypting()
{
<#
    .SYNOPSIS
        Start encrypting the specified volume.

    .DESCRIPTION
        Start encrypting the specified volume asynchronously.

    .PARAMETER DeviceId
        The device ID of the volume to be encrypted.

    .PARAMETER EncryptionMethod
        Encryption method.
#>

    Param(
        [Parameter(Mandatory=$True)][string]$DeviceId, 
        [Parameter(Mandatory=$True)][EncryptionMethod]$EncryptionMethod
        )

    Write-Debug "StartEncrypting DeviceId=$DeviceId EncryptionMethod=$EncryptionMethod"

    # Start encrypting. Does not wait for completion.
    [psobject]$volume = GetEncryptableVolume -DeviceId $deviceId
    [uint32]$hResult = $volume.Encrypt($EncryptionMethod).ReturnValue

    if (($hResult -ne $S_OK))
    {
        Throw "Failed to start encrypting volume $DeviceId." + (GetMbamWmiErrorMessage $hResult)
    }

    Write-Debug "StartEncrypting: Returning from function"
}

Function EnableKeyProtectors()
{
<#
    .SYNOPSIS
        Enable the key protectors of the specified volume.

    .DESCRIPTION
        Enable the key protectors of the specified volume. This ensures that the volume's encryption key
        is not exposed in the clear on the hard disk.

    .PARAMETER DeviceId
        The device ID of the volume whose protectors will be enabled.
#>

    Param([Parameter(Mandatory=$True)][string]$DeviceId)

    Write-Debug "EnableKeyProtectors DeviceId=$DeviceId"

    [psobject]$volume = GetEncryptableVolume -DeviceId $deviceId
    [uint32]$hResult = $volume.EnableKeyProtectors().ReturnValue

    if (($hResult -ne $S_OK))
    {
        Throw "Failed to enable the key protectors of the volume $DeviceId." + (GetMbamWmiErrorMessage $hResult)
    }

    Write-Debug "EnableKeyProtectors: Returning from function"
}

Function GetProtectionStatus()
{
<#
    .SYNOPSIS
        Get the protection status of the specified volume.

    .DESCRIPTION
        Get the protection status of the specified volume.

    .PARAMETER DeviceId
        The device ID of the volume whose protection status will be obtained.

    .RETURNVALUE
        The protection status of the specified volume.
#>

    Param([Parameter(Mandatory=$True)][string]$DeviceId)

    Write-Debug "GetProtectionStatus DeviceId=$DeviceId"

    [psobject]$volume = GetEncryptableVolume -DeviceId $deviceId
    [psobject]$protectionStatusObj = $volume.GetProtectionStatus()
    [uint32]$hResult = $protectionStatusObj.ReturnValue
    [ProtectionStatus]$protectionStatus = $protectionStatusObj.ProtectionStatus
    
    if ($hResult -ne $S_OK)
    {
        Throw "Failed to get the protection status of volume $DeviceId." + (GetMbamWmiErrorMessage $hResult)
    }

    Write-Debug "GetProtectionStatus: Returning $protectionStatus"

    return $protectionStatus
}

Function EncryptAndEscrowOsVolume()
{
<#
    .SYNOPSIS
        Encrypt the OS volume and enable the protectors.

    .DESCRIPTION
        Add numerical protector if not present on the OS device, Escrow the recovery key
        with MBAM and start encrypting the device.

    .PARAMETER EncryptionMethod
        Encryption method.

    .PARAMETER RecoveryServiceEndpoint
        MBAM recovery service endpoint.
    
    .PARAMETER IgnoreEscrowRecoveryKeyFailure
        If not present, failure to escrow recovery key will throw an exception.

    .PARAMETER DoNotResumeSuspendedEncryption
        If present, suspended encryption will not be resumed.

    .RETURNVALUE
        An array containing the drive letter of the OS drive.
#>

    Param(
        [Parameter(Mandatory=$True)][EncryptionMethod]$EncryptionMethod,
        [Parameter(Mandatory=$True)][string]$RecoveryServiceEndpoint,
        [switch]$IgnoreEscrowRecoveryKeyFailure,
        [switch]$DoNotResumeSuspendedEncryption
    )

    Write-Debug("EncryptAndEscrowOsVolume EncryptionMethod=$EncryptionMethod " +
        "RecoveryServiceEndpoint=$RecoveryServiceEndpoint " +
        "IgnoreEscrowRecoveryKeyFailure=$IgnoreEscrowRecoveryKeyFailure" +
        "DoNotResumeSuspendedEncryption=$DoNotResumeSuspendedEncryption")
 
    [string]$deviceId = GetOsDeviceId

    if (-not (IsProtectorPresent -DeviceId $deviceId -ProtectorType NUMERICALPASSWORD_PROTECTOR))
    {
        AddNumericalPasswordProtectorToVolume -DeviceId $deviceId
    }

    [uint32]$hResult = EscrowVolumeRecoveryInfo `
        -RecoveryServiceEndpoint $RecoveryServiceEndpoint `
        -DeviceId $deviceId `
        -IgnoreError:$IgnoreEscrowRecoveryKeyFailure

    if (IsEncryptionNeeded -DeviceId $deviceId -DoNotResumeSuspendedEncryption:$DoNotResumeSuspendedEncryption)
    {
        StartEncrypting -EncryptionMethod $EncryptionMethod -DeviceId $deviceId
        EnableKeyProtectors -DeviceId $deviceId
    }

    Write-Debug("EncryptAndEscrowOsVolume: Return " + @($deviceId) | Out-String)
    return @($deviceId)
}

Function EncryptAndEscrowDataVolumes()
{
<#
    .SYNOPSIS
        Encrypt data volumes and enable the protectors.

    .DESCRIPTION
        Adds numerical protectors if not present on the data drives, escrows the
        recovery keys and start encryption on the volumes.

    .PARAMETER EncryptionMethod
        Encryption method.

    .PARAMETER RecoveryServiceEndpoint
        MBAM recovery service endpoint.
    
    .PARAMETER $IgnoreEscrowRecoveryKeyFailure
        If not present, failure to escrow recovery key will throw an exception.

    .PARAMETER DoNotResumeSuspendedEncryption
        If present, suspended encryption will not be resumed.

    .RETURNVALUE
        An array containing the device IDs being encrypted.
#>

    Param(
        [Parameter(Mandatory=$True)][EncryptionMethod]$EncryptionMethod,
        [Parameter(Mandatory=$True)][string]$RecoveryServiceEndpoint,
        [switch]$IgnoreEscrowRecoveryKeyFailure,
        [switch]$DoNotResumeSuspendedEncryption
        )

    Write-Debug("EncryptAndEscrowDataVolumes EncryptionMethod=$EncryptionMethod " +
        "RecoveryServiceEndpoint=$RecoveryServiceEndpoint " +
        "IgnoreEscrowRecoveryKeyFailure=$IgnoreEscrowRecoveryKeyFailure" +
        "DoNotResumeSuspendedEncryption=$DoNotResumeSuspendedEncryption")

    [system.array]$DevicesToEncrypt = @()
    [int]$fixedVolumeType = [MbamVolumeType]::FIXED_DATA_DRIVE
    [system.array]$volumes = Get-WmiObject -Query ("SELECT * FROM MBAM_Volume WHERE BitLockerManagementVolumeType = $fixedVolumeType") -Namespace $MbamWmiNamespace

    if ($volumes -ne $null)
    {
        foreach ($volume in $volumes)
        {
            [string]$deviceId = $volume.DeviceId
            $DevicesToEncrypt += @($deviceId)

            if (-not (IsProtectorPresent -DeviceId $deviceId -ProtectorType NUMERICALPASSWORD_PROTECTOR))
            {
                AddNumericalPasswordProtectorToVolume -DeviceId $deviceId
            }

            [uint32]$hResult = EscrowVolumeRecoveryInfo `
                -RecoveryServiceEndpoint $RecoveryServiceEndpoint `
                -DeviceId $deviceId `
                -IgnoreError:$IgnoreEscrowRecoveryKeyFailure
    
            if (-not (IsAutoUnlockProtectorPresent -DeviceId $deviceId))
            {
                AddAutoUnlockProtectorToDataVolume -DeviceId $DeviceId
            }

            if (IsEncryptionNeeded -DeviceId $DeviceId -DoNotResumeSuspendedEncryption:$DoNotResumeSuspendedEncryption)
            {
                StartEncrypting -EncryptionMethod $EncryptionMethod -DeviceId $deviceId
                EnableKeyProtectors -DeviceId $deviceId
            }
        }
    }
    
    Write-Debug("EncryptAndEscrowDataVolumes: Return " + $DevicesToEncrypt|Out-String)
    return $DevicesToEncrypt
}

Function GetEncryptableVolume()
{
<#
    .SYNOPSIS
        Lookup a volume from Win32_EncryptableVolume.

    .DESCRIPTION
        Lookups up the Win32_EncryptableVolume object for a given volume. Throws
        if the volume is not found.

    .PARAMETER DeviceId
        Device id to lookup.

    .RETURNVALUE
        Win32_EncryptableVolume Volume object for given device ID.
#>

    Param([Parameter(Mandatory=$True)][string]$DeviceId)

    [string]$id = (EscapeWmiString $DeviceId)
    [psobject]$volume = Get-WmiObject -Query ("SELECT * FROM Win32_EncryptableVolume WHERE DeviceId = '$id'") -Namespace $BitLockerWmiNamespace

    if ($volume -eq $Null)
    {
        Throw "Win32_EncryptableVolume WMI lookup failed to find device $DeviceId."
    }

    return $volume
}

Function EscapeWmiString([string]$stringToEscape)
{
<#
    .SYNOPSIS
        Internal helper to escape back slash characters in WMI strings.

    .PARAMETER stringToEscape
        String with backslashes to escape with double backslashes.

    .RETURNVALUE
        String with escaped backslash characters.
#>

    [string]$result = $stringToEscape.Replace("\", "\\")
    return $result
}

Function GetConversionStatus([psobject]$encryptableVolume)
{
<#
    .SYNOPSIS
        Internal helper for getting encryption status from a volume
#>

    [psobject]$conversionStatus = $encryptableVolume.GetConversionStatus()
    return $conversionStatus
}

Function WaitForEncryptionCompletion()
{
<#
    .SYNOPSIS
        Blocks until a drive is finished encrypting.

    .DESCRIPTION
        Polls until the conversion status on the device drops to 1 (Encrypted).

    .PARAMETER DeviceId
        The device ID to monitor.l
#>

    Param([Parameter(Mandatory=$True)][string]$DeviceId)
    Write-Debug "WaitForEncryptionCompletion DeviceId=$DeviceId"

    [psobject]$volume = GetEncryptableVolume -DeviceId $deviceId
    [bool]$complete = $False

    while (-not $complete)
    {
        $complete = $True
        [psobject]$conversionStatusObj = (GetConversionStatus $volume)

        if ($conversionStatusObj.ReturnValue -ne 0)
        {
            Throw "Error getting encryption status on device $DeviceId." + 
                (GetMbamWmiErrorMessage($conversionStatusObj.ReturnValue))
        }

        [ConversionStatus]$status = $conversionStatusObj.ConversionStatus

        if ($status -eq [ConversionStatus]::ENCRYPTION_IN_PROGRESS)
        {
            [uint32]$percentage = $conversionStatusObj.EncryptionPercentage
            Write-Host("Encryption of device $DeviceId is $percentage % complete")
            $complete = $False
        }

        if (-not $complete)
        {
            Write-Debug "WaitForEncryptionCompletion: Sleeping for 60 seconds/"
            Sleep -Seconds 60
        }
    }

    Write-Debug "WaitForEncryptionCompletion: Returned from function"
}

Function GetOsVersion
{
<#
    .SYNOPSIS
        Gets the OS version from WMI Win32_OperatingSystem.

    .DESCRIPTION
        Gets the OS version from WMI Win32_OperatingSystem as integer values.

    .RETURNVALUE
        An hash table with major and minor os version as uint32 values.
#>

    Write-Debug "GetOsVersion"

    # Split the WMI version into segments
    [psobject]$wmiVersion = (Get-WmiObject -Query ("SELECT * FROM Win32_OperatingSystem"))

    if ($wmiVersion -eq $Null)
    {
        Throw "WMI query to Win32_OperatingSystem failed."
    }

    [string[]]$osVersion = $wmiVersion.Version.Split('.')

    # OS version should be in a n.n.n format
    if ($osVersion.count -lt 2)
    {
        Throw "OS Version must have at least 2 segments."
    }

    # Convert the segments into integers for caller to use
    [uint32]$major = ($osVersion[0]);
    [uint32]$minor = ($osVersion[1]);

    # Return an array of major and minor OS version

    [hashtable]$version = @{}
    $version.major = $major
    $version.minor = $minor

    Write-Debug "GetOsVersion: Return Major=$version.major Minor=$version.minor"
    return $version
}

Function IsWindows7OrAbove()
{
<#
    .SYNOPSIS
        Minimum OS version checker.

    .DESCRIPTION
        Checks the OS version for a minimum of Windows 7.

    .RETURNVALUE
        True if Windows 7 or above, False otherwise.
#>

    Write-Debug "IsWindows7OrAbove"

    $retval = $False

    if ((((GetOsVersion).major -eq 6) -and ((GetOsVersion).minor -gt 0)) -or ((GetOsVersion).major -gt 6))
    {
        $retval = $True
    }

    Write-Debug "IsWindows7OrAbove: Return $retval"
    return $retval
 }

 Function IsDomainJoined()
 {
 <#
    .SYNOPSIS
        Checks that the computer is domain joined.

    .DESCRIPTION
        Queries Win32_ComputerSystem to see if computer is domain joined.

    .RETURNVALUE
        True is domain joined, False if not.
 #>

    Write-Debug "IsDomainJoined"

    [bool]$retval = $false
    [psobject] $computerSystemObj = Get-WmiObject Win32_ComputerSystem

    if (-not $computerSystemObj)
    {
        Throw "IsDomainJoined: Failed to get WMI Win32_ComputerSystem."
    }
 
    $retval = ($computerSystemObj.PartOfDomain -eq $True)

    Write-Debug "IsDomainJoined: Return $retval"
    return $retval
 }

Function ExecuteCommand()
{
<#
    .SYNOPSIS
        Executes a command.

    .DESCRIPTION
        Executes a command and captures output.

    .PARAMETER Command
        The command to execute.

    .PARAMETER ArgList
        A string containing the arguments to pass to the command.

    .RETURNVALUE
        A hash table with three named values: [uint32]ExitCode, [ArrayList]StdOut, [ArrayList]StdError) where:
            ExitCode is the process exit code.
            StdOut is an array of strings capturing stdout.
            StdErr is a string of all error output generated by the command.
#>

    Param(
        [Parameter(Mandatory=$True)][string]$Command, 
        [string]$ArgList
        )
    
    Write-Debug "ExecuteCommand Command=$Command ArgList=$ArgList"

    # Save the ErrorActionPreference
    $originalErrorActionPreference = $ErrorActionPreference

    # Set the ErrorActionPreference to hide errors
    $ErrorActionPreference = "SilentlyContinue"

    # Initialize the output vars
    [System.Collections.ArrayList]$stdout = @()
    [System.Collections.ArrayList]$stderr = @()
    [string]$errout = ""

    # The argument list is optional
    if ($ArgList -eq $Null)
    {
        $ArgList = ""
    }

    # Execute the command

    try
    {
        $global:LASTEXITCODE = 0
        $null =  Invoke-Expression "$Command $ArgList 2>''" -ErrorVariable stderr -OutVariable stdout
    }
    catch
    {
        # stderr and return code are used instead of exceptions
    }
    
    # Set ErrorActionPreference to the original value
    $ErrorActionPreference = $originalErrorActionPreference

    # Get the exception part of the ErrorRecord
    if ($stderr -and ($stderr.Count -gt 0))
    {
        $errout = $stderr[0].Exception.Message
    }

    [hashtable]$result = @{}
    $result.ExitCode = $LASTEXITCODE
    $result.StdOut = $stdout
    $result.StdErr = $errout

    # Clear the exit code to prevent MDT from reading it and signaling failure.
    $global:LASTEXITCODE = 0

    Write-Debug "ExecuteCommand: Return ExitCode=$result.ExitCode"
    Write-Debug "ExecuteCommand: Return StdErr="
    foreach ($line in $result.StdErr)
    {
        Write-Debug $line
    }
    Write-Debug "ExecuteCommand: Return StdOut="
    foreach ($line in $result.StdOut)
    {
        Write-Debug $line
    }
    
    return $result
}

Function FindCommand()
{
<#
    .SYNOPSIS
        Find a system command.

    .DESCRIPTION
        Looks for a command in system32 and sysnative directories. If the command
        is not found, an exception is thrown.

    .PARAMETER Command
        The name of the command to locate.

    .RETURNVALUE
        The full system path of the command if found. If not found, 
        the command is returned unchanged.
#>

    Param([Parameter(Mandatory=$True)][string]$Command)
    Write-Debug "FindCommand Command=$Command"

    [string]$systemRoot = (Get-ChildItem -Path Env:SystemRoot).Value
    [string]$commandToReturn = ""

    if (Test-Path -Path ("$systemRoot\system32\$Command"))
    {
        $commandToReturn = "$systemRoot\system32\$Command"
    }
    elseif (Test-Path -Path("$systemRoot\sysnative\$Command"))
    {
        $commandToReturn = "$systemRoot\sysnative\$Command"
    }
    else
    {
        Throw "System command $Command was not found."
    }

    Write-Debug "FindCommand: Return $commandToReturn"
    return $commandToReturn
}

Function IsElevated
{
<#
    .SYNOPSIS
        Check if script is running with Administrator privileges.

    .DESCRIPTION
        Check if script is running with Administrator privileges.

    .RETURNVALUE
        True if script is running with Administrator privileges.
#>

    Write-Debug "IsElevated"

    [System.Security.Principal.WindowsIdentity]$windowsIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    [System.Security.Principal.WindowsPrincipal]$windowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($windowsIdentity)
    [System.Security.Principal.WindowsBuiltInRole]$adminRole="Administrator"
    [bool]$elevated=$windowsPrincipal.IsInRole($adminRole)

    Write-Debug "IsElevated: Return $elevated"
    return $elevated
}

Function IsReadyForBitLocker()
{
<#
    .SYNOPSIS
        Wrapper to bdehdcfg -driveinfo.

    .DESCRIPTION
        Runs bdehdcfg -driveinfo to see if a machine is configured for BitLocker.
        If not ready for BitLocker, the full output of the bdehdcfg command is sent
        to stdout for debugging the reason.

    .RETURNVALUE
        True if computer is ready for BitLocker, False if not.
#>

    Write-Debug "IsReadyForBitLocker"

    [string]$command = FindCommand -Command "bdehdcfg.exe"
    [string]$arguments = "-driveinfo"

    $result = ExecuteCommand -Command $command -ArgList $arguments

    [bool]$found = ($result.ExitCode -eq $BDEHDCFG_E_BDECFG_READY_FOR_BITLOCKER)

    if (-not $found)
    {
        Write-Host "Failed to verify that computer is ready for BitLocker. Bdehdcfg.exe output:"

        foreach ($line in $result.StdOut)
        {
            Write-Host $line
        }
    }

    Write-Debug "IsReadyForBitLocker: Return $found"
    return $found
}

Function IsValidMbamVersion()
{
<#
    .SYNOPSIS
        Check if a valid version of MBAM is installed that supports the script.

    .DESCRIPTION
        Check if a valid version of MBAM is installed that supports the script.
        This script has dependency on the new WMI methods introduced in MBAM 2.5 SP1.

    .RETURNVALUE
        True if a valid version of MBAM is installed, False if not.
#>

    Write-Debug "IsValidMbamVersion"

    [bool]$retval = $false
    [string]$mbamRegKeyPath = "HKLM:\SOFTWARE\Microsoft\MBAM"

    # Check MBAM registry values: "Installed" should be 1 and "AgentVersion" should be at least "2.5.1000".
    if (Test-Path $mbamRegKeypath)
    {
        $mbamRegKey = (Get-Item $mbamRegKeyPath)
        [Int32]$installed = $mbamRegKey.GetValue("Installed")
        if ($installed -eq 1)
        {
            [Version]$mbamVersion = $mbamRegKey.GetValue("AgentVersion")
            if (($mbamVersion -ne $null))
            { 
                if (($mbamVersion.Major -gt 2) -or 
                    (($mbamVersion.Major -eq 2) -and ($mbamVersion.Minor -gt 5)) -or
                    (($mbamVersion.Major -eq 2) -and ($mbamVersion.Minor -eq 5) -and ($mbamVersion.Build -ge 1000)))
                {
                    $retval = $true
                }
            }
        }
    }

    Write-Debug "IsValidMbamVersion: Return $retval"
    return $retval
}

Function IsTpmPresent()
{
<#
    .SYNOPSIS
        Check if TPM is present.

    .DESCRIPTION
        Check if the computer has a 1.2 TPM or later.
        If TPM is turned off in the BIOS, this function will return False.

    .RETURNVALUE
        True if TPM is present, False if not.
#>

    Write-Debug "IsTpmPresent"

    [bool]$retval = $false

    # Get the Win32_Tpm WMI instance and check the version.
    [psobject]$tpm = Get-WmiObject -Query ("SELECT * FROM Win32_Tpm") -Namespace $TpmWmiNamespace
    if ($tpm -ne $null)
    {
        [Version]$tpmVersion = (GetTpmVersionFromSpecVersion $tpm.SpecVersion)
        if (($tpmVersion.Major -gt 1) -or
            (($tpmVersion.Major -eq 1) -and ($tpmVersion.Minor -ge 2)))
        {
            $retval = $True
        }
    }

    Write-Debug "IsTpmPresent: Return $retval"
    return $retval
}

Function GetTpmVersionFromSpecVersion()
{
<#
    .SYNOPSIS
        Get TPM major and minor version from TPM specification version.

    .DESCRIPTION
        Get TPM major and minor version from TPM specification version. 
        A TPM spec version includes the major and minor TCG specification version,
        the specification revision level, and the errata revision level, e.g. "1.2, 2, 0".
        We are only interested in the major and minor version.

    .PARAMETER TpmSpecVersion
        TPM specification version.

    .RETURNVALUE
        TPM major and minor version.
#>

    Param([Parameter(Mandatory=$True)][string]$specVersion)
    Write-Debug "GetTpmVersionFromSpecVersion"

    [string]$version = ""

    try
    {
        # Extract the hexadecimal major and minor version and convert to decimal.
        ([string]$hexMajor, [string]$hexMinor) = $specVersion.split(",")[0].Trim().split(".")
        [string]$major = [Convert]::ToInt32($hexMajor, 16)
        [string]$minor = [Convert]::ToInt32($hexMinor, 16)
        $version = ($major + "." + $minor)
    }
    catch
    {
        Throw "Failed to get the TPM version from TPM specification version: $specVersion."
    }

    Write-Debug "GetTpmVersionFromSpecVersion: Return $version"
    return $version
}

<#Function IsMbamPolicyApplied()
{
<#
    .SYNOPSIS
        Determines if MBAM policy has been applied to the machine.

    .DESCRIPTION
       Determines if MBAM policy has been applied to the machine. This script
       may not succeed it MBAM policy is detected.

    .RETURNVALUE
        True if MBAM policy is detected, False otherwise.
#>

    #[psobject]$mbamVolume = Get-WmiObject -Query ("SELECT Compliant FROM Mbam_Volume WHERE BitLockerManagementVolumeType = '1'") -Namespace $MbamWmiNamespace

   # if ($mbamVolume -eq $null)
    #{
     #   Throw "Failed to execute WMI Mbam_Volume.EscrowRecoveryKey. Make sure MBAM client is 2.5 SP1 or greater."
    #}

   # return -not ($mbamVolume.Compliant -eq "2")
#>}


###############################################################################
#
# Main script section
#
###############################################################################

Function Invoke-MbamClientDeployment()
{
<#
    .SYNOPSIS
        Configures a client machine for MBAM

    .DESCRIPTION
        Encrypts a computer and escrows the BitLocker recovery keys with MBAM

    .PARAMETER RecoveryServiceEndpoint
        MBAM recovery service endpoint URL.

    .PARAMETER StatusReportingServiceEndpoint
        MBAM status reporting service endpoint URL.

    .PARAMETER EncryptionMethod
        BitLocker encryption method.

    .PARAMETER EncryptAndEscrowDataVolumes
        Encrypt non-removable data volumes.

    .PARAMETER WaitForEncryptionToComplete
        If present, script will block until all drives are encrypted.

    .PARAMETER IgnoreEscrowOwnerAuthFailure
        If present, failure escrow the TPM owner with MBAM will not cause an exception.

    .PARAMETER IgnoreEscrowRecoveryKeyFailure
        If present, failure to escrow BitLocker recovery key will not cause an exception.

    .PARAMETER IgnoreReportStatusFailure
        If present, failure to report status will not cause an exception.

    .PARAMETER DoNotResumeSuspendedEncryption
        If present, suspended encryption will not be resumed.

    .RETURNVALUE
        Returns 0 on success
#>

    Param(
        [Parameter(HelpMessage="URL of MBAM recovery service endpoint")][string]$RecoveryServiceEndpoint = $null,
        [Parameter(HelpMessage="URL of MBAM reporting service endpoint")][string]$StatusReportingServiceEndpoint = $null,
        [Parameter(HelpMessage="Default is AES128")][string]$EncryptionMethod = "AES128",
        [switch]$EncryptAndEscrowDataVolumes,
        [switch]$WaitForEncryptionToComplete,
        [switch]$IgnoreEscrowOwnerAuthFailure,
        [switch]$IgnoreEscrowRecoveryKeyFailure,
        [switch]$IgnoreReportStatusFailure,
        [switch]$DoNotResumeSuspendedEncryption
        )

    if ([string]::IsNullOrEmpty($RecoveryServiceEndpoint))
    {
        Throw "RecoveryServiceEndpoint is required."
    }

    # Redefine encryption method as enum

    [EncryptionMethod]$EncryptionMethod = $EncryptionMethod

    Write-Debug("RecoveryServiceEndpoint is $RecoveryServiceEndpoint")
    Write-Debug("StatusReportingServiceEndpoint is $StatusReportingServiceEndpoint")

    #
    # Prerequisite check
    #

    Write-Host "Checking prerequisites ..."

    if (-not (IsElevated))
    {
        Throw "Script must run with elevated privileges."
    }

    if (-not (IsWindows7OrAbove))
    {
        Throw "MBAM client deployment is only supported on Windows 7 or greater."
    }

    if (-not (IsValidMbamVersion))
    {
        Throw "MBAM client deployment is only supported on MBAM 2.5 SP1 or greater."
    }

    if (-not (IsDomainJoined))
    {
        Throw "System must be domain joined."
    }
    
    #if (IsMbamPolicyApplied)
    #{
    #    Throw "MBAM policy was detected. Verify that the OU used for pre-deployment does not apply MBAM policy."
    #}

    if (-not (IsTpmPresent))
    {
        Write-Host "Compatible TPM cannot be found on this computer. The volumes will not be encrypted. MBAM client deployment requires 1.2 TPM or later.";
        return # exit without throwing exception
    }

    if (-not (IsReadyForBitLocker))
    {
        Throw "System is not ready for BitLocker. Verify that a BDE partition exists."
    }

    #
    # Prepare the TPM and escrow Owner-Auth
    #

    Write-Host "Preparing TPM and escrowing owner-auth to $RecoveryServiceEndpoint ..."

    [uint32]$hResult = (PrepareTpmAndEscrowOwnerAuth `
        -RecoveryServiceEndpoint $RecoveryServiceEndpoint `
        -IgnoreEscrowOwnerAuthFailure:$IgnoreEscrowOwnerAuthFailure)

    #
    # Add the TPM protector if no protector exists that uses TPM.
    #

    Write-Host "Adding TPM protector to OS volume ..."

    [string]$deviceId = GetOsDeviceId
    if (-not (IsTpmProtectorPresent -DeviceId $deviceId))
    {
        AddTpmProtectorToOsVolume
    }
    
    #
    # Encrypt the OS volume and Escrow recovery key with MBAM
    #

    Write-Host "Escrowing OS volume recovery key to $RecoveryServiceEndpoint and starting encryption ..."

    [system.array]$VolumesToEncrypt = EncryptAndEscrowOsVolume `
        -EncryptionMethod $EncryptionMethod `
        -RecoveryServiceEndpoint $RecoveryServiceEndpoint `
        -IgnoreEscrowRecoveryKeyFailure:$IgnoreEscrowRecoveryKeyFailure `
        -DoNotResumeSuspendedEncryption:$DoNotResumeSuspendedEncryption

    #
    # Encrypt the data volume(s) and Escrow recovery keys with MBAM
    #

    if ($EncryptAndEscrowDataVolumes)
    {
        Write-Host "Escrowing data volume recovery key(s) to $RecoveryServiceEndpoint and starting encryption ..."

        $VolumesToEncrypt += EncryptAndEscrowDataVolumes `
            -EncryptionMethod $EncryptionMethod `
            -RecoveryServiceEndpoint $RecoveryServiceEndpoint `
            -IgnoreEscrowRecoveryKeyFailure:$IgnoreEscrowRecoveryKeyFailure `
            -DoNotResumeSuspendedEncryption:$DoNotResumeSuspendedEncryption
    }

    #
    # Wait for encryption to complete on all volumes
    #

    if ($WaitForEncryptionToComplete)
    {
        foreach ($deviceId in $VolumesToEncrypt)
        {
            if (($deviceId -ne $null) -and (![string]::IsNullOrEmpty($deviceId)))
            {
                WaitForEncryptionCompletion -DeviceId $deviceId
            }
        }
    }

    #
    # Report system status to MBAM
    #

    if (($StatusReportingServiceEndpoint -ne $null) -and (![string]::IsNullOrEmpty($StatusReportingServiceEndpoint)))
    {
        Write-Host "Reporting encryption status to $StatusReportingServiceEndpoint ..."

        [uint32]$hResult = (ReportStatus `
            -ReportingServiceEndpoint $StatusReportingServiceEndpoint `
            -IgnoreError:$IgnoreReportStatusFailure)
    }

    #
    # Set the registry to indicate a first run so the MBAM agent can
    # ask for a PIN/Password once on first login.
    #

    Set-ItemProperty -Path HKLM:\Software\Microsoft\Mbam -Name EnactOnFirstLoginRequired -Value 1 -Type DWord
}

###############################################################################
#
# Script Main
#
###############################################################################

# If unit testing, don't call Invoke-MbamClientDeployment since parameters
# will not be available

if ((Test-Path variable:IsPesterInUse) -and $IsPesterInUse)
{
    return
}

Invoke-MbamClientDeployment `
    -RecoveryServiceEndpoint:$RecoveryServiceEndpoint `
    -StatusReportingServiceEndpoint:$StatusReportingServiceEndpoint `
    -EncryptionMethod:$EncryptionMethod `
    -EncryptAndEscrowDataVolumes:$EncryptAndEscrowDataVolumes `
    -WaitForEncryptionToComplete:$WaitForEncryptionToComplete `
    -IgnoreEscrowOwnerAuthFailure:$IgnoreEscrowOwnerAuthFailure `
    -IgnoreEscrowRecoveryKeyFailure:$IgnoreEscrowRecoveryKeyFailure `
    -IgnoreReportStatusFailure:$IgnoreReportStatusFailure `
    -DoNotResumeSuspendedEncryption:$DoNotResumeSuspendedEncryption

# SIG # Begin signature block
# MIIa9AYJKoZIhvcNAQcCoIIa5TCCGuECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUJaw5PEHKoscahbc2y4/+HUyq
# ntmgghWCMIIEwzCCA6ugAwIBAgITMwAAAHD0GL8jIfxQnQAAAAAAcDANBgkqhkiG
# 9w0BAQUFADB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEw
# HwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwHhcNMTUwMzIwMTczMjAy
# WhcNMTYwNjIwMTczMjAyWjCBszELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjENMAsGA1UECxMETU9QUjEnMCUGA1UECxMebkNpcGhlciBEU0UgRVNO
# OkY1MjgtMzc3Ny04QTc2MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoxTZ7xygeRG9
# LZoEnSM0gqVCHSsA0dIbMSnIKivzLfRui93iG/gT9MBfcFOv5zMPdEoHFGzcKAO4
# Kgp4xG4gjguAb1Z7k/RxT8LTq8bsLa6V0GNnsGSmNAMM44quKFICmTX5PGTbKzJ3
# wjTuUh5flwZ0CX/wovfVkercYttThkdujAFb4iV7ePw9coMie1mToq+TyRgu5/YK
# VA6YDWUGV3eTka+Ur4S+uG+thPT7FeKT4thINnVZMgENcXYAlUlpbNTGNjpaMNDA
# ynOJ5pT2Ix4SYFEACMHe2j9IhO21r9TTmjiVqbqjWLV4aEa/D4xjcb46Q0NZEPBK
# unvW5QYT3QIDAQABo4IBCTCCAQUwHQYDVR0OBBYEFG3P87iErvfMdr24e6w9l2GB
# dCsnMB8GA1UdIwQYMBaAFCM0+NlSRnAK7UD7dvuzK7DDNbMPMFQGA1UdHwRNMEsw
# SaBHoEWGQ2h0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3Rz
# L01pY3Jvc29mdFRpbWVTdGFtcFBDQS5jcmwwWAYIKwYBBQUHAQEETDBKMEgGCCsG
# AQUFBzAChjxodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY3Jv
# c29mdFRpbWVTdGFtcFBDQS5jcnQwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZI
# hvcNAQEFBQADggEBAF46KvVn9AUwKt7hue9n/Cr/bnIpn558xxPDo+WOPATpJhVN
# 98JnglwKW8UK7lXwoy2Ooh2isywt0BHimioB0TAmZ6GmbokxHG7dxHFU8Ami3cHW
# NnPADP9VCGv8oZT9XSwnIezRIwbcBCzvuQLbA7tHcxgK632ZzV8G4Ij3ipPFEhEb
# 81KVo3Kg0ljZwyzia3931GNT6oK4L0dkKJjHgzvxayhh+AqIgkVSkumDJklct848
# mn+voFGTxby6y9ErtbuQGQqmp2p++P0VfkZEh6UG1PxKcDjG6LVK9NuuL+xDyYmi
# KMVV2cG6W6pgu6W7+dUCjg4PbcI1cMCo7A2hsrgwggTsMIID1KADAgECAhMzAAAB
# Cix5rtd5e6asAAEAAAEKMA0GCSqGSIb3DQEBBQUAMHkxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xIzAhBgNVBAMTGk1pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBMB4XDTE1MDYwNDE3NDI0NVoXDTE2MDkwNDE3NDI0NVowgYMxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xDTALBgNVBAsTBE1PUFIx
# HjAcBgNVBAMTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBAJL8bza74QO5KNZG0aJhuqVG+2MWPi75R9LH7O3HmbEm
# UXW92swPBhQRpGwZnsBfTVSJ5E1Q2I3NoWGldxOaHKftDXT3p1Z56Cj3U9KxemPg
# 9ZSXt+zZR/hsPfMliLO8CsUEp458hUh2HGFGqhnEemKLwcI1qvtYb8VjC5NJMIEb
# e99/fE+0R21feByvtveWE1LvudFNOeVz3khOPBSqlw05zItR4VzRO/COZ+owYKlN
# Wp1DvdsjusAP10sQnZxN8FGihKrknKc91qPvChhIqPqxTqWYDku/8BTzAMiwSNZb
# /jjXiREtBbpDAk8iAJYlrX01boRoqyAYOCj+HKIQsaUCAwEAAaOCAWAwggFcMBMG
# A1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBSJ/gox6ibN5m3HkZG5lIyiGGE3
# NDBRBgNVHREESjBIpEYwRDENMAsGA1UECxMETU9QUjEzMDEGA1UEBRMqMzE1OTUr
# MDQwNzkzNTAtMTZmYS00YzYwLWI2YmYtOWQyYjFjZDA1OTg0MB8GA1UdIwQYMBaA
# FMsR6MrStBZYAck3LjMWFrlMmgofMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9j
# cmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY0NvZFNpZ1BDQV8w
# OC0zMS0yMDEwLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6
# Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljQ29kU2lnUENBXzA4LTMx
# LTIwMTAuY3J0MA0GCSqGSIb3DQEBBQUAA4IBAQCmqFOR3zsB/mFdBlrrZvAM2PfZ
# hNMAUQ4Q0aTRFyjnjDM4K9hDxgOLdeszkvSp4mf9AtulHU5DRV0bSePgTxbwfo/w
# iBHKgq2k+6apX/WXYMh7xL98m2ntH4LB8c2OeEti9dcNHNdTEtaWUu81vRmOoECT
# oQqlLRacwkZ0COvb9NilSTZUEhFVA7N7FvtH/vto/MBFXOI/Enkzou+Cxd5AGQfu
# FcUKm1kFQanQl56BngNb/ErjGi4FrFBHL4z6edgeIPgF+ylrGBT6cgS3C6eaZOwR
# XU9FSY0pGi370LYJU180lOAWxLnqczXoV+/h6xbDGMcGszvPYYTitkSJlKOGMIIF
# vDCCA6SgAwIBAgIKYTMmGgAAAAAAMTANBgkqhkiG9w0BAQUFADBfMRMwEQYKCZIm
# iZPyLGQBGRYDY29tMRkwFwYKCZImiZPyLGQBGRYJbWljcm9zb2Z0MS0wKwYDVQQD
# EyRNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMTAwODMx
# MjIxOTMyWhcNMjAwODMxMjIyOTMyWjB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSMwIQYDVQQDExpNaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBD
# QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJyWVwZMGS/HZpgICBC
# mXZTbD4b1m/My/Hqa/6XFhDg3zp0gxq3L6Ay7P/ewkJOI9VyANs1VwqJyq4gSfTw
# aKxNS42lvXlLcZtHB9r9Jd+ddYjPqnNEf9eB2/O98jakyVxF3K+tPeAoaJcap6Vy
# c1bxF5Tk/TWUcqDWdl8ed0WDhTgW0HNbBbpnUo2lsmkv2hkL/pJ0KeJ2L1TdFDBZ
# +NKNYv3LyV9GMVC5JxPkQDDPcikQKCLHN049oDI9kM2hOAaFXE5WgigqBTK3S9dP
# Y+fSLWLxRT3nrAgA9kahntFbjCZT6HqqSvJGzzc8OJ60d1ylF56NyxGPVjzBrAlf
# A9MCAwEAAaOCAV4wggFaMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFMsR6MrS
# tBZYAck3LjMWFrlMmgofMAsGA1UdDwQEAwIBhjASBgkrBgEEAYI3FQEEBQIDAQAB
# MCMGCSsGAQQBgjcVAgQWBBT90TFO0yaKleGYYDuoMW+mPLzYLTAZBgkrBgEEAYI3
# FAIEDB4KAFMAdQBiAEMAQTAfBgNVHSMEGDAWgBQOrIJgQFYnl+UlE/wq4QpTlVnk
# pDBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtp
# L2NybC9wcm9kdWN0cy9taWNyb3NvZnRyb290Y2VydC5jcmwwVAYIKwYBBQUHAQEE
# SDBGMEQGCCsGAQUFBzAChjhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2Nl
# cnRzL01pY3Jvc29mdFJvb3RDZXJ0LmNydDANBgkqhkiG9w0BAQUFAAOCAgEAWTk+
# fyZGr+tvQLEytWrrDi9uqEn361917Uw7LddDrQv+y+ktMaMjzHxQmIAhXaw9L0y6
# oqhWnONwu7i0+Hm1SXL3PupBf8rhDBdpy6WcIC36C1DEVs0t40rSvHDnqA2iA6VW
# 4LiKS1fylUKc8fPv7uOGHzQ8uFaa8FMjhSqkghyT4pQHHfLiTviMocroE6WRTsgb
# 0o9ylSpxbZsa+BzwU9ZnzCL/XB3Nooy9J7J5Y1ZEolHN+emjWFbdmwJFRC9f9Nqu
# 1IIybvyklRPk62nnqaIsvsgrEA5ljpnb9aL6EiYJZTiU8XofSrvR4Vbo0HiWGFzJ
# NRZf3ZMdSY4tvq00RBzuEBUaAF3dNVshzpjHCe6FDoxPbQ4TTj18KUicctHzbMrB
# 7HCjV5JXfZSNoBtIA1r3z6NnCnSlNu0tLxfI5nI3EvRvsTxngvlSso0zFmUeDord
# EN5k9G/ORtTTF+l5xAS00/ss3x+KnqwK+xMnQK3k+eGpf0a7B2BHZWBATrBC7E7t
# s3Z52Ao0CW0cgDEf4g5U3eWh++VHEK1kmP9QFi58vwUheuKVQSdpw5OPlcmN2Jsh
# rg1cnPCiroZogwxqLbt2awAdlq3yFnv2FoMkuYjPaqhHMS+a3ONxPdcAfmJH0c6I
# ybgY+g5yjcGjPa8CQGr/aZuW4hCoELQ3UAjWwz0wggYHMIID76ADAgECAgphFmg0
# AAAAAAAcMA0GCSqGSIb3DQEBBQUAMF8xEzARBgoJkiaJk/IsZAEZFgNjb20xGTAX
# BgoJkiaJk/IsZAEZFgltaWNyb3NvZnQxLTArBgNVBAMTJE1pY3Jvc29mdCBSb290
# IENlcnRpZmljYXRlIEF1dGhvcml0eTAeFw0wNzA0MDMxMjUzMDlaFw0yMTA0MDMx
# MzAzMDlaMHcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xITAf
# BgNVBAMTGE1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQTCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBAJ+hbLHf20iSKnxrLhnhveLjxZlRI1Ctzt0YTiQP7tGn
# 0UytdDAgEesH1VSVFUmUG0KSrphcMCbaAGvoe73siQcP9w4EmPCJzB/LMySHnfL0
# Zxws/HvniB3q506jocEjU8qN+kXPCdBer9CwQgSi+aZsk2fXKNxGU7CG0OUoRi4n
# rIZPVVIM5AMs+2qQkDBuh/NZMJ36ftaXs+ghl3740hPzCLdTbVK0RZCfSABKR2YR
# JylmqJfk0waBSqL5hKcRRxQJgp+E7VV4/gGaHVAIhQAQMEbtt94jRrvELVSfrx54
# QTF3zJvfO4OToWECtR0Nsfz3m7IBziJLVP/5BcPCIAsCAwEAAaOCAaswggGnMA8G
# A1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFCM0+NlSRnAK7UD7dvuzK7DDNbMPMAsG
# A1UdDwQEAwIBhjAQBgkrBgEEAYI3FQEEAwIBADCBmAYDVR0jBIGQMIGNgBQOrIJg
# QFYnl+UlE/wq4QpTlVnkpKFjpGEwXzETMBEGCgmSJomT8ixkARkWA2NvbTEZMBcG
# CgmSJomT8ixkARkWCW1pY3Jvc29mdDEtMCsGA1UEAxMkTWljcm9zb2Z0IFJvb3Qg
# Q2VydGlmaWNhdGUgQXV0aG9yaXR5ghB5rRahSqClrUxzWPQHEy5lMFAGA1UdHwRJ
# MEcwRaBDoEGGP2h0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1
# Y3RzL21pY3Jvc29mdHJvb3RjZXJ0LmNybDBUBggrBgEFBQcBAQRIMEYwRAYIKwYB
# BQUHMAKGOGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljcm9z
# b2Z0Um9vdENlcnQuY3J0MBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEB
# BQUAA4ICAQAQl4rDXANENt3ptK132855UU0BsS50cVttDBOrzr57j7gu1BKijG1i
# uFcCy04gE1CZ3XpA4le7r1iaHOEdAYasu3jyi9DsOwHu4r6PCgXIjUji8FMV3U+r
# kuTnjWrVgMHmlPIGL4UD6ZEqJCJw+/b85HiZLg33B+JwvBhOnY5rCnKVuKE5nGct
# xVEO6mJcPxaYiyA/4gcaMvnMMUp2MT0rcgvI6nA9/4UKE9/CCmGO8Ne4F+tOi3/F
# NSteo7/rvH0LQnvUU3Ih7jDKu3hlXFsBFwoUDtLaFJj1PLlmWLMtL+f5hYbMUVbo
# nXCUbKw5TNT2eb+qGHpiKe+imyk0BncaYsk9Hm0fgvALxyy7z0Oz5fnsfbXjpKh0
# NbhOxXEjEiZ2CzxSjHFaRkMUvLOzsE1nyJ9C/4B5IYCeFTBm6EISXhrIniIh0EPp
# K+m79EjMLNTYMoBMJipIJF9a6lbvpt6Znco6b72BJ3QGEe52Ib+bgsEnVLaxaj2J
# oXZhtG6hE6a/qkfwEm/9ijJssv7fUciMI8lmvZ0dhxJkAj0tr1mPuOQh5bWwymO0
# eFQF1EEuUKyUsKV4q7OglnUa2ZKHE3UiLzKoCG6gW4wlv6DvhMoh1useT8ma7kng
# 9wFlb4kLfchpyOZu6qeXzjEp/w7FW1zYTRuh2Povnj8uVRZryROj/TGCBNwwggTY
# AgEBMIGQMHkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xIzAh
# BgNVBAMTGk1pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBAhMzAAABCix5rtd5e6as
# AAEAAAEKMAkGBSsOAwIaBQCggfUwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFDYh
# kiGKNfOkJt4phNN9NKJF/JhNMIGUBgorBgEEAYI3AgEMMYGFMIGCoGSAYgBNAGkA
# YwByAG8AcwBvAGYAdAAgAEIAaQB0AEwAbwBjAGsAZQByACAAQQBkAG0AaQBuAGkA
# cwB0AHIAYQB0AGkAbwBuACAAYQBuAGQAIABNAG8AbgBpAHQAbwByAGkAbgBnoRqA
# GGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTANBgkqhkiG9w0BAQEFAASCAQAzOHe2
# h3KbgPlrdTtcxNZxleGRd6N+VqLaS3404VbrVn2EJISjZPNIuKx6DyL+h+k4QTFI
# aSeVZwmrB20118vkYTSUMvVL2Vtwt9uuOdiGhTzNOlnZFHnZscXxyvH2h7Nb2tRW
# MZhEbovAfe51CZ3HZIo3xHS6juEStTGRA8uqkZFJd5cSMK2N2OVPftQckDo2IJJR
# cC7aAdI1KKtLj2XP2hgIhzhDmXUVwqL+rCwQhE7GVbBbWUw9bNY2NpiKJNAfnYfT
# MsqD+SSxs/+9KYQlfp2h1JlXeJMu/ks0qr4DczI71jOj5ql11b22K8MfYyuO4v7Z
# usTbJf29Zv4AZn0VoYICKDCCAiQGCSqGSIb3DQEJBjGCAhUwggIRAgEBMIGOMHcx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xITAfBgNVBAMTGE1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQQITMwAAAHD0GL8jIfxQnQAAAAAAcDAJBgUr
# DgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUx
# DxcNMTUwNjE4MjMyOTAyWjAjBgkqhkiG9w0BCQQxFgQUJMu1AbCXcaDX0qt+XZAr
# vHZvmsMwDQYJKoZIhvcNAQEFBQAEggEAOzpezHed1Rs/SI7cKQNrNc7s8zN4jVvZ
# hV43NiAQrjm4v650doYglz4H+iwkx3efSXCYDeVvVQ8Ep89DQm2TLnHiPiMI0l8W
# 9YNJvlJyKDOtau76ilmBhzP+hqn6OXKM2kIpzkt7kYtyKbntkd2Kmu7K6Qe62lBp
# RZwdAr/vv+DomNFDDmIMA++fctliY8DoF5+MUuTz8b5NxUDcSuOxHhC9rVg3Oiq0
# ObSxTKzsa0Emlzqpy44rNjUK72gjOsChbxLn44qSCLGQ9iZtIoeHceVHUp/oLo5U
# 4P9F62FPzXeFwp7PdpsJgHHS1//k2Eh5+5p5QdU3N23hnav9tT3FOA==
# SIG # End signature block
