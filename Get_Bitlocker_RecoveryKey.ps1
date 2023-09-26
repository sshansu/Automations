<#
This sample script is not supported under any Microsoft standard support program or service.
The sample script is provided AS IS without warranty of any kind.
Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
The entire risk arising out of the use or performance of the sample scripts and documentation remains with you.
In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, #without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages
#>
##################################################################################
#Gets Bitlocker Recovery key for Azure AD device and writes to output.
#
##################################################################################

# Connect to Microsoft Graph with required scopes
Connect-MgGraph -Scopes BitLockerKey.Read.All, DeviceManagementManagedDevices.Read.All, DeviceManagementManagedDevices.ReadWrite.All

# Get device names from a file
$devicesnames = Get-Content C:\temp\IntuneDeviceName.txt 
$table = @()

# Create a table of devices
foreach ($name in $devicesnames) {
    $devices = Get-MgDeviceManagementManagedDevice -Filter "DeviceName eq '$($name)'" | select AzureAdDeviceId, DeviceName 
    $table += New-Object -TypeName PSCustomObject -Property @{
        AzureADid = $devices.AzureAdDeviceId
        DeviceName = $devices.DeviceName 
    }
}

# Initialize a hash table to store results
$results = @{}

# Loop over devices in the table
foreach ($device in $table) {
    Write-Host "Working on '$($device.DeviceName)'" -ForegroundColor Green

    # Retrieve BitLocker recovery keys for the device
    $recoveryKeys = Get-MgInformationProtectionBitlockerRecoveryKey -Filter "DeviceId eq '$($device.AzureADid)'" | 
                    select Id, CreatedDateTime, DeviceId, VolumeType, @{
                        Name = "Key"
                        Expression = {
                            $recoveryKey = (Get-MgInformationProtectionBitlockerRecoveryKey -BitlockerRecoveryKeyId $_.Id -Property key).key
                            if ([string]::IsNullOrEmpty($recoveryKey)) {
                                "Not applicable"
                            } else {
                                $recoveryKey
                            }
                        }
                    }

    # Sort the recovery keys by CreatedDateTime in descending order to get the latest key
    $latestRecoveryKey = $recoveryKeys | Sort-Object -Property CreatedDateTime -Descending | Select-Object -First 1

    # Calculate the total recovery key count
    $recoveryKeyCount = $recoveryKeys.key.Count

    # If there are no recovery keys, set RecoveryKeyCount to 0
    if ($recoveryKeyCount -eq 0) {
        $recoveryKeyCount = 0
    }

    # Store the latest recovery key and RecoveryKeyCount in the results
    $results[$device.DeviceName] = [PSCustomObject]@{
        "DeviceDisplayName" = $device.DeviceName  # Added DeviceDisplayName as the first column
        "Bitlocker ID" = $latestRecoveryKey.Id
        "DeviceId" = $device.AzureADid
        "CreatedDateTime" = $latestRecoveryKey.CreatedDateTime
        "Key" = $latestRecoveryKey.Key
        "VolumeType" = $latestRecoveryKey.VolumeType
        "RecoveryKeyCount" = $recoveryKeyCount
    }
}

# Generate a date and time stamp for the CSV file name
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$csvPath = "C:\IntuneExport\BitlockerRecoveryKeys_$timestamp.csv"

# Export the results to the CSV file
$results.Values | Export-Csv -Path $csvPath -NoTypeInformation

