<#
This sample script is not supported under any Microsoft standard support program or service.
The sample script is provided AS IS without warranty of any kind.
Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
The entire risk arising out of the use or performance of the sample scripts and documentation remains with you.
In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever 
(including, #without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or 
inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages

THIS SCRIPT WILL BE USED AS AN AZURE AUTOMATION SCRIPT WHICH WILL UPDATE A STORAGE ACCOUNT TABLE WITH A COMPUTER NAME. 
the computer name will be later rendered by machines during Autopilot process and then applied.
#>

Connect-AzAccount -identity | out-null

$ResourceGroup = "XSCloudAzAuto"
$Storage = "cloudrep"
$Table = "deviceName"
$partitionKey1 = "DeviceName"
$Prefix = "Arcade-"

$StorContext = Get-AzStorageAccount -ResourceGroupName $ResourceGroup -Name $Storage
$table = Get-AzStorageTable -Name $Table -Context $StorContext.Context
$devname = $table.CloudTable

# Get last value
$lastvalue = Get-AzTableRow -Table $devname | select -ExpandProperty rowkey

#Create new name
#sleep 1
[int]$i = ($lastvalue).Split("$($Prefix)").trim() | select -Last 1
#sleep 1
[int]$newint = [int]$i+1
$newname = "$($Prefix)" + "0" + $([int]$newint)

#Write-output "New name generated: $($newname)"

# Create new entry
Add-AzTableRow -table $devname -partitionKey $partitionKey1 -rowKey ($($newname)) | out-null

#Remove previous
# Create a filter and get the entity to be updated.
[string]$filter = `
    [Microsoft.Azure.Cosmos.Table.TableQuery]::GenerateFilterCondition("RowKey",`
    [Microsoft.Azure.Cosmos.Table.QueryComparisons]::Equal,$($lastvalue))

$device = Get-AzTableRow -table $devname -customFilter $filter

# Delete row.
$device | Remove-AzTableRow -table $devname
#Write-output "Previous name deleted: $($device.RowKey)"

$q = $newname | convertto-json
return $q

#Write-output $newname 

