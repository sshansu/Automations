<#
This sample script is not supported under any Microsoft standard support program or service.
The sample script is provided AS IS without warranty of any kind.
Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
The entire risk arising out of the use or performance of the sample scripts and documentation remains with you.
In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, #without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages
#>

$TenantID=""
$GraphAppId = "14d82eec-204b-4c2f-b7e8-296a70dab67e" 
$DisplayName="Automation Account Name" 
$Permissions = @(
    'DeviceManagementManagedDevices.Read.All'
    'Device.Read.All'
    'WindowsUpdates.ReadWrite.All'
    'DeviceManagementServiceConfig.Read.All'
    'Directory.Read.All'
    'DeviceManagementConfiguration.Read.All'
    'Organization.Read.All'
    'DeviceManagementApps.Read.All'
)
# Install the module (You need admin on the machine)
Install-Module AzureAD 

Connect-AzureAD -TenantId $TenantID 
$MSI = (Get-AzureADServicePrincipal -Filter "displayName eq '$DisplayName'")
$GraphServicePrincipal = Get-AzureADServicePrincipal -Filter "appId eq '$GraphAppId'"
foreach ($Permission in $Permissions)
{
    $AppRole = $GraphServicePrincipal.AppRoles | 
        Where-Object {$_.Value -eq $Permission -and $_.AllowedMemberTypes -contains "Application"}
    New-AzureAdServiceAppRoleAssignment -ObjectId $MSI.ObjectId -PrincipalId $MSI.ObjectId -ResourceId $GraphServicePrincipal.ObjectId -Id $AppRole.Id
}