<#
This sample script is not supported under any Microsoft standard support program or service.
The sample script is provided AS IS without warranty of any kind.
Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
The entire risk arising out of the use or performance of the sample scripts and documentation remains with you.
In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, #without limitation, damages for 
loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if 
Microsoft has been advised of the possibility of such damages

This script requires azure application registered with below permissions granted to graph API

Device.Read.All
Device.Read
DeviceManagementApps.Read.All
DeviceManagementConfiguration.Read.All
DeviceManagementServiceConfig.Read.All
Directory.Read.All

For the script to work, you must have exported the imported GPO settings in a CSV Format. We'll have to execute Export_GPOSettings_from_GPOAnalytics.ps1 first. 
#>

#$global:authToken = $null
$global:TenantID = ""
$global:ClientID = ""
$global:ClientSecret = ""
#>

####################################################
Function Get-AuthToken {
	<#
	.SYNOPSIS
	This function is used to get an auth_token for the Microsoft Graph API
	.DESCRIPTION
	The function authenticates with the Graph API Interface with client credentials to get an access_token for working with the REST API
	.EXAMPLE
	Get-AuthToken -TenantID "0000-0000-0000" -ClientID "0000-0000-0000" -ClientSecret "sw4t3ajHTwaregfasdgAWREGawrgfasdgAWREGw4t24r"
	Authenticates you with the Graph API interface and creates the AuthHeader to use when invoking REST Requests
	.NOTES
	NAME: Get-AuthToken
	#>
	param(
		[Parameter(Mandatory=$true)]
		$TenantID,
		[Parameter(Mandatory=$true)]
		$ClientID,
		[Parameter(Mandatory=$true)]
		$ClientSecret
	)
	try{
		# Define parameters for Microsoft Graph access token retrieval
		$resource = "https://graph.microsoft.com"
		$authority = "https://login.microsoftonline.com/$TenantID"
		$tokenEndpointUri = "$authority/oauth2/token"

		# Get the access token using grant type client_credentials for Application Permissions
		$content = "grant_type=client_credentials&client_id=$ClientID&client_secret=$ClientSecret&resource=$resource"
		$response = Invoke-RestMethod -Uri $tokenEndpointUri -Body $content -Method Post -UseBasicParsing
		Write-Host "Got new Access Token!" -ForegroundColor Green
		# If the accesstoken is valid then create the authentication header
		if($response.access_token){
		# Creating header for Authorization token
		$authHeader = @{
			'Content-Type'='application/json'
			'Authorization'="Bearer " + $response.access_token
			'ExpiresOn'=$response.expires_on
			}
		return $authHeader
		}
		else{
			Write-Error "Authorization Access Token is null, check that the client_id and client_secret is correct..."
			break
		}
	}
	catch{
		FatalWebError -Exeption $_.Exception -Function "Get-AuthToken"
	}
}
####################################################

####################################################
Function Get-AppDeviceStatuses(){

<#
.SYNOPSIS
This function is used to get an App Device Statuses from the Graph API REST interface
NAME: Get-AppDeviceStatuses
#>

# Defining Variables
$graphApiVersion = "beta"
$Resource = "deviceAppManagement/mobileApps"
    
    try {
    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$AppID/deviceStatuses"
    $Devices = @()
	do {
        Validate-AuthToken
		$Result = Invoke-RestMethod -Uri $uri -Headers $global:authToken -Method Get
		$Devices += $Result.Value
		$uri = $Result.'@odata.nextLink'
	} while ($uri -ne $null)
	$Devices

    }

    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-Host "Response content:`n$responseBody" -f Red
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

    }

}
####################################################

####################################################
Function Get-GroupMembers(){

<#
.SYNOPSIS
This function is used to get an App Device Statuses from the Graph API REST interface
NAME: Get-AppDeviceStatuses
#>

# Defining Variables
$graphApiVersion = "v1.0"
$Resource = "groups"
    
    try {
    $GroupMemURI = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$GroupID/members"
    $GroupDevices = @()
	do {
        Validate-AuthToken
        write-host "$GroupMemURI"
		$QueryResult = Invoke-RestMethod -Uri $GroupMemURI -Headers $global:authToken -Method Get
		$GroupDevices += $QueryResult.Value
		$GroupMemURI = $QueryResult.'@odata.nextLink'
	} while ($GroupMemURI -ne $null)
	$GroupDevices

    }

    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-Host "Response content:`n$responseBody" -f Red
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

    }

}
####################################################

####################################################
Function Validate-AuthToken{
	# Checking if authToken exists before running authentication
	if($global:authToken){
		# Setting DateTime to Universal time to work in all timezones
		#$DateTime = (Get-Date).ToUniversalTime()
		$CurrentTimeUnix = $((get-date ([DateTime]::UtcNow) -UFormat +%s)).split((Get-Culture).NumberFormat.NumberDecimalSeparator)[0]
		# If the authToken exists checking when it expires
		#$TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes
		$TokenExpires = [MATH]::floor(([int]$authToken.ExpiresOn - [int]$CurrentTimeUnix) / 60)
		if($TokenExpires -le 0){
			write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
			$global:authToken = Get-AuthToken -TenantID $global:TenantID -ClientID $global:ClientID -ClientSecret $global:ClientSecret
		}
	}
	# Authentication doesn't exist, calling Get-AuthToken function
	else {
		# Getting the authorization token
		$global:authToken = Get-AuthToken -TenantID $global:TenantID -ClientID $global:ClientID -ClientSecret $global:ClientSecret
	}
}
####################################################

#Get Token
Validate-AuthToken

$AppID = "ffe33ac5-41ad-43f6-a224-b9d84b0ab1f5"
$GroupID = "f7bf9de4-52a8-474f-ae49-c6f47ff57441"
$Method = "Get"

$AppURL = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$AppID/deviceStatuses"
$GroupURL = "https://graph.microsoft.com/v1.0/groups/$GroupID/members"
$AppNameURL = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$AppID"

$AppQuery = Invoke-RestMethod -Uri $AppURL –Headers $global:authToken –Method $Method
$GroupMemQuery  = Invoke-RestMethod -Uri $GroupURL –Headers $global:authToken –Method $Method
$AppNameQuery = Invoke-RestMethod -Uri $AppNameURL –Headers $global:authToken –Method $Method

$Devices = Get-AppDeviceStatuses #$AppQuery.value.DeviceName
$GroupMembers  = Get-GroupMembers | select DisplayName, TrustType, ManagementType
$Members = $GroupMembers   | select DisplayName, TrustType, ManagementType

function Get-MatchCount
    {
        Foreach($Device1 in $($Devices.devicename))
            {
                [PSCustomObject]@{
                    Device = $Device1
                    Common = $Device1 -in $($Members).displayname
                }
                $i++
                
            }
    }

$MatchingResults1 = @()
$i = 0
<#do
    {
        Write-Progress -Activity "Get Device match" -Status "Progress: $($i/$Devices.devicename.count*100)%"

    }until#>
$MatchingResults1 += Get-MatchCount
$UnknownResults1 = Foreach($member in $($Members | select -Unique))
{
    [PSCustomObject]@{
        User = $member
        Common = $member -notin $Devices
    }
}

# Sample outputs
$final = $MatchingResults | where{$_.Common -eq "True"} | select Device -ExpandProperty Device | select -Unique
foreach($Data in $final)
    {
        Get-AppDeviceStatuses | select UserprincipalName, DeviceName, InstallState, installStateDetail, lastSyncDateTime, errorCode, osVersion, osDescription, @{n="AppName";e={$AppNameQuery.displayName}}, displayVersion | where{$_.DeviceName -eq $Data} | `
        Export-Csv -Path "C:\Temp\Devices_AppReport_$($AppNameQuery.displayName).csv" -Append -NoTypeInformation
    }

$finalunknown = ($UnknownResults | where{$_.Common -eq "True"} | select user).user | select -Unique
$finalunknown | foreach { Add-Content -Path "C:\Temp\Devices_AppReport_$($AppNameQuery.displayName).csv" -value $_}
$inputCSV = Import-Csv "C:\Temp\Devices_AppReport_$($AppNameQuery.displayName).csv" | Sort-Object * -Unique
$inputCsv | Export-Csv "C:\Temp\Devices_AppReport_$($AppNameQuery.displayName).csv" -NoTypeInformation
write-host "Report exported to 'C:\Temp\Devices_AppReport_$($AppNameQuery.displayName).csv'" -ForegroundColor Green
write-host "Devices with App Results : $($Final.count)"
write-host "Devices with Unknown App Results : $($FinalUnknown.count)"

invoke-item "C:\Temp\Devices_AppReport_Microsoft 365 Apps for Windows 10.csv"


