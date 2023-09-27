<#
This sample script is not supported under any Microsoft standard support program or service.
The sample script is provided AS IS without warranty of any kind.
Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
The entire risk arising out of the use or performance of the sample scripts and documentation remains with you.
In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, #without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages
#>

[cmdletbinding()]
param (
    [Parameter(Mandatory)]
    $DeviceName, 
    [Parameter(Mandatory)]
    [ValidateSet("True","False")]
    $KeepEnrollmentData,
    [Parameter(Mandatory)]
    [ValidateSet("True","False")]
    $KeepUserData,
    [Parameter(Mandatory)]
    [ValidateSet("True","False")]
    $UseProtectedWipe
)


$ExecutionTime = Get-Date
$StartTime = Get-Date $ExecutionTime -Format dd-MM-yyyy-HH-mm-ss

#Initialize Variables
#$global:authToken = $null
$global:TenantID = ""
$global:ClientID = ""
$global:ClientSecret = ""
$LogFile = "C:\Windows\Temp\graph.log"

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
		#FatalWebError -Exeption $_.Exception -Function "Get-AuthToken"
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

Validate-AuthToken

# Begin Function to wipe device

Function Wipe-device(){

    param($DeviceName)

    Write-host "Working on $DeviceName" -ForegroundColor Cyan

    # Get Device ID
    $DeviceURI = "https://graph.microsoft.com/beta/deviceManagement/manageddevices?`$filter=deviceName eq '$DeviceName'&`$select=id,deviceName"
    $Deviceoutput = Invoke-RestMethod -Uri $DeviceURI -Headers $global:authToken -Method Get
    $DeviceResult = $Deviceoutput.value
    
    # invoke wipe
    $params = @{
    keepEnrollmentData = "$($KeepEnrollmentData)";
    keepUserData = "$($KeepUserData)";
    useProtectedWipe = "$($UseProtectedWipe)"
    }
    $wipeRequest = $params | ConvertTo-Json

    # Begin
    $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$($DeviceResult.Id)')/wipe"
    $output = Invoke-RestMethod -Uri $uri -Headers $global:authToken -Method POST -Body $wipeRequest

    $table = @()
    # Get results 
    $ResultsURI = "https://graph.microsoft.com/beta/deviceManagement/manageddevices('$($DeviceResult.Id)')?$select=deviceactionresults"
    $WipeResult = Invoke-RestMethod -Uri $ResultsURI -Headers $global:authToken -Method Get
    $wipestatus = $WipeResult.deviceActionResults
    [datetime]$startDateTime = $wipestatus.startDateTime

    # Hash results
    $table += New-Object -TypeName PSCustomObject -Property @{
    DeviceName = $DeviceResult.deviceName
    ActionState = $wipestatus.actionState
    WipeStartTime = $startDateTime | get-date -Format g
    }
    
    Write-Output $table
}

Wipe-device -DeviceName $DeviceName
Write-host "Done!" -ForegroundColor Cyan



