[cmdletbinding()]
param (
    [Parameter(Mandatory=$false)]
    [string]$ApplicationName, 
    [Parameter(Mandatory=$false)]
    [string]$DeviceName
)

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
####################################################

# get user id
Function Get-UserID(){
    param($DeviceName)

    $table = @()

    # Get Device ID
    $DeviceURI = "https://graph.microsoft.com/beta/deviceManagement/manageddevices?`$filter=deviceName eq '$DeviceName'&`$select=id"
    $Deviceoutput = Invoke-RestMethod -Uri $DeviceURI -Headers $global:authToken -Method Get
    $DeviceResult = $Deviceoutput.value

    # Get User ID
    $UserURI = "https://graph.microsoft.com/beta/deviceManagement/manageddevices('$($DeviceResult.Id)')/users?`$select=id, displayName"
    $UserOutput = Invoke-RestMethod -Uri $UserURI -Headers $global:authToken -Method Get
    $UserResult = $UserOutput.value

    $table += New-Object -TypeName PSCustomObject -Property @{
    DeviceName = $DeviceName
    DeviceID = $DeviceResult.Id
    UserName = $UserResult.displayName
    UserID = $UserResult.id
    }

write-output $table
}

# Get application state
Function Get-AppInstallState() {
param($ApplicationName)

    $Uri = "https://graph.microsoft.com/beta/users('$($Uid.UserID)')/mobileAppIntentAndStates('$($Uid.DeviceID)')"
    $value = Invoke-RestMethod -Uri $Uri -Headers $global:authToken -Method Get
    $AppResult = $value.mobileAppList | where{$_.displayName -eq $ApplicationName} | select displayName, installState
    if($AppResult)
        {
            Write-output $AppResult 
        }
    else
        {
            Write-host "No such app found" -ForegroundColor Red
        }
    }

$UID = Get-UserID -DeviceName $DeviceName
Get-AppInstallState -ApplicationName $ApplicationName
