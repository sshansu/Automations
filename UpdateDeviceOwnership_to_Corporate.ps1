<#
This sample script is not supported under any Microsoft standard support program or service.
The sample script is provided AS IS without warranty of any kind.
Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
The entire risk arising out of the use or performance of the sample scripts and documentation remains with you.
In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, #without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages
#>

#Initialize Variables
#$global:authToken = $null
$global:TenantID = "1d2f5bab-e836-4ffa-9e9c-b6fc5d8998ee"
$global:ClientID = "2922e832-ce02-4fcd-a0cb-e85c791d9ebf"
$global:ClientSecret = "iXZ8Q~9pOZaiBm1UFVy_sdgLScYk-4irky9oja6T"

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

Function Get-GroupMembership() {
Param($GroupName)

    try
        {
            $GroupURI = "https://graph.microsoft.com/beta/groups?`$filter=displayName eq '$GroupName'" # &`$select=id,displayName"
            $GroupOutput = Invoke-RestMethod -Uri $GroupURI -Headers $global:authToken -Method Get
            $GMResult = $GroupOutput.value

            $GroupMemberURI = "https://graph.microsoft.com/beta/groups/$($GMResult.id)/members?`$select=displayName"
            $GroupMemberOutput = Invoke-RestMethod -Uri $GroupMemberURI -Headers $global:authToken -Method Get
            $DeviceResult = $GroupMemberOutput.value
            write-output $DeviceResult
        }
    catch [system.exception]
        {
            write-host $_.exception.message
        }
}

Function Update-DeviceOwnership() {
Param($DeviceName)

    try
        {
            $DeviceURi = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=deviceName eq '$DeviceName'&`$select=id,deviceName"
            $DeviceOutput = Invoke-RestMethod -Uri $DeviceURi -Headers $global:authToken -Method Get -ErrorAction Stop
            $DeviceResult = $DeviceOutput.value

            $PatchURI = "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$($DeviceResult.id)')"
            $BodyContent = @{
                    "ownerType"="company"
                } | ConvertTo-Json

            $PatchOutput = Invoke-RestMethod -Uri $PatchURI -Headers $global:authToken -Method Patch -Body $BodyContent -ErrorAction Stop
            if(!($PatchOutput))
                {
                    write-host "Updated ownership of $DeviceName to 'Company'" -ForegroundColor cyan
                }
        }
    catch [System.Exception]
        {
            write-host "Failed to update ownership type of $DeviceName due to $($_.exception.message)" -ForegroundColor Green
        }
}

$Group = Read-Host "Enter device group consisting of personal windows devices"
$Devices = Get-GroupMembership -GroupName $Group

#begin
write-host "Group Name: $($Group)" -ForegroundColor Yellow
write-host "Total devices: $($Devices.Count)" -ForegroundColor Yellow
write-host "Begin with change of device ownership" -ForegroundColor Yellow
Foreach($Device in $Devices.displayName)
    {
        Update-DeviceOwnership -DeviceName $Device
    }

write-host "Done!" -ForegroundColor Green




