<#
This sample script is not supported under any Microsoft standard support program or service.
The sample script is provided AS IS without warranty of any kind.
Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
The entire risk arising out of the use or performance of the sample scripts and documentation remains with you.
In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, #without limitation, damages for 
loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if 
Microsoft has been advised of the possibility of such damages

This script requires azure application registered with below permissions granted to graph API

Device.ReadWrite.All
DeviceManagementManagedDevices.ReadWrite.All
Directory.Read.All
Group.Read.All
GroupMember.Read.All
User.Read

The script updates extension attribute to a particular region for all the iOS and Android for Work devices owned by users of a specific group. 
Specify the User Group Name and Device Location on lines 106 and 107
Once the script executes, create a dynamic device group using ExtensionAttribute criteria. 

#>

#Initialize Variables
#$global:authToken = $null
$global:TenantID = ""
$global:ClientID = ""
$global:ClientSecret = ""

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

Write-host ""
Write-host "Starting script...." -ForegroundColor Yellow
$GroupName = "Licensed Users"
$DeviceLocation = "Delhi"

# Function to query group membership
Function Get-GroupMembership() {
Param($GroupName)

    try
        {
            $GroupURI = "https://graph.microsoft.com/beta/groups?`$filter=displayName eq '$GroupName'&`$select=id,displayName"
            $GroupOutput = Invoke-RestMethod -Uri $GroupURI -Headers $global:authToken -Method Get
            $GMResult = $GroupOutput.value

            $GroupMemberURI = "https://graph.microsoft.com/beta/groups/$($GMResult.id)/members?`$select=id,displayName"
            $GroupMemberOutput = Invoke-RestMethod -Uri $GroupMemberURI -Headers $global:authToken -Method Get
            $DeviceResult = $GroupMemberOutput.value | select id, displayName
            write-output $DeviceResult
        }
    catch [system.exception]
        {
            write-host $_.exception.message
        }
    
}

# Function to get iOS and Android devices owned by group members
Function Get-UserDevices(){
    param($Userid, $UserName)

    $table = @()
    $URL = "https://graph.microsoft.com/beta/users/$($Userid)/ownedDevices?`$select=displayName,operatingSystem,id,deviceId"
    $Output = Invoke-RestMethod -Uri $URL -Headers $global:authToken -Method Get
    $Result = $Output.value | where{($_.operatingSystem -in ('IPad','AndroidForWork'))}  ##--- ADD MORE OSes IF NEEDED
    if(!($Result)){}else{
    $table += New-Object -TypeName PSCustomObject -Property @{
            Userid = $Userid
            UserName = $UserName
            Id = $Result.id
            DeviceId = $Result.deviceId
            device = $Result.displayName
            OS = $Result.operatingSystem
        }
    }
    Write-Output $table
  }

# Function to update extension attribute to local region
Function Update-ExtentionAttribute {
    param($id, $device, $extension)
    $URI = "https://graph.microsoft.com/v1.0/devices/$($id)"

    # Construct the update data
    $params = @{
        extensionAttributes = @{
            extensionAttribute2 = $extension
        }
    }
    $body = $params | ConvertTo-Json

    try 
        {
            $result = Invoke-RestMethod -Uri $URI -Method Patch -Headers $global:authToken -Body $body
            if(!($result)) 
                {
                    Write-Host "Updated extension attribute of $($device) to $($extension)" -ForegroundColor Cyan
                }
        } 
    catch [system.exception]
        {
            Write-Host "Failed to update extension attribute of $($device) due to $($_.exception.message)" -ForegroundColor Red
        }
}

# Begin query
$users = Get-GroupMembership -GroupName $GroupName
Write-host "Total members in $($GroupName): $($users.count)" -ForegroundColor Yellow
Write-host "Location to update: $DeviceLocation" -ForegroundColor Yellow

Foreach($user in $users)
    {
       sleep 2
       Write-host "Working on $($user.displayName)" -ForegroundColor Cyan
       $Devices = Get-UserDevices -Userid $user.id -UserName $user.displayName
       foreach($Item in $Devices)
            {
                Update-ExtentionAttribute -id $Item.id -device $Item.device -extension $DeviceLocation
            }
    }

Write-Host "Done!" -ForegroundColor Green
