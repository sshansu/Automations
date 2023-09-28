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
Group.Read.All
GroupMember.Read.All

For the script to work, you must have exported the imported GPO settings in a CSV Format. We'll have to execute Export_GPOSettings_from_GPOAnalytics.ps1 first. 
#>

#Initialize Variables
#$global:authToken = $null

#DeviceName	SettingName	SettingStatus	ComplianceStatus	Grace Period	compliance Name
#   PC1	        WLS	    Non-Compliant	    In-grace	    date expiry	

# 1. input group name
# 2. for each machine in group, get compliance setting status as per above format 

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

Function Get-UserDeviceID(){
    param($DeviceName)

    $table = @()
    try
        {
            # Get Device ID
            $DeviceURI = "https://graph.microsoft.com/beta/deviceManagement/manageddevices?`$filter=deviceName eq '$DeviceName'&`$select=id,deviceName,complianceState,complianceGracePeriodExpirationDateTime"
            $Deviceoutput = Invoke-RestMethod -Uri $DeviceURI -Headers $global:authToken -Method Get
            $DeviceResult = $Deviceoutput.value

            # Get User ID
            $UserURI = "https://graph.microsoft.com/beta/deviceManagement/manageddevices('$($DeviceResult.Id)')/users?`$select=id, displayName"
            $UserOutput = Invoke-RestMethod -Uri $UserURI -Headers $global:authToken -Method Get 
            $UserResult = $UserOutput.value

            $table += New-Object -TypeName PSCustomObject -Property @{
            DeviceName = $DeviceName
            DeviceID = $DeviceResult.Id
            ComplianceState = $DeviceResult.complianceState
            GracePeriodExpireDT = $DeviceResult.complianceGracePeriodExpirationDateTime
            UserName = $UserResult.displayName
            UserID = $UserResult.id
            }
        }
    catch [system.exception]
        {
            write-host $_.exception.message
        }
write-output $table
}

Function Get-CompliancePolicy(){
    param($ComplianceName)
    try
        {
            $URL = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies?`$select=id,displayName,version"
            $Output = Invoke-RestMethod -Uri $URL -Headers $global:authToken -Method Get
            $value = $Output.value | where{$_.displayName -eq $ComplianceName} | select id,displayName,version
            $value
        }
    catch [system.exception]
        {
            write-host $_.exception.message
        }
}

Function Get-ComplianceSettingStatus() {
param($DeviceName, $ComplianceName, $Setting)
        
        # Get Params

        $ComplianceID = Get-CompliancePolicy -ComplianceName "Compliance Policy _ W"
        $UserDeviceID = Get-UserDeviceID -DeviceName $DeviceName

        $uri2 = "https://graph.microsoft.com/beta/deviceManagement/reports/getDevicePolicySettingsComplianceReport"
        $params1 = @{
	        select = @(
	        )
	        skip = 0
	        top = 50
	        filter = "(DeviceId eq '$($UserDeviceID.DeviceID)') and (PolicyId eq '$($ComplianceID.id)') and (UserId eq '$($UserDeviceID.UserID)') and (PolicyVersion eq '$($ComplianceID.version)')"
	        orderBy = @(
		        "SettingName asc"
	        )
	        search = ""
        }

        $body1 = $params1 | ConvertTo-Json
        $result1 = Invoke-restmethod -Uri $Uri2 -Headers $global:authToken -Method Post -Body $body1
        [array]$value = $result1.values
        [array]$a = $value

        # Convert the input text to an array of lines
                $inputOutput = $value | out-string
        $lines = $inputOutput -split "`r`n"

        # Initialize variables to store the data
        $settingName = $null
        $status = $null

        # Loop through the lines and extract the required data
        for($i = 0; $i -lt $lines.Length; $i++) {
            if ($lines[$i] -eq $Setting) {
                $settingName = $lines[$i]
                break
            }
        }

        for($i = 0; $i -lt $lines.Length; $i++) {
            if ($lines[$i] -match "compliant") {
                $status = $lines[$i]
                break
            }
        }

        # Output the result in the desired format
        $hash = @()
        if ($settingName -ne $null -and $status -ne $null) 
            {
                $hash += New-Object -TypeName PSCustomObject -Property @{
                DeviceName = $DeviceName
                SettingName = $settingName
                Status = $status
                CompliancePolicy = $ComplianceName
                ComplianceState = $UserDeviceID.ComplianceState
                GracePeriodExpireDT = $UserDeviceID.GracePeriodExpireDT
                }
            } 
        else 
            {
                Write-Host "Data not found in the input for $DeviceName" -ForegroundColor red
            }

        write-output $hash 

}

$table = @()
$Group = "All Devices"
$Policy = "Compliance Policy _ W"
$Setting = "AppPresent"

$FullList = Get-GroupMembership -GroupName $Group
$Devices = $FullList.displayName | select -Unique
Write-host "Total Devices: $($Devices.count)" -ForegroundColor Cyan
Write-host "Processing compliance results" -ForegroundColor Cyan
foreach($Device in $Devices)
    {
        write-host "Working on $Device" -ForegroundColor Yellow
        $Results = Get-ComplianceSettingStatus -DeviceName $Device -ComplianceName $Policy -Setting $Setting
        if($Results -notmatch "Data not found in the input")
            {
                $table += New-Object -TypeName PSCustomObject -Property @{
                DeviceName = $Results.DeviceName
                SettingName = $Results.SettingName
                Status = $Results.Status
                CompliancePolicy = $Results.CompliancePolicy
                ComplianceState = $Results.ComplianceState
                GracePeriodExpireDT = $Results.GracePeriodExpireDT
            }
        }
        
    }
 $table | select DeviceName, SettingName, Status, CompliancePolicy, ComplianceState, GracePeriodExpireDT | `
 Export-Csv -Path $exportfile -Append -NoTypeInformation
 Write-host "Exported report to $exportfile" -ForegroundColor Green
