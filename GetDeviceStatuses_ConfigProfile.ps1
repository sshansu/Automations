<#
This sample script is not supported under any Microsoft standard support program or service.
The sample script is provided AS IS without warranty of any kind.
Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
The entire risk arising out of the use or performance of the sample scripts and documentation remains with you.
In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, #without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages
#>

$ExecutionTime = Get-Date
$StartTime = Get-Date $ExecutionTime -Format dd-MM-yyyy-HH-mm-ss

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

# Function to read Device Configuration Assignments
Function Get-ConfigurationPolicyIDs() {
        $Dump = @()
        $DCURL = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?`$select=name,id"
        do {
            Validate-AuthToken
            $QueryResult = Invoke-RestMethod -Uri $DCURL -Headers $global:authToken -Method Get
	        $Dump += $QueryResult.value
	        $DCURL = $QueryResult.'@odata.nextLink'
        } while ($DCURL -ne $null)
        write-host "Retrieved list of configuration profiles" -ForegroundColor Green
        write-host "Count of configuration profiles: $($Dump.count)" -ForegroundColor Green
        write-output $Dump
 }

Function Get-CustomConfigurationPolicyIDs() {
        $Dump = @()
        $CustomURL = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$select=displayName,id"
        do {
            Validate-AuthToken
            $QueryResult = Invoke-RestMethod -Uri $CustomURL -Headers $global:authToken -Method Get
	        $Dump += $QueryResult.value
	        $CustomURL = $QueryResult.'@odata.nextLink' 
        } while ($CustomURL -ne $null)
        $output = $dump | where{$_.'@odata.type' -eq '#microsoft.graph.windows10CustomConfiguration'}
        write-host "Retrieved list of custom configuration profiles" -ForegroundColor Green
        write-host "Count of custom configuration profiles: $($output.count)" -ForegroundColor Green
        write-output $output
}

Function Get-ConfigurationPoliciesDeviceStatuses() {
    Param
        (
            $policyid,
            $policyname,
            [Parameter(Mandatory)]
            [ValidateSet("Settings Catalog", "Custom")]
            $PolicyType
        )

        $count = 0
        $dump = @()
        
        Validate-AuthToken
        Write-host " "
        write-host "Working on $($policyname)" -ForegroundColor Cyan

        $params = @{
	    select = @(
            "DeviceName"
		    "PolicyName"
            "ReportStatus"
	    )
	    filter = "((PolicyBaseTypeName eq 'Microsoft.Management.Services.Api.DeviceConfiguration') or (PolicyBaseTypeName eq 'DeviceManagementConfigurationPolicy') or (PolicyBaseTypeName eq 'DeviceConfigurationAdmxPolicy')) and (PolicyId eq '$($policyid)')"
	    orderBy = @(
	    )
        }
        $body = $params | ConvertTo-Json

        $uri = "https://graph.microsoft.com/beta/deviceManagement/reports/microsoft.graph.getConfigurationPolicyDevicesReport"
        $QueryResult = Invoke-RestMethod -Uri $uri -Headers $global:authToken -Method Post -Body $body
        $array1 = $QueryResult.values

        $newarr1 = @()
        $columns1 = @('DeviceName','PolicyName','ReportStatus')
        foreach ($item1 in $array1){
            $itemlist = $item1 | Select-Object -Unique  #Sort-Object -Property @{Expression={$_.Trim()}} -Unique
            $obj = New-Object PSObject
            for ($i=0; $i -lt $columns1.Length; $i++){
                $obj | Add-Member -MemberType NoteProperty -Name $columns1[$i] -Value $itemlist[$i]
            }
            $newarr1+=$obj
            $obj=$null
        }
        if($PolicyType -eq "Settings Catalog"){ $Type = $PolicyType } elseif($PolicyType -eq "Custom") { $Type = $PolicyType } 
        $newarr1 | Export-Csv "C:\temp\ConfigurationPolicyDeviceStatus_$($Type).csv" -NoTypeInformation -Append
        write-host "Exported results from: $($policyname)" -ForegroundColor Green
 }
 
#Dump Device statuses for Configuration Profiles based on settings catalog
WRite-host "Checking for Settings Catalog device statuses" -ForegroundColor Green
$Policies = Get-ConfigurationPolicyIDs 
Foreach($policy in $Policies)
    {
        Get-ConfigurationPoliciesDeviceStatuses -policyid $policy.id -policyname $policy.name -PolicyType 'Settings Catalog'
    }

#Dump Device statuses for Configuration Profiles based on custom policies
WRite-host " "
WRite-host "Checking for Custom Policy device statuses" -ForegroundColor Green
$customPolicies = Get-CustomConfigurationPolicyIDs
Foreach($policy in $customPolicies)
    {
        Get-ConfigurationPoliciesDeviceStatuses -policyid $policy.id -policyname $policy.displayName -PolicyType Custom
    }